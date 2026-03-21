# TokenFlare Architecture & Technical Wiki

## What is TokenFlare?

TokenFlare is a **serverless Adversary-in-the-Middle (AiTM) phishing framework** targeting Microsoft Entra ID (Azure AD) OAuth flows. It deploys as a Cloudflare Worker — a lightweight JavaScript function running on Cloudflare's edge network — that acts as a transparent HTTPS reverse proxy between a victim's browser and Microsoft's login infrastructure (`login.microsoftonline.com`).

The victim sees the **real Microsoft login page**, completes **real MFA**, and is redirected to a legitimate destination. TokenFlare silently captures credentials, authorization codes, session cookies, and (with the webhook auto-exchange feature) full access + refresh tokens — all without disrupting the authentication flow.

---

## How AiTM Phishing Differs from Other Techniques

### AiTM (TokenFlare) vs Traditional Credential Phishing

| Aspect | Traditional Phishing | AiTM (TokenFlare) |
|--------|---------------------|-------------------|
| Login page | Fake clone (static HTML) | Real Microsoft page (proxied) |
| MFA | Defeated only by real-time relay | Defeated by design — captures post-MFA session |
| Victim experience | May notice visual differences | Indistinguishable from real login |
| What's captured | Username + password only | Credentials + auth codes + session cookies + tokens |
| Maintenance | Must update cloned pages when MS changes UI | Zero maintenance — always shows current MS page |

### AiTM (TokenFlare) vs Illicit Consent Grant

| Aspect | AiTM (TokenFlare) | Illicit Consent Grant |
|--------|-------------------|----------------------|
| Attack vector | Proxy intercepts real authentication | Malicious app requests OAuth consent |
| Victim action | Enters credentials + completes MFA | Clicks "Accept" on consent prompt |
| What's captured | Full session (creds, tokens, cookies) | Scoped API access (only consented permissions) |
| MFA involvement | Captures and bypasses MFA | No MFA involved (user already authenticated) |
| Persistence | Until tokens expire / sessions revoked | Until consent is revoked (potentially indefinite) |
| Detection | Anomalous sign-in IP in Entra logs | New app consent grant in audit logs |
| Prevention | FIDO2/passkeys (origin-bound MFA) | Restrict user consent, require admin approval |

### AiTM (TokenFlare) vs Other AiTM Tools

| Aspect | TokenFlare | Evilginx / Modlishka / Muraena |
|--------|-----------|-------------------------------|
| Infrastructure | Cloudflare Worker (serverless) | Standalone reverse proxy on a VPS |
| TLS certificate | Automatic from Cloudflare | Manual (Let's Encrypt / certbot) |
| Setup time | Minutes | 30-60 minutes (VPS + DNS + certs) |
| Takedown resistance | Serverless = no single server to block | IP-based blocking is straightforward |
| Code size | ~600 lines of JavaScript | Thousands of lines (Go binaries) |
| Deployment | `wrangler deploy` | Install binary, configure, run |
| Local testing | `wrangler dev` | Run binary locally |

---

## Architecture Overview

### Core Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TokenFlare System                            │
│                                                                     │
│  ┌──────────────┐   ┌───────────────┐   ┌────────────────────────┐ │
│  │ Python CLI   │   │ Worker        │   │ Webhook Listener       │ │
│  │              │   │ (src/worker.js)│   │ (tokenflare-webhook.py)│ │
│  │ tokenflare.py│   │               │   │                        │ │
│  │ lib/         │   │ Runs on CF    │   │ Runs locally           │ │
│  │  cli.py      │   │ edge or local │   │                        │ │
│  │  commands.py │   │ via wrangler  │   │ Endpoints:             │ │
│  │  config.py   │   │               │   │  POST /webhook         │ │
│  │  utils.py    │   │               │   │  POST /exchange        │ │
│  │  __init__.py │   │               │   │  GET /                 │ │
│  └──────────────┘   └───────────────┘   └────────────────────────┘ │
│         │                   │                       │               │
│    Configures          Captures &              Receives,            │
│    wrangler.toml       proxies               exchanges,             │
│    and certs           traffic               stores tokens          │
└─────────────────────────────────────────────────────────────────────┘
```

### 1. The Worker (`src/worker.js`)

The Worker is the core — approximately 600 lines of JavaScript that implements the entire AiTM proxy. It runs on the Cloudflare Workers runtime (V8 JavaScript engine) either on Cloudflare's global edge network or locally via `wrangler dev`.

**Request pipeline (the `fetch` handler):**

```
Incoming Request
    │
    ▼
1. preflightBlocks()     ── IP filtering, User-Agent checks, AS org blocking
    │                        Blocks bots, scrapers, and unauthorized IPs
    │
    ▼
2. makeUpstreamUrl()     ── Routes the request:
    │                        /verifyme?uuid=VALID → proxy to Microsoft OAuth
    │                        /verifyme?uuid=INVALID → redirect to UNAUTH_REDIR
    │                        / (root) → redirect to UNAUTH_REDIR
    │                        /other/paths → pass-through proxy to upstream
    │
    ▼
3. Credential Capture    ── For POST requests: clone body, parse login/passwd
    │  (non-blocking)        fields, send to webhook via notifyCredentials()
    │
    ▼
4. Proxy to Upstream     ── fetch() to login.microsoftonline.com with:
    │                        - Rewritten Host, Origin, Referer headers
    │                        - Custom or proxied User-Agent
    │                        - X-TokenFlare IoC header
    │                        - redirect: 'manual' (intercept 302s)
    │
    ▼
5. Response Processing   ── Inspect the upstream response:
    │
    ├─► Location header  ── If contains redirect_uri + code=:
    │   analysis              - Parse auth code, client_id, redirect_uri
    │                         - Send structured JSON to /exchange endpoint
    │                         - Send human-readable alert to /webhook
    │                         - Rewrite Location to FINAL_REDIR
    │
    ├─► Cookie capture   ── If Set-Cookie contains ESTSAUTH:
    │                         - Notify cookies to webhook
    │
    ├─► Cookie rewrite   ── Replace login.microsoftonline.com domain
    │                        with proxy domain in all Set-Cookie headers
    │
    ├─► Security header  ── Remove CSP, X-Frame-Options, Clear-Site-Data
    │   relaxation           Add permissive CORS headers
    │
    └─► Body rewrite     ── For text responses: replace all occurrences of
                             login.microsoftonline.com with proxy hostname
                             so relative links point back through the proxy
```

### 2. The Python CLI (`tokenflare.py` + `lib/`)

A convenience wrapper for configuration and deployment. Not involved in the proxy flow at all.

| Command | What it does |
|---------|-------------|
| `init <domain>` | Generates 20 UUIDs, self-signed cert, updates wrangler.toml |
| `configure campaign` | Interactive wizard: OAuth flow, lure paths, webhook URL |
| `configure cf` | Stores Cloudflare API credentials for remote deployment |
| `configure ssl` | Let's Encrypt cert via certbot, or manual cert paths |
| `deploy local` | Runs `wrangler dev` with HTTPS on port 443 |
| `deploy remote` | Runs `wrangler deploy` to Cloudflare |
| `status` | Shows current configuration and lure URLs |

### 3. The Webhook Listener (`tokenflare-webhook.py`)

A local Python HTTP server that receives notifications from the Worker and automatically exchanges auth codes for tokens.

**Two endpoints, two purposes:**

| Endpoint | Purpose | Data flow |
|----------|---------|-----------|
| `POST /webhook` | Human-readable notifications | Worker → display creds/codes/cookies in terminal |
| `POST /exchange` | Structured auth code payload | Worker → parse → exchange with Entra → store tokens |

**Auto-exchange flow:**

```
Worker captures auth code in Location header
    │
    ├──► POST /webhook     "Auth Code Obtained! Code URL: ..."
    │    (human-readable)   Displayed in terminal
    │
    └──► POST /exchange    { code, client_id, redirect_uri, scope }
         (structured JSON)
              │
              ▼
         exchange_auth_code()
              │
              ▼
         POST https://login.microsoftonline.com/common/oauth2/v2.0/token
              grant_type=authorization_code
              client_id=<from payload>
              redirect_uri=<from payload>
              code=<from payload>
              │
              ▼
         Receives: access_token + refresh_token + id_token
              │
              ├──► Display in terminal (color-coded, JWT decoded)
              ├──► Save to loot.json (JSONL format)
              └──► Push to TokenSmith (optional, --tokensmith-url)
```

**Why no `client_secret` is needed:** All OAuth clients used by TokenFlare are **public clients** (native/SPA applications registered by Microsoft). Public clients authenticate with only `client_id` + `redirect_uri` — no secret, no certificate, no PKCE code verifier.

---

## The Phishing Flow in Detail

### Step-by-step: What happens when a victim clicks the lure

```
Step 1: Victim clicks lure URL
        https://evil.workers.dev/verifyme?uuid=550e8400-...

Step 2: Worker validates UUID against LURE_UUID list
        ✓ Valid → proxy to Microsoft OAuth
        ✗ Invalid → redirect to UNAUTH_REDIR (looks like nothing happened)

Step 3: Worker redirects victim to Microsoft login
        302 → https://login.microsoftonline.com/common/oauth2/v2.0/authorize
              ?client_id=1950a258-...
              &redirect_uri=https://login.microsoftonline.com/.../nativeclient
              &scope=openid+offline_access+https://graph.microsoft.com/.default

        But the browser shows: https://evil.workers.dev/common/oauth2/v2.0/authorize...
        (domain is the proxy, content is real Microsoft)

Step 4: Victim sees real Microsoft login page
        Enters username → real Entra processes it
        Enters password → POST body captured by Worker (non-blocking clone)
        Completes MFA → real Entra processes it

Step 5: Entra issues auth code via 302 redirect
        Location: https://login.microsoftonline.com/.../nativeclient?code=0.AXkA...

        Worker intercepts this Location header:
        - Extracts auth code, client_id, redirect_uri
        - Sends structured JSON to webhook /exchange endpoint
        - Rewrites Location to FINAL_REDIR (e.g., office.com)

Step 6: Victim's browser follows rewritten redirect
        → lands on office.com (or whatever FINAL_REDIR is set to)
        Victim thinks: "I just logged in normally"

Step 7: Webhook listener receives auth code
        → Immediately exchanges with Entra for tokens
        → access_token + refresh_token obtained in <2 seconds
        → Tokens saved to loot.json
        → Optionally pushed to TokenSmith for enumeration

Step 8: Worker captures session cookies
        ESTSAUTH and ESTSAUTHPERSISTENT cookies from Set-Cookie headers
        → Sent to webhook for session hijacking capability
```

### What the attacker now has

| Artifact | Use | Lifetime |
|----------|-----|----------|
| Username + password | Credential reuse, password spray other services | Until password changed |
| Access token | Direct API access (Graph, ARM, etc.) | ~1 hour |
| Refresh token | Mint new access tokens, FOCI exchange | Days to weeks |
| ID token | User identity claims, tenant info | ~1 hour |
| Session cookies | Browser session hijacking | Session lifetime |

---

## OAuth Flow Configurations

TokenFlare supports multiple OAuth upstream paths, each with different capabilities:

| Flow | Client ID | FOCI? | Refresh Token? | Best for |
|------|-----------|-------|----------------|----------|
| **Graph + FOCI** (recommended) | `1950a258` (Azure PowerShell) | Yes (family 1) | Yes (`offline_access`) | TokenSmith integration, full post-exploitation |
| OfficeHome | `4765445b` (Office) | No | No (missing `offline_access`) | Quick credential capture only |
| Teams | `1fec8e78` (Teams) | Yes (family 1) | Yes | Alternative FOCI client |
| Intune | `9ba1a5c7` (Intune) | Yes (family 1) | Yes | Conditional Access device bypass |

### Why FOCI matters

FOCI (Family of Client IDs) is a Microsoft identity platform feature where refresh tokens from one app in the "family" can be exchanged for access tokens to any other app in the same family. Family 1 includes ~160 Microsoft applications: Teams, Outlook, OneDrive, SharePoint, Azure CLI, Power BI, and more.

A single refresh token from TokenFlare → TokenSmith can enumerate the entire family:
```
Captured refresh token (Azure PowerShell)
    → Exchange for Teams token → read Teams messages
    → Exchange for Outlook token → read email
    → Exchange for OneDrive token → access files
    → Exchange for SharePoint token → access sites
    → Exchange for ARM token → enumerate Azure infrastructure
```

---

## Local Deployment

### How it works

`wrangler dev` runs the Cloudflare Workers runtime locally using `workerd` — Cloudflare's open-source C++ runtime based on the V8 JavaScript engine. This is the **same runtime** used on Cloudflare's edge network, just running on your machine.

```
┌─────────────────────────────────────────────────┐
│  Your Machine                                    │
│                                                  │
│  ┌──────────────┐    ┌───────────────────────┐  │
│  │ Browser      │    │ wrangler dev          │  │
│  │              │◄──►│                       │  │
│  │ https://     │    │ workerd runtime (V8)  │  │
│  │ localhost:   │    │ ┌───────────────────┐ │  │
│  │ 8443/        │    │ │ src/worker.js     │ │  │
│  │ verifyme?    │    │ │ (your proxy code) │ │  │
│  │ uuid=...     │    │ └────────┬──────────┘ │  │
│  └──────────────┘    │          │            │  │
│                      └──────────┼────────────┘  │
│                                 │               │
│  ┌──────────────┐               │               │
│  │ tokenflare-  │               │               │
│  │ webhook.py   │◄──────────────┘               │
│  │ :9999        │         webhook notifications │
│  └──────────────┘                               │
└─────────────────────────────────────────────────┘
                          │
                          │ HTTPS (outbound only)
                          ▼
                ┌───────────────────┐
                │ login.microsoft   │
                │ online.com        │
                │ (real Entra ID)   │
                └───────────────────┘
```

### Local vs Remote deployment

| Aspect | Local (`wrangler dev`) | Remote (`wrangler deploy`) |
|--------|----------------------|---------------------------|
| Runtime | workerd on your machine | Cloudflare edge (200+ cities) |
| TLS cert | Self-signed (browser warning) | Cloudflare-issued (trusted) |
| Reachability | localhost / LAN only | Public internet |
| Cloudflare account | Not required | Required (free tier works) |
| Use case | Testing, research, lab environments | Live engagements |
| IP in Entra logs | Your machine's public IP | Cloudflare edge IP |
| `cf-connecting-ip` | Not available (preflightBlocks limited) | Real client IP |
| Cost | Free | Free tier: 100K requests/day |

### Local deployment limitations

1. **Self-signed certificate** — Browsers show `ERR_CERT_AUTHORITY_INVALID`. Acceptable for testing (click through the warning) but a dead giveaway in a real engagement.

2. **Not internet-reachable** — Only your machine (or LAN) can access the proxy. For testing, this is actually a feature — you can't accidentally phish someone.

3. **No `cf-connecting-ip`** — The Worker uses this Cloudflare header for IP-based blocking. Locally, this header doesn't exist, so IP allowlisting/blocklisting is non-functional.

4. **Port binding** — Port 443 requires root/admin. Use a high port like 8443 for local testing.

---

## OpSec Features

### Bot and scanner detection

The Worker blocks requests based on:

- **IP prefix blocking** — Known scanner/cloud IPs (8.8.8.x, etc.)
- **IP allowlisting** — Restrict to specific IPs during testing
- **User-Agent filtering** — Blocks googlebot, bingbot, and other crawlers
- **AS Organization blocking** — Blocks traffic from Google, Digital Ocean, etc.
- **Mozilla check** — Requires `Mozilla/5.0` in UA (filters non-browser clients)

### UUID-gated lure URLs

Each phishing link includes a UUID: `/verifyme?uuid=550e8400-...`. The Worker validates the UUID against a configured list. Invalid or missing UUIDs redirect to `UNAUTH_REDIR` (default: office.com) — the proxy is invisible to anyone without a valid lure link.

20 UUIDs are generated during `init`, allowing unique tracking per target.

### Intentional IoCs

For authorized testing, the Worker adds detectable markers:

```
Header:     X-TokenFlare: Authorised-Security-Testing
User-Agent: TokenFlare/1.0 For_Authorised_Testing_Only
```

Both are configurable in `wrangler.toml` and would be removed by a real attacker.

---

## Detection and Defense

### How to detect AiTM phishing (blue team perspective)

| Detection Layer | What to look for |
|----------------|-----------------|
| **Browser** | URL bar shows a domain other than `login.microsoftonline.com` during login |
| **Entra sign-in logs** | Sign-in from unusual IP/ASN (Cloudflare IPs or attacker VPS) |
| **Entra sign-in logs** | Successful MFA followed by immediate token use from a different IP |
| **Network** | DNS requests for suspicious domains during authentication |
| **SIEM** | Multiple users authenticating from the same IP in a short window |
| **Conditional Access** | Sign-in from non-compliant device (attacker replaying token) |

### Effective defenses

| Defense | Effectiveness | Why |
|---------|--------------|-----|
| **FIDO2 / Passkeys** | Defeats AiTM completely | Origin-bound — cryptographic proof tied to `login.microsoftonline.com` domain. A proxy domain cannot satisfy the challenge. |
| **Compliant device requirement** | Prevents token replay | Attacker has the token but not the device. Token can't be used from an unmanaged machine. |
| **Token Protection** | Prevents token export | Binds tokens to the device's PRT (Primary Refresh Token). Tokens can't be used on a different device. |
| **CAE (Continuous Access Evaluation)** | Limits damage window | Revokes tokens in near-real-time when security events occur (password change, disable account, IP change). |
| **Sign-in risk policies** | May detect anomalies | Impossible travel, anonymous IP, unfamiliar sign-in properties. But AiTM can evade by proxying from a plausible location. |

### What does NOT work

| Defense | Why it fails against AiTM |
|---------|--------------------------|
| SMS/TOTP MFA | Captured post-completion — the proxy relays the MFA challenge and response |
| Push notification MFA | User approves on their real device; the proxy captures the resulting session |
| Password complexity | Credentials are entered into the real Microsoft page — complexity is irrelevant |
| Email link scanning | The lure URL is a real HTTPS site (Cloudflare-certified domain) — link scanners may not flag it |
| IP blocklisting | Cloudflare has thousands of edge IPs; blocking them blocks legitimate Cloudflare traffic |

---

## File Reference

| File | Purpose | Lines |
|------|---------|-------|
| `src/worker.js` | AiTM proxy — the entire attack surface | ~600 |
| `tokenflare-webhook.py` | Webhook listener + auto token exchange + TokenSmith push | ~350 |
| `tokenflare.py` | CLI entry point | ~10 |
| `lib/__init__.py` | Constants: OAuth URLs, display names, defaults | ~40 |
| `lib/cli.py` | Argument parsing, command dispatch | ~190 |
| `lib/commands.py` | All command implementations (init, configure, deploy, status) | ~930 |
| `lib/config.py` | TOML parsing, Cloudflare API testing | ~150 |
| `lib/utils.py` | Cert generation, UUID generation, cross-platform admin check | ~120 |
| `wrangler.toml` | Worker configuration: OAuth paths, lure settings, webhook URL | ~75 |

---

## References

- [TokenFlare Blog Post (JUMPSEC Labs)](https://labs.jumpsec.com/tokenflare-serverless-AiTM-phishing-in-under-60-seconds/)
- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
- [Wrangler CLI (workers-sdk)](https://github.com/cloudflare/workers-sdk)
- [FOCI Research (SecureWorks)](https://github.com/secureworks/family-of-client-ids-research)
- [Microsoft Entra ID Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/)
- [FIDO2/Passkeys as AiTM Defense](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless)
