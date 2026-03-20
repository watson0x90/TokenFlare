# TokenFlare

**Serverless AITM Phishing Simulation Framework for Entra ID / M365**

<p align="center">
 <img src="tokenflare_logo.png" width="500px" alt="TokenFlare" />
</p>

## Features

- Lean: Core logic (in `src/worker.js` only ~530 lines of JavaScript).
- Modular: Supports a number of OAuth flows, with [Intune Conditional Access bypass](https://labs.jumpsec.com/tokensmith-bypassing-intune-compliant-device-conditional-access/) support out of the box
- Easily tweaked: Set up client branding, URL structure (custom lure path and parameter), final redirect after completing auth, and more, with the semi-interactive `tokenflare configure campaign` subcommand.
- Local or remote deployment: Supports getting SSL certs with Certbot for you, or deployment to CF directly.
- Built in OpSec: bot and scraper blocking, your campaign wouldn't be burnt in 10 minutes.
- Fast: get working, production ready infra within minutes.

Companion blog post: [Link](https://labs.jumpsec.com/tokenflare-serverless-AiTM-phishing-in-under-60-seconds/)

## Prerequisites

- Python 3.7+
- Node.js 20+ with Wrangler CLI. On Linux, we recommend [NodeSource](https://github.com/nodesource/distributions):
  ```bash
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
  npm install -g wrangler
  ```
- CloudFlare account with API Token (for remote deployment):
  1. [CloudFlare Dashboard](https://dash.cloudflare.com/profile/api-tokens) → Create Token
  2. Use template **"Edit Cloudflare Workers"** → Include your account under Account Resources → [optional] IP filtering
- [Optional] Certbot for local SSL: `sudo apt install certbot`
- OpenSSL (required by `init` for self-signed certificate generation)

>Note: Developed and tested on an Ubuntu VPS hosted on a public cloud. Running on localhost is possible but not recommended (for reasons such as port forwarding, DNS record pointing to you, etc)

## Quick Start

```bash
# 1. Initialise
python3 tokenflare.py init yourdomain.com

# 2. Configure campaign (interactive wizard)
python3 tokenflare.py configure campaign

# 2.5. Get valid SSL certificate for the domain pointing to your VPS
sudo python3 tokenflare.py configure ssl

# 3. Deploy locally for testing
sudo python3 tokenflare.py deploy local


# 4. Deploy to CloudFlare
python3 tokenflare.py configure cf
python3 tokenflare.py deploy remote

# 5. Troubleshooting
# change some settings in wrangler.toml, src/worker.js, or with tokenflare configure, then
python3 tokenflare.py deploy local #or
python3 tokenflare.py deploy remote
```

## Local Testing (No CloudFlare Account Required)

You can run TokenFlare entirely locally using `wrangler dev`, which starts the Cloudflare Worker runtime on your machine. No CloudFlare account, API token, or remote deployment is needed.

### What you need

| Requirement | Purpose |
|-------------|---------|
| Node.js 20+ | Runs the Wrangler CLI and Worker runtime |
| `wrangler` CLI | `npm install -g wrangler` (or use via `npx wrangler`) |
| OpenSSL | Generates self-signed TLS certificate (used by `init`) |
| Python 3.7+ | Runs the `tokenflare.py` CLI wrapper |
| A webhook endpoint | Receives captured credentials (see below) |

> **Windows users:** The `init` and `deploy local` commands call `os.geteuid()` which only exists on Linux/macOS. On Windows, skip the Python CLI and run `wrangler dev` directly — see [Manual method (cross-platform)](#manual-method-cross-platform) below.

### Method 1: Using the CLI (Linux/macOS)

```bash
# Step 1: Initialise — generates UUIDs, self-signed cert, updates wrangler.toml
sudo python3 tokenflare.py init localhost

# Step 2: Configure campaign — interactive wizard for lure paths, webhook, OAuth target
python3 tokenflare.py configure campaign

# Step 3: Launch the local worker
sudo python3 tokenflare.py deploy local
```

This starts an HTTPS server on `https://localhost:443`. The lure URL will be:
```
https://localhost/verifyme?uuid=<one-of-the-generated-uuids>
```

Use `python3 tokenflare.py status --get-lure-url` to see all generated lure URLs.

### Method 2: Manual method (cross-platform)

If you're on Windows, or prefer not to use the Python CLI, you can set up and run the worker directly:

**Step 1: Install wrangler**
```bash
npm install -g wrangler
```

**Step 2: Generate a self-signed certificate**
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost"
```

**Step 3: Edit `wrangler.toml`**

Set these variables in the `[vars]` section:

| Variable | What to set | Example |
|----------|-------------|---------|
| `LURE_UUID` | One or more UUIDs (comma-separated) | `"550e8400-e29b-41d4-a716-446655440000"` |
| `LOCAL_PHISHING_DOMAIN` | `localhost` or your test domain | `"localhost"` |
| `WEBHOOK_URL` | Your webhook endpoint (see below) | `"https://webhook.site/your-unique-id"` |
| `DEBUGGING` | Set to `"true"` for verbose console output | `"true"` |

You can generate a UUID with Python: `python -c "import uuid; print(uuid.uuid4())"`

**Step 4: Start the worker**
```bash
wrangler dev --ip 0.0.0.0 --port 443 \
  --local-protocol https \
  --https-key-path certs/key.pem \
  --https-cert-path certs/cert.pem
```

> **Tip:** On Linux, binding to port 443 requires root (`sudo`). You can use a high port instead (e.g., `--port 8443`) to avoid this, but you'll need to include the port in your lure URL: `https://localhost:8443/verifyme?uuid=...`

**Step 5: Visit the lure URL**

Open your browser and navigate to:
```
https://localhost/verifyme?uuid=<your-uuid-from-step-3>
```

Your browser will show a certificate warning (expected with self-signed certs) — accept it to proceed. You should be redirected through the Microsoft OAuth flow.

### Setting up a webhook for local testing

TokenFlare exfils captured credentials to a webhook. For local testing:

**Option 1: `tokenflare-webhook.py` (recommended)**

A purpose-built local webhook listener is included in this repo. It parses all TokenFlare webhook formats (Generic, Slack, Discord, Teams), color-codes captures by type, and optionally logs to file.

```bash
# Terminal 1: Start the webhook listener
python tokenflare-webhook.py                     # Listen on port 9999 (default)
python tokenflare-webhook.py -p 8080             # Custom port
python tokenflare-webhook.py -p 9999 -o loot.json  # Log captures to JSONL file
python tokenflare-webhook.py --show-raw           # Also print raw JSON payloads
```

Then set in `wrangler.toml`:
```toml
WEBHOOK_URL = "http://localhost:9999/webhook"
```

```bash
# Terminal 2: Start the worker
wrangler dev --ip 0.0.0.0 --port 443 ...
```

The listener will display captured credentials, auth codes, and cookies in real time with color-coded output and a running session summary. On exit (Ctrl+C), it prints a final capture count.

**Option 2: webhook.site**

Go to `https://webhook.site`, copy your unique URL, and set it as `WEBHOOK_URL` in `wrangler.toml`. Captured credentials will appear in real time on the webhook.site page. Useful if you don't want to run a local listener, but be aware that credentials are sent to a third-party service.

> **Note:** When running locally, `wrangler dev` console output will show request/response logs. With `DEBUGGING = "true"` in `wrangler.toml`, the worker logs additional detail to the console, which can be useful even without a webhook.

### What to expect during local testing

1. Visit the lure URL → you are redirected to the real Microsoft login page (proxied through the local worker)
2. The browser URL bar shows `localhost` (or your test domain), not `login.microsoftonline.com`
3. Enter credentials → they are intercepted (non-blocking) and sent to your webhook
4. MFA prompts appear as normal → completing MFA gives the worker the auth code and session cookies
5. After auth completes, you are redirected to the `FINAL_REDIR` URL (default: `https://www.office.com`)

### Troubleshooting local deployment

| Problem | Solution |
|---------|----------|
| `wrangler: command not found` | `npm install -g wrangler` or use `npx wrangler dev ...` |
| `EACCES: permission denied` on port 443 | Use `sudo` (Linux/macOS) or choose a high port like `8443` |
| Browser shows `ERR_CERT_AUTHORITY_INVALID` | Expected with self-signed certs — click "Advanced" → "Proceed" |
| Redirected to `UNAUTH_REDIR` instead of login | Your UUID doesn't match `LURE_UUID` in `wrangler.toml` |
| Webhook not receiving data | Check `WEBHOOK_URL` is reachable from the worker. For local listeners, ensure the port is open |
| `os.geteuid` error on Windows | Use the manual method — run `wrangler dev` directly instead of `python3 tokenflare.py deploy local` |
| Microsoft login page doesn't load | Check `UPSTREAM_PATH` in `wrangler.toml` is a valid OAuth URL. Try the default OfficeHome path |

## Commands

| Command | Description |
|---------|-------------|
| `init <domain>` | Initialise project for domain |
| `configure campaign` | Interactive campaign setup |
| `configure cf` | CloudFlare credentials |
| `configure ssl` | SSL certificate setup |
| `deploy local` | Local HTTPS proxy |
| `deploy remote` | Deploy to CloudFlare |
| `status` | Configuration overview |
| `status --get-lure-url` | Show lure URLs |

## Captured Credentials

Credentials, auth codes, and session cookies are sent to your configured webhook. Supports Slack, Discord, Teams, and generic webhooks (auto-detected from URL).

Configure during `configure campaign` or set `WEBHOOK_URL` in wrangler.toml.

Local credential saving in files is not implemented due to serverless nature of Workers. If you'd like to add `log(creds);` in src/worker.js, beware that CF might redact JWTs, cookies or creds captured. Having a working webhook is the most reliable method in our experience.

## Easy IoCs for blue teams

```
Header:     X-TokenFlare: Authorised-Security-Testing
User-Agent: TokenFlare/1.0 For_Authorised_Testing_Only
```

## Acknowledgements


Many Thanks to:
- [TE](https://github.com/tdejmp) - for helping, debugging, teaching me a ton and otherwise being an awesome human being.
- [Dave @Cyb3rC3lt](https://github.com/Cyb3rC3lt/) - for creating our v1 internal prod Worker.
- [Zolderio](https://github.com/zolderio/) - for creating the prototype PoC Worker that started it all.
- [ChoiSG](https://github.com/ChoiSG) - for flagging Global API Key support.

## Disclaimer

**FOR AUTHORISED SECURITY TESTING ONLY**

Unauthorised use against systems you do not own or have permission to test is illegal.

Using Cloudflare's services to penetration test a third party might go against some of their T&C's. Don't write to us if your prod CF account was banned - consider yourself warned. 

## License

See LICENSE file.
