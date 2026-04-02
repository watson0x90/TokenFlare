"""
TokenFlare Library Module
"""

from typing import Dict

# Version information
VERSION = "1.0"
BANNER = """
 ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄   ▄ ▄▄▄▄▄▄▄ ▄▄    ▄ ▄▄▄▄▄▄▄ ▄▄▄     ▄▄▄▄▄▄▄ ▄▄▄▄▄▄   ▄▄▄▄▄▄▄ 
█       █       █   █ █ █       █  █  █ █       █   █   █       █   ▄  █ █       █
█▄     ▄█   ▄   █   █▄█ █    ▄▄▄█   █▄█ █    ▄▄▄█   █   █   ▄   █  █ █ █ █    ▄▄▄█
  █   █ █  █ █  █      ▄█   █▄▄▄█       █   █▄▄▄█   █   █  █▄█  █   █▄▄█▄█   █▄▄▄ 
  █   █ █  █▄█  █     █▄█    ▄▄▄█  ▄    █    ▄▄▄█   █▄▄▄█       █    ▄▄  █    ▄▄▄█
  █   █ █       █    ▄  █   █▄▄▄█ █ █   █   █   █       █   ▄   █   █  █ █   █▄▄▄ 
  █▄▄▄█ █▄▄▄▄▄▄▄█▄▄▄█ █▄█▄▄▄▄▄▄▄█▄█  █▄▄█▄▄▄█   █▄▄▄▄▄▄▄█▄▄█ █▄▄█▄▄▄█  █▄█▄▄▄▄▄▄▄█

                                         by Sunny Chau (@gladstomych) JUMPSEC Labs  
                                                                          Dec 2025

""".format(version=VERSION)

# OAuth URL Templates for Entra ID flows
# A single phish captures ONE token. If the client is FOCI-capable, TokenSmith's
# FOCI Discovery can exchange the refresh token to ALL 38 FOCI clients.
OAUTH_URLS: Dict[str, str] = {
    'office_foci': '/common/oauth2/v2.0/authorize?client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&response_type=code&scope=openid+offline_access+https%3A%2F%2Fgraph.microsoft.com%2F.default',
    'azpowershell_foci': '/common/oauth2/v2.0/authorize?client_id=1950a258-227b-4e31-a9cf-717495945fc2&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&response_type=code&scope=openid+offline_access+https%3A%2F%2Fgraph.microsoft.com%2F.default',
    'teams_foci': '/common/oauth2/v2.0/authorize?client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&response_type=code&scope=openid+offline_access+https%3A%2F%2Fgraph.microsoft.com%2F.default',
    'intune_foci': '/common/oauth2/v2.0/authorize?client_id=9ba1a5c7-f17a-4de9-a1f1-6178c8d51223&redirect_uri=ms-appx-web%3A%2F%2FMicrosoft.AAD.BrokerPlugin%2FS-1-15-2-2666988183-1750391847-2906264630-3525785777-2857982319-3063633125-1907478113&response_type=code&scope=openid+offline_access+https%3A%2F%2Fgraph.microsoft.com%2F.default',
    'officehome': '/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&nonce=28145',
}

# OAuth URL Display Names — shown in configure campaign wizard
OAUTH_DISPLAY_NAMES: Dict[str, str] = {
    'office_foci': 'Microsoft Office (FOCI, recommended) — broadest consent, urn:oob redirect, 38-client exchange',
    'azpowershell_foci': 'Azure PowerShell (FOCI) — Graph access, nativeclient redirect',
    'teams_foci': 'Microsoft Teams (FOCI) — broad consent, urn:oob redirect',
    'intune_foci': 'Microsoft Intune (FOCI) — Conditional Access device bypass testing',
    'officehome': 'Office Home (NOT FOCI) — rich session cookies but no FOCI exchange, no refresh token',
}

# Default lure configuration (used when not explicitly set in wrangler.toml)
DEFAULT_LURE_PATH = '/verifyme'
DEFAULT_LURE_PARAM = 'uuid'
