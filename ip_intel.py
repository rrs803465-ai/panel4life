"""
Detects whether a connecting IP looks like a VPN/proxy/hosting-provider
address, so the panel can (a) flag it for the admin at signup and (b) refuse
VPS creation outright while it's live — this is meant to make the existing
"one VPS per IP" alt-account rule harder to route around.

HONEST LIMITS — no IP intelligence source is airtight:
  - False negatives: brand-new/unlisted VPN exit nodes, residential proxies,
    or a VPN provider whose ASN isn't recognized yet will slip through.
  - False positives: some legitimate residential ISPs or small businesses
    occasionally get miscategorized as "hosting" by IP databases.
  - This uses the free tier of ip-api.com (no key, ~45 requests/min limit,
    plain HTTP not HTTPS). Good enough for a "make it strict" best-effort
    check, not a certified fraud-detection product.

FAILS OPEN: if the lookup itself fails (network issue, rate limit, service
down), this returns "not a VPN" rather than blocking real users because a
third-party API hiccuped.
"""

import requests

# Checked against the ISP/org/AS name strings the API returns. Deliberately
# broad per request ("strict") — covers major consumer VPN brands AND
# generic hosting/datacenter providers, since open proxies and "residential"
# VPNs frequently run out of exactly those.
_VPN_KEYWORDS = [
    "vpn", "proxy", "nordvpn", "expressvpn", "surfshark", "cyberghost",
    "private internet access", "protonvpn", "proton vpn", "mullvad",
    "windscribe", "tunnelbear", "ipvanish", "hotspot shield", "hide.me",
    "purevpn", "vyprvpn", "torguard", "perfect privacy", "privado",
    "digitalocean", "amazon", "aws", "google cloud", "azure",
    "microsoft corporation", "ovh", "hetzner", "vultr", "linode",
    "akamai", "choopa", "m247", "leaseweb", "contabo", "datacamp",
    "hostwinds", "psychz", "worldstream", "iweb", "cloudflare",
    "hosting", "datacenter", "data center", "colocation", "dedicated server",
]


def _lookup(ip):
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,isp,org,as,proxy,hosting,query"},
            timeout=4,
        )
        data = resp.json()
        if data.get("status") != "success":
            return None
        return data
    except Exception:
        return None


def is_vpn_or_proxy(ip):
    """
    Returns (is_vpn: bool, label: str|None). label is a short human-readable
    reason (e.g. the ISP/org name, or "Flagged proxy/VPN") suitable for
    showing directly in the admin panel.
    """
    if not ip or ip in ("127.0.0.1", "::1"):
        return False, None

    data = _lookup(ip)
    if not data:
        return False, None  # fail open — see module docstring

    isp = data.get("isp") or ""
    org = data.get("org") or ""
    asname = data.get("as") or ""
    haystack = f"{isp} {org} {asname}".lower()
    display_name = isp or org or asname or "unknown ISP"

    if data.get("proxy"):
        return True, f"Flagged proxy/VPN ({display_name})"
    if data.get("hosting"):
        return True, f"Hosting/Datacenter IP ({display_name})"

    for kw in _VPN_KEYWORDS:
        if kw in haystack:
            return True, display_name

    return False, None
