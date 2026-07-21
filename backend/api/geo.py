"""
AlertIQ 2.0 - Threat Map Geolocation Helper
------------------------------------------------
Provides (lat, lng) coordinates for an IP address, for use on the
Threat Map page.

IMPORTANT HONESTY NOTE (read before changing this file):

Private/RFC1918 IP addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x) and
loopback/link-local addresses have NO real-world geographic location -
they are not publicly routable, so no GeoIP service (real or otherwise)
can honestly place them on a map. In a home/lab deployment (e.g. a Kali
attacker box and a Windows victim box on the same LAN), every IP
AlertIQ sees will typically be private.

So this module does two different things depending on the IP:

  1. KNOWN PUBLIC IPS (a small hardcoded table below) - these get their
     real, accurate public location. Currently covers the handful of
     well-known public DNS resolvers used by the beacon/botnet test
     scripts (Google, Cloudflare, Quad9), since those are genuinely
     public infrastructure with well-documented locations.

  2. EVERYTHING ELSE (private IPs, or any public IP not in the table)
     - gets a deterministic, clearly-labeled ILLUSTRATIVE point. Same
       IP always maps to the same point (stable across restarts), but
       the point is NOT a real geolocation - it exists purely so the
       map has somewhere consistent to draw an arc to/from. The API
       response always includes `is_approximate: true` for these, and
       the frontend must render a visible "illustrative location, not
       geolocated" indicator whenever this flag is set. Never remove
       that flag/label - presenting a made-up point as a real location
       would be misleading.
"""
from __future__ import annotations

import hashlib
import ipaddress

# ---- 1. Known public IPs: real, documented locations ----
# (lat, lng, label)
KNOWN_PUBLIC_IPS: dict[str, tuple[float, float, str]] = {
    "8.8.8.8": (37.4056, -122.0775, "Google DNS (Mountain View, US)"),
    "8.8.4.4": (37.4056, -122.0775, "Google DNS (Mountain View, US)"),
    "1.1.1.1": (-27.4698, 153.0251, "Cloudflare DNS (Brisbane, AU)"),
    "1.0.0.1": (-27.4698, 153.0251, "Cloudflare DNS (Brisbane, AU)"),
    "9.9.9.9": (47.3769, 8.5417, "Quad9 DNS (Zurich, CH)"),
}

# ---- 2. Illustrative points for private/unknown IPs ----
# Deliberately a short, clearly-fictional-for-this-purpose list of world
# cities used ONLY to spread private-network devices out visually.
_ILLUSTRATIVE_POINTS: list[tuple[float, float, str]] = [
    (28.6139, 77.2090, "New Delhi (illustrative)"),
    (51.5074, -0.1278, "London (illustrative)"),
    (40.7128, -74.0060, "New York (illustrative)"),
    (35.6762, 139.6503, "Tokyo (illustrative)"),
    (-33.8688, 151.2093, "Sydney (illustrative)"),
    (52.5200, 13.4050, "Berlin (illustrative)"),
    (1.3521, 103.8198, "Singapore (illustrative)"),
    (55.7558, 37.6173, "Moscow (illustrative)"),
]


def is_private_or_reserved(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparsable - treat as "no real location", not a crash
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast


def _illustrative_point_for(ip: str) -> tuple[float, float, str]:
    # Deterministic: same IP always lands on the same point, across
    # restarts, since it's a pure hash of the string (no randomness).
    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    index = digest[0] % len(_ILLUSTRATIVE_POINTS)
    return _ILLUSTRATIVE_POINTS[index]


def locate(ip: str | None) -> dict:
    """Returns {lat, lng, label, is_approximate} for an IP.

    is_approximate=True means: this point is NOT a real geolocation,
    it's a stable placeholder for visualization only (see module
    docstring). The frontend must visibly flag these.
    """
    if not ip:
        lat, lng, label = _illustrative_point_for("unknown")
        return {"lat": lat, "lng": lng, "label": "Unknown", "is_approximate": True}

    known = KNOWN_PUBLIC_IPS.get(ip)
    if known is not None:
        lat, lng, label = known
        return {"lat": lat, "lng": lng, "label": label, "is_approximate": False}

    lat, lng, label = _illustrative_point_for(ip)
    return {"lat": lat, "lng": lng, "label": label, "is_approximate": True}


def project_equirectangular(lat: float, lng: float, width: float = 1000.0, height: float = 500.0) -> tuple[float, float]:
    """Projects lat/lng onto a flat equirectangular canvas (2:1 aspect).

    x: 0 (lng=-180) .. width (lng=180)
    y: 0 (lat=90, north) .. height (lat=-90, south)
    """
    x = (lng + 180.0) / 360.0 * width
    y = (90.0 - lat) / 180.0 * height
    return round(x, 2), round(y, 2)
