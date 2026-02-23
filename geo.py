#!/usr/bin/env python3
"""
honeyPot — GeoIP Module
Resolves IP → country, city, lat, lon.
Uses GeoLite2 (local) with ip-api.com as fallback.
"""

import os, time
from config import GEOIP_DB

_cache = {}          # ip -> result
_bad   = set()       # IPs that failed; skip retrying for a while
_bad_ts= {}          # ip -> last failure time

# Private / local prefixes — skip GeoIP for these
_PRIVATE = ("127.", "10.", "192.168.", "::1", "0.", "169.254.", "fc", "fd")

def _is_private(ip):
    return any(ip.startswith(p) for p in _PRIVATE) or ip in ("localhost",)

# Try to load GeoLite2
_reader = None
try:
    import geoip2.database
    if os.path.exists(GEOIP_DB):
        _reader = geoip2.database.Reader(GEOIP_DB)
        print(f"[GeoIP] Loaded: {GEOIP_DB}")
    else:
        print(f"[GeoIP] DB not found at {GEOIP_DB}")
except ImportError:
    print("[GeoIP] geoip2 not installed — pip install geoip2")

try:
    import requests as _req
    _req_ok = True
except ImportError:
    _req_ok = False

_LOCAL = {
    "country":      "Local",
    "country_code": "LO",
    "city":         "Local Network",
    "latitude":     None,
    "longitude":    None,
    "asn":          "",
    "org":          "",
}

_UNKNOWN = {
    "country":      "Unknown",
    "country_code": "XX",
    "city":         "",
    "latitude":     None,
    "longitude":    None,
    "asn":          "",
    "org":          "",
}

def lookup(ip: str) -> dict:
    """Return geo dict for an IP address."""
    if ip in _cache:
        return _cache[ip]

    if _is_private(ip):
        _cache[ip] = _LOCAL.copy()
        return _cache[ip]

    # Skip recently failed IPs (retry after 10 min)
    if ip in _bad and time.time() - _bad_ts.get(ip, 0) < 600:
        return _UNKNOWN.copy()

    result = None

    # 1. GeoLite2 local DB (fast, offline)
    if _reader:
        try:
            r = _reader.city(ip)
            result = {
                "country":      r.country.name or "Unknown",
                "country_code": (r.country.iso_code or "XX").upper(),
                "city":         r.city.name or "",
                "latitude":     r.location.latitude,
                "longitude":    r.location.longitude,
                "asn":          "",
                "org":          "",
            }
        except Exception:
            pass

    # 2. ip-api.com fallback (needs internet, free tier)
    if not result and _req_ok:
        try:
            resp = _req.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as,org",
                timeout=4
            )
            d = resp.json()
            if d.get("status") == "success":
                result = {
                    "country":      d.get("country", "Unknown"),
                    "country_code": (d.get("countryCode") or "XX").upper(),
                    "city":         d.get("city", ""),
                    "latitude":     d.get("lat"),
                    "longitude":    d.get("lon"),
                    "asn":          d.get("as", ""),
                    "org":          d.get("org", ""),
                }
        except Exception:
            pass

    if not result:
        _bad.add(ip)
        _bad_ts[ip] = time.time()
        return _UNKNOWN.copy()

    _cache[ip] = result
    return result
