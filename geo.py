#!/usr/bin/env python3
"""
honeyPot — GeoIP Module
Resolves IP → country, city, lat, lon, org, ISP, proxy, hosting.
Uses GeoLite2 (local) for geo, then ip-api.com for org/ISP/proxy enrichment.
"""

import os, time, threading
from config import GEOIP_DB

_cache     = {}   # ip -> result (full enriched dict)
_enrich_ts = {}   # ip -> last enrichment time (avoid re-querying too soon)
_bad       = set()
_bad_ts    = {}
_rate_lock = threading.Lock()
_last_api_call = 0.0          # global timestamp of last ip-api.com request
_API_MIN_INTERVAL = 1.35      # seconds between ip-api.com calls (~44/min, under 45 limit)

_PRIVATE = ("127.", "10.", "192.168.", "::1", "0.", "169.254.", "fc", "fd")

def _is_private(ip):
    return any(ip.startswith(p) for p in _PRIVATE) or ip in ("localhost",)

# ── GeoLite2 reader ────────────────────────────────────────────────────────
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
    "country": "Local", "country_code": "LO", "city": "Local Network",
    "latitude": None, "longitude": None, "asn": "", "org": "", "isp": "",
    "is_proxy": False, "is_hosting": False,
}

_UNKNOWN = {
    "country": "Unknown", "country_code": "XX", "city": "",
    "latitude": None, "longitude": None, "asn": "", "org": "", "isp": "",
    "is_proxy": False, "is_hosting": False,
}


def _ipapi_enrich(ip: str) -> dict:
    """
    Call ip-api.com free API to get org, ISP, ASN, proxy, hosting flags.
    Rate-limited to ~44 req/min. Returns {} on failure.
    """
    global _last_api_call
    if not _req_ok:
        return {}

    with _rate_lock:
        wait = _API_MIN_INTERVAL - (time.time() - _last_api_call)
        if wait > 0:
            time.sleep(wait)
        _last_api_call = time.time()

    try:
        resp = _req.get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,city,lat,lon,as,org,isp,proxy,hosting",
            timeout=5,
        )
        d = resp.json()
        if d.get("status") != "success":
            return {}
        return {
            "country":      d.get("country", "Unknown"),
            "country_code": (d.get("countryCode") or "XX").upper(),
            "city":         d.get("city", ""),
            "latitude":     d.get("lat"),
            "longitude":    d.get("lon"),
            "asn":          d.get("as", ""),
            "org":          d.get("org", ""),
            "isp":          d.get("isp", ""),
            "is_proxy":     bool(d.get("proxy")),
            "is_hosting":   bool(d.get("hosting")),
        }
    except Exception:
        return {}


def lookup(ip: str) -> dict:
    """Return enriched geo dict for an IP address."""
    if ip in _cache:
        return _cache[ip]

    if _is_private(ip):
        _cache[ip] = _LOCAL.copy()
        return _cache[ip]

    if ip in _bad and time.time() - _bad_ts.get(ip, 0) < 600:
        return _UNKNOWN.copy()

    result = None

    # 1. GeoLite2 — fast offline geo lookup
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
                "isp":          "",
                "is_proxy":     False,
                "is_hosting":   False,
            }
        except Exception:
            pass

    # 2. ip-api.com — always enriches with org/ISP/proxy/hosting
    #    If GeoLite2 succeeded we still call it for the enrichment fields.
    #    We skip only if the IP was recently enriched (within 30 min).
    recently_enriched = time.time() - _enrich_ts.get(ip, 0) < 1800
    if not recently_enriched:
        enriched = _ipapi_enrich(ip)
        if enriched:
            _enrich_ts[ip] = time.time()
            if result:
                # Merge: keep GeoLite2 geo but add enrichment fields
                result["asn"]        = enriched.get("asn", "")
                result["org"]        = enriched.get("org", "")
                result["isp"]        = enriched.get("isp", "")
                result["is_proxy"]   = enriched.get("is_proxy", False)
                result["is_hosting"] = enriched.get("is_hosting", False)
            else:
                result = enriched
        elif not result:
            _bad.add(ip)
            _bad_ts[ip] = time.time()
            return _UNKNOWN.copy()

    if not result:
        _bad.add(ip)
        _bad_ts[ip] = time.time()
        return _UNKNOWN.copy()

    _cache[ip] = result
    return result
