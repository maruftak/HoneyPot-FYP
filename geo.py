#!/usr/bin/env python3
"""
honeyPot — GeoIP Module
Resolves IP → country, city, lat, lon, org, ISP, proxy, hosting.
Uses GeoLite2 (local) for geo, then ip-api.com for org/ISP/proxy enrichment.
"""

import json
import logging
import os
import time
import threading
from typing import Dict, Any

import config

logger = logging.getLogger(__name__)

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
    if os.path.exists(config.GEOIP_DB_PATH):
        _reader = geoip2.database.Reader(config.GEOIP_DB_PATH)
        print(f"[GeoIP] Loaded: {config.GEOIP_DB_PATH}")
    else:
        print(f"[GeoIP] DB not found at {config.GEOIP_DB_PATH}")
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

    if ip in _bad and time.time() - _bad_ts.get(ip, 0) < 60:
        return _UNKNOWN.copy()

    result = {
        "country": "Unknown",
        "city": "",
        "latitude": 0.0,
        "longitude": 0.0,
        "asn": "",
        "org": "",
        "is_tor": False,
        "is_vpn": False,
        "is_proxy": False,
        "anonymization_method": None,
    }

    # 1. GeoLite2 — fast offline geo lookup
    if _reader:
        try:
            r = _reader.city(ip)
            result.update({
                "country":      r.country.name or r.country.iso_code or "Unknown",
                "country_code": r.country.iso_code or "XX",
                "city":         r.city.name or "",
                "latitude":     float(r.location.latitude or 0),
                "longitude":    float(r.location.longitude or 0),
                "asn":          str(r.traits.autonomous_system_number or ""),
                "org":          r.traits.organization_name or "",
            })
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")

    # Check Tor
    if _is_tor_exit(ip):
        result["is_tor"] = True
        result["anonymization_method"] = "tor"

    # Check VPN
    vpn_data = _check_vpn(ip)
    if vpn_data:
        result.update(vpn_data)
        result["is_vpn"] = True
        result["anonymization_method"] = "vpn"

    # 2. ip-api.com — enriches with org/ISP/proxy/hosting AND fills in geo
    #    when GeoLite2 missed (country still "Unknown" or lat/lon still 0).
    geo_missing = result.get("country") in ("Unknown", "", None) or not result.get("latitude")
    recently_enriched = time.time() - _enrich_ts.get(ip, 0) < 300
    if not recently_enriched or geo_missing:
        enriched = _ipapi_enrich(ip)
        if enriched:
            _enrich_ts[ip] = time.time()
            # Always copy org/ISP/proxy fields
            result["asn"]        = enriched.get("asn", result.get("asn", ""))
            result["org"]        = enriched.get("org", result.get("org", ""))
            result["isp"]        = enriched.get("isp", "")
            result["is_proxy"]   = enriched.get("is_proxy", False)
            result["is_hosting"] = enriched.get("is_hosting", False)
            # Fill in geo fields if GeoLite2 missed them
            if geo_missing:
                result["country"]   = enriched.get("country", "Unknown")
                result["city"]      = enriched.get("city", "")
                result["latitude"]  = enriched.get("latitude") or 0.0
                result["longitude"] = enriched.get("longitude") or 0.0
        elif geo_missing:
            _bad.add(ip)
            _bad_ts[ip] = time.time()
            return _UNKNOWN.copy()

    if not result:
        _bad.add(ip)
        _bad_ts[ip] = time.time()
        return _UNKNOWN.copy()

    _cache[ip] = result
    return result


def _is_tor_exit(ip: str) -> bool:
    """Check if IP is a Tor exit node."""
    try:
        if not os.path.exists(config.TOR_EXIT_NODES_FILE):
            return False
        with open(config.TOR_EXIT_NODES_FILE) as f:
            exits = json.load(f)
        return ip in exits.get("exits", [])
    except Exception:
        return False


def _check_vpn(ip: str) -> Dict[str, Any]:
    """Check if IP belongs to a known VPN provider."""
    try:
        if not os.path.exists(config.VPN_RANGES_FILE):
            return {}
        with open(config.VPN_RANGES_FILE) as f:
            vpn_data = json.load(f)

        # Simple IP-to-provider lookup (would need proper CIDR matching in production)
        for provider, ips in vpn_data.items():
            if ip in ips:
                return {"vpn_provider": provider}
    except Exception:
        pass

    return {}
