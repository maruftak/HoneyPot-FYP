#!/usr/bin/env python3
"""
honeyPot — VirusTotal Lookup Module
Checks captured file SHA256 hashes against VT API v3.
Free tier: 4 requests/min, 500/day.
"""

import threading
import time

import config

_VT_URL   = "https://www.virustotal.com/api/v3/files/{sha256}"
_HEADERS  = {"x-apikey": config.VIRUSTOTAL_API_KEY}
_INTERVAL = 16  # seconds between requests to stay under 4/min
_lock     = threading.Lock()
_last_req = 0.0

try:
    import requests as _req
    _req_ok = True
except ImportError:
    _req_ok = False


def lookup(sha256: str) -> dict:
    """
    Query VT for a SHA256 hash. Returns a result dict:
      {
        "found":       bool,
        "malicious":   int,
        "suspicious":  int,
        "total":       int,
        "family":      str or None,
        "threat_label":str or None,
        "permalink":   str,
      }
    Returns {"found": False} on error or unknown hash.
    """
    if not _req_ok or not config.VIRUSTOTAL_API_KEY:
        return {"found": False}

    # Rate-limit: free tier is 4 req/min
    global _last_req
    with _lock:
        wait = _INTERVAL - (time.time() - _last_req)
        if wait > 0:
            time.sleep(wait)
        _last_req = time.time()

    try:
        resp = _req.get(
            _VT_URL.format(sha256=sha256),
            headers=_HEADERS,
            timeout=15,
        )
    except Exception as e:
        print(f"[VT] Request error: {e}")
        return {"found": False}

    if resp.status_code == 404:
        return {"found": False}

    if resp.status_code != 200:
        print(f"[VT] Unexpected status {resp.status_code}")
        return {"found": False}

    try:
        data  = resp.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})

        # Best-effort family name
        label = None
        ptc   = data.get("popular_threat_classification") or {}
        if ptc.get("suggested_threat_label"):
            label = ptc["suggested_threat_label"]
        elif data.get("meaningful_name"):
            label = data["meaningful_name"]

        return {
            "found":        True,
            "malicious":    stats.get("malicious",  0),
            "suspicious":   stats.get("suspicious", 0),
            "undetected":   stats.get("undetected", 0),
            "total":        sum(stats.values()),
            "family":       label,
            "threat_label": label,
            "permalink":    f"https://www.virustotal.com/gui/file/{sha256}",
        }
    except Exception as e:
        print(f"[VT] Parse error: {e}")
        return {"found": False}


def lookup_async(sha256: str, on_result):
    """Run lookup in a background thread, call on_result(sha256, result) when done."""
    def _run():
        result = lookup(sha256)
        try:
            on_result(sha256, result)
        except Exception as e:
            print(f"[VT] on_result error: {e}")
    threading.Thread(target=_run, daemon=True).start()
