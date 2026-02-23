#!/usr/bin/env python3
"""
honeyPot — Dashboard Backend
Serves dashboard.html + all /api/* endpoints.

Usage:  python3 dashboard.py [--port 5001]
"""

import os, time, datetime
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

import db, config

BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_HTML = os.path.join(BASE_DIR, "dashboard.html")
START_TIME     = time.time()

app = Flask(__name__)
CORS(app)

# ─── Simple in-memory cache (key → (ts, value)) ───────────────────────────────
_cache = {}

def cached(ttl=5):
    def dec(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = fn.__name__ + str(request.args)
            hit = _cache.get(key)
            if hit and time.time() - hit[0] < ttl:
                return hit[1]
            result = fn(*args, **kwargs)
            _cache[key] = (time.time(), result)
            return result
        return wrapper
    return dec

# ─── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if os.path.exists(DASHBOARD_HTML):
        return send_file(DASHBOARD_HTML)
    return "<h1>honeyPot</h1><p>Place dashboard.html next to dashboard.py</p>", 404

@app.route("/api/health")
def api_health():
    return jsonify({
        "status":               "ok",
        "project":              config.PROJECT_NAME,
        "version":              config.VERSION,
        "uptime_seconds":       int(time.time() - START_TIME),
        "db_exists":            os.path.exists(config.DB_PATH),
        "telegram_enabled":     config.TELEGRAM_ENABLED,
        "timestamp":            datetime.datetime.utcnow().isoformat(),
    })

@app.route("/api/stats")
@cached(8)
def api_stats():
    hours = request.args.get("hours", 24, type=int)
    s = db.get_stats(hours)
    s["uptime_seconds"] = int(time.time() - START_TIME)
    return jsonify(s)

@app.route("/api/geo-data")
@cached(15)
def api_geo_data():
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_geo_data(hours)
    markers = []
    for r in rows:
        n = r["cnt"]
        sev = "critical" if n > 500 else "high" if n > 100 else "medium" if n > 20 else "low"
        markers.append({
            "lat":      r["latitude"],
            "lon":      r["longitude"],
            "country":  r["country"] or "Unknown",
            "count":    n,
            "bots":     r["bots"] or 0,
            "tors":     r["tors"] or 0,
            "severity": sev,
            "last":     r["last_seen"],
        })
    return jsonify({
        "markers": markers,
        "total":   len(markers),
        "honeypot": {
            "lat": 51.5074, "lon": -0.1278,
            "label": "honeyPot Sensor"
        },
    })

@app.route("/api/sessions")
@cached(5)
def api_sessions():
    hours   = request.args.get("hours",   24,  type=int)
    limit   = request.args.get("limit",   150, type=int)
    service = request.args.get("service", "")
    threat  = request.args.get("threat",  "")
    rows = db.get_recent_attacks(hours, limit, service or None, threat or None)
    result = []
    for r in rows:
        cmds = []
        try:
            cmds = __import__("json").loads(r.get("commands", "[]"))
        except Exception:
            pass
        result.append({
            "ts":        r.get("timestamp",""),
            "ip":        r.get("source_ip",""),
            "country":   r.get("country","Unknown"),
            "city":      r.get("city",""),
            "service":   (r.get("service","") or "").upper(),
            "port":      r.get("dest_port",0),
            "method":    r.get("method",""),
            "path":      r.get("path","")[:80],
            "username":  r.get("username",""),
            "password":  r.get("password",""),
            "user_agent":r.get("user_agent","")[:100],
            "cve":       r.get("cve_id",""),
            "threat":    r.get("threat_level","low"),
            "is_botnet": bool(r.get("is_botnet",0)),
            "is_tor":    bool(r.get("is_tor",0)),
            "commands":  cmds[:5],
            "attack_type":r.get("attack_type",""),
        })
    return jsonify({"sessions": result, "total": len(result)})

@app.route("/api/chart-data")
@cached(10)
def api_chart_data():
    rng   = request.args.get("range", "24h")
    hours = 168 if rng == "7d" else (720 if rng == "30d" else 24)
    rows  = db.get_timeline(hours)

    labels     = []
    totals     = []
    botnets    = []
    cves       = []

    for r in rows:
        labels.append(r["bucket"])
        totals.append(r["total"])
        botnets.append(r["botnets"] or 0)
        cves.append(r["cves"] or 0)

    return jsonify({
        "labels": labels,
        "datasets": {
            "connections": totals,
            "malicious":   botnets,
            "cve_exploits":cves,
        },
    })

@app.route("/api/top-ips")
@cached(10)
def api_top_ips():
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 20, type=int)
    rows  = db.get_top_ips(hours, limit)
    return jsonify({
        "top_ips": [{
            "ip":        r["source_ip"],
            "count":     r["cnt"],
            "country":   r["country"] or "Unknown",
            "is_botnet": bool(r.get("bots",0)),
            "is_tor":    bool(r.get("tors",0)),
            "last_seen": r.get("last_seen",""),
            "services":  (r.get("services","") or "").split(","),
        } for r in rows]
    })

@app.route("/api/countries")
@cached(10)
def api_countries():
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_top_countries(hours)
    return jsonify({
        "countries": [{"name": r["country"], "count": r["cnt"], "ips": r["ips"]} for r in rows]
    })

@app.route("/api/cve-exploits")
@cached(15)
def api_cve_exploits():
    hours = request.args.get("hours", 168, type=int)
    rows  = db.get_cve_data(hours)
    total    = sum(r["cnt"] for r in rows)
    critical = sum(r["cnt"] for r in rows if r["severity"] == "critical")
    return jsonify({
        "cves": [{
            "cve_id":     r["cve_id"],
            "name":       r["cve_name"] or "",
            "severity":   r["severity"] or "unknown",
            "service":    r["service"] or "",
            "count":      r["cnt"],
            "unique_ips": r["unique_ips"],
            "last":       r["last_seen"],
        } for r in rows],
        "total":       total,
        "critical":    critical,
        "unique_cves": len(rows),
    })

@app.route("/api/top-credentials")
@cached(15)
def api_top_credentials():
    hours = request.args.get("hours", 168, type=int)
    rows  = db.get_top_credentials(hours)
    return jsonify({
        "credentials": [{
            "username":  r["username"],
            "password":  r["password"] or "",
            "count":     r["cnt"],
            "is_botnet": bool(r.get("bots",0)),
        } for r in rows],
        "total": len(rows),
    })

@app.route("/api/malware-urls")
@cached(15)
def api_malware_urls():
    hours = request.args.get("hours", 168, type=int)
    rows  = db.get_malware_urls(hours)
    return jsonify({
        "urls": [{
            "url":        r["url"],
            "family":     r["family"] or "Unknown",
            "arch":       r["arch"] or "unknown",
            "count":      r["cnt"],
            "unique_ips": r["unique_ips"],
            "last":       r["last_seen"],
        } for r in rows]
    })

@app.route("/api/honeytokens")
@cached(10)
def api_honeytokens():
    hours = request.args.get("hours", 168, type=int)
    data  = db.get_honeytoken_data(hours)
    return jsonify(data)

@app.route("/api/alerts")
@cached(5)
def api_alerts():
    hours = request.args.get("hours", 1,  type=int)
    limit = request.args.get("limit", 25, type=int)
    return jsonify({"alerts": db.get_alerts(hours, limit)})

@app.route("/api/service-stats")
@cached(10)
def api_service_stats():
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_service_breakdown(hours)
    KNOWN = {
        "telnet":23,"ssh":22,"ftp":21,"smtp":25,"http":80,"https":443,
        "http_alt":8080,"rtsp":554,"onvif":8000,"mqtt":1883,"redis":6379,
        "mysql":3306,"docker":2375,"memcached":11211,"vnc":5900,"rdp":3389,"modbus":502,
    }
    seen   = set()
    result = []
    for r in rows:
        svc = (r["service"] or "").lower()
        seen.add(svc)
        result.append({
            "service":    svc.upper(),
            "port":       r.get("dest_port") or KNOWN.get(svc, 0),
            "hits":       r["cnt"],
            "unique_ips": r["unique_ips"],
            "is_botnet":  bool(r.get("bots",0)),
            "last_seen":  r.get("last_seen",""),
            "active":     True,
        })
    for svc, port in KNOWN.items():
        if svc not in seen:
            result.append({"service":svc.upper(),"port":port,"hits":0,
                          "unique_ips":0,"is_botnet":False,"last_seen":"","active":True})
    return jsonify({"services": result})

@app.route("/api/report")
@cached(30)
def api_report():
    hours = request.args.get("hours", 24, type=int)
    return jsonify(db.get_report_data(hours))

@app.route("/api/hourly-heatmap")
@cached(60)
def api_hourly_heatmap():
    return jsonify({"buckets": db.get_hourly_heatmap()})

@app.route("/api/botnet-distribution")
@cached(30)
def api_botnet_distribution():
    return jsonify(db.get_botnet_distribution())

@app.route("/api/live-log")
@cached(3)
def api_live_log():
    """Most recent 50 attacks for the live log stream."""
    rows = db.get_recent_attacks(hours=1, limit=50)
    result = []
    for r in rows:
        result.append({
            "ts":       r.get("timestamp",""),
            "ip":       r.get("source_ip",""),
            "country":  r.get("country",""),
            "service":  (r.get("service","") or "").upper(),
            "method":   r.get("method",""),
            "path":     (r.get("path","") or "")[:60],
            "threat":   r.get("threat_level","low"),
            "is_botnet":bool(r.get("is_botnet",0)),
            "cve":      r.get("cve_id",""),
        })
    return jsonify({"events": result})

@app.after_request
def _headers(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Cache-Control"]                = "no-cache, no-store"
    return resp

# ─── Entry ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host",  default="0.0.0.0")
    p.add_argument("--port",  default=5001, type=int)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    db.init()

    print(f"""
╔══════════════════════════════════════════════════════╗
║  honeyPot Dashboard  —  http://{args.host}:{args.port}
╠══════════════════════════════════════════════════════╣
║  /api/health          /api/stats                     ║
║  /api/geo-data        /api/sessions                  ║
║  /api/chart-data      /api/top-ips                   ║
║  /api/countries       /api/cve-exploits              ║
║  /api/top-credentials /api/malware-urls              ║
║  /api/honeytokens     /api/alerts                    ║
║  /api/service-stats   /api/report                    ║
║  /api/live-log                                       ║
╚══════════════════════════════════════════════════════╝
""")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
