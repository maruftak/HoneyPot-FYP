#!/usr/bin/env python3
"""
honeyPot — Dashboard Backend
Serves dashboard.html + all /api/* endpoints.

Usage:  python3 dashboard.py [--port 5001]
"""

import json
import os, time, datetime
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

import db, config

BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_HTML = os.path.join(BASE_DIR, "dashboard.html")
START_TIME     = time.time()

app = Flask(__name__)
CORS(app)

# ─── Simple in-memory cache ────────────────────────────────────────────────────
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

@app.route("/favicon.ico")
@app.route("/apple-touch-icon.png")
@app.route("/apple-touch-icon-precomposed.png")
def favicon():
    return "", 204

@app.route("/api/health")
def api_health():
    return jsonify({
        "status":           "ok",
        "project":          config.PROJECT_NAME,
        "version":          config.VERSION,
        "uptime_seconds":   int(time.time() - START_TIME),
        "db_exists":        os.path.exists(config.DB_PATH),
        "telegram_enabled": config.TELEGRAM_ENABLED,
        "timestamp":        datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })

@app.route("/api/stats")
@cached(2)
def api_stats():
    hours = request.args.get("hours", 24, type=int)
    s = db.get_stats(hours)
    s["uptime_seconds"] = int(time.time() - START_TIME)
    return jsonify(s)

@app.route("/api/geo-data")
@cached(5)
def api_geo_data():
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_geo_data(hours)
    markers = []
    for r in rows:
        n   = r["cnt"]
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
        "honeypot": {"lat": 32.65, "lon": 51.67, "label": "honeyPot Sensor (Isfahan)"},
    })

@app.route("/api/sessions")
@cached(2)
def api_sessions():
    hours   = request.args.get("hours",   24,  type=int)
    limit   = request.args.get("limit",   200, type=int)
    service = request.args.get("service", "")
    threat  = request.args.get("threat",  "")
    is_tor  = request.args.get("is_tor",  "")
    is_vpn  = request.args.get("is_vpn",  "")
    is_proxy= request.args.get("is_proxy","")

    rows = db.get_recent_attacks(hours, limit, service or None, threat or None)
    result = []
    for r in rows:
        # client-side filter for anonymization flags (db may not support)
        if is_tor   == "1" and not r.get("is_tor"):   continue
        if is_vpn   == "1" and not r.get("is_vpn"):   continue
        if is_proxy == "1" and not r.get("is_proxy"): continue

        cmds = []
        try:
            cmds = json.loads(r.get("commands", "[]"))
        except Exception:
            pass
        result.append({
            "ts":                   r.get("timestamp",""),
            "ip":                   r.get("source_ip",""),
            "country":              r.get("country","Unknown"),
            "city":                 r.get("city",""),
            "service":              (r.get("service","") or "").upper(),
            "port":                 r.get("dest_port",0),
            "method":               r.get("method",""),
            "path":                 r.get("path","")[:80],
            "username":             r.get("username",""),
            "password":             r.get("password",""),
            "user_agent":           r.get("user_agent","")[:100],
            "cve":                  r.get("cve_id",""),
            "threat":               r.get("threat_level","low"),
            "is_botnet":            bool(r.get("is_botnet",0)),
            "is_tor":               bool(r.get("is_tor",0)),
            "is_vpn":               bool(r.get("is_vpn",0)),
            "is_proxy":             bool(r.get("is_proxy",0)),
            "vpn_provider":         r.get("vpn_provider",""),
            "vpn_exit_country":     r.get("vpn_exit_country",""),
            "tor_exit_node":        bool(r.get("tor_exit_node",0)),
            "tor_exit_ip":          r.get("tor_exit_ip",""),
            "proxy_type":           r.get("proxy_type",""),
            "anonymized":           bool(r.get("anonymized",0)),
            "anonymization_method": r.get("anonymization_method",""),
            "scanner_tool":         r.get("scanner_tool",""),
            "attack_type":          r.get("attack_type",""),
            "attack_patterns":      r.get("attack_patterns",""),
            "asn":                  r.get("asn",""),
            "org":                  r.get("org",""),
            "commands":             cmds[:5],
        })
    return jsonify({"sessions": result, "total": len(result)})

@app.route("/api/chart-data")
def api_chart_data():
    rng   = request.args.get("range", "24h")
    hours = {"24h": 24, "7d": 168, "30d": 720}.get(rng, 24)
    timeline = db.get_timeline(hours) or []
    labels   = [row.get("bucket") for row in timeline]
    datasets = {
        "connections":  [row.get("total",   0) for row in timeline],
        "malicious":    [row.get("botnets", 0) for row in timeline],
        "cve_exploits": [row.get("cves",    0) for row in timeline],
    }
    return jsonify({"labels": labels, "datasets": datasets})

@app.route("/api/top-ips")
@cached(3)
def api_top_ips():
    hours = request.args.get("hours", 24,  type=int)
    limit = request.args.get("limit", 20,  type=int)
    rows  = db.get_top_ips(hours, limit)
    return jsonify({
        "top_ips": [{
            "ip":           r["source_ip"],
            "count":        r["cnt"],
            "country":      r["country"] or "Unknown",
            "is_botnet":    bool(r.get("bots",0)),
            "is_tor":       bool(r.get("tors",0)),
            "last_seen":    r.get("last_seen",""),
            "services":     (r.get("services","") or "").split(","),
            "scanner_tool": r.get("scanner_tool",""),
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
    import re as _re
    hours = request.args.get("hours", 168, type=int)
    rows  = db.get_malware_urls(hours)

    extracted_urls = {}
    for s in db.get_recent_attacks(hours, limit=5000):
        try:
            cmds = json.loads(s.get("commands", "[]"))
        except Exception:
            cmds = []
        for cmd in cmds:
            urls = _re.findall(r'(https?://[^\s;\"\']+)', cmd)
            urls += _re.findall(r'(ftp://[^\s;\"\']+)', cmd)
            for p in cmd.split():
                if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', p) and ('wget' in cmd or 'tftp' in cmd):
                    urls.append("http://" + p)
            for u in urls:
                if u not in extracted_urls:
                    extracted_urls[u] = {"url":u,"family":"Mirai/IoT Botnet","arch":"arm/mips","count":0,"ips":set(),"last":s.get("timestamp","")}
                extracted_urls[u]["count"] += 1
                extracted_urls[u]["ips"].add(s.get("source_ip",""))
                if s.get("timestamp","") > extracted_urls[u]["last"]:
                    extracted_urls[u]["last"] = s.get("timestamp","")

    existing = {r["url"] for r in rows} if rows else set()
    merged   = []
    if rows:
        for r in rows:
            merged.append({"url":r["url"],"family":r["family"] or "Unknown","arch":r["arch"] or "unknown","count":r["cnt"],"unique_ips":r["unique_ips"],"last":r["last_seen"]})
    for u, d in extracted_urls.items():
        if u not in existing:
            merged.append({"url":d["url"],"family":d["family"],"arch":d["arch"],"count":d["count"],"unique_ips":len(d["ips"]),"last":d["last"]})
    merged = sorted(merged, key=lambda x: x["count"], reverse=True)
    return jsonify({"urls": merged})

@app.route("/api/honeytokens")
@cached(10)
def api_honeytokens():
    hours = request.args.get("hours", 168, type=int)
    data  = db.get_honeytoken_data(hours)
    return jsonify(data)

@app.route("/api/alerts")
@cached(5)
def api_alerts():
    hours = request.args.get("hours", 24,  type=int)
    limit = request.args.get("limit", 50,  type=int)
    return jsonify({"alerts": db.get_alerts(hours, limit)})

@app.route("/api/service-stats")
@cached(10)
def api_service_stats():
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_service_breakdown(hours)
    KNOWN = {
        "telnet":23,"ssh":2222,"ftp":21,"tftp":69,"http":80,"https":443,
        "http_alt":8080,"rtsp":554,"onvif":8000,"mqtt":1883,
        "vnc":5900,"modbus":502,"coap":5683,"hik_sdk":8200,"ssdp":1900,
    }
    seen, result = set(), []
    for r in rows:
        svc = (r["service"] or "").lower()
        seen.add(svc)
        result.append({
            "service":    svc.upper(),
            "port":       r.get("dest_port") or KNOWN.get(svc,0),
            "hits":       r["cnt"],
            "unique_ips": r["unique_ips"],
            "is_botnet":  bool(r.get("bots",0)),
            "last_seen":  r.get("last_seen",""),
            "active":     True,
        })
    for svc, port in KNOWN.items():
        if svc not in seen:
            result.append({"service":svc.upper(),"port":port,"hits":0,"unique_ips":0,"is_botnet":False,"last_seen":"","active":True})
    return jsonify({"services": result})

# ══════════════════════════════════════════════════════════════════════════════
#  NEW: VPN / TOR ENDPOINT TRACKING
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/anonymization-stats")
@cached(10)
def api_anonymization_stats():
    """
    Returns Tor exit node usage, VPN provider breakdown,
    proxy types, and endpoint change timeline.
    """
    hours = request.args.get("hours", 168, type=int)
    rows  = db.get_recent_attacks(hours, limit=10000)

    tor_ips      = {}   # ip -> {count, exit_ip, last}
    vpn_providers= {}   # provider -> {count, ips, exit_countries, timeline}
    proxy_types  = {}   # type -> count
    anon_timeline= {}   # hour-bucket -> {tor, vpn, proxy, clean}

    for r in rows:
        ip  = r.get("source_ip","")
        ts  = r.get("timestamp","")
        bucket = ts[:13] if ts else ""   # "2026-03-20T14"

        # Timeline bucket init
        if bucket not in anon_timeline:
            anon_timeline[bucket] = {"tor":0,"vpn":0,"proxy":0,"clean":0}

        if r.get("is_tor"):
            # Tor tracking
            exit_ip = r.get("tor_exit_ip") or ip
            if ip not in tor_ips:
                tor_ips[ip] = {"count":0,"exit_ip":exit_ip,"last":ts,"country":r.get("country","")}
            tor_ips[ip]["count"] += 1
            tor_ips[ip]["last"]   = ts
            anon_timeline[bucket]["tor"] += 1

        elif r.get("is_vpn"):
            provider = r.get("vpn_provider") or "Unknown VPN"
            exit_c   = r.get("vpn_exit_country") or r.get("country","")
            if provider not in vpn_providers:
                vpn_providers[provider] = {"count":0,"ips":set(),"exit_countries":{},"last":ts}
            vpn_providers[provider]["count"]  += 1
            vpn_providers[provider]["ips"].add(ip)
            vpn_providers[provider]["last"]    = ts
            vpn_providers[provider]["exit_countries"][exit_c] = \
                vpn_providers[provider]["exit_countries"].get(exit_c, 0) + 1
            anon_timeline[bucket]["vpn"] += 1

        elif r.get("is_proxy"):
            ptype = r.get("proxy_type") or "Unknown Proxy"
            proxy_types[ptype] = proxy_types.get(ptype, 0) + 1
            anon_timeline[bucket]["proxy"] += 1
        else:
            anon_timeline[bucket]["clean"] += 1

    # Serialise (sets → sorted lists)
    vpn_list = []
    for provider, data in sorted(vpn_providers.items(), key=lambda x: -x[1]["count"]):
        vpn_list.append({
            "provider":       provider,
            "count":          data["count"],
            "unique_ips":     len(data["ips"]),
            "exit_countries": sorted(data["exit_countries"].items(), key=lambda x: -x[1]),
            "last":           data["last"],
        })

    tor_list = sorted(tor_ips.values(), key=lambda x: -x["count"])

    proxy_list = [{"type":k,"count":v} for k,v in sorted(proxy_types.items(), key=lambda x: -x[1])]

    timeline_list = [
        {"bucket": k, **v}
        for k, v in sorted(anon_timeline.items())
    ]

    totals = {
        "tor":   sum(d["count"] for d in tor_ips.values()),
        "vpn":   sum(d["count"] for d in vpn_providers.values()),
        "proxy": sum(proxy_types.values()),
        "clean": sum(v["clean"] for v in anon_timeline.values()),
    }

    return jsonify({
        "totals":        totals,
        "tor_nodes":     tor_list[:50],
        "vpn_providers": vpn_list,
        "proxy_types":   proxy_list,
        "timeline":      timeline_list[-48:],  # last 48 hourly buckets
    })

@app.route("/api/vpn-endpoint-changes")
@cached(15)
def api_vpn_endpoint_changes():
    """
    Detects when the same attacker IP changed VPN exit country / provider
    across sessions — indicates endpoint hopping.
    """
    hours = request.args.get("hours", 168, type=int)
    rows  = db.get_recent_attacks(hours, limit=10000)

    # ip -> list of (ts, provider, exit_country)
    ip_sessions = {}
    for r in rows:
        if not (r.get("is_vpn") or r.get("is_tor")):
            continue
        ip = r.get("source_ip","")
        if ip not in ip_sessions:
            ip_sessions[ip] = []
        ip_sessions[ip].append({
            "ts":       r.get("timestamp",""),
            "provider": r.get("vpn_provider") or ("Tor" if r.get("is_tor") else "Unknown"),
            "exit":     r.get("vpn_exit_country") or r.get("country",""),
            "is_tor":   bool(r.get("is_tor")),
        })

    changes = []
    for ip, sessions in ip_sessions.items():
        sessions.sort(key=lambda x: x["ts"])
        prev = None
        for sess in sessions:
            if prev and (prev["provider"] != sess["provider"] or prev["exit"] != sess["exit"]):
                changes.append({
                    "ip":          ip,
                    "from_provider": prev["provider"],
                    "from_exit":     prev["exit"],
                    "to_provider":   sess["provider"],
                    "to_exit":       sess["exit"],
                    "changed_at":    sess["ts"],
                    "is_tor":        sess["is_tor"],
                })
            prev = sess

    changes.sort(key=lambda x: x["changed_at"], reverse=True)
    return jsonify({"endpoint_changes": changes[:100], "total": len(changes)})

# ══════════════════════════════════════════════════════════════════════════════
#  NEW: IoT-SPECIFIC ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/iot-stats")
@cached(10)
def api_iot_stats():
    """
    IoT-specific breakdown: RTSP stream attempts, ONVIF probes,
    Modbus/ICS hits, botnet family distribution, camera-specific CVEs.
    """
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_recent_attacks(hours, limit=10000)

    rtsp_attempts  = 0
    onvif_probes   = 0
    modbus_hits    = 0
    hikvision_hits = 0
    stream_requests= 0
    default_creds  = 0
    botnet_cmds    = []
    arch_targets   = {}
    iot_cves       = {}

    HIKVISION_PATHS = ["/ISAPI/","/doc/page/login","/PSIA/","/SDK/","/Streaming/","/onvif/","/cgi-bin/"]

    for r in rows:
        svc  = (r.get("service","") or "").lower()
        path = (r.get("path","") or "").lower()
        ua   = (r.get("user_agent","") or "").lower()

        if svc == "rtsp":
            rtsp_attempts += 1
        if svc == "onvif" or "onvif" in path:
            onvif_probes += 1
        if svc == "modbus":
            modbus_hits += 1
        if any(p in path for p in HIKVISION_PATHS):
            hikvision_hits += 1
        if "/streaming" in path or "/channels" in path:
            stream_requests += 1

        u = r.get("username","") or ""
        p = r.get("password","") or ""
        if u in ("admin","root","") and p in ("admin","12345","password","root",""):
            default_creds += 1

        cve = r.get("cve_id","")
        if cve:
            iot_cves[cve] = iot_cves.get(cve, 0) + 1

        try:
            cmds = json.loads(r.get("commands","[]"))
            for cmd in cmds:
                for arch in ["arm7","arm6","arm5","arm","mips","mipsel","x86","i686"]:
                    if arch in cmd.lower():
                        arch_targets[arch] = arch_targets.get(arch,0)+1
                botnet_cmds.append(cmd[:80])
        except Exception:
            pass

    return jsonify({
        "rtsp_attempts":   rtsp_attempts,
        "onvif_probes":    onvif_probes,
        "modbus_hits":     modbus_hits,
        "hikvision_hits":  hikvision_hits,
        "stream_requests": stream_requests,
        "default_creds":   default_creds,
        "arch_targets":    arch_targets,
        "iot_cves":        sorted(iot_cves.items(), key=lambda x: -x[1])[:10],
        "total_iot_events": rtsp_attempts + onvif_probes + modbus_hits + hikvision_hits,
    })

# ══════════════════════════════════════════════════════════════════════════════
#  EXISTING ENDPOINTS (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

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
@cached(1)
def api_live_log():
    rows = db.get_recent_attacks(hours=1, limit=50)
    result = []
    for r in rows:
        result.append({
            "ts":                   r.get("timestamp",""),
            "ip":                   r.get("source_ip",""),
            "country":              r.get("country",""),
            "service":              (r.get("service","") or "").upper(),
            "method":               r.get("method",""),
            "path":                 (r.get("path","") or "")[:60],
            "threat":               r.get("threat_level","low"),
            "is_botnet":            bool(r.get("is_botnet",0)),
            "is_tor":               bool(r.get("is_tor",0)),
            "is_vpn":               bool(r.get("is_vpn",0)),
            "is_proxy":             bool(r.get("is_proxy",0)),
            "vpn_provider":         r.get("vpn_provider",""),
            "anonymization_method": r.get("anonymization_method",""),
            "scanner_tool":         r.get("scanner_tool",""),
            "cve":                  r.get("cve_id",""),
            "attack_type":          r.get("attack_type",""),
        })
    return jsonify({"events": result})

@app.route("/api/ping")
def api_ping():
    return jsonify({
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "uptime":    int(time.time() - START_TIME),
    })

# ══════════════════════════════════════════════════════════════════════════════
#  FULL REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/full-report")
@cached(60)
def api_full_report():
    """
    Generate a complete threat intelligence report with all IoT + anonymization data.
    Returns structured JSON that the dashboard renders as a formatted text report.
    """
    hours = request.args.get("hours", 24, type=int)

    # Gather all data in parallel
    stats       = db.get_stats(hours)
    countries   = db.get_top_countries(hours)
    top_ips     = db.get_top_ips(hours, 20)
    cves        = db.get_cve_data(hours)
    creds       = db.get_top_credentials(hours)
    services    = db.get_service_breakdown(hours)
    malware     = db.get_malware_urls(hours)

    # Anonymization data
    sessions    = db.get_recent_attacks(hours, limit=10000)
    tor_count   = sum(1 for r in sessions if r.get("is_tor"))
    vpn_count   = sum(1 for r in sessions if r.get("is_vpn"))
    proxy_count = sum(1 for r in sessions if r.get("is_proxy"))

    vpn_providers = {}
    for r in sessions:
        if r.get("is_vpn") and r.get("vpn_provider"):
            p = r["vpn_provider"]
            vpn_providers[p] = vpn_providers.get(p, 0) + 1

    tor_exits = {}
    for r in sessions:
        if r.get("is_tor"):
            ip = r.get("tor_exit_ip") or r.get("source_ip","")
            tor_exits[ip] = tor_exits.get(ip, 0) + 1

    # IoT metrics
    rtsp_hits  = sum(1 for r in sessions if (r.get("service","") or "").lower() == "rtsp")
    onvif_hits = sum(1 for r in sessions if (r.get("service","") or "").lower() == "onvif")
    modbus_hits= sum(1 for r in sessions if (r.get("service","") or "").lower() == "modbus")
    hik_hits   = sum(1 for r in sessions if any(p in (r.get("path","") or "") for p in ["/ISAPI/","/PSIA/","/Streaming/"]))
    default_creds = sum(1 for r in sessions if r.get("username") in ("admin","root") and r.get("password") in ("admin","12345","password","root",""))

    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    report = {
        "generated_at": now_str,
        "period_hours": hours,
        "device": f"{getattr(config,'DEVICE_VENDOR','Hikvision')} {getattr(config,'DEVICE_MODEL','DS-2CD2043G2-I')}",
        "firmware": getattr(config, "DEVICE_FIRMWARE", "V5.7.15 build 230313"),

        "executive_summary": {
            "total_attacks":    stats.get("total_attacks", 0),
            "unique_ips":       stats.get("unique_ips", 0),
            "countries":        stats.get("country_count", 0),
            "cve_exploits":     stats.get("cve_exploits", 0),
            "botnets":          stats.get("botnet_count", 0),
            "malware_urls":     stats.get("malware_downloads", 0),
            "honeytokens":      stats.get("honeytokens_triggered", 0),
            "anonymized_total": tor_count + vpn_count + proxy_count,
            "tor_attackers":    tor_count,
            "vpn_attackers":    vpn_count,
            "proxy_attackers":  proxy_count,
        },

        "iot_summary": {
            "rtsp_stream_attempts":   rtsp_hits,
            "onvif_probes":           onvif_hits,
            "modbus_ics_hits":        modbus_hits,
            "hikvision_isapi_hits":   hik_hits,
            "default_credential_use": default_creds,
            "camera_targeted_cves":   len([c for c in cves if c.get("service") in ("rtsp","onvif","http")]),
        },

        "top_countries": [{"country": c["country"], "attacks": c["cnt"]} for c in countries[:10]],

        "top_ips": [{
            "ip":       ip["source_ip"],
            "count":    ip["cnt"],
            "country":  ip["country"],
            "is_botnet":bool(ip.get("bots",0)),
            "is_tor":   bool(ip.get("tors",0)),
        } for ip in top_ips[:15]],

        "cve_exploits": [{
            "cve_id":   c["cve_id"],
            "name":     c["cve_name"] or "",
            "severity": c["severity"],
            "service":  c["service"],
            "count":    c["cnt"],
        } for c in cves[:10]],

        "top_credentials": [{
            "username":  cr["username"],
            "password":  cr["password"],
            "count":     cr["cnt"],
            "is_botnet": bool(cr.get("bots",0)),
        } for cr in creds[:10]],

        "malware_urls": [{
            "url":    m["url"],
            "family": m["family"],
            "arch":   m["arch"],
            "count":  m["cnt"],
        } for m in malware[:10]] if malware else [],

        "anonymization": {
            "tor_exit_nodes":   sorted(tor_exits.items(), key=lambda x: -x[1])[:10],
            "vpn_providers":    sorted(vpn_providers.items(), key=lambda x: -x[1])[:10],
            "percent_anonymous": round((tor_count + vpn_count + proxy_count) / max(stats.get("total_attacks",1), 1) * 100, 1),
        },

        "service_breakdown": [{
            "service": s["service"],
            "hits":    s["cnt"],
            "unique_ips": s["unique_ips"],
        } for s in services[:17]],

        "threat_assessment": _generate_threat_assessment(stats, cves, tor_count, vpn_count, rtsp_hits, onvif_hits),
        "recommendations":   _generate_recommendations(stats, cves, default_creds, rtsp_hits),
    }

    return jsonify(report)


def _generate_threat_assessment(stats, cves, tor_count, vpn_count, rtsp_hits, onvif_hits):
    lines = []
    total = stats.get("total_attacks", 0)

    if total == 0:
        return ["No attacks recorded in this time period."]

    critical_cves = [c for c in cves if c.get("severity") == "critical"]
    if critical_cves:
        lines.append(f"CRITICAL: {len(critical_cves)} distinct critical CVEs actively exploited against this device, including {critical_cves[0]['cve_id']}.")

    if stats.get("botnet_count",0) > 0:
        lines.append(f"HIGH: Botnet credential spraying detected — {stats['botnet_count']} attempts using known botnet credential pairs (Mirai/Gafgyt/Mozi family patterns).")

    if rtsp_hits > 0:
        lines.append(f"HIGH: {rtsp_hits} RTSP stream access attempts. Attackers are actively targeting live camera feed access.")

    if onvif_hits > 0:
        lines.append(f"MEDIUM: {onvif_hits} ONVIF protocol probes detected. Attackers are enumerating camera capabilities and stream URIs.")

    anon_pct = round((tor_count + vpn_count) / max(total, 1) * 100, 1)
    if anon_pct > 20:
        lines.append(f"HIGH: {anon_pct}% of attacks originated from anonymised infrastructure (Tor/VPN), indicating deliberate operational security by threat actors.")
    elif anon_pct > 5:
        lines.append(f"MEDIUM: {anon_pct}% of attacks used anonymisation tools (Tor/VPN).")

    if stats.get("malware_downloads", 0) > 0:
        lines.append(f"CRITICAL: {stats['malware_downloads']} malware payload download attempts captured. IoT botnet recruitment activity confirmed.")

    if not lines:
        lines.append(f"LOW: {total} automated scans/probes recorded. No advanced threat activity detected.")

    return lines


def _generate_recommendations(stats, cves, default_creds, rtsp_hits):
    recs = []

    if default_creds > 0:
        recs.append("Change all default credentials immediately (admin/12345, root/root). This device is being actively targeted with default credential attacks.")

    if rtsp_hits > 0:
        recs.append("Restrict RTSP access (port 554) to authorised IP ranges only. Consider disabling if not required externally.")

    cve_ids = [c["cve_id"] for c in cves if c.get("severity") == "critical"]
    if cve_ids:
        recs.append(f"Apply patches for {', '.join(cve_ids[:3])}. These CVEs are being actively exploited in the wild against this device model.")

    if stats.get("botnet_count", 0) > 0:
        recs.append("Implement account lockout after 3 failed login attempts. Botnet credential spraying attacks are actively targeting this device.")

    recs.append("Enable HTTPS-only access and disable HTTP (port 80). All management traffic should be encrypted.")
    recs.append("Segment IoT cameras on a dedicated VLAN with no direct internet access. Use a reverse proxy for remote access.")
    recs.append("Enable firmware auto-update or schedule monthly firmware reviews. Hikvision releases critical patches regularly.")
    recs.append("Disable UPnP and any unused services (Telnet port 23 should always be disabled on production devices).")

    return recs


@app.after_request
def after_request_headers(resp):
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
║  /api/service-stats   /api/full-report               ║
║  /api/live-log        /api/anonymization-stats       ║
║  /api/vpn-endpoint-changes /api/iot-stats            ║
╚══════════════════════════════════════════════════════╝
""")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)