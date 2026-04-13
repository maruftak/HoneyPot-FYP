#!/usr/bin/env python3
"""
honeyPot — Dashboard Backend
Serves dashboard.html + all /api/* endpoints.

Usage:  python3 dashboard.py [--port 5001]
"""

import csv
import io
import json
import os, time, datetime
from flask import Flask, jsonify, request, send_file, Response
from flask_cors import CORS

import db, config

BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_HTML = os.path.join(BASE_DIR, "dashboard.html")
START_TIME     = time.time()

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:5001", "http://localhost:3000"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"],
        "supports_credentials": True,
    }
})

# ─── HTTP Basic Auth ───────────────────────────────────────────────────────────
_NO_AUTH_PATHS = {"/favicon.ico", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"}

@app.after_request
def _strip_server_header(resp):
    """Hide Werkzeug/Python fingerprint from Shodan/Censys."""
    resp.headers["Server"] = "App-webs/"
    return resp

@app.before_request
def check_auth():
    """Enforce HTTPS-only auth in production."""
    if request.path in _NO_AUTH_PATHS:
        return
    
    auth = request.authorization
    if (not auth or auth.username != config.DASHBOARD_USERNAME or 
        auth.password != config.DASHBOARD_PASSWORD):
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="IPCamera"'},
        )

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
@cached(60)
def api_stats():
    hours = request.args.get("hours", 24, type=int)
    s = db.get_stats(hours)
    s["uptime_seconds"] = int(time.time() - START_TIME)
    return jsonify(s)

@app.route("/api/geo-data")
@cached(60)
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
        "honeypot": {"lat": 19.08, "lon": 72.88, "label": "honeyPot Sensor (Mumbai)"},
    })

def _build_session_row(r):
    cmds = []
    raw_cmds = r.get("commands", "[]") or "[]"
    try:
        parsed = json.loads(raw_cmds)
        if isinstance(parsed, list):
            cmds = parsed
        elif isinstance(parsed, dict):
            # VNC stores a dict in commands — extract typed text as a cmd
            typed = parsed.get("typed", "")
            if typed:
                cmds = [f"[typed] {typed}"]
            clipboard = parsed.get("clipboard", "")
            if clipboard:
                cmds.append(f"[clipboard] {clipboard}")
            cves = parsed.get("cves", [])
            if cves:
                cmds.append(f"[CVEs] {', '.join(cves)}")
            enc = parsed.get("encodings", [])
            if enc:
                cmds.append(f"[encodings] {enc}")
            cmds.append(f"[fb_requests={parsed.get('fb_requests',0)} keys={parsed.get('key_count',0)} dur={parsed.get('duration_s',0)}s client={parsed.get('client','')}]")
    except Exception:
        if raw_cmds and raw_cmds != "[]":
            cmds = [raw_cmds[:200]]

    # Build a rich summary for the "Path / Commands" column
    payload   = (r.get("payload") or "")
    raw_pay   = (r.get("raw_payload") or "")
    path      = (r.get("path") or "")
    method    = (r.get("method") or "")
    ua        = (r.get("user_agent") or "")

    # Service-specific detail string shown in table and modal
    detail = ""
    if cmds:
        detail = cmds[0]
    elif payload:
        detail = payload[:120]
    elif path:
        detail = f"{method} {path}".strip()
    elif raw_pay:
        detail = raw_pay[:120]

    return {
        "ts":                   r.get("timestamp",""),
        "ip":                   r.get("source_ip",""),
        "country":              r.get("country","Unknown"),
        "city":                 r.get("city",""),
        "service":              (r.get("service","") or "").upper(),
        "port":                 r.get("dest_port",0),
        "method":               method,
        "path":                 path[:120],
        "username":             r.get("username",""),
        "password":             r.get("password",""),
        "user_agent":           ua[:150],
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
        "commands":             cmds,
        "cmd_count":            len(cmds),
        "payload":              payload[:1000],
        "raw_payload":          raw_pay[:500],
        "detail":               detail,
        "session_id":           r.get("session_id",""),
    }

def _apply_session_filters(rows, filters):
    """Apply in-memory filters that db layer doesn't support."""
    is_tor   = filters.get("is_tor")
    is_vpn   = filters.get("is_vpn")
    is_proxy = filters.get("is_proxy")
    is_botnet= filters.get("is_botnet")
    country  = (filters.get("country") or "").lower()
    attack_t = (filters.get("attack_type") or "").lower()
    cve_id   = (filters.get("cve_id") or "").lower()
    src_ip   = (filters.get("ip") or "").strip()
    from_ts  = filters.get("from_ts") or ""
    to_ts    = filters.get("to_ts") or ""

    result = []
    for r in rows:
        if is_tor    == "1" and not r.get("is_tor"):   continue
        if is_vpn    == "1" and not r.get("is_vpn"):   continue
        if is_proxy  == "1" and not r.get("is_proxy"): continue
        if is_botnet == "1" and not r.get("is_botnet"):continue
        if country and (r.get("country","") or "").lower() != country: continue
        if attack_t and attack_t not in (r.get("attack_type","") or "").lower(): continue
        if cve_id   and cve_id   not in (r.get("cve_id","") or "").lower(): continue
        if src_ip   and r.get("source_ip","") != src_ip: continue
        ts = r.get("timestamp","")
        if from_ts and ts < from_ts: continue
        if to_ts   and ts > to_ts:   continue
        result.append(r)
    return result

@app.route("/api/sessions")
@cached(30)
def api_sessions():
    hours    = request.args.get("hours",       168, type=int)
    limit    = request.args.get("limit",       200, type=int)
    offset   = request.args.get("offset",      0,   type=int)
    service  = request.args.get("service",     "")
    threat   = request.args.get("threat",      "")
    filters  = {
        "is_tor":      request.args.get("is_tor"),
        "is_vpn":      request.args.get("is_vpn"),
        "is_proxy":    request.args.get("is_proxy"),
        "is_botnet":   request.args.get("is_botnet"),
        "country":     request.args.get("country"),
        "attack_type": request.args.get("attack_type"),
        "cve_id":      request.args.get("cve_id"),
        "ip":          request.args.get("ip"),
        "from_ts":     request.args.get("from_ts"),
        "to_ts":       request.args.get("to_ts"),
    }
    
    # Get true DB count
    true_total = db.query(
        "SELECT COUNT(*) as c FROM attacks WHERE timestamp > ?",
        (db._cutoff(hours),)
    )[0]["c"] if db.query(f"SELECT COUNT(*) as c FROM attacks WHERE timestamp > ?", (db._cutoff(hours),)) else 0

    # When no service filter: query each service separately so high-volume services
    # (VNC alone is 318k rows) don't crowd out all others.
    # With a service filter, query directly.
    if not service:
        known_services = db.get_service_breakdown(hours)
        svc_names      = [r["service"] for r in known_services if r.get("service")]
        svc_count      = max(len(svc_names), 1)
        # Fetch enough per service to cover offset+limit with room for filtering
        per_fetch      = max(200, (offset + limit) // svc_count + 50)
        combined = []
        for svc in svc_names:
            svc_rows = db.get_recent_attacks(hours, per_fetch, svc, threat or None)
            combined.extend(svc_rows)
        combined.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        all_rows = _apply_session_filters(combined, filters)
    else:
        all_rows = db.get_recent_attacks(hours, offset + limit + 500, service, threat or None)
        all_rows = _apply_session_filters(all_rows, filters)

    page_rows = all_rows[offset: offset + limit]
    result    = [_build_session_row(r) for r in page_rows]
    return jsonify({
        "sessions":    result,
        # true_total = real DB count; shown in UI as "showing X of TRUE_TOTAL"
        "total":       true_total,
        # fetched = how many rows were pulled into memory (per-service cap)
        "fetched":     len(all_rows),
        "offset":      offset,
        "limit":       limit,
        "has_more":    (offset + limit) < len(all_rows),
    })

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
@cached(60)
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
@cached(60)
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
    hours   = request.args.get("hours", 168, type=int)
    service = request.args.get("service", "", type=str) or None
    rows    = db.get_top_credentials(hours, service=service)
    # Build per-service totals for the chart
    svc_totals = {}
    for r in rows:
        svc = r.get("service") or "unknown"
        svc_totals[svc] = svc_totals.get(svc, 0) + r["cnt"]
    return jsonify({
        "credentials": [{
            "username":  r["username"],
            "password":  r["password"] or "",
            "service":   r.get("service") or "unknown",
            "count":     r["cnt"],
            "is_botnet": bool(r.get("bots",0)),
        } for r in rows],
        "service_totals": svc_totals,
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
        cred_count = r.get("cred_count", 0) or 0
        result.append({
            "service":    svc.upper(),
            "port":       r.get("dest_port") or KNOWN.get(svc,0),
            "hits":       r["cnt"],
            "unique_ips": r["unique_ips"],
            "cred_count": cred_count,
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
@cached(90)
def api_anonymization_stats():
    """
    Returns Tor exit node usage, VPN provider breakdown,
    proxy types, and endpoint change timeline.
    """
    hours = request.args.get("hours", 168, type=int)
    return jsonify(db.get_anonymization_stats(hours))

@app.route("/api/notable-events")
@cached(10)
def api_notable_events():
    """Returns the most dangerous/interesting sessions: cred captures, CVE exploits, commands run, firmware upgrades."""
    hours = request.args.get("hours", 168, type=int)
    limit = request.args.get("limit", 50,  type=int)
    rows  = db.get_notable_events(hours, limit)
    return jsonify({"events": [_build_session_row(r) for r in rows], "total": len(rows)})


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
@cached(90)
def api_iot_stats():
    """
    IoT-specific breakdown: RTSP stream attempts, ONVIF probes,
    Modbus/ICS hits, botnet family distribution, camera-specific CVEs.
    """
    hours = request.args.get("hours", 24, type=int)
    return jsonify(db.get_iot_stats(hours))

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
@cached(120)
def api_botnet_distribution():
    return jsonify({"families": db.get_botnet_distribution()})

_CRED_FAMILY_MAP = [
    ("root","xc3511","Mirai"),("root","vizxv","Mirai"),
    ("root","7ujMko0vizxv","Mirai"),("root","7ujMko0admin","Mirai"),
    ("root","anko","Mirai"),("root","klv123","Mirai"),
    ("root","klv1234","Mirai"),("root","zlxx.","Mirai"),
    ("root","dreambox","Mirai"),("mother","fucker","Mirai"),
    ("root","hi3518","Mirai/Satori"),("root","xmhdipc","Mirai/Satori"),
    ("root","juantech","Mirai/Okiru"),("root","realtek","Mirai/Okiru"),
    ("root","ikwb","Mirai/Okiru"),("root","jvbzd","Mirai/Okiru"),
    ("root","Zte521","Mirai/ZTE"),
    ("ubnt","ubnt","Mirai/UBNT"),
    ("666666","666666","Mirai/DVR"),("888888","888888","Mirai/DVR"),
    ("root","000000","Mirai/DVR"),("root","888888","Mirai/DVR"),
    ("pi","raspberry","Mirai/Raspberry"),
    ("nproc","nproc","Mozi"),
]

def _infer_cred_family(username, password):
    u, p = (username or "").strip(), (password or "").strip()
    for mu, mp, fam in _CRED_FAMILY_MAP:
        if u == mu and p == mp:
            return fam
    return "Mirai/Generic"

@app.route("/api/botnet-names")
@cached(60)
def api_botnet_names():
    import re as _re
    hours = request.args.get("hours", 168, type=int)
    cutoff = db._cutoff(hours)

    names = {}   # family/name -> count
    sigs  = {}   # variant signature -> count

    # 1. Commands-based: busybox hostname NAME and /bin/busybox VARIANT probes
    cmd_rows = db.query(
        "SELECT commands FROM attacks WHERE commands LIKE '%busybox%' AND timestamp > ?",
        (cutoff,)
    )
    for row in cmd_rows:
        try:
            cmds = json.loads(row["commands"])
        except Exception:
            continue
        for cmd in cmds:
            m = _re.search(r'busybox\s+hostname\s+([A-Za-z0-9_\-]{2,20})', cmd)
            if m:
                name = m.group(1)
                if name.upper() not in ("HOSTNAME","DVR","CAMERA","ROUTER","NVR","NONE"):
                    names[name] = names.get(name, 0) + 1
            m2 = _re.match(r'^/?bin/busybox\s+([A-Z][A-Za-z0-9]{3,15})$', cmd.strip())
            if m2:
                sig = m2.group(1)
                sigs[sig] = sigs.get(sig, 0) + 1

    # 2. scanner_tool field: e.g. "Mirai/ECCHI" set by Mirai variant probe handler
    tool_rows = db.query(
        "SELECT scanner_tool, COUNT(*) as cnt FROM attacks "
        "WHERE scanner_tool LIKE 'Mirai/%' AND timestamp > ? "
        "GROUP BY scanner_tool ORDER BY cnt DESC LIMIT 20",
        (cutoff,)
    )
    for r in tool_rows:
        tool = r.get("scanner_tool","")
        variant = tool.split("/",1)[-1] if "/" in tool else tool
        if variant:
            names[variant] = names.get(variant, 0) + r.get("cnt", 0)

    # 3. botnet_family column (set by honeypot for new attacks)
    fam_rows = db.query(
        "SELECT botnet_family, COUNT(*) as cnt FROM attacks "
        "WHERE botnet_family IS NOT NULL AND botnet_family != '' AND timestamp > ? "
        "GROUP BY botnet_family ORDER BY cnt DESC LIMIT 20",
        (cutoff,)
    )
    for r in fam_rows:
        fam = r.get("botnet_family","")
        if fam and fam.upper() not in ("UNKNOWN","NONE"):
            names[fam] = names.get(fam, 0) + r.get("cnt", 0)

    # 4. Credential inference for existing data (botnet attacks without family set)
    cred_rows = db.query(
        "SELECT username, password, COUNT(*) as cnt FROM attacks "
        "WHERE is_botnet=1 AND (botnet_family IS NULL OR botnet_family='') "
        "AND timestamp > ? GROUP BY username, password",
        (cutoff,)
    )
    for r in cred_rows:
        fam = _infer_cred_family(r.get("username",""), r.get("password",""))
        names[fam] = names.get(fam, 0) + r.get("cnt", 0)

    names_sorted = sorted(names.items(), key=lambda x: -x[1])
    sigs_sorted  = sorted(sigs.items(),  key=lambda x: -x[1])
    return jsonify({
        "names": [{"name": k, "count": v} for k, v in names_sorted[:20]],
        "sigs":  [{"name": k, "count": v} for k, v in sigs_sorted[:20]],
        "total_named": sum(names.values()),
    })

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


# ══════════════════════════════════════════════════════════════════════════════
#  EXPORT ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/export/csv")
def api_export_csv():
    """Download filtered attacks as CSV."""
    hours    = request.args.get("hours",    168,  type=int)
    limit    = request.args.get("limit",    10000,type=int)
    service  = request.args.get("service",  "")
    threat   = request.args.get("threat",   "")
    filters  = {
        "is_tor":     request.args.get("is_tor",""),
        "is_vpn":     request.args.get("is_vpn",""),
        "is_proxy":   request.args.get("is_proxy",""),
        "is_botnet":  request.args.get("is_botnet",""),
        "country":    request.args.get("country",""),
        "attack_type":request.args.get("attack_type",""),
        "cve_id":     request.args.get("cve_id",""),
        "ip":         request.args.get("ip",""),
        "from_ts":    request.args.get("from_ts",""),
        "to_ts":      request.args.get("to_ts",""),
    }

    rows = db.get_recent_attacks(hours, limit * 2, service or None, threat or None)
    rows = _apply_session_filters(rows, filters)[:limit]

    fields = ["timestamp","source_ip","country","city","service","dest_port",
              "attack_type","threat_level","username","password","cve_id",
              "user_agent","is_botnet","is_tor","is_vpn","is_proxy",
              "vpn_provider","asn","org","path","method","scanner_tool"]

    out = io.StringIO()
    w   = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({f: r.get(f,"") for f in fields})

    fname = f"honeypot_attacks_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M')}.csv"
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )


@app.route("/api/export/json")
def api_export_json():
    """Download filtered attacks as JSON."""
    hours    = request.args.get("hours",    168,  type=int)
    limit    = request.args.get("limit",    10000,type=int)
    service  = request.args.get("service",  "")
    threat   = request.args.get("threat",   "")
    filters  = {
        "is_tor":     request.args.get("is_tor",""),
        "is_vpn":     request.args.get("is_vpn",""),
        "is_proxy":   request.args.get("is_proxy",""),
        "is_botnet":  request.args.get("is_botnet",""),
        "country":    request.args.get("country",""),
        "attack_type":request.args.get("attack_type",""),
        "cve_id":     request.args.get("cve_id",""),
        "ip":         request.args.get("ip",""),
        "from_ts":    request.args.get("from_ts",""),
        "to_ts":      request.args.get("to_ts",""),
    }

    rows   = db.get_recent_attacks(hours, limit * 2, service or None, threat or None)
    rows   = _apply_session_filters(rows, filters)[:limit]
    result = [_build_session_row(r) for r in rows]

    payload = json.dumps({
        "exported_at": datetime.datetime.utcnow().isoformat(),
        "period_hours": hours,
        "total": len(result),
        "attacks": result,
    }, indent=2)

    fname = f"honeypot_attacks_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M')}.json"
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )


@app.route("/api/captures")
def api_captures():
    """Return list of captured malware/upload files."""
    try:
        import malware_capture
        entries = malware_capture.get_all()
        # newest first
        entries = sorted(entries, key=lambda x: x.get("timestamp",""), reverse=True)
        return jsonify({"captures": entries, "total": len(entries)})
    except Exception as e:
        return jsonify({"captures": [], "total": 0, "error": str(e)})

@app.route("/api/export/report-txt")
def api_export_report_txt():
    """Download full threat report as a plain-text file."""
    hours   = request.args.get("hours", 24, type=int)
    stats   = db.get_stats(hours)
    cves    = db.get_cve_data(hours)
    creds   = db.get_top_credentials(hours)
    countries = db.get_top_countries(hours)
    top_ips = db.get_top_ips(hours, 15)
    services= db.get_service_breakdown(hours)
    sessions= db.get_recent_attacks(hours, limit=10000)

    tor_c   = sum(1 for r in sessions if r.get("is_tor"))
    vpn_c   = sum(1 for r in sessions if r.get("is_vpn"))
    proxy_c = sum(1 for r in sessions if r.get("is_proxy"))
    total   = stats.get("total_attacks", 0)
    anon_pct= round((tor_c + vpn_c + proxy_c) / max(total, 1) * 100, 1)

    # Attack type breakdown
    atypes = {}
    for r in sessions:
        at = r.get("attack_type","unknown") or "unknown"
        atypes[at] = atypes.get(at, 0) + 1
    top_atypes = sorted(atypes.items(), key=lambda x: -x[1])[:10]

    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "═" * 70,
        f"  HONEYPOT THREAT INTELLIGENCE REPORT",
        f"  Generated: {now}  |  Period: Last {hours}h",
        f"  Device: Hikvision DS-2CD2043G2-I  |  Firmware: V5.7.15",
        "═" * 70,
        "",
        "── EXECUTIVE SUMMARY ──────────────────────────────────────────────",
        f"  Total attack events   : {total:,}",
        f"  Unique source IPs     : {stats.get('unique_ips',0):,}",
        f"  Countries represented : {stats.get('country_count',0)}",
        f"  CVE exploits detected : {stats.get('cve_exploits',0)}",
        f"  Botnet attempts       : {stats.get('botnet_count',0)}",
        f"  Malware downloads     : {stats.get('malware_downloads',0)}",
        f"  Honeytoken triggers   : {stats.get('honeytokens_triggered',0)}",
        f"  Anonymised traffic    : {tor_c + vpn_c + proxy_c} events ({anon_pct}%)",
        f"    ├─ Tor exit nodes   : {tor_c}",
        f"    ├─ VPN              : {vpn_c}",
        f"    └─ Proxy            : {proxy_c}",
        "",
        "── TOP ATTACK TYPES ────────────────────────────────────────────────",
    ]
    for at, cnt in top_atypes:
        pct = round(cnt / max(total, 1) * 100, 1)
        lines.append(f"  {at:<40s} {cnt:>6,}  ({pct}%)")

    lines += [
        "",
        "── SERVICE BREAKDOWN ───────────────────────────────────────────────",
        f"  {'Service':<12} {'Port':>5}  {'Hits':>8}  {'Unique IPs':>10}",
        "  " + "─" * 42,
    ]
    for s in sorted(services, key=lambda x: -x.get("cnt",0))[:17]:
        lines.append(f"  {(s.get('service','') or '').upper():<12} {s.get('dest_port',0):>5}  {s.get('cnt',0):>8,}  {s.get('unique_ips',0):>10,}")

    lines += [
        "",
        "── TOP SOURCE COUNTRIES ────────────────────────────────────────────",
    ]
    for c in countries[:15]:
        pct = round(c["cnt"] / max(total,1) * 100, 1)
        lines.append(f"  {(c['country'] or 'Unknown'):<25}  {c['cnt']:>8,}  ({pct}%)")

    lines += [
        "",
        "── TOP ATTACKER IPs ────────────────────────────────────────────────",
        f"  {'IP':<17} {'Country':<20} {'Hits':>7}  {'Flags'}",
        "  " + "─" * 60,
    ]
    for ip in top_ips[:15]:
        flags = []
        if ip.get("bots"): flags.append("BOTNET")
        if ip.get("tors"): flags.append("TOR")
        lines.append(f"  {ip['source_ip']:<17} {(ip.get('country') or 'Unknown'):<20} {ip['cnt']:>7,}  {' '.join(flags)}")

    lines += [
        "",
        "── CVE EXPLOITS DETECTED ───────────────────────────────────────────",
        f"  {'CVE ID':<20} {'Severity':<10} {'Service':<10} {'Hits':>6}  {'Unique IPs':>10}",
        "  " + "─" * 62,
    ]
    for c in cves[:15]:
        lines.append(f"  {c.get('cve_id',''):<20} {c.get('severity',''):<10} {(c.get('service','') or '').upper():<10} {c.get('cnt',0):>6,}  {c.get('unique_ips',0):>10,}")

    lines += [
        "",
        "── TOP CREDENTIAL ATTEMPTS ─────────────────────────────────────────",
        f"  {'Username':<20} {'Password':<25} {'Count':>7}",
        "  " + "─" * 55,
    ]
    for cr in creds[:15]:
        lines.append(f"  {(cr.get('username','') or ''):<20} {(cr.get('password','') or ''):<25} {cr.get('cnt',0):>7,}")

    lines += [
        "",
        "── THREAT ASSESSMENT ───────────────────────────────────────────────",
    ]
    lines += ["  " + l for l in _generate_threat_assessment(stats, cves, tor_c, vpn_c,
              sum(1 for r in sessions if (r.get("service","") or "") == "rtsp"),
              sum(1 for r in sessions if (r.get("service","") or "") == "onvif"))]

    lines += [
        "",
        "── RECOMMENDATIONS ─────────────────────────────────────────────────",
    ]
    for i, rec in enumerate(_generate_recommendations(
            stats, cves,
            sum(1 for r in sessions if r.get("username") in ("admin","root") and r.get("password") in ("admin","12345","password","root","")),
            sum(1 for r in sessions if (r.get("service","") or "") == "rtsp")), 1):
        lines.append(f"  {i}. {rec}")

    lines += ["", "═" * 70, "  END OF REPORT", "═" * 70]

    text  = "\n".join(lines) + "\n"
    fname = f"honeypot_report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M')}.txt"
    return Response(
        text,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK TYPE BREAKDOWN
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/attack-types")
@cached(10)
def api_attack_types():
    """Full breakdown of every attack_type value with counts, services, trend."""
    hours   = request.args.get("hours",   168, type=int)
    service = request.args.get("service", "")
    rows    = db.get_recent_attacks(hours, limit=50000, service=service or None)

    atype_stats = {}   # attack_type -> {count, unique_ips, services, threat_levels, last}
    for r in rows:
        at  = r.get("attack_type","unknown") or "unknown"
        ip  = r.get("source_ip","")
        svc = (r.get("service","") or "").upper()
        thr = r.get("threat_level","low") or "low"
        ts  = r.get("timestamp","")

        if at not in atype_stats:
            atype_stats[at] = {"count":0,"ips":set(),"services":{},"threats":{},"last":""}
        d = atype_stats[at]
        d["count"] += 1
        d["ips"].add(ip)
        d["services"][svc] = d["services"].get(svc,0) + 1
        d["threats"][thr]  = d["threats"].get(thr,0)  + 1
        if ts > d["last"]: d["last"] = ts

    total = sum(d["count"] for d in atype_stats.values())
    result = []
    for at, d in sorted(atype_stats.items(), key=lambda x: -x[1]["count"]):
        top_svc = max(d["services"].items(), key=lambda x: x[1])[0] if d["services"] else ""
        top_thr = max(d["threats"].items(),  key=lambda x: x[1])[0] if d["threats"]  else "low"
        result.append({
            "attack_type": at,
            "count":       d["count"],
            "unique_ips":  len(d["ips"]),
            "pct":         round(d["count"] / max(total,1) * 100, 1),
            "top_service": top_svc,
            "top_threat":  top_thr,
            "services":    d["services"],
            "last":        d["last"],
        })

    return jsonify({
        "attack_types": result,
        "total":        total,
        "unique_types": len(result),
    })


# ══════════════════════════════════════════════════════════════════════════════
#  SERVICE DRILL-DOWN
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/service-drill")
@cached(10)
def api_service_drill():
    """Deep stats for a specific service."""
    service = request.args.get("service", "ssh").lower()
    hours   = request.args.get("hours",   168, type=int)
    rows    = db.get_recent_attacks(hours, limit=20000, service=service)

    total       = len(rows)
    auth_fail   = sum(1 for r in rows if "auth_fail" in (r.get("attack_type","") or ""))
    auth_ok     = sum(1 for r in rows if "auth_success" in (r.get("attack_type","") or ""))
    cve_hits    = sum(1 for r in rows if r.get("cve_id"))
    tor_hits    = sum(1 for r in rows if r.get("is_tor"))
    vpn_hits    = sum(1 for r in rows if r.get("is_vpn"))
    botnet_hits = sum(1 for r in rows if r.get("is_botnet"))

    atypes  = {}
    cves    = {}
    top_ips = {}
    countries = {}
    scanners  = {}

    for r in rows:
        at  = r.get("attack_type","unknown") or "unknown"
        cve = r.get("cve_id","") or ""
        ip  = r.get("source_ip","")
        c   = r.get("country","Unknown") or "Unknown"
        sc  = r.get("scanner_tool","") or ""

        atypes[at]  = atypes.get(at, 0) + 1
        if cve: cves[cve] = cves.get(cve, 0) + 1
        top_ips[ip] = top_ips.get(ip, 0) + 1
        countries[c]= countries.get(c,  0) + 1
        if sc: scanners[sc] = scanners.get(sc, 0) + 1

    # Hourly timeline
    timeline = {}
    for r in rows:
        ts = (r.get("timestamp","") or "")[:13]
        timeline[ts] = timeline.get(ts, 0) + 1

    return jsonify({
        "service":    service.upper(),
        "hours":      hours,
        "total":      total,
        "auth_failures": auth_fail,
        "auth_successes": auth_ok,
        "cve_exploits": cve_hits,
        "tor_hits":   tor_hits,
        "vpn_hits":   vpn_hits,
        "botnet_hits":botnet_hits,
        "attack_types": sorted(atypes.items(), key=lambda x: -x[1])[:20],
        "cves_seen":    sorted(cves.items(),   key=lambda x: -x[1])[:10],
        "top_ips":      sorted(top_ips.items(),key=lambda x: -x[1])[:10],
        "top_countries":sorted(countries.items(),key=lambda x: -x[1])[:10],
        "scanner_tools":sorted(scanners.items(),key=lambda x: -x[1])[:10],
        "timeline": [{"bucket": k, "count": v} for k, v in sorted(timeline.items())[-48:]],
    })


# ══════════════════════════════════════════════════════════════════════════════
#  CREDENTIAL ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

_DEFAULT_CREDS = {
    ("admin","admin"),("admin","12345"),("admin","password"),("admin","123456"),
    ("root","root"),("root","12345"),("root","toor"),("root","password"),
    ("admin",""),("root",""),("user","user"),("guest","guest"),
    ("admin","admin123"),("admin","hikvision"),("ubnt","ubnt"),
    ("pi","raspberry"),("admin","1234"),("root","1234"),
}

@app.route("/api/credential-analysis")
@cached(15)
def api_credential_analysis():
    """Username/password pattern analysis."""
    hours = request.args.get("hours", 168, type=int)
    rows  = db.get_recent_attacks(hours, limit=50000)

    usernames = {}
    passwords = {}
    combos    = {}
    default_c = 0
    empty_pass= 0
    long_pass = 0  # > 20 chars (possible hash / stuffing)
    services_with_creds = {}

    for r in rows:
        u   = r.get("username","") or ""
        p   = r.get("password","") or ""
        svc = (r.get("service","") or "").upper()

        if not u and not p:
            continue

        usernames[u] = usernames.get(u, 0) + 1
        if p:
            passwords[p] = passwords.get(p, 0) + 1
        if not p:
            empty_pass += 1
        if len(p) > 20:
            long_pass += 1
        if (u, p) in _DEFAULT_CREDS:
            default_c += 1

        combo = f"{u}:{p}"
        combos[combo] = combos.get(combo, 0) + 1

        if svc:
            if svc not in services_with_creds:
                services_with_creds[svc] = {"total":0,"unique_users":set()}
            services_with_creds[svc]["total"] += 1
            services_with_creds[svc]["unique_users"].add(u)

    total_cred_events = sum(usernames.values())

    svc_list = []
    for svc, d in sorted(services_with_creds.items(), key=lambda x: -x[1]["total"]):
        svc_list.append({"service": svc, "total": d["total"], "unique_users": len(d["unique_users"])})

    return jsonify({
        "total_credential_events": total_cred_events,
        "default_credential_use":  default_c,
        "empty_password_attempts": empty_pass,
        "long_password_attempts":  long_pass,
        "unique_usernames":        len(usernames),
        "unique_passwords":        len(passwords),
        "unique_combos":           len(combos),
        "top_usernames":  sorted(usernames.items(), key=lambda x: -x[1])[:20],
        "top_passwords":  sorted(passwords.items(), key=lambda x: -x[1])[:20],
        "top_combos":     [{"combo":k,"count":v} for k,v in sorted(combos.items(), key=lambda x: -x[1])[:20]],
        "by_service":     svc_list,
    })


# ══════════════════════════════════════════════════════════════════════════════
#  SINGLE IP PROFILE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/ip-profile")
@cached(5)
def api_ip_profile():
    """Full profile for a specific IP: all events, timeline, tools, CVEs."""
    ip    = request.args.get("ip","").strip()
    hours = request.args.get("hours", 168, type=int)
    if not ip:
        return jsonify({"error": "ip parameter required"}), 400

    rows = db.get_recent_attacks(hours, limit=5000)
    rows = [r for r in rows if r.get("source_ip","") == ip]

    if not rows:
        return jsonify({"ip": ip, "found": False, "total": 0})

    services_hit = {}
    attack_types = {}
    cves_used    = {}
    scanners     = {}
    usernames    = {}
    passwords    = {}
    timeline     = {}

    for r in rows:
        svc = (r.get("service","") or "").upper()
        at  = r.get("attack_type","") or ""
        cve = r.get("cve_id","") or ""
        sc  = r.get("scanner_tool","") or ""
        u   = r.get("username","") or ""
        p   = r.get("password","") or ""
        ts  = (r.get("timestamp","") or "")[:13]

        services_hit[svc]  = services_hit.get(svc,0) + 1
        attack_types[at]   = attack_types.get(at,0) + 1
        if cve: cves_used[cve] = cves_used.get(cve,0) + 1
        if sc:  scanners[sc]   = scanners.get(sc,0) + 1
        if u:   usernames[u]   = usernames.get(u,0) + 1
        if p:   passwords[p]   = passwords.get(p,0) + 1
        timeline[ts] = timeline.get(ts,0) + 1

    first  = min(r.get("timestamp","") for r in rows)
    last   = max(r.get("timestamp","") for r in rows)
    sample = rows[0]

    return jsonify({
        "ip":         ip,
        "found":      True,
        "total":      len(rows),
        "first_seen": first,
        "last_seen":  last,
        "country":    sample.get("country",""),
        "city":       sample.get("city",""),
        "asn":        sample.get("asn",""),
        "org":        sample.get("org",""),
        "is_tor":     bool(sample.get("is_tor",0)),
        "is_vpn":     bool(sample.get("is_vpn",0)),
        "is_proxy":   bool(sample.get("is_proxy",0)),
        "vpn_provider": sample.get("vpn_provider",""),
        "services_hit":  sorted(services_hit.items(), key=lambda x: -x[1]),
        "attack_types":  sorted(attack_types.items(),key=lambda x: -x[1]),
        "cves_used":     sorted(cves_used.items(),   key=lambda x: -x[1]),
        "scanner_tools": sorted(scanners.items(),    key=lambda x: -x[1]),
        "usernames_tried": sorted(usernames.items(), key=lambda x: -x[1])[:10],
        "passwords_tried": sorted(passwords.items(), key=lambda x: -x[1])[:10],
        "timeline": [{"bucket":k,"count":v} for k,v in sorted(timeline.items())],
        "recent_events": [_build_session_row(r) for r in rows[:20]],
    })


# ══════════════════════════════════════════════════════════════════════════════
#  GRANULAR ATTACK TIMELINE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/attack-timeline")
@cached(10)
def api_attack_timeline():
    """Hourly/daily/weekly timeline with per-service and per-threat breakdown."""
    granularity = request.args.get("granularity", "hour")  # hour | day | week
    hours       = request.args.get("hours", 168, type=int)
    service     = request.args.get("service","")
    rows        = db.get_recent_attacks(hours, limit=50000, service=service or None)

    # bucket_len: hour=13 chars ("2026-03-25T14"), day=10, week=7
    blen = {"hour": 13, "day": 10, "week": 7}.get(granularity, 13)

    buckets = {}  # bucket -> {total, by_service, by_threat, cves, botnets}
    for r in rows:
        ts  = (r.get("timestamp","") or "")[:blen]
        svc = (r.get("service","") or "unknown").upper()
        thr = r.get("threat_level","low") or "low"

        if ts not in buckets:
            buckets[ts] = {"total":0,"by_service":{},"by_threat":{"critical":0,"high":0,"medium":0,"low":0},"cves":0,"botnets":0}
        b = buckets[ts]
        b["total"] += 1
        b["by_service"][svc] = b["by_service"].get(svc, 0) + 1
        b["by_threat"][thr]  = b["by_threat"].get(thr, 0) + 1
        if r.get("cve_id"):     b["cves"]    += 1
        if r.get("is_botnet"):  b["botnets"] += 1

    result = [{"bucket": k, **v} for k, v in sorted(buckets.items())]
    total  = sum(b["total"] for b in buckets.values())

    # Peak bucket
    peak = max(result, key=lambda x: x["total"]) if result else {}

    return jsonify({
        "granularity": granularity,
        "hours":       hours,
        "total":       total,
        "buckets":     result,
        "peak_bucket": peak.get("bucket",""),
        "peak_count":  peak.get("total",0),
    })


# ══════════════════════════════════════════════════════════════════════════════
#  COMPREHENSIVE THREAT SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/threat-summary")
@cached(15)
def api_threat_summary():
    """
    Comprehensive narrative threat summary with key findings, statistics,
    attack pattern analysis, and auto-generated insights.
    """
    hours    = request.args.get("hours", 24, type=int)
    stats    = db.get_stats(hours)
    cves     = db.get_cve_data(hours)
    creds    = db.get_top_credentials(hours)
    countries= db.get_top_countries(hours)
    services = db.get_service_breakdown(hours)
    sessions = db.get_recent_attacks(hours, limit=20000)

    total     = stats.get("total_attacks", 0)
    unique_ips= stats.get("unique_ips", 0)

    # Anonymization
    tor_c   = sum(1 for r in sessions if r.get("is_tor"))
    vpn_c   = sum(1 for r in sessions if r.get("is_vpn"))
    proxy_c = sum(1 for r in sessions if r.get("is_proxy"))
    anon    = tor_c + vpn_c + proxy_c
    anon_pct= round(anon / max(total,1) * 100, 1)

    # Attack types
    atypes = {}
    for r in sessions:
        at = r.get("attack_type","unknown") or "unknown"
        atypes[at] = atypes.get(at,0) + 1
    top3_atypes = sorted(atypes.items(), key=lambda x: -x[1])[:3]

    # Threat level distribution
    threats = {"critical":0,"high":0,"medium":0,"low":0}
    for r in sessions:
        tl = r.get("threat_level","low") or "low"
        threats[tl] = threats.get(tl, 0) + 1

    # Most hit service
    svc_counts = {(s.get("service","") or "").upper(): s.get("cnt",0) for s in services}
    top_svc = max(svc_counts.items(), key=lambda x: x[1]) if svc_counts else ("N/A", 0)

    # Default creds
    default_c = sum(1 for r in sessions
                    if r.get("username") in ("admin","root","")
                    and r.get("password") in ("admin","12345","password","root",""))
    def_pct   = round(default_c / max(total,1) * 100, 1)

    # CVE severity breakdown
    crit_cves = [c for c in cves if c.get("severity") == "critical"]
    high_cves = [c for c in cves if c.get("severity") == "high"]

    # Unique attacker orgs / ASNs
    orgs = {}
    for r in sessions:
        org = r.get("org","") or ""
        if org: orgs[org] = orgs.get(org,0) + 1
    top_orgs = sorted(orgs.items(), key=lambda x: -x[1])[:5]

    # VPN providers
    vpn_provs = {}
    for r in sessions:
        if r.get("is_vpn") and r.get("vpn_provider"):
            p = r["vpn_provider"]
            vpn_provs[p] = vpn_provs.get(p,0) + 1
    top_vpn = sorted(vpn_provs.items(), key=lambda x: -x[1])[:5]

    # Botnet families
    botnet_fams = {}
    for r in sessions:
        bf = r.get("botnet_family","") or ""
        if bf: botnet_fams[bf] = botnet_fams.get(bf,0) + 1
    top_botnets = sorted(botnet_fams.items(), key=lambda x: -x[1])[:5]

    # Build narrative insights
    insights = []
    if total == 0:
        insights.append("No attack events recorded in this period.")
    else:
        insights.append(f"This honeypot received {total:,} attack events from {unique_ips:,} unique IPs across {stats.get('country_count',0)} countries in the last {hours} hours.")

        if top3_atypes:
            desc = ", ".join(f"{at} ({cnt:,})" for at, cnt in top3_atypes)
            insights.append(f"The most common attack types were: {desc}.")

        if def_pct > 0:
            insights.append(f"{def_pct}% of credential attempts used default/factory credentials (admin/admin, root/12345, etc.) — a hallmark of IoT botnet credential spraying.")

        if crit_cves:
            cve_names = ", ".join(c["cve_id"] for c in crit_cves[:3])
            insights.append(f"{len(crit_cves)} critical CVE(s) were actively exploited: {cve_names}. These target known Hikvision/RTSP/ONVIF vulnerabilities.")

        if anon_pct > 0:
            detail = []
            if tor_c: detail.append(f"{tor_c} via Tor")
            if vpn_c: detail.append(f"{vpn_c} via VPN")
            if proxy_c: detail.append(f"{proxy_c} via proxy")
            insights.append(f"{anon_pct}% of traffic ({', '.join(detail)}) used anonymisation infrastructure, suggesting deliberate operational security by some threat actors.")

        if top_svc[1] > 0:
            insights.append(f"The most targeted service was {top_svc[0]} with {top_svc[1]:,} events.")

        if stats.get("malware_downloads",0) > 0:
            insights.append(f"{stats['malware_downloads']} malware payload download attempts were captured, confirming active IoT botnet recruitment activity.")

        if stats.get("honeytokens_triggered",0) > 0:
            insights.append(f"{stats['honeytokens_triggered']} honeytoken triggers recorded — attackers accessed deliberately planted fake credentials/files.")

        if countries:
            top3_c = ", ".join(f"{c['country']} ({c['cnt']:,})" for c in countries[:3])
            insights.append(f"Top attacking countries: {top3_c}.")

        if top_orgs:
            org_str = ", ".join(f"{o} ({n})" for o, n in top_orgs[:3])
            insights.append(f"Top attacking organisations/ASNs: {org_str}.")

        if top_botnets:
            bot_str = ", ".join(f"{b} ({n})" for b, n in top_botnets[:3])
            insights.append(f"Botnet families detected: {bot_str}.")

    return jsonify({
        "generated_at":    datetime.datetime.utcnow().isoformat(),
        "period_hours":    hours,
        "insights":        insights,
        "key_metrics": {
            "total_attacks":        total,
            "unique_ips":           unique_ips,
            "countries":            stats.get("country_count",0),
            "critical_cves":        len(crit_cves),
            "high_cves":            len(high_cves),
            "total_cves":           len(cves),
            "default_cred_pct":     def_pct,
            "anon_pct":             anon_pct,
            "tor_events":           tor_c,
            "vpn_events":           vpn_c,
            "proxy_events":         proxy_c,
            "botnet_events":        stats.get("botnet_count",0),
            "malware_downloads":    stats.get("malware_downloads",0),
            "honeytokens":          stats.get("honeytokens_triggered",0),
        },
        "threat_level_dist": threats,
        "top_attack_types":  top3_atypes,
        "top_service":       {"service": top_svc[0], "count": top_svc[1]},
        "top_countries":     [{"country":c["country"],"count":c["cnt"]} for c in countries[:10]],
        "critical_cves":     [{"cve_id":c["cve_id"],"name":c.get("cve_name",""),"count":c["cnt"]} for c in crit_cves[:10]],
        "top_credentials":   [{"username":c["username"],"password":c.get("password",""),"count":c["cnt"]} for c in creds[:10]],
        "top_vpn_providers": [{"provider":p,"count":n} for p,n in top_vpn],
        "top_orgs":          [{"org":o,"count":n} for o,n in top_orgs],
        "top_botnets":       [{"family":b,"count":n} for b,n in top_botnets],
        "recommendations":   _generate_recommendations(
            stats, cves, default_c,
            sum(1 for r in sessions if (r.get("service","") or "").lower() == "rtsp")
        ),
    })


# ══════════════════════════════════════════════════════════════════════════════
#  ABUSEIPDB INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

_ABUSEIPDB_REPORTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "logs", "abuseipdb_reports.json")

def _load_abuseipdb_reports():
    try:
        if os.path.exists(_ABUSEIPDB_REPORTS_FILE):
            with open(_ABUSEIPDB_REPORTS_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return []

def _save_abuseipdb_report(ip, categories, comment, score):
    try:
        reports = _load_abuseipdb_reports()
        reports.append({
            "ip":         ip,
            "timestamp":  datetime.datetime.utcnow().isoformat(),
            "categories": categories,
            "comment":    comment[:300],
            "score":      score,
        })
        os.makedirs(os.path.dirname(_ABUSEIPDB_REPORTS_FILE), exist_ok=True)
        with open(_ABUSEIPDB_REPORTS_FILE, "w") as f:
            json.dump(reports[-2000:], f)
    except Exception:
        pass

@app.route("/api/abuseipdb/check")
def api_abuseipdb_check():
    """Check a single IP's AbuseIPDB confidence score."""
    ip  = request.args.get("ip", "").strip()
    key = request.args.get("key", "").strip() or config.ABUSEIPDB_API_KEY
    if not ip:
        return jsonify({"error": "ip parameter required"}), 400
    if not key:
        return jsonify({"error": "no_api_key",
                        "message": "No AbuseIPDB API key configured."}), 503
    try:
        import urllib.request as _ur, urllib.parse as _up
        url = ("https://api.abuseipdb.com/api/v2/check?"
               + _up.urlencode({"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}))
        req = _ur.Request(url, headers={"Key": key, "Accept": "application/json"})
        with _ur.urlopen(req, timeout=8) as resp:
            raw = json.loads(resp.read())
        d   = raw.get("data", {})
        already_reported = any(r["ip"] == ip for r in _load_abuseipdb_reports())
        return jsonify({
            "ip":               d.get("ipAddress", ip),
            "score":            d.get("abuseConfidenceScore", 0),
            "country":          d.get("countryCode", ""),
            "isp":              d.get("isp", ""),
            "usage_type":       d.get("usageType", ""),
            "total_reports":    d.get("totalReports", 0),
            "num_users":        d.get("numDistinctUsers", 0),
            "last_reported":    d.get("lastReportedAt", ""),
            "is_tor":           bool(d.get("isTor", False)),
            "domain":           d.get("domain", ""),
            "already_reported": already_reported,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/abuseipdb/report", methods=["POST"])
def api_abuseipdb_report():
    """Submit an IP report to AbuseIPDB."""
    body       = request.get_json(force=True) or {}
    ip         = (body.get("ip") or "").strip()
    categories = (body.get("categories") or "18,22").strip()
    comment    = (body.get("comment") or "")[:1000]
    key        = (body.get("key") or "").strip() or config.ABUSEIPDB_API_KEY

    if not ip:
        return jsonify({"error": "ip required"}), 400
    if not key:
        return jsonify({"error": "no_api_key",
                        "message": "No AbuseIPDB API key configured."}), 503
    try:
        import urllib.request as _ur, urllib.parse as _up
        payload = _up.urlencode({
            "ip":         ip,
            "categories": categories,
            "comment":    comment,
        }).encode()
        req = _ur.Request(
            "https://api.abuseipdb.com/api/v2/report",
            data=payload,
            headers={"Key": key, "Accept": "application/json"},
        )
        with _ur.urlopen(req, timeout=10) as resp:
            raw = json.loads(resp.read())
        score = raw.get("data", {}).get("abuseConfidenceScore", 0)
        _save_abuseipdb_report(ip, categories, comment, score)
        return jsonify({"success": True, "ip": ip, "score": score})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/abuseipdb/bulk-check", methods=["POST"])
def api_abuseipdb_bulk_check():
    """Check multiple IPs at once (up to 20). Returns scores dict."""
    body = request.get_json(force=True) or {}
    ips  = (body.get("ips") or [])[:20]
    key  = (body.get("key") or "").strip() or config.ABUSEIPDB_API_KEY
    if not key:
        return jsonify({"error": "no_api_key"}), 503
    results = {}
    already = {r["ip"] for r in _load_abuseipdb_reports()}
    import urllib.request as _ur, urllib.parse as _up
    for ip in ips:
        try:
            url = ("https://api.abuseipdb.com/api/v2/check?"
                   + _up.urlencode({"ipAddress": ip, "maxAgeInDays": 90}))
            req = _ur.Request(url, headers={"Key": key, "Accept": "application/json"})
            with _ur.urlopen(req, timeout=6) as resp:
                d = json.loads(resp.read()).get("data", {})
            results[ip] = {
                "score":          d.get("abuseConfidenceScore", 0),
                "total_reports":  d.get("totalReports", 0),
                "country":        d.get("countryCode", ""),
                "isp":            d.get("isp", ""),
                "is_tor":         bool(d.get("isTor", False)),
                "already_reported": ip in already,
            }
        except Exception as e:
            results[ip] = {"error": str(e), "score": -1}
    return jsonify({"results": results})


@app.route("/api/abuseipdb/history")
def api_abuseipdb_history():
    """Return previously reported IPs from this honeypot."""
    reports = _load_abuseipdb_reports()
    reports.reverse()   # newest first
    return jsonify({"reports": reports[:200], "total": len(reports)})


@app.route("/api/abuseipdb/save-key", methods=["POST"])
def api_abuseipdb_save_key():
    """Persist an API key to the environment for the running process."""
    body = request.get_json(force=True) or {}
    key  = (body.get("key") or "").strip()
    if not key:
        return jsonify({"error": "key required"}), 400
    # Write to a key file so it survives dashboard restarts
    key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "logs", ".abuseipdb_key")
    try:
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        with open(key_file, "w") as f:
            f.write(key.strip())
        config.ABUSEIPDB_API_KEY = key.strip()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Load persisted API key on startup
def _load_persisted_abuseipdb_key():
    key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "logs", ".abuseipdb_key")
    try:
        if os.path.exists(key_file) and not config.ABUSEIPDB_API_KEY:
            with open(key_file) as f:
                k = f.read().strip()
            if k:
                config.ABUSEIPDB_API_KEY = k
    except Exception:
        pass

_load_persisted_abuseipdb_key()


@app.after_request
def after_request_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "http://localhost:5001")
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp

# ─── Entry ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host",  default="127.0.0.1")
    p.add_argument("--port",  default=5001, type=int)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    db.init()

    import threading

    # Background WAL checkpoint — runs every 5 minutes to keep WAL file small
    def _wal_checkpoint():
        import sqlite3
        while True:
            time.sleep(300)
            try:
                conn = sqlite3.connect(db.DB_PATH, timeout=10)
                conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
                conn.close()
            except Exception:
                pass
    threading.Thread(target=_wal_checkpoint, daemon=True).start()

    # Warm the cache in a background thread so the first page load is fast
    def _warm():
        try:
            db.get_stats(24)
            db.get_geo_data(24)
            db.get_top_countries(24)
            db.get_top_ips(24, 10)
            db.get_timeline(24)
            db.get_hourly_heatmap()
            db.get_botnet_distribution()
            db.get_service_breakdown(24)
            db.get_iot_stats(24)
            db.get_anonymization_stats(168)
            db.get_notable_events(168, 100)
        except Exception:
            pass
    threading.Thread(target=_warm, daemon=True).start()

    print(f"""
╔══════════════════════════════════════════════════════════╗
║  honeyPot Dashboard  —  http://{args.host}:{args.port}
╠══════════════════════════════════════════════════════════╣
║  CORE                                                    ║
║  /api/health          /api/stats                         ║
║  /api/geo-data        /api/sessions      (full filters)  ║
║  /api/chart-data      /api/top-ips                       ║
║  /api/countries       /api/cve-exploits                  ║
║  /api/top-credentials /api/malware-urls                  ║
║  /api/honeytokens     /api/alerts                        ║
║  /api/service-stats   /api/live-log                      ║
║  ANALYTICS                                               ║
║  /api/threat-summary  /api/attack-types                  ║
║  /api/service-drill   /api/credential-analysis           ║
║  /api/ip-profile      /api/attack-timeline               ║
║  /api/anonymization-stats  /api/iot-stats                ║
║  /api/full-report     /api/vpn-endpoint-changes          ║
║  EXPORT                                                  ║
║  /api/export/csv      /api/export/json                   ║
║  /api/export/report-txt                                  ║
║  /api/vpn-endpoint-changes /api/iot-stats            ║
╚══════════════════════════════════════════════════════╝
""")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)