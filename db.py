#!/usr/bin/env python3
"""
honeyPot — Database Layer
SQLite backend for all attack logging and dashboard queries.
"""

import sqlite3, json, datetime, os
from threading import Lock
from config import DB_PATH, LOG_DIR

_lock = Lock()

# ─── Schema ───────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS attacks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,
    source_ip        TEXT    NOT NULL,
    source_port      INTEGER DEFAULT 0,
    dest_port        INTEGER DEFAULT 0,
    service          TEXT    NOT NULL,
    protocol         TEXT    DEFAULT 'TCP',
    method           TEXT    DEFAULT '',
    path             TEXT    DEFAULT '',
    user_agent       TEXT    DEFAULT '',
    payload          TEXT    DEFAULT '',
    username         TEXT    DEFAULT '',
    password         TEXT    DEFAULT '',
    country          TEXT    DEFAULT 'Unknown',
    city             TEXT    DEFAULT '',
    latitude         REAL,
    longitude        REAL,
    attack_type      TEXT    DEFAULT '',
    threat_level     TEXT    DEFAULT 'low',
    cve_id           TEXT    DEFAULT '',
    session_id       TEXT    DEFAULT '',
    is_botnet        INTEGER DEFAULT 0,
    is_tor           INTEGER DEFAULT 0,
    commands         TEXT    DEFAULT '[]',
    raw_payload      TEXT    DEFAULT ''
);

CREATE TABLE IF NOT EXISTS cve_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    cve_name    TEXT DEFAULT '',
    severity    TEXT DEFAULT 'unknown',
    service     TEXT DEFAULT '',
    payload     TEXT DEFAULT '',
    country     TEXT DEFAULT 'Unknown'
);

CREATE TABLE IF NOT EXISTS malware_urls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    url         TEXT NOT NULL,
    command     TEXT DEFAULT '',
    family      TEXT DEFAULT 'Unknown',
    arch        TEXT DEFAULT 'unknown',
    country     TEXT DEFAULT 'Unknown'
);

CREATE TABLE IF NOT EXISTS honeytoken_triggers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    token_type  TEXT NOT NULL,
    token_value TEXT DEFAULT '',
    service     TEXT DEFAULT '',
    country     TEXT DEFAULT 'Unknown',
    city        TEXT DEFAULT '',
    commands    TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS threat_scores (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    risk_score  REAL DEFAULT 0,
    risk_level  TEXT DEFAULT 'low',
    factors     TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    chain_id    TEXT NOT NULL,
    stages      TEXT DEFAULT '[]',
    is_active   INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS device_fingerprints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    device_type TEXT DEFAULT '',
    vendor      TEXT DEFAULT '',
    model       TEXT DEFAULT '',
    firmware    TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ip_profiles (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip           TEXT UNIQUE NOT NULL,
    total_attacks       INTEGER DEFAULT 0,
    unique_services     INTEGER DEFAULT 0,
    is_botnet           INTEGER DEFAULT 0,
    is_tor              INTEGER DEFAULT 0,
    reputation_score    REAL DEFAULT 0,
    last_seen           TEXT,
    first_seen          TEXT,
    attack_progression  TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_atk_ts   ON attacks(timestamp);
CREATE INDEX IF NOT EXISTS idx_atk_ip   ON attacks(source_ip);
CREATE INDEX IF NOT EXISTS idx_atk_svc  ON attacks(service);
CREATE INDEX IF NOT EXISTS idx_atk_ctry ON attacks(country);
CREATE INDEX IF NOT EXISTS idx_cve_ts   ON cve_attempts(timestamp);
CREATE INDEX IF NOT EXISTS idx_mal_ts   ON malware_urls(timestamp);
CREATE INDEX IF NOT EXISTS idx_ht_ts    ON honeytoken_triggers(timestamp);
CREATE INDEX IF NOT EXISTS idx_ts_ip    ON threat_scores(source_ip);
CREATE INDEX IF NOT EXISTS idx_chain_ip ON attack_chains(source_ip);
CREATE INDEX IF NOT EXISTS idx_fp_ip    ON device_fingerprints(source_ip);
"""

def init():
    """Initialise database and create tables."""
    os.makedirs(LOG_DIR, exist_ok=True)
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()
    print(f"[DB] Initialised: {DB_PATH}")

def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _now():
    return datetime.datetime.utcnow().isoformat()

# ─── Write operations ─────────────────────────────────────────────────────────
def log_attack(d: dict):
    with _lock:
        try:
            conn = _connect()
            conn.execute("""
                INSERT INTO attacks
                  (timestamp, source_ip, source_port, dest_port, service, protocol,
                   method, path, user_agent, payload, username, password,
                   country, city, latitude, longitude,
                   attack_type, threat_level, cve_id, session_id,
                   is_botnet, is_tor, commands, raw_payload)
                VALUES
                  (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                d.get("timestamp",   _now()),
                d.get("source_ip",   d.get("ip", "")),
                d.get("source_port", 0),
                d.get("dest_port",   d.get("destination_port", 0)),
                d.get("service",     ""),
                d.get("protocol",    "TCP"),
                d.get("method",      ""),
                d.get("path",        d.get("payload", "")[:512]),
                d.get("user_agent",  "")[:512],
                d.get("payload",     "")[:1024],
                d.get("username",    ""),
                d.get("password",    ""),
                d.get("country",     "Unknown"),
                d.get("city",        ""),
                d.get("latitude",    None),
                d.get("longitude",   None),
                d.get("attack_type", ""),
                d.get("threat_level","low"),
                d.get("cve_id",      ""),
                d.get("session_id",  ""),
                1 if d.get("is_botnet") else 0,
                1 if d.get("is_tor")    else 0,
                json.dumps(d.get("commands", [])),
                d.get("raw_payload", "")[:2048],
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] log_attack error: {e}")

def log_cve(timestamp, source_ip, cve_id, cve_name, severity, service, payload, country="Unknown"):
    with _lock:
        try:
            conn = _connect()
            conn.execute(
                "INSERT INTO cve_attempts(timestamp,source_ip,cve_id,cve_name,severity,service,payload,country) VALUES(?,?,?,?,?,?,?,?)",
                (timestamp, source_ip, cve_id, cve_name, severity, service, payload[:1024], country)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] log_cve error: {e}")

def log_malware(timestamp, source_ip, url, command, family="Unknown", arch="unknown", country="Unknown"):
    with _lock:
        try:
            conn = _connect()
            conn.execute(
                "INSERT INTO malware_urls(timestamp,source_ip,url,command,family,arch,country) VALUES(?,?,?,?,?,?,?)",
                (timestamp, source_ip, url, command[:512], family, arch, country)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] log_malware error: {e}")

def log_honeytoken(timestamp, source_ip, token_type, token_value, service, country, city="", commands=None):
    with _lock:
        try:
            conn = _connect()
            conn.execute(
                "INSERT INTO honeytoken_triggers(timestamp,source_ip,token_type,token_value,service,country,city,commands) VALUES(?,?,?,?,?,?,?,?)",
                (timestamp, source_ip, token_type, token_value, service, country, city, json.dumps(commands or []))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] log_honeytoken error: {e}")

def log_threat_score(timestamp, source_ip, risk_score, risk_level, factors=None):
    """Log threat intelligence score for IP"""
    with _lock:
        try:
            conn = _connect()
            conn.execute(
                "INSERT INTO threat_scores(timestamp,source_ip,risk_score,risk_level,factors) VALUES(?,?,?,?,?)",
                (timestamp, source_ip, risk_score, risk_level, json.dumps(factors or []))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] log_threat_score error: {e}")

def log_attack_chain(timestamp, source_ip, chain_id, stages):
    """Log detected attack chain/progression"""
    with _lock:
        try:
            conn = _connect()
            conn.execute(
                "INSERT INTO attack_chains(timestamp,source_ip,chain_id,stages,is_active) VALUES(?,?,?,?,1)",
                (timestamp, source_ip, chain_id, json.dumps(stages or []))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] log_attack_chain error: {e}")

def log_device_fingerprint(timestamp, source_ip, device_type, vendor, model, firmware):
    """Log detected device type from banner/response"""
    with _lock:
        try:
            conn = _connect()
            conn.execute(
                "INSERT INTO device_fingerprints(timestamp,source_ip,device_type,vendor,model,firmware) VALUES(?,?,?,?,?,?)",
                (timestamp, source_ip, device_type, vendor, model, firmware)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] log_device_fingerprint error: {e}")

def update_ip_profile(source_ip, attack_data):
    """Update IP profile with aggregated stats"""
    with _lock:
        try:
            conn = _connect()
            # Check if profile exists
            existing = conn.execute("SELECT id FROM ip_profiles WHERE source_ip=?", (source_ip,)).fetchone()
            
            if existing:
                conn.execute("""
                    UPDATE ip_profiles SET
                        total_attacks = total_attacks + 1,
                        is_botnet = MAX(is_botnet, ?),
                        is_tor = MAX(is_tor, ?),
                        last_seen = ?
                    WHERE source_ip = ?
                """, (
                    1 if attack_data.get("is_botnet") else 0,
                    1 if attack_data.get("is_tor") else 0,
                    _now(),
                    source_ip
                ))
            else:
                conn.execute("""
                    INSERT INTO ip_profiles
                    (source_ip, total_attacks, unique_services, is_botnet, is_tor, last_seen, first_seen)
                    VALUES(?,1,1,?,?,?,?)
                """, (
                    source_ip,
                    1 if attack_data.get("is_botnet") else 0,
                    1 if attack_data.get("is_tor") else 0,
                    _now(),
                    _now()
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] update_ip_profile error: {e}")

# ─── Read operations ──────────────────────────────────────────────────────────
def _cutoff(hours):
    return (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).isoformat()

def query(sql, params=()):
    """Generic read query — returns list of Row dicts."""
    try:
        conn = _connect()
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        conn.close()
        return rows
    except Exception as e:
        print(f"[DB] query error: {e}")
        return []

def scalar(sql, params=()):
    """Returns first column of first row, or 0."""
    try:
        conn = _connect()
        row = conn.execute(sql, params).fetchone()
        conn.close()
        return row[0] if row else 0
    except Exception as e:
        print(f"[DB] scalar error: {e}")
        return 0

def get_stats(hours=24):
    c = _cutoff(hours)
    svc_rows = query("SELECT service, COUNT(*) n FROM attacks WHERE timestamp>? GROUP BY service", (c,))
    svc = {r["service"]: r["n"] for r in svc_rows}
    return {
        "total_attacks":        scalar("SELECT COUNT(*) FROM attacks WHERE timestamp>?", (c,)),
        "unique_ips":           scalar("SELECT COUNT(DISTINCT source_ip) FROM attacks WHERE timestamp>?", (c,)),
        "country_count":        scalar("SELECT COUNT(DISTINCT country) FROM attacks WHERE timestamp>? AND country!='Unknown' AND country!='Local'", (c,)),
        "botnet_count":         scalar("SELECT COUNT(*) FROM attacks WHERE timestamp>? AND is_botnet=1", (c,)),
        "tor_count":            scalar("SELECT COUNT(*) FROM attacks WHERE timestamp>? AND is_tor=1", (c,)),
        "cve_exploits":         scalar("SELECT COUNT(*) FROM cve_attempts WHERE timestamp>?", (c,)),
        "malware_downloads":    scalar("SELECT COUNT(*) FROM malware_urls WHERE timestamp>?", (c,)),
        "honeytokens_triggered":scalar("SELECT COUNT(*) FROM honeytoken_triggers WHERE timestamp>?", (c,)),
        "http_attacks":         svc.get("http", 0) + svc.get("https", 0) + svc.get("http_alt", 0),
        "telnet_attacks":       svc.get("telnet", 0),
        "ssh_attacks":          svc.get("ssh", 0),
        "ftp_attacks":          svc.get("ftp", 0),
        "rtsp_attacks":         svc.get("rtsp", 0),
        "mqtt_attacks":         svc.get("mqtt", 0),
        "redis_attacks":        svc.get("redis", 0),
        "mysql_attacks":        svc.get("mysql", 0),
        "docker_attacks":       svc.get("docker", 0),
        "vnc_attacks":          svc.get("vnc", 0),
        "rdp_attacks":          svc.get("rdp", 0),
        "modbus_attacks":       svc.get("modbus", 0),
        "services":             svc,
    }

def get_geo_data(hours=24):
    c = _cutoff(hours)
    return query("""
        SELECT latitude, longitude, country,
               COUNT(*) cnt,
               SUM(is_botnet) bots,
               SUM(is_tor) tors,
               MAX(timestamp) last_seen
        FROM attacks
        WHERE timestamp>? AND latitude IS NOT NULL AND longitude IS NOT NULL
        GROUP BY ROUND(latitude,1), ROUND(longitude,1), country
        ORDER BY cnt DESC
    """, (c,))

def get_recent_attacks(hours=24, limit=200, service=None, threat=None):
    c   = _cutoff(hours)
    sql = "SELECT * FROM attacks WHERE timestamp>?"
    params = [c]
    if service:
        sql += " AND service=?"; params.append(service.lower())
    if threat:
        sql += " AND threat_level=?"; params.append(threat)
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    return query(sql, params)

def get_timeline(hours=24):
    c  = _cutoff(hours)
    if hours <= 24:
        fmt, trunc = "%Y-%m-%dT%H:00", "strftime('%Y-%m-%dT%H:00', timestamp)"
    else:
        fmt, trunc = "%Y-%m-%d", "strftime('%Y-%m-%d', timestamp)"
    return query(f"""
        SELECT {trunc} bucket,
               COUNT(*) total,
               SUM(is_botnet) botnets,
               SUM(CASE WHEN cve_id!='' THEN 1 ELSE 0 END) cves
        FROM attacks WHERE timestamp>?
        GROUP BY bucket ORDER BY bucket
    """, (c,))

def get_top_ips(hours=24, limit=20):
    c = _cutoff(hours)
    return query("""
        SELECT source_ip, country, COUNT(*) cnt,
               SUM(is_botnet) bots, SUM(is_tor) tors,
               MAX(timestamp) last_seen,
               GROUP_CONCAT(DISTINCT service) services
        FROM attacks WHERE timestamp>?
        GROUP BY source_ip ORDER BY cnt DESC LIMIT ?
    """, (c, limit))

def get_top_countries(hours=24, limit=20):
    c = _cutoff(hours)
    return query("""
        SELECT country, COUNT(*) cnt, COUNT(DISTINCT source_ip) ips
        FROM attacks WHERE timestamp>? AND country!='Unknown' AND country!='Local'
        GROUP BY country ORDER BY cnt DESC LIMIT ?
    """, (c, limit))

def get_top_credentials(hours=168, limit=30):
    c = _cutoff(hours)
    return query("""
        SELECT username, password, COUNT(*) cnt, SUM(is_botnet) bots
        FROM attacks WHERE timestamp>? AND username!='' AND username IS NOT NULL
        GROUP BY username, password ORDER BY cnt DESC LIMIT ?
    """, (c, limit))

def get_cve_data(hours=168):
    c = _cutoff(hours)
    return query("""
        SELECT cve_id, cve_name, severity, service,
               COUNT(*) cnt, COUNT(DISTINCT source_ip) unique_ips,
               MAX(timestamp) last_seen
        FROM cve_attempts WHERE timestamp>?
        GROUP BY cve_id ORDER BY cnt DESC
    """, (c,))

def get_malware_urls(hours=168):
    c = _cutoff(hours)
    return query("""
        SELECT url, family, arch, COUNT(*) cnt,
               COUNT(DISTINCT source_ip) unique_ips,
               MAX(timestamp) last_seen
        FROM malware_urls WHERE timestamp>?
        GROUP BY url ORDER BY cnt DESC LIMIT 50
    """, (c,))

def get_honeytoken_data(hours=168):
    c = _cutoff(hours)
    rows = query("SELECT * FROM honeytoken_triggers WHERE timestamp>? ORDER BY timestamp DESC", (c,))
    from collections import Counter
    by_file = Counter(r["token_value"] for r in rows)
    return {
        "total":       len(rows),
        "unique_ips":  len({r["source_ip"] for r in rows}),
        "by_file":     [{"path": p, "count": n} for p, n in by_file.most_common()],
        "recent":      rows[:30],
    }

def get_alerts(hours=1, limit=25):
    c = _cutoff(hours)
    alerts = []

    for r in query("SELECT * FROM cve_attempts WHERE timestamp>? ORDER BY timestamp DESC LIMIT 8", (c,)):
        alerts.append({
            "timestamp": r["timestamp"],
            "type": "CVE_EXPLOIT",
            "severity": "critical",
            "ip": r["source_ip"],
            "country": r["country"],
            "message": f"{r['cve_id']} — {r['cve_name']} from {r['source_ip']}",
        })
    for r in query("SELECT * FROM honeytoken_triggers WHERE timestamp>? ORDER BY timestamp DESC LIMIT 8", (c,)):
        alerts.append({
            "timestamp": r["timestamp"],
            "type": "HONEYTOKEN",
            "severity": "critical",
            "ip": r["source_ip"],
            "country": r["country"],
            "message": f"Honeytoken [{r['token_type']}] {r['token_value']} — {r['source_ip']} ({r['country']})",
        })
    for r in query("SELECT * FROM attacks WHERE timestamp>? AND is_botnet=1 ORDER BY timestamp DESC LIMIT 8", (c,)):
        alerts.append({
            "timestamp": r["timestamp"],
            "type": "BOTNET",
            "severity": "high",
            "ip": r["source_ip"],
            "country": r["country"],
            "message": f"Botnet cred {r['username']}/{r['password']} — {r['source_ip']} ({r['country']})",
        })
    for r in query("SELECT * FROM attacks WHERE timestamp>? AND service='docker' ORDER BY timestamp DESC LIMIT 5", (c,)):
        alerts.append({
            "timestamp": r["timestamp"],
            "type": "DOCKER",
            "severity": "critical",
            "ip": r["source_ip"],
            "country": r["country"],
            "message": f"Docker API escape attempt — {r['source_ip']} ({r['country']}) path: {r['path'][:60]}",
        })

    alerts.sort(key=lambda x: x["timestamp"], reverse=True)
    return alerts[:limit]

def get_service_breakdown(hours=24):
    c = _cutoff(hours)
    return query("""
        SELECT service, dest_port, COUNT(*) cnt,
               COUNT(DISTINCT source_ip) unique_ips,
               SUM(is_botnet) bots,
               MAX(timestamp) last_seen
        FROM attacks WHERE timestamp>?
        GROUP BY service ORDER BY cnt DESC
    """, (c,))

def get_hourly_heatmap():
    """Return 24 attack counts (one per hour-of-day, UTC) over last 7 days."""
    rows = query("""
        SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS hour,
               COUNT(*) cnt
        FROM attacks
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY hour
        ORDER BY hour
    """)
    bucket = [0] * 24
    for r in rows:
        h = r["hour"]
        if 0 <= h <= 23:
            bucket[h] = r["cnt"]
    return bucket

def get_botnet_distribution():
    """Classify botnet sessions into families using command heuristics."""
    rows = query("""
        SELECT commands FROM attacks
        WHERE is_botnet=1 AND commands!='[]'
        AND timestamp > datetime('now', '-7 days')
    """)
    import json as _json
    families = {"Mirai": 0, "Gafgyt": 0, "Sora": 0, "Muhstik": 0, "Mozi": 0, "Other": 0}
    indicators = {
        "Mirai":   ["busybox", "/bin/busybox", "cat /proc/mounts", "echo -ne", "MIRAI"],
        "Gafgyt":  ["HTTPFLOOD", "UDPFLOOD", "PING", "HOLD", "tftp -g"],
        "Sora":    ["SORA", "/bin/busybox SORA"],
        "Muhstik": ["muhstik", "JOIN #", "irc"],
        "Mozi":    ["mozi", "nttpd", "dht"],
    }
    total = 0
    for r in rows:
        try:
            cmds = _json.loads(r["commands"])
        except Exception:
            cmds = []
        s = " ".join(cmds).lower()
        matched = False
        for fam, kws in indicators.items():
            if any(kw.lower() in s for kw in kws):
                families[fam] += 1
                matched = True
                break
        if not matched:
            families["Other"] += 1
        total += 1

    # If no command data, at least count botnet hits by credential
    if total == 0:
        cnt = scalar("SELECT COUNT(*) FROM attacks WHERE is_botnet=1 AND timestamp > datetime('now','-7 days')")
        families["Other"] = cnt
    return {"families": families, "total": sum(families.values())}

def get_report_data(hours=24):
    c  = _cutoff(hours)
    t  = get_timeline(hours)
    return {
        "generated_at":  datetime.datetime.utcnow().isoformat(),
        "period_hours":  hours,
        "stats":         get_stats(hours),
        "top_ips":       get_top_ips(hours, 10),
        "top_countries": get_top_countries(hours, 10),
        "cve_data":      get_cve_data(hours),
        "timeline":      t,
        "services":      get_service_breakdown(hours),
    }
