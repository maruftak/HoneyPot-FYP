#!/usr/bin/env python3
"""
honeyPot Database Layer
SQLite with WAL mode for concurrent read/write access.
Connection pooling for multi-threaded access.
"""

import sqlite3
import threading
import json
import time
import datetime
import logging
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

import config

logger = logging.getLogger(__name__)

DB_PATH    = config.DB_PATH
_lock      = threading.RLock()
_pool      = []
_pool_size = getattr(config, "DB_POOL_SIZE",  5)
_timeout   = getattr(config, "DB_TIMEOUT",   30)
_wal_mode  = getattr(config, "DB_WAL_MODE",  True)

# ── Query-level in-process TTL cache ─────────────────────────────────────────
_qcache: Dict[str, tuple] = {}   # key → (result, expire_epoch)
_qcache_lock = threading.Lock()

def _cached(key: str, fn, ttl: int = 300):
    """Return cached result if fresh, otherwise call fn(), cache and return."""
    now = time.time()
    with _qcache_lock:
        entry = _qcache.get(key)
        if entry and entry[1] > now:
            return entry[0]
    result = fn()
    with _qcache_lock:
        _qcache[key] = (result, now + ttl)
    return result


def init():
    """Initialize database schema if not exists.
    Silently skips DDL if the DB is read-only (tables already exist on the host).
    """
    ddl_statements = [
        """CREATE TABLE IF NOT EXISTS attacks (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp            TEXT NOT NULL DEFAULT (datetime('now')),
                source_ip            TEXT NOT NULL,
                source_port          INTEGER,
                dest_port            INTEGER,
                service              TEXT,
                protocol             TEXT,
                attack_type          TEXT,
                threat_level         TEXT,
                username             TEXT,
                password             TEXT,
                cve_id               TEXT,
                cve_name             TEXT,
                is_botnet            INTEGER DEFAULT 0,
                botnet_family        TEXT,
                botnet_creds         TEXT,
                country              TEXT,
                city                 TEXT,
                latitude             REAL,
                longitude            REAL,
                asn                  TEXT,
                org                  TEXT,
                is_tor               INTEGER DEFAULT 0,
                tor_exit_ip          TEXT,
                tor_exit_node        TEXT,
                is_vpn               INTEGER DEFAULT 0,
                vpn_provider         TEXT,
                vpn_exit_country     TEXT,
                is_proxy             INTEGER DEFAULT 0,
                proxy_type           TEXT,
                anonymized           INTEGER DEFAULT 0,
                anonymization_method TEXT,
                method               TEXT,
                path                 TEXT,
                user_agent           TEXT,
                payload              TEXT,
                raw_payload          TEXT,
                scanner_tool         TEXT,
                scanner_version      TEXT,
                device_info          TEXT,
                firmware_version     TEXT,
                architecture         TEXT,
                commands             TEXT,
                attack_patterns      TEXT,
                session_id           TEXT UNIQUE,
                event_type           TEXT,
                metadata             TEXT
            )""",
        "CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_attacks_source_ip ON attacks(source_ip)",
        "CREATE INDEX IF NOT EXISTS idx_attacks_service   ON attacks(service)",
        "CREATE INDEX IF NOT EXISTS idx_attacks_threat    ON attacks(threat_level)",
        "CREATE INDEX IF NOT EXISTS idx_attacks_country   ON attacks(country)",
        "CREATE INDEX IF NOT EXISTS idx_attacks_is_tor    ON attacks(is_tor)",
        "CREATE INDEX IF NOT EXISTS idx_attacks_is_vpn    ON attacks(is_vpn)",
        "CREATE INDEX IF NOT EXISTS idx_attacks_cve       ON attacks(cve_id)",
        # Covering indexes for GROUP BY queries (68s → <1s for countries, geo, etc.)
        "CREATE INDEX IF NOT EXISTS idx_atk_ts_ctry_ip ON attacks(timestamp, country, source_ip)",
        "CREATE INDEX IF NOT EXISTS idx_atk_ts_ip_svc  ON attacks(timestamp, source_ip, service, is_botnet, is_tor, scanner_tool)",
        "CREATE INDEX IF NOT EXISTS idx_atk_ts_lat     ON attacks(timestamp, latitude, longitude, country, is_botnet, is_tor)",
        """CREATE TABLE IF NOT EXISTS honeytoken_triggers (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
                token_type  TEXT,
                token_value TEXT,
                source_ip   TEXT,
                service     TEXT,
                country     TEXT,
                city        TEXT DEFAULT '',
                commands    TEXT DEFAULT '[]'
            )""",
        "CREATE INDEX IF NOT EXISTS idx_ht_timestamp ON honeytoken_triggers(timestamp)",
    ]
    try:
        with _get_conn() as conn:
            for stmt in ddl_statements:
                conn.execute(stmt)
            conn.commit()
    except Exception as e:
        # DB may be read-only (owned by root on the host) — tables already exist
        logger.warning(f"init() DDL skipped (read-only or already exists): {e}")
    
    if _wal_mode:
        with _get_conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.commit()
    
    logger.info(f"Database initialized: {DB_PATH}")


@contextmanager
def _get_conn():
    """Get a database connection from pool or create new."""
    conn = None
    try:
        with _lock:
            if _pool:
                conn = _pool.pop()
        
        if conn is None:
            conn = sqlite3.connect(DB_PATH, timeout=_timeout, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
        
        yield conn
    finally:
        if conn:
            with _lock:
                if len(_pool) < _pool_size:
                    _pool.append(conn)
                else:
                    conn.close()


def log_attack(data: Dict[str, Any]) -> int:
    """
    Log an attack event. Returns the inserted row ID.
    
    Args:
        data: Dictionary with attack fields (timestamp, source_ip, service, etc.)
    
    Returns:
        Row ID of inserted attack
    """
    if not data:
        return 0
    
    # Ensure timestamp exists
    if "timestamp" not in data or not data["timestamp"]:
        data["timestamp"] = datetime.datetime.utcnow().isoformat()
    
    # Serialize complex fields
    if isinstance(data.get("commands"), (list, dict)):
        data["commands"] = json.dumps(data["commands"])
    if isinstance(data.get("metadata"), dict):
        data["metadata"] = json.dumps(data["metadata"])
    if isinstance(data.get("attack_patterns"), list):
        data["attack_patterns"] = json.dumps(data["attack_patterns"])
    
    fields = [k for k in data.keys() if k in [
        "timestamp", "source_ip", "source_port", "dest_port", "service", "protocol",
        "attack_type", "threat_level", "username", "password", "cve_id", "cve_name",
        "is_botnet", "botnet_family", "botnet_creds", "country", "city", "latitude",
        "longitude", "asn", "org", "is_tor", "tor_exit_ip", "tor_exit_node", "is_vpn",
        "vpn_provider", "vpn_exit_country", "is_proxy", "proxy_type", "anonymized",
        "anonymization_method", "method", "path", "user_agent", "payload", "raw_payload",
        "scanner_tool", "scanner_version", "device_info", "firmware_version",
        "architecture", "commands", "attack_patterns", "session_id", "event_type", "metadata"
    ]]
    
    placeholders = ",".join(["?" for _ in fields])
    columns = ",".join(fields)
    values = [data.get(k) for k in fields]
    
    try:
        with _get_conn() as conn:
            cursor = conn.execute(
                f"INSERT INTO attacks ({columns}) VALUES ({placeholders})",
                values
            )
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error logging attack: {e}", exc_info=True)
        return 0


def get_stats(hours: int = 24) -> Dict[str, Any]:
    """Get attack statistics for the past N hours (single-pass, cached)."""
    def _fetch():
        cutoff = _cutoff(hours)
        try:
            with _get_conn() as conn:
                # Single combined pass — replaces 13 separate COUNT queries
                row = conn.execute("""
                    SELECT
                        COUNT(*)                                                          AS total,
                        COUNT(DISTINCT source_ip)                                         AS unique_ips,
                        COUNT(DISTINCT CASE WHEN country IS NOT NULL THEN country END)    AS countries,
                        SUM(CASE WHEN cve_id IS NOT NULL THEN 1 ELSE 0 END)              AS cve_exploits,
                        SUM(CASE WHEN is_botnet=1       THEN 1 ELSE 0 END)              AS botnet,
                        SUM(CASE WHEN payload LIKE '%http%'
                                  AND (attack_type LIKE '%download%'
                                   OR  attack_type LIKE '%malware%')
                                  THEN 1 ELSE 0 END)                                     AS malware,
                        SUM(CASE WHEN lower(service)='ssh'                       THEN 1 ELSE 0 END) AS ssh,
                        SUM(CASE WHEN lower(service) IN ('http','https')         THEN 1 ELSE 0 END) AS http,
                        SUM(CASE WHEN lower(service)='rtsp'                      THEN 1 ELSE 0 END) AS rtsp,
                        SUM(CASE WHEN lower(service)='onvif'                     THEN 1 ELSE 0 END) AS onvif,
                        SUM(CASE WHEN is_tor=1                     THEN 1 ELSE 0 END)   AS tor,
                        SUM(CASE WHEN is_vpn=1                     THEN 1 ELSE 0 END)   AS vpn
                    FROM attacks WHERE timestamp > ?
                """, (cutoff,)).fetchone()

                honeytokens = conn.execute(
                    "SELECT COUNT(*) as c FROM honeytoken_triggers WHERE timestamp > ?",
                    (cutoff,)
                ).fetchone()["c"]

                d = dict(row)
                return {
                    "total_attacks":       d["total"]       or 0,
                    "unique_ips":          d["unique_ips"]  or 0,
                    "country_count":       d["countries"]   or 0,
                    "cve_exploits":        d["cve_exploits"] or 0,
                    "botnet_count":        d["botnet"]      or 0,
                    "malware_downloads":   d["malware"]     or 0,
                    "honeytokens_triggered": honeytokens,
                    "ssh_attacks":         d["ssh"]         or 0,
                    "http_attacks":        d["http"]        or 0,
                    "rtsp_attacks":        d["rtsp"]        or 0,
                    "onvif_attacks":       d["onvif"]       or 0,
                    "tor_attackers":       d["tor"]         or 0,
                    "vpn_attackers":       d["vpn"]         or 0,
                    "brute_force_bursts":  0,
                    "uptime_seconds":      0,
                }
        except Exception as e:
            logger.error(f"Error getting stats: {e}", exc_info=True)
            return {}
    return _cached(f"stats:{hours}", _fetch, ttl=60)


def get_recent_attacks(
    hours: int = 168,
    limit: int = 500,
    service: Optional[str] = None,
    threat: Optional[str] = None
) -> List[Dict]:
    """Get recent attack events with optional filtering."""
    cutoff = _cutoff(hours)
    
    try:
        with _get_conn() as conn:
            query = "SELECT * FROM attacks WHERE timestamp > ?"
            params = [cutoff]
            
            if service:
                query += " AND lower(service)=lower(?)"
                params.append(service)

            if threat:
                query += " AND threat_level=?"
                params.append(threat)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error getting recent attacks: {e}", exc_info=True)
        return []


def get_top_ips(hours: int = 168, limit: int = 20) -> List[Dict]:
    """Get most active source IPs (cached, covering-index hint)."""
    def _fetch():
        cutoff = _cutoff(hours)
        try:
            with _get_conn() as conn:
                rows = conn.execute("""
                    SELECT
                        source_ip,
                        COUNT(*) as cnt,
                        country,
                        MAX(timestamp) as last_seen,
                        MAX(is_botnet) as bots,
                        MAX(is_tor) as tors,
                        GROUP_CONCAT(service, ',') as services,
                        MAX(scanner_tool) as scanner_tool
                    FROM attacks INDEXED BY idx_atk_ts_ip_svc
                    WHERE timestamp > ?
                    GROUP BY source_ip
                    ORDER BY cnt DESC
                    LIMIT ?
                """, (cutoff, limit)).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            # Fallback if covering index not yet created
            cutoff = _cutoff(hours)
            try:
                with _get_conn() as conn:
                    rows = conn.execute("""
                        SELECT
                            source_ip,
                            COUNT(*) as cnt,
                            country,
                            MAX(timestamp) as last_seen,
                            MAX(is_botnet) as bots,
                            MAX(is_tor) as tors,
                            GROUP_CONCAT(service, ',') as services,
                            MAX(scanner_tool) as scanner_tool
                        FROM attacks
                        WHERE timestamp > ?
                        GROUP BY source_ip
                        ORDER BY cnt DESC
                        LIMIT ?
                    """, (cutoff, limit)).fetchall()
                    return [dict(r) for r in rows]
            except Exception as e:
                logger.error(f"Error getting top IPs: {e}", exc_info=True)
                return []
    return _cached(f"top_ips:{hours}:{limit}", _fetch, ttl=120)


def get_top_countries(hours: int = 168) -> List[Dict]:
    """Get top attacking countries (cached, covering-index hint)."""
    def _fetch():
        cutoff = _cutoff(hours)
        try:
            with _get_conn() as conn:
                rows = conn.execute("""
                    SELECT
                        country,
                        COUNT(*) as cnt,
                        COUNT(DISTINCT source_ip) as ips
                    FROM attacks INDEXED BY idx_atk_ts_ctry_ip
                    WHERE timestamp > ? AND country IS NOT NULL
                    GROUP BY country
                    ORDER BY cnt DESC
                    LIMIT 50
                """, (cutoff,)).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            # Fallback if covering index not yet created
            cutoff = _cutoff(hours)
            try:
                with _get_conn() as conn:
                    rows = conn.execute("""
                        SELECT
                            country,
                            COUNT(*) as cnt,
                            COUNT(DISTINCT source_ip) as ips
                        FROM attacks
                        WHERE timestamp > ? AND country IS NOT NULL
                        GROUP BY country
                        ORDER BY cnt DESC
                        LIMIT 50
                    """, (cutoff,)).fetchall()
                    return [dict(r) for r in rows]
            except Exception as e:
                logger.error(f"Error getting top countries: {e}", exc_info=True)
                return []
    return _cached(f"top_countries:{hours}", _fetch, ttl=120)


def get_geo_data(hours: int = 168) -> List[Dict]:
    """Get geographic distribution for map (cached, covering-index hint)."""
    def _fetch():
        cutoff = _cutoff(hours)
        try:
            with _get_conn() as conn:
                rows = conn.execute("""
                    SELECT
                        country,
                        latitude,
                        longitude,
                        COUNT(*) as cnt,
                        SUM(is_botnet) as bots,
                        SUM(is_tor) as tors,
                        MAX(timestamp) as last_seen
                    FROM attacks INDEXED BY idx_atk_ts_lat
                    WHERE timestamp > ? AND latitude IS NOT NULL
                    GROUP BY country
                    ORDER BY cnt DESC
                """, (cutoff,)).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            # Fallback if covering index not yet created
            cutoff = _cutoff(hours)
            try:
                with _get_conn() as conn:
                    rows = conn.execute("""
                        SELECT
                            country,
                            latitude,
                            longitude,
                            COUNT(*) as cnt,
                            SUM(is_botnet) as bots,
                            SUM(is_tor) as tors,
                            MAX(timestamp) as last_seen
                        FROM attacks
                        WHERE timestamp > ? AND latitude IS NOT NULL
                        GROUP BY country
                        ORDER BY cnt DESC
                    """, (cutoff,)).fetchall()
                    return [dict(r) for r in rows]
            except Exception as e:
                logger.error(f"Error getting geo data: {e}", exc_info=True)
                return []
    return _cached(f"geo_data:{hours}", _fetch, ttl=120)


def get_cve_data(hours: int = 168) -> List[Dict]:
    """Get CVE exploit statistics."""
    cutoff = _cutoff(hours)
    
    try:
        with _get_conn() as conn:
            rows = conn.execute("""
                SELECT
                    cve_id,
                    cve_name,
                    service,
                    COUNT(*) as cnt,
                    COUNT(DISTINCT source_ip) as unique_ips,
                    CASE
                        WHEN cve_id LIKE '%critical%' THEN 'critical'
                        WHEN cve_id IN ('CVE-2019-15681','CVE-2020-14397','CVE-2020-25708') THEN 'critical'
                        ELSE 'high'
                    END as severity,
                    MAX(timestamp) as last_seen
                FROM attacks
                WHERE timestamp > ? AND cve_id IS NOT NULL
                GROUP BY cve_id
                ORDER BY cnt DESC
                LIMIT 100
            """, (cutoff,)).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error getting CVE data: {e}", exc_info=True)
        return []


def get_top_credentials(hours: int = 168, service: Optional[str] = None) -> List[Dict]:
    """Get most common credential pairs used in attacks."""
    cutoff = _cutoff(hours)
    
    try:
        with _get_conn() as conn:
            query = """
                SELECT
                    username,
                    password,
                    service,
                    COUNT(*) as cnt,
                    SUM(is_botnet) as bots
                FROM attacks
                WHERE timestamp > ? AND (username IS NOT NULL OR password IS NOT NULL)
            """
            params = [cutoff]
            
            if service:
                query += " AND lower(service)=lower(?)"
                params.append(service)

            query += " GROUP BY username, password, service ORDER BY cnt DESC LIMIT 100"
            
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error getting credentials: {e}", exc_info=True)
        return []


def get_malware_urls(hours: int = 168) -> List[Dict]:
    """Get detected malware download URLs."""
    cutoff = _cutoff(hours)
    
    try:
        with _get_conn() as conn:
            rows = conn.execute("""
                SELECT
                    payload as url,
                    'Mirai/IoT' as family,
                    architecture,
                    COUNT(*) as cnt,
                    COUNT(DISTINCT source_ip) as unique_ips,
                    MAX(timestamp) as last_seen
                FROM attacks
                WHERE timestamp > ? AND payload LIKE 'http%' AND (attack_type LIKE '%download%' OR commands LIKE '%wget%')
                GROUP BY payload
                ORDER BY cnt DESC
                LIMIT 50
            """, (cutoff,)).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error getting malware URLs: {e}", exc_info=True)
        return []


def get_service_breakdown(hours: int = 168) -> List[Dict]:
    """Get attack counts by service (cached)."""
    def _fetch():
        cutoff = _cutoff(hours)
        try:
            with _get_conn() as conn:
                rows = conn.execute("""
                    SELECT
                        upper(service) as service,
                        dest_port,
                        COUNT(*) as cnt,
                        COUNT(DISTINCT source_ip) as unique_ips,
                        SUM(is_botnet) as bots,
                        SUM(CASE WHEN username IS NOT NULL THEN 1 ELSE 0 END) as cred_count,
                        MAX(timestamp) as last_seen
                    FROM attacks
                    WHERE timestamp > ?
                    GROUP BY lower(service)
                    ORDER BY cnt DESC
                """, (cutoff,)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting service breakdown: {e}", exc_info=True)
            return []
    return _cached(f"service_breakdown:{hours}", _fetch, ttl=120)


def get_anonymization_stats(hours: int = 168) -> Dict[str, Any]:
    """Get anonymization (Tor/VPN) statistics (single-pass, cached)."""
    def _fetch():
        cutoff = _cutoff(hours)
        try:
            with _get_conn() as conn:
                # Single-pass totals — replaces 4 separate COUNT queries
                row = conn.execute("""
                    SELECT
                        SUM(CASE WHEN is_tor=1   THEN 1 ELSE 0 END) AS tor,
                        SUM(CASE WHEN is_vpn=1   THEN 1 ELSE 0 END) AS vpn,
                        SUM(CASE WHEN is_proxy=1 THEN 1 ELSE 0 END) AS proxy,
                        SUM(CASE WHEN is_tor=0 AND is_vpn=0 AND is_proxy=0 THEN 1 ELSE 0 END) AS clean
                    FROM attacks WHERE timestamp > ?
                """, (cutoff,)).fetchone()

                vpn_providers = conn.execute("""
                    SELECT vpn_provider, COUNT(*) as count
                    FROM attacks
                    WHERE timestamp > ? AND is_vpn=1 AND vpn_provider IS NOT NULL
                    GROUP BY vpn_provider ORDER BY count DESC LIMIT 20
                """, (cutoff,)).fetchall()

                tor_exits = conn.execute("""
                    SELECT tor_exit_ip, COUNT(*) as count
                    FROM attacks
                    WHERE timestamp > ? AND is_tor=1 AND tor_exit_ip IS NOT NULL
                    GROUP BY tor_exit_ip ORDER BY count DESC LIMIT 20
                """, (cutoff,)).fetchall()

                d = dict(row)
                tor_c = d["tor"] or 0
                vpn_c = d["vpn"] or 0
                prx_c = d["proxy"] or 0
                cln_c = d["clean"] or 0
                total = tor_c + vpn_c + prx_c + cln_c

                return {
                    "totals": {"tor": tor_c, "vpn": vpn_c, "proxy": prx_c, "clean": cln_c},
                    "vpn_providers": [{"provider": dict(r)["vpn_provider"], "count": dict(r)["count"]} for r in vpn_providers],
                    "tor_exits":     [{"ip": dict(r)["tor_exit_ip"],       "count": dict(r)["count"]} for r in tor_exits],
                    "percent_anonymous": round((tor_c + vpn_c + prx_c) / max(total, 1) * 100, 1),
                    "timeline": get_anonymization_timeline(hours),
                }
        except Exception as e:
            logger.error(f"Error getting anonymization stats: {e}", exc_info=True)
            return {"totals": {}, "vpn_providers": [], "tor_exits": []}
    return _cached(f"anon_stats:{hours}", _fetch, ttl=120)


def get_iot_stats(hours: int = 24) -> Dict[str, Any]:
    """Get IoT-specific statistics (single-pass, cached)."""
    def _fetch():
        cutoff = _cutoff(hours)
        try:
            with _get_conn() as conn:
                # Single-pass for all service counts — replaces 5 separate COUNTs
                row = conn.execute("""
                    SELECT
                        SUM(CASE WHEN lower(service)='rtsp'   THEN 1 ELSE 0 END) AS rtsp,
                        SUM(CASE WHEN lower(service)='onvif'  THEN 1 ELSE 0 END) AS onvif,
                        SUM(CASE WHEN lower(service)='modbus' THEN 1 ELSE 0 END) AS modbus,
                        SUM(CASE WHEN path LIKE '%/ISAPI/%' THEN 1 ELSE 0 END) AS isapi,
                        SUM(CASE WHEN username IN ('admin','root')
                                  AND password IN ('admin','12345','password','root','')
                                  THEN 1 ELSE 0 END) AS default_creds
                    FROM attacks WHERE timestamp > ?
                """, (cutoff,)).fetchone()

                cves = conn.execute("""
                    SELECT DISTINCT cve_id FROM attacks
                    WHERE timestamp > ? AND cve_id IS NOT NULL
                      AND lower(service) IN ('rtsp','onvif','http')
                """, (cutoff,)).fetchall()

                arches = conn.execute("""
                    SELECT architecture, COUNT(*) as cnt
                    FROM attacks
                    WHERE timestamp > ? AND architecture IS NOT NULL
                    GROUP BY architecture ORDER BY cnt DESC
                """, (cutoff,)).fetchall()

                d = dict(row)
                return {
                    "rtsp_attempts":  d["rtsp"]          or 0,
                    "onvif_probes":   d["onvif"]         or 0,
                    "modbus_hits":    d["modbus"]        or 0,
                    "hikvision_hits": d["isapi"]         or 0,
                    "default_creds":  d["default_creds"] or 0,
                    "iot_cves":       [(dict(r)["cve_id"], 1) for r in cves],
                    "arch_targets":   {dict(r)["architecture"]: dict(r)["cnt"] for r in arches},
                }
        except Exception as e:
            logger.error(f"Error getting IoT stats: {e}", exc_info=True)
            return {}
    return _cached(f"iot_stats:{hours}", _fetch, ttl=120)


def get_timeline(hours: int = 24) -> List[Dict]:
    """Get hourly attack timeline (cached)."""
    def _fetch():
        cutoff = _cutoff(hours)
        try:
            with _get_conn() as conn:
                rows = conn.execute("""
                    SELECT
                        strftime('%Y-%m-%dT%H:00:00', timestamp) as bucket,
                        COUNT(*) as total,
                        SUM(is_botnet) as botnets,
                        SUM(CASE WHEN cve_id IS NOT NULL THEN 1 ELSE 0 END) as cves
                    FROM attacks
                    WHERE timestamp > ?
                    GROUP BY bucket
                    ORDER BY bucket
                """, (cutoff,)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting timeline: {e}", exc_info=True)
            return []
    return _cached(f"timeline:{hours}", _fetch, ttl=60)


def get_hourly_heatmap() -> List[int]:
    """Get attack distribution by hour of day (UTC, cached)."""
    def _fetch():
        try:
            with _get_conn() as conn:
                rows = conn.execute("""
                    SELECT
                        CAST(strftime('%H', timestamp) as INTEGER) as hour,
                        COUNT(*) as cnt
                    FROM attacks
                    WHERE timestamp > datetime('now', '-7 days')
                    GROUP BY hour
                    ORDER BY hour
                """).fetchall()
                heatmap = [0] * 24
                for r in rows:
                    h = dict(r)["hour"]
                    if 0 <= h < 24:
                        heatmap[h] = dict(r)["cnt"]
                return heatmap
        except Exception as e:
            logger.error(f"Error getting hourly heatmap: {e}", exc_info=True)
            return [0] * 24
    return _cached("hourly_heatmap", _fetch, ttl=300)


def get_botnet_distribution() -> Dict[str, int]:
    """Get botnet family distribution (cached)."""
    def _fetch():
        try:
            with _get_conn() as conn:
                rows = conn.execute("""
                    SELECT
                        CASE
                            WHEN botnet_family LIKE '%mirai%' THEN 'Mirai'
                            WHEN botnet_family LIKE '%gafgyt%' THEN 'Gafgyt'
                            WHEN botnet_family LIKE '%mozi%' THEN 'Mozi'
                            WHEN botnet_family LIKE '%doflo%' THEN 'Doflo'
                            ELSE 'Other'
                        END as family,
                        COUNT(*) as cnt
                    FROM attacks
                    WHERE is_botnet=1 AND timestamp > datetime('now', '-30 days')
                    GROUP BY family
                    ORDER BY cnt DESC
                """).fetchall()
                return {dict(r)["family"]: dict(r)["cnt"] for r in rows}
        except Exception as e:
            logger.error(f"Error getting botnet distribution: {e}", exc_info=True)
            return {}
    return _cached("botnet_dist", _fetch, ttl=300)


def get_notable_events(hours: int = 168, limit: int = 100) -> List[Dict]:
    """Get critical/interesting events (CVEs, botnets, commands)."""
    cutoff = _cutoff(hours)
    
    try:
        with _get_conn() as conn:
            rows = conn.execute("""
                SELECT *
                FROM attacks
                WHERE timestamp > ? AND (
                    cve_id IS NOT NULL OR
                    is_botnet=1 OR
                    threat_level='critical' OR
                    commands IS NOT NULL OR
                    clipboard_paste IS NOT NULL
                )
                ORDER BY timestamp DESC
                LIMIT ?
            """, (cutoff, limit)).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error getting notable events: {e}", exc_info=True)
        return []


def get_anonymization_timeline(hours: int = 168) -> List[Dict]:
    """Get anonymization usage timeline (cached)."""
    def _fetch():
        cutoff = _cutoff(hours)
        try:
            with _get_conn() as conn:
                rows = conn.execute("""
                    SELECT
                        strftime('%Y-%m-%dT%H:00:00', timestamp) as bucket,
                        SUM(is_tor) as tor,
                        SUM(is_vpn) as vpn,
                        SUM(is_proxy) as proxy
                    FROM attacks
                    WHERE timestamp > ?
                    GROUP BY bucket
                    ORDER BY bucket
                """, (cutoff,)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error getting anonymization timeline: {e}", exc_info=True)
            return []
    return _cached(f"anon_timeline:{hours}", _fetch, ttl=120)


def query(sql: str, params: tuple = ()) -> List[Dict]:
    """Execute a raw query (for advanced use)."""
    try:
        with _get_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Query error: {e}", exc_info=True)
        return []


def get_honeytoken_data(hours: int = 168) -> Dict[str, Any]:
    """Get honeytoken trigger statistics and recent hits."""
    cutoff = _cutoff(hours)
    try:
        with _get_conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) as c FROM honeytoken_triggers WHERE timestamp > ?",
                (cutoff,)
            ).fetchone()["c"]

            unique_ips = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) as c FROM honeytoken_triggers WHERE timestamp > ?",
                (cutoff,)
            ).fetchone()["c"]

            by_type = conn.execute("""
                SELECT token_type, COUNT(*) as cnt,
                       COUNT(DISTINCT source_ip) as unique_ips,
                       MAX(timestamp) as last_seen
                FROM honeytoken_triggers WHERE timestamp > ?
                GROUP BY token_type ORDER BY cnt DESC
            """, (cutoff,)).fetchall()

            recent = conn.execute("""
                SELECT timestamp, token_type, token_value,
                       source_ip, service, country, city, commands
                FROM honeytoken_triggers
                WHERE timestamp > ?
                ORDER BY timestamp DESC LIMIT 100
            """, (cutoff,)).fetchall()

        return {
            "total":      total,
            "unique_ips": unique_ips,
            "by_type":    [dict(r) for r in by_type],
            "recent":     [dict(r) for r in recent],
        }
    except Exception as e:
        logger.error(f"Error getting honeytoken data: {e}", exc_info=True)
        return {"total": 0, "unique_ips": 0, "by_type": [], "recent": []}


def get_alerts(hours: int = 24, limit: int = 50) -> List[Dict]:
    """
    Generate alerts from recent attack data.
    Priority order: CVE exploits → botnet → honeytoken → brute-force → scanner.
    """
    cutoff = _cutoff(hours)
    alerts: List[Dict] = []

    try:
        with _get_conn() as conn:
            # CVE exploits — critical
            cve_rows = conn.execute("""
                SELECT timestamp, source_ip, country, service,
                       cve_id, cve_name, threat_level, payload
                FROM attacks
                WHERE timestamp > ? AND cve_id IS NOT NULL
                ORDER BY timestamp DESC LIMIT ?
            """, (cutoff, limit)).fetchall()
            for r in cve_rows:
                d = dict(r)
                alerts.append({
                    "severity":  "critical",
                    "type":      "cve_exploit",
                    "title":     f"CVE Exploit: {d.get('cve_id','')} ({d.get('cve_name','Unknown')})",
                    "source_ip": d["source_ip"],
                    "country":   d.get("country", ""),
                    "service":   d.get("service", ""),
                    "timestamp": d["timestamp"],
                    "detail":    (d.get("payload") or "")[:200],
                })

            # Botnet command sessions — high
            bot_rows = conn.execute("""
                SELECT timestamp, source_ip, country, service,
                       botnet_family, commands, threat_level
                FROM attacks
                WHERE timestamp > ? AND is_botnet=1
                  AND commands IS NOT NULL
                ORDER BY timestamp DESC LIMIT ?
            """, (cutoff, limit)).fetchall()
            for r in bot_rows:
                d = dict(r)
                alerts.append({
                    "severity":  "high",
                    "type":      "botnet",
                    "title":     f"Botnet Activity: {d.get('botnet_family','Unknown')}",
                    "source_ip": d["source_ip"],
                    "country":   d.get("country", ""),
                    "service":   d.get("service", ""),
                    "timestamp": d["timestamp"],
                    "detail":    (d.get("commands") or "")[:200],
                })

            # Honeytoken hits — high
            ht_rows = conn.execute("""
                SELECT timestamp, source_ip, country, service,
                       token_type, token_value, city, commands
                FROM honeytoken_triggers
                WHERE timestamp > ?
                ORDER BY timestamp DESC LIMIT ?
            """, (cutoff, limit)).fetchall()
            for r in ht_rows:
                d = dict(r)
                alerts.append({
                    "severity":  "high",
                    "type":      "honeytoken",
                    "title":     f"Honeytoken Triggered: {d.get('token_type','')}",
                    "source_ip": d["source_ip"],
                    "country":   d.get("country", ""),
                    "service":   d.get("service", ""),
                    "timestamp": d["timestamp"],
                    "detail":    str(d.get("token_value") or ""),
                })

            # Brute-force bursts — medium (≥10 attempts same IP, 10-min window)
            bf_rows = conn.execute("""
                SELECT source_ip, country, service,
                       COUNT(*) as attempts,
                       MAX(timestamp) as last_seen
                FROM attacks
                WHERE timestamp > ?
                  AND username IS NOT NULL
                GROUP BY source_ip, service
                HAVING attempts >= 10
                ORDER BY attempts DESC LIMIT ?
            """, (cutoff, limit)).fetchall()
            for r in bf_rows:
                d = dict(r)
                alerts.append({
                    "severity":  "medium",
                    "type":      "brute_force",
                    "title":     f"Brute Force: {d['attempts']} attempts on {d.get('service','').upper()}",
                    "source_ip": d["source_ip"],
                    "country":   d.get("country", ""),
                    "service":   d.get("service", ""),
                    "timestamp": d["last_seen"],
                    "detail":    f"{d['attempts']} credential attempts",
                })

    except Exception as e:
        logger.error(f"Error getting alerts: {e}", exc_info=True)

    # Sort by severity then time, return top N
    _sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: (_sev.get(a["severity"], 9), a["timestamp"]))
    return alerts[:limit]


def log_honeytoken(timestamp: str, source_ip: str, token_type: str,
                   token_value: str, service: str,
                   country: str = "", city: str = "",
                   commands: str = "[]") -> int:
    """Log a honeytoken trigger to the honeytoken_triggers table."""
    try:
        with _get_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO honeytoken_triggers
                   (timestamp, source_ip, token_type, token_value, service, country, city, commands)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, source_ip, token_type, str(token_value),
                 service.upper(), country, city, commands)
            )
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error logging honeytoken: {e}", exc_info=True)
        return 0


def log_malware(timestamp: str, source_ip: str, url: str, command: str,
                family: str = "", arch: str = "", country: str = "") -> int:
    """Log a malware download attempt as an attack row."""
    return log_attack({
        "timestamp":    timestamp,
        "source_ip":    source_ip,
        "payload":      url[:2000] if url else "",
        "commands":     command,
        "botnet_family": family,
        "architecture": arch,
        "country":      country,
        "attack_type":  "malware_download",
        "is_botnet":    1,
        "threat_level": "high",
        "service":      "HTTP",
    })


def log_cve(timestamp: str, source_ip: str, cve_id: str, cve_name: str,
            severity: str, service: str, payload: str, country: str = "") -> int:
    """Log a CVE exploit attempt as an attack row."""
    return log_attack({
        "timestamp":    timestamp,
        "source_ip":    source_ip,
        "service":      service.upper(),
        "cve_id":       cve_id,
        "cve_name":     cve_name,
        "threat_level": severity,
        "payload":      payload[:2000] if payload else "",
        "country":      country,
        "attack_type":  "cve_exploit",
    })


def get_report_data(hours: int = 24) -> Dict[str, Any]:
    """Aggregate all stats for the report/export endpoints."""
    return {
        "generated_at":  datetime.datetime.utcnow().isoformat(),
        "period_hours":  hours,
        "stats":         get_stats(hours),
        "top_ips":       get_top_ips(hours, 10),
        "top_countries": get_top_countries(hours),
        "cve_data":      get_cve_data(hours),
        "timeline":      get_timeline(hours),
        "services":      get_service_breakdown(hours),
        "honeytokens":   get_honeytoken_data(hours),
        "alerts":        get_alerts(hours, 20),
    }


def _cutoff(hours: int) -> str:
    """Generate ISO timestamp for N hours ago."""
    return (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).isoformat()