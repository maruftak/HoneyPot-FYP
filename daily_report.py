#!/usr/bin/env python3
"""
honeyPot — Daily Telegram Summary
Run via cron at 08:00 UTC daily.
  0 8 * * * /usr/bin/python3 /home/ubuntu/honeyPot/daily_report.py
"""

import os, sys, sqlite3, datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config, alerts

DB_PATH = config.DB_PATH


def _q(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur.fetchall()


def _scalar(conn, sql, params=()):
    r = _q(conn, sql, params)
    return r[0][0] if r else 0


def build_report():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    now  = datetime.datetime.utcnow()
    ago  = (now - datetime.timedelta(hours=24)).isoformat()

    total     = _scalar(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>?", (ago,))
    unique_ip = _scalar(conn, "SELECT COUNT(DISTINCT source_ip) FROM attacks WHERE timestamp>?", (ago,))
    countries = _scalar(conn, "SELECT COUNT(DISTINCT country) FROM attacks WHERE timestamp>? AND country NOT IN ('','Unknown')", (ago,))
    botnets   = _scalar(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND is_botnet=1", (ago,))
    cves      = _scalar(conn, "SELECT COUNT(*) FROM cve_attempts WHERE timestamp>?", (ago,))
    vpn       = _scalar(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND is_vpn=1", (ago,))
    tor       = _scalar(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND is_tor=1", (ago,))
    bursts    = _scalar(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND attack_type='BRUTE_FORCE_BURST'", (ago,))
    honeytoks = _scalar(conn, "SELECT COUNT(*) FROM honeytoken_triggers WHERE timestamp>?", (ago,))
    captures  = 0
    try:
        import malware_capture
        captures = len([c for c in malware_capture.get_all()
                        if c.get("timestamp","") >= ago])
    except Exception:
        pass

    # Top 3 countries
    top_countries = _q(conn,
        "SELECT country, COUNT(*) n FROM attacks WHERE timestamp>? AND country NOT IN ('','Unknown') "
        "GROUP BY country ORDER BY n DESC LIMIT 3", (ago,))

    # Top 3 CVEs
    top_cves = _q(conn,
        "SELECT cve_id, COUNT(*) n FROM cve_attempts WHERE timestamp>? "
        "GROUP BY cve_id ORDER BY n DESC LIMIT 3", (ago,))

    # Top 3 credentials (exclude SSH banner garbage / long binary strings)
    top_creds = _q(conn,
        "SELECT username, password, COUNT(*) n FROM attacks "
        "WHERE timestamp>? AND username!='' AND password!='' "
        "AND length(username)<64 AND length(password)<64 "
        "AND username NOT LIKE 'SSH-%' AND username NOT LIKE '%curve25519%' "
        "GROUP BY username, password ORDER BY n DESC LIMIT 3", (ago,))

    # Most active service
    top_svc = _q(conn,
        "SELECT service, COUNT(*) n FROM attacks WHERE timestamp>? "
        "GROUP BY service ORDER BY n DESC LIMIT 1", (ago,))

    conn.close()

    date_str = now.strftime("%d %b %Y")

    lines = [
        f"📊 <b>honeyPot Daily Report — {date_str}</b>",
        "",
        "🌍 <b>Activity (last 24h)</b>",
        f"  Attacks:      <code>{total:,}</code>",
        f"  Unique IPs:   <code>{unique_ip}</code>  ({countries} countries)",
        f"  Services hit: <code>{top_svc[0][0].upper() if top_svc else '—'}</code> most active",
        "",
        "⚔️ <b>Threats</b>",
        f"  CVE exploits:    <code>{cves}</code>",
        f"  Botnet creds:    <code>{botnets}</code>",
        f"  Brute bursts:    <code>{bursts}</code>",
        f"  VPN attackers:   <code>{vpn}</code>",
        f"  Tor attackers:   <code>{tor}</code>",
        f"  Honeytokens hit: <code>{honeytoks}</code>",
        f"  Malware uploads: <code>{captures}</code>",
    ]

    if top_countries:
        lines += ["", "🗺 <b>Top Countries</b>"]
        for country, n in top_countries:
            lines.append(f"  {country}: <code>{n}</code>")

    if top_cves:
        lines += ["", "💀 <b>Top CVEs</b>"]
        for cve_id, n in top_cves:
            lines.append(f"  {cve_id}: <code>{n}x</code>")

    if top_creds:
        lines += ["", "🔑 <b>Top Credentials</b>"]
        for u, p, n in top_creds:
            lines.append(f"  <code>{u}/{p}</code> × {n}")

    if total == 0:
        lines += ["", "😴 <i>Quiet day — no attacks recorded.</i>"]

    lines.append(f"\n<i>— {config.PROJECT_NAME}</i>")
    return "\n".join(lines)


if __name__ == "__main__":
    msg = build_report()
    print(msg)   # also print to stdout for cron logs
    alerts._send(msg)
    print("[daily_report] Sent.")
