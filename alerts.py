#!/usr/bin/env python3
"""
honeyPot — Telegram Alert Module
Sends structured alerts to Telegram with cooldown to avoid spam.
"""

import time, threading
from config import (
    TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ENABLED,
    ALERT_SPAM_COOLDOWN, PROJECT_NAME
)

_lock     = threading.Lock()
_cooldown = {}   # key -> last_sent timestamp

try:
    import requests as _req
    _req_ok = True
except ImportError:
    _req_ok = False

ICONS = {
    "CRITICAL":  "🚨",
    "HIGH":      "⚠️",
    "MEDIUM":    "🟡",
    "LOW":       "🟢",
    "INFO":      "ℹ️",
    "SUCCESS":   "✅",
    "BOTNET":    "🤖",
    "HONEYTOKEN":"🍯",
    "CVE":       "💀",
    "DOCKER":    "🐳",
    "MALWARE":   "☣️",
    "START":     "🚀",
    "STOP":      "🛑",
    "RDP":       "🖥️",
    "VNC":       "🖥️",
    "REDIS":     "🗄️",
    "MODBUS":    "⚙️",
}

def _cooldown_key(alert_type, ip):
    return f"{alert_type}:{ip}"

def _is_cooled_down(key):
    with _lock:
        last = _cooldown.get(key, 0)
        if time.time() - last < ALERT_SPAM_COOLDOWN:
            return True
        _cooldown[key] = time.time()
        return False

def _send(text):
    """Raw send to Telegram — runs in daemon thread."""
    if not TELEGRAM_ENABLED or not _req_ok:
        return
    def _do():
        try:
            _req.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={
                    "chat_id":                  TELEGRAM_CHAT_ID,
                    "text":                     text,
                    "parse_mode":               "HTML",
                    "disable_web_page_preview": True,
                },
                timeout=10
            )
        except Exception as e:
            print(f"[Telegram] Send failed: {e}")
    threading.Thread(target=_do, daemon=True).start()

def _fmt(icon, title, fields: list):
    """Build a clean Telegram HTML message."""
    lines = [f"{icon} <b>{title}</b>", ""]
    for label, value in fields:
        lines.append(f"<b>{label}:</b> <code>{value}</code>")
    lines.append(f"\n<i>— {PROJECT_NAME}</i>")
    return "\n".join(lines)

# ─── Public alert functions ────────────────────────────────────────────────────

def startup(services_count, device_model, device_firmware):
    msg = _fmt("🚀", f"{PROJECT_NAME} Started", [
        ("Services",  str(services_count)),
        ("Device",    device_model),
        ("Firmware",  device_firmware),
        ("Status",    "ONLINE — collecting attacks"),
    ])
    _send(msg)

def shutdown(total_sessions, total_ips):
    msg = _fmt("🛑", f"{PROJECT_NAME} Stopped", [
        ("Sessions",  str(total_sessions)),
        ("Unique IPs",str(total_ips)),
    ])
    _send(msg)

def new_attacker(ip, country, city, service):
    key = _cooldown_key("NEW_IP", ip)
    if _is_cooled_down(key):
        return
    msg = _fmt("🌍", "New Attacker Detected", [
        ("IP",      ip),
        ("Country", f"{country} / {city}" if city else country),
        ("Service", service.upper()),
    ])
    _send(msg)

def botnet_cred(ip, country, service, username, password, family="Unknown"):
    key = _cooldown_key("BOTNET", ip)
    if _is_cooled_down(key):
        return
    msg = _fmt("🤖", "Botnet Credentials Detected", [
        ("IP",       ip),
        ("Country",  country),
        ("Service",  service.upper()),
        ("Username", username),
        ("Password", password),
        ("Family",   family),
    ])
    _send(msg)

def cve_exploit(ip, country, cve_id, cve_name, severity, service, path=""):
    key = _cooldown_key(f"CVE:{cve_id}", ip)
    if _is_cooled_down(key):
        return
    msg = _fmt("💀", f"CVE Exploit Attempt — {severity.upper()}", [
        ("CVE",     cve_id),
        ("Name",    cve_name),
        ("IP",      ip),
        ("Country", country),
        ("Service", service.upper()),
        ("Path",    path[:80] if path else ""),
    ])
    _send(msg)

def honeytoken(ip, country, token_type, token_value, service):
    key = _cooldown_key("HONEYTOKEN", ip)
    if _is_cooled_down(key):
        return
    msg = _fmt("🍯", "HONEYTOKEN TRIGGERED", [
        ("IP",      ip),
        ("Country", country),
        ("Type",    token_type),
        ("Value",   token_value[:60]),
        ("Service", service.upper()),
    ])
    _send(msg)

def docker_escape(ip, country, path):
    key = _cooldown_key("DOCKER", ip)
    if _is_cooled_down(key):
        return
    msg = _fmt("🐳", "Docker API Escape Attempt — CRITICAL", [
        ("IP",      ip),
        ("Country", country),
        ("Endpoint",path[:80]),
    ])
    _send(msg)

def malware_download(ip, country, url, family, arch):
    key = _cooldown_key("MALWARE", ip)
    if _is_cooled_down(key):
        return
    msg = _fmt("☣️", "Malware Download Detected", [
        ("IP",      ip),
        ("Country", country),
        ("URL",     url[:80]),
        ("Family",  family),
        ("Arch",    arch),
    ])
    _send(msg)

def redis_rce(ip, country, command):
    key = _cooldown_key("REDIS", ip)
    if _is_cooled_down(key):
        return
    msg = _fmt("🗄️", "Redis RCE Attempt", [
        ("IP",      ip),
        ("Country", country),
        ("Command", command[:80]),
    ])
    _send(msg)

def generic(icon_key, title, fields, ip="", cooldown_key=None):
    key = _cooldown_key(cooldown_key or title, ip or "global")
    if _is_cooled_down(key):
        return
    icon = ICONS.get(icon_key.upper(), "📊")
    msg = _fmt(icon, title, fields)
    _send(msg)
