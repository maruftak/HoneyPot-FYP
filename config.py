#!/usr/bin/env python3
"""
honeyPot — Central Configuration
Edit this file to configure your deployment.
"""

import os

# ─── Project ──────────────────────────────────────────────────────────────────
PROJECT_NAME = "honeyPot"
VERSION      = "1.0.0"

# ─── Network ──────────────────────────────────────────────────────────────────
HONEYPOT_HOST     = "0.0.0.0"
DASHBOARD_HOST    = "0.0.0.0"
DASHBOARD_PORT    = 5001

# ─── Telegram Alerts ──────────────────────────────────────────────────────────
# Set via environment variables OR fill in directly here
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN",   "")   # e.g. "123456:ABC-DEF..."
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")   # e.g. "123456789"
TELEGRAM_ENABLED = bool(TELEGRAM_TOKEN and TELEGRAM_CHAT_ID)

# Alert thresholds — how many events before a Telegram message fires
ALERT_NEW_IP_EVERY    = 1    # every new attacker IP
ALERT_CVE_EVERY       = 1    # every CVE exploit attempt
ALERT_BOTNET_EVERY    = 1    # every botnet credential attempt
ALERT_HONEYTOKEN_EVERY= 1    # every honeytoken trigger
ALERT_DOCKER_EVERY    = 1    # every Docker API hit
ALERT_SPAM_COOLDOWN   = 30   # seconds between identical alerts from same IP

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
LOG_DIR        = os.path.join(BASE_DIR, "logs")
DB_PATH        = os.path.join(LOG_DIR,  "honeypot.db")
SESSION_LOG    = os.path.join(LOG_DIR,  "sessions.jsonl")
HONEYTOKEN_LOG = os.path.join(LOG_DIR,  "honeytokens.jsonl")
GEOIP_DB       = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")

# ─── Rate Limiting ────────────────────────────────────────────────────────────
RATE_LIMIT_CONN_PER_MIN = 120   # max connections per IP per minute
RATE_LIMIT_BAN_SECONDS  = 1800  # 30 min ban after exceeding limit

# ─── Device Profile (what we pretend to be) ──────────────────────────────────
DEVICE_VENDOR   = "Hikvision"
DEVICE_MODEL    = "DS-2CD2043G2-I"
DEVICE_FIRMWARE = "V5.7.15 build 230313"
DEVICE_MAC      = "44:19:B6:7A:2C:D9"
DEVICE_IP       = "0.0.0.0"   # filled at startup

# ─── Honeypot Services ────────────────────────────────────────────────────────
# Set port to 0 to disable a service
SERVICE_PORTS = {
    "telnet":    23,
    "ssh":       22,
    "ftp":       21,
    "smtp":      25,
    "http":      80,
    "https":     443,
    "http_alt":  8080,
    "rtsp":      554,
    "onvif":     8000,
    "mqtt":      1883,
    "redis":     6379,
    "mysql":     3306,
    "docker":    2375,
    "memcached": 11211,
    "vnc":       5900,
    "rdp":       3389,
    "modbus":    502,
}

# ─── Threat Intelligence ──────────────────────────────────────────────────────
# Known botnet credential pairs (username, password)
BOTNET_CREDS = {
    ("root","root"),("admin","admin"),("root","12345"),("admin","password"),
    ("root","default"),("admin","1234"),("root","xc3511"),("root","vizxv"),
    ("admin","smcadmin"),("root","anko"),("root","7ujMko0vizxv"),("root","5up"),
    ("root","zlxx."),("admin","meinsm"),("tech","tech"),("mother","fucker"),
    ("user","user"),("support","support"),("root","toor"),("admin","1111"),
    ("root","klv123"),("pi","raspberry"),("admin",""),("root","pass"),
    ("admin","12345"),("guest","guest"),("admin","admin123"),("root","admin"),
    ("admin","admin@2024"),("root","Root@2024"),("default","default"),
    ("admin","hikvision"),("admin","supervisor"),("operator","operator"),
    ("service","service"),("demo","demo123"),("test","test123"),
    ("admin","888888"),("root","888888"),("admin","123456"),("root","54321"),
    ("admin","54321"),("root","666666"),("admin","666666"),("root","7ujMko0admin"),
    ("admin","7ujMko0admin"),("root","system"),("admin","system"),
    ("ubnt","ubnt"),("vagrant","vagrant"),("user","1234"),("1234","1234"),
}

# CVE patterns to detect in payloads
CVE_PATTERNS = {
    "CVE-2017-7921": {
        "name":     "Hikvision Auth Bypass",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/ISAPI/Security/userCheck|/ISAPI/Security/users|/ISAPI/Security/sessionLogin",
    },
    "CVE-2021-36260": {
        "name":     "Hikvision Command Injection",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/SDK/webLanguage|webLanguage\.xml|/index\.html\?",
    },
    "CVE-2017-7923": {
        "name":     "Hikvision Password Disclosure",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/ISAPI/Security/users\?auth=|HikvisionAuthBypass",
    },
    "CVE-2021-44228": {
        "name":     "Log4Shell JNDI Injection",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"\$\{jndi:",
    },
    "CVE-2014-6271": {
        "name":     "Shellshock Bash RCE",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"\(\)\s*\{",
    },
    "CVE-2023-44487": {
        "name":     "HTTP/2 Rapid Reset DDoS",
        "severity": "high",
        "service":  "http",
        "pattern":  r"PRI \* HTTP/2\.0",
    },
    "CVE-2024-3400": {
        "name":     "PAN-OS GlobalProtect RCE",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/global-protect/portal/javascript|GlobalProtect",
    },
    "CVE-2024-21887": {
        "name":     "Ivanti Connect Secure RCE",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/api/v1/endpoints/activate",
    },
    "CVE-2022-30525": {
        "name":     "Zyxel Firewall OS Command Injection",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/ztp/cgi-bin/handler",
    },
    "CVE-2023-20198": {
        "name":     "Cisco IOS XE Web UI Privilege Escalation",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/webui/|%2fwebui%2f",
    },
    "REDIS-RCE": {
        "name":     "Redis CONFIG SET RCE",
        "severity": "critical",
        "service":  "redis",
        "pattern":  r"CONFIG\s+SET\s+(dir|dbfilename)",
    },
    "DOCKER-ESCAPE": {
        "name":     "Docker API Container Escape",
        "severity": "critical",
        "service":  "docker",
        "pattern":  r"/containers/|/exec/|/images/create",
    },
}

# Honeytoken file paths — accessing these fires an alert
HONEYTOKEN_FILES = [
    "/backup/passwords.txt",
    "/root/.env",
    "/root/passwords.txt",
    "/root/.ssh/id_rsa",
    "/etc/shadow",
    "/mnt/mtd/Config/account.ini",
    "/.env",
    "/.aws/credentials",
    "/var/www/.env",
    "/config.php",
    "/wp-config.php",
    "/.git/config",
    "/docker-compose.yml",
    "/api/keys.json",
    "/kubernetes/config",
    "/root/.bash_history",
]

# Honeytoken credentials — using these fires a CRITICAL alert
HONEYTOKEN_CREDS = {
    ("admin",      "SuperSecret123!"),
    ("backup",     "Backup2024!"),
    ("dbuser",     "MyDB_P@ssw0rd"),
    ("root",       "ProductionKey999"),
    ("cloudadmin", "Cloud@Admin123"),
    ("deploy",     "Deploy@2024!"),
}
