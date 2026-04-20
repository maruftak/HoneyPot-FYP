#!/usr/bin/env python3
"""
honeyPot Configuration
All settings centralized here. Override via environment variables.
"""

import os

# ─── Basic Settings ───────────────────────────────────────────────────────────
PROJECT_NAME = "honeyPot"
VERSION = "1.0.0"
SENSOR_NAME              = os.getenv("SENSOR_NAME", "honeyPot")
ALERT_SPAM_COOLDOWN      = int(os.getenv("ALERT_SPAM_COOLDOWN", "30"))
HONEYPOT_HOST            = os.getenv("HONEYPOT_HOST", "0.0.0.0")
VIRUSTOTAL_API_KEY       = os.getenv("VT_API_KEY", "")
RATE_LIMIT_CONN_PER_MIN  = int(os.getenv("RATE_LIMIT_CONN_PER_MIN", "120"))
RATE_LIMIT_BAN_SECONDS   = int(os.getenv("RATE_LIMIT_BAN_SECONDS", "1800"))

# Database
DB_PATH = os.getenv("HONEYPOT_DB_PATH", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "honeypot.db"
))

# ─── Dashboard Auth ───────────────────────────────────────────────────────────
# CRITICAL: Change these before deploying to production
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "honeypot2024")
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "5001"))
DASHBOARD_ENABLE_HTTPS = os.getenv("DASHBOARD_ENABLE_HTTPS", "false").lower() == "true"
DASHBOARD_SSL_CERT = os.getenv("DASHBOARD_SSL_CERT", "")
DASHBOARD_SSL_KEY = os.getenv("DASHBOARD_SSL_KEY", "")

# ─── IoT Device Emulation ──────────────────────────────────────────────────────
DEVICE_VENDOR = "Hikvision"
DEVICE_MODEL = "DS-2CD2043G2-I"
DEVICE_FIRMWARE = "V5.7.15 build 230313"
DEVICE_SERIAL = os.getenv("DEVICE_SERIAL", "DS-XXXXXXXXXXXX")

# Device network config (for responses)
DEVICE_IP = os.getenv("DEVICE_IP", "192.168.1.108")
DEVICE_GATEWAY = os.getenv("DEVICE_GATEWAY", "192.168.1.1")
DEVICE_MAC = os.getenv("DEVICE_MAC", "00:11:22:33:44:55")

# ─── Honeypot Services ────────────────────────────────────────────────────────
# Which services to enable
ENABLE_SSH = os.getenv("ENABLE_SSH", "true").lower() == "true"
ENABLE_TELNET = os.getenv("ENABLE_TELNET", "true").lower() == "true"
ENABLE_FTP = os.getenv("ENABLE_FTP", "true").lower() == "true"
ENABLE_HTTP = os.getenv("ENABLE_HTTP", "true").lower() == "true"
ENABLE_HTTPS = os.getenv("ENABLE_HTTPS", "false").lower() == "true"
ENABLE_RTSP = os.getenv("ENABLE_RTSP", "true").lower() == "true"
ENABLE_ONVIF = os.getenv("ENABLE_ONVIF", "true").lower() == "true"
ENABLE_VNC = os.getenv("ENABLE_VNC", "true").lower() == "true"
ENABLE_MQTT = os.getenv("ENABLE_MQTT", "false").lower() == "true"
ENABLE_MODBUS = os.getenv("ENABLE_MODBUS", "false").lower() == "true"
ENABLE_REDIS = os.getenv("ENABLE_REDIS", "false").lower() == "true"

SERVICE_PORTS = {
    # ── Core IoT attack surface ──────────────────────────────────────────────
    "telnet":     23,    # Mirai primary vector
    "telnet_alt": 2323,  # Mirai alternate Telnet — scanned equally to port 23
    "ssh":        2222,  # iptables redirects :22 → :2222
    "ftp":        21,
    "tftp":       69,    # UDP — Mirai payload delivery / firmware overwrite
    # ── IP Camera / DVR / NVR ───────────────────────────────────────────────
    "http":       80,
    "https":      443,
    "http_alt":   8080,
    "rtsp":       554,   # IP camera video streams
    "onvif":      8000,  # ONVIF camera management
    "hik_sdk":    8200,  # Hikvision iVMS / iVMS-4200 SDK
    "dahua":      37777, # Dahua DVR/NVR proprietary protocol
    "xmeye":      34567, # HiSilicon / XMEye / CamHi protocol (millions of cheap cameras)
    # ── IoT messaging & discovery ────────────────────────────────────────────
    "mqtt":       1883,  # IoT message broker
    "coap":       5683,  # UDP — constrained IoT protocol
    "ssdp":       1900,  # UDP — UPnP discovery
    # ── IoT device management ────────────────────────────────────────────────
    "tr069":      7547,  # TR-069 CWMP — ISP router/CPE management (Mirai Aidra target)
    "adb":        5555,  # Android Debug Bridge — smart TVs, Android NVRs (Fbot target)
    # ── Industrial / SCADA ──────────────────────────────────────────────────
    "modbus":     502,
    # ── Remote access ────────────────────────────────────────────────────────
    "vnc":        5900,
    # ── Cloud-native / container attack surface ──────────────────────────────
    "redis":      6379,  # Redis — common RCE via CONFIG SET + BGSAVE
    "docker":     2375,  # Docker daemon API — container escape / cryptominer
    # ── High-value missed IoT web ports ──────────────────────────────────────
    "dvr_web":    9527,  # XiongMai/NetSurveillance cameras (millions on Shodan, Satori target)
    "nvr_web":    8888,  # Generic cheap NVR/DVR alternate web port
}

# Service ports
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
TELNET_PORT = int(os.getenv("TELNET_PORT", "23"))
FTP_PORT = int(os.getenv("FTP_PORT", "21"))
HTTP_PORT = int(os.getenv("HTTP_PORT", "80"))
HTTPS_PORT = int(os.getenv("HTTPS_PORT", "443"))
RTSP_PORT = int(os.getenv("RTSP_PORT", "554"))
ONVIF_PORT = int(os.getenv("ONVIF_PORT", "8000"))
VNC_PORT = int(os.getenv("VNC_PORT", "5900"))
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MODBUS_PORT = int(os.getenv("MODBUS_PORT", "502"))
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# ─── GeoIP & Threat Intelligence ──────────────────────────────────────────────
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "GeoLite2-City.mmdb"
))

# Tor exit node list (auto-downloaded)
TOR_EXIT_NODES_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "tor_exits.json"
)

# VPN IP ranges (CIDR blocks — auto-downloaded or manual)
VPN_RANGES_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "vpn_ranges.json"
)

# ─── AbuseIPDB Integration ────────────────────────────────────────────────────
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_ENABLED = bool(ABUSEIPDB_API_KEY)
ABUSEIPDB_AUTO_REPORT = os.getenv("ABUSEIPDB_AUTO_REPORT", "false").lower() == "true"
ABUSEIPDB_AUTO_REPORT_THRESHOLD = int(os.getenv("ABUSEIPDB_AUTO_REPORT_THRESHOLD", "3"))

# ─── Alerts & Notifications ───────────────────────────────────────────────────
TELEGRAM_ENABLED = os.getenv("TELEGRAM_ENABLED", "false").lower() == "true"
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Email alerts
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
EMAIL_FROM = os.getenv("EMAIL_FROM", "honeypot@example.com")
EMAIL_TO = os.getenv("EMAIL_TO", "admin@example.com")
EMAIL_SMTP_SERVER = os.getenv("EMAIL_SMTP_SERVER", "localhost")
EMAIL_SMTP_PORT = int(os.getenv("EMAIL_SMTP_PORT", "587"))
EMAIL_SMTP_USERNAME = os.getenv("EMAIL_SMTP_USERNAME", "")
EMAIL_SMTP_PASSWORD = os.getenv("EMAIL_SMTP_PASSWORD", "")

# ─── Honeytokens ──────────────────────────────────────────────────────────────
HONEYTOKENS_ENABLED = os.getenv("HONEYTOKENS_ENABLED", "true").lower() == "true"
HONEYTOKEN_PATHS = [
    "/etc/passwd.bak", "/root/.ssh/id_rsa", "/.aws/credentials",
    "/home/admin/notes.txt", "/backup/db_creds.sql", "/etc/shadow",
]

# ─── Performance & Logging ────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "logs", "honeypot.log"
)
LOG_MAX_SIZE = int(os.getenv("LOG_MAX_SIZE", "52428800"))  # 50 MB
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "10"))

# Database
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
DB_TIMEOUT = int(os.getenv("DB_TIMEOUT", "30"))
DB_WAL_MODE = os.getenv("DB_WAL_MODE", "true").lower() == "true"

# Cache
CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))
CACHE_STATS_TTL = int(os.getenv("CACHE_STATS_TTL", "60"))

# ─── Advanced ──────────────────────────────────────────────────────────────────
SYSLOG_ENABLED = os.getenv("SYSLOG_ENABLED", "false").lower() == "true"
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "localhost")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))

# Disable honeypot functionality for testing (logs without services)
TESTING_MODE = os.getenv("TESTING_MODE", "false").lower() == "true"

# Ensure data directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"), exist_ok=True)

# ─── Threat Intelligence ──────────────────────────────────────────────────────
# Known botnet credential pairs (username, password)
BOTNET_CREDS = {
    # ── Mirai original 60 credential pairs ────────────────────────────────────
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
    # ── Additional Mirai/Satori/Okiru pairs (HiSilicon, DVR, router defaults) ─
    ("root","hi3518"),        # HiSilicon SoC default (Hikvision/Dahua chipset)
    ("root","xmhdipc"),       # XMeye/Dahua IP cameras
    ("root","juantech"),      # Juantech DVR
    ("root","realtek"),       # Realtek SDK devices
    ("root","jvbzd"),         # Comtrend/generic
    ("root","ikwb"),          # Netcam
    ("root","dreambox"),      # Dreambox STB
    ("root","000000"),        # Many Chinese cameras
    ("root","klv1234"),       # Variant
    ("root","Zte521"),        # ZTE router default
    ("root","hi3518"),
    ("666666","666666"),      # DVR 6-digit default
    ("888888","888888"),      # DVR 8-digit default
    ("supervisor","supervisor"), # Axis cameras
    ("Administrator","admin"),   # Windows-style IoT
    ("admin","1111111"),
    ("admin","1234567"),
    ("admin","admin1234"),
    ("root","1111"),
    ("root","123456789"),
    ("root","nopasswd"),
    ("root",""),              # blank password
    ("admin","camera"),
    ("admin","ipcam"),
    ("admin","dvr"),
    ("hikvision","12345"),
    ("root","hi3520"),        # HiSilicon variant
    ("root","hik12345"),
}

# CVE patterns to detect in payloads
CVE_PATTERNS = {
    "CVE-2017-7921": {
        "name":     "Hikvision Auth Bypass",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/ISAPI/Security/userCheck|/ISAPI/Security/users|/ISAPI/Security/sessionLogin|/doc/page/login\.asp|/doc/page/main\.asp",
    },
    "CVE-2021-36260": {
        "name":     "Hikvision Command Injection",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/SDK/webLanguage|webLanguage\.xml|/index\.html\?|/codebase/version\.xml|/doc/xml/version\.xml|/doc/script/",
    },
    "CVE-2017-7923": {
        "name":     "Hikvision Password Disclosure",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/ISAPI/Security/users\?auth=|HikvisionAuthBypass",
    },
    "CVE-2021-35394": {
        "name":     "Realtek SDK Remote Code Execution",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/boaform/admin/formLogin|/boaform/|/goform/formLogin|/goform/",
    },
    "CVE-2022-22965": {
        "name":     "Spring4Shell RCE",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/actuator/|/spring/|class\.module\.classLoader",
    },
    "CVE-2019-0232": {
        "name":     "Apache Tomcat Manager RCE",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/manager/html|/manager/text/|/manager/status",
    },
    "CVE-2023-1389": {
        "name":     "TP-Link Archer AX21 RCE",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/cgi-bin/luci/;stok=/locale|/cgi-bin/luci",
    },
    "CVE-2018-10562": {
        "name":     "Dasan GPON RCE",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/GponForm/diag_Form|/diag\.html",
    },
    "CVE-2020-25078": {
        "name":     "D-Link DCS Camera Info Disclosure",
        "severity": "high",
        "service":  "http",
        "pattern":  r"/config/getuser|/cgi-bin/ssi\.cgi|/cgi-bin/admin/getparam",
    },
    "CVE-2022-26134": {
        "name":     "Confluence OGNL Injection RCE",
        "severity": "critical",
        "service":  "http",
        "pattern":  r"/rest/api/|%24%7B|confluence",
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
    # Decoy download files — serve realistic fake content
    "/firmware.bin",
    "/upgrade.bin",
    "/config.tar.gz",
    "/backup.tar.gz",
    "/etc/passwd",
    "/system.cfg",
    "/nvram.cfg",
    "/proc/version",
    # IoT/camera-specific honeytokens — embedded as trap links in the dashboard
    "/ISAPI/System/configurationData",
    "/cgi-bin/snapshot.cgi",
    "/cgi-bin/config_export.cgi",
    "/cgi-bin/deviceInfo.cgi",
    "/onvif/device_service",
    # Config files served over HTTP
    "/mnt/mtd/Config/account.ini",
    "/mnt/mtd/Config/network.ini",
    "/Streaming/Channels/",
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

