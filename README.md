# honeyPot — IoT Threat Intelligence Platform

A high-interaction honeypot masquerading as a **Hikvision DS-2CD2043G2-I** IP camera,
capturing real-world IoT attacks across 20+ protocols with a full threat intelligence dashboard.

![Dashboard](https://img.shields.io/badge/status-live-00ff88?style=flat-square)
![Python](https://img.shields.io/badge/python-3.9+-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## What It Does

- Emulates a real Hikvision IP camera with a **consistent device identity** across every protocol (HTTP, RTSP, ONVIF, SSH, FTP, Telnet, HIK SDK, and more)
- Captures credentials, CVE exploit attempts, malware URLs, botnet sessions, and command payloads
- Tracks attacker kill chains and multi-stage attack progressions
- Scores each attacker with a risk model and flags botnets, Tor exit nodes, and VPN IPs
- Generates daily PDF threat intelligence reports and sends them via Telegram or email
- Visualises everything on a real-time threat intelligence dashboard with HTTP Basic Auth

---

## Emulated Protocols & Services

| Port | Protocol | What It Emulates |
|------|----------|-----------------|
| 23 / 2323 | Telnet | BusyBox IoT shell (Mirai primary vector) |
| 2222 | SSH | Paramiko-based shell emulating Hikvision/BusyBox Linux |
| 21 | FTP | Camera FTP server |
| 69 | TFTP (UDP) | Firmware delivery / Mirai payload staging |
| 80 / 8080 | HTTP | Full Hikvision ISAPI, CGI, and web interface |
| 443 | HTTPS | TLS-wrapped HTTP service |
| 554 | RTSP | IP camera video stream endpoint |
| 8000 | ONVIF | ONVIF camera management (WS-Discovery) |
| 8200 | HIK SDK | Hikvision iVMS-4200 SDK protocol |
| 37777 | Dahua | Dahua DVR/NVR proprietary protocol |
| 34567 | XMEye | HiSilicon / XMEye / CamHi (millions of cheap cameras) |
| 1883 | MQTT | IoT message broker |
| 5683 | CoAP (UDP) | Constrained IoT protocol (RFC 7252) |
| 1900 | SSDP (UDP) | UPnP device discovery |
| 7547 | TR-069 | ISP CPE management / Mirai Aidra RCE vector |
| 5555 | ADB | Android Debug Bridge (smart TVs, Android NVRs) |
| 5900 | VNC | Remote desktop |
| 6379 | Redis | Redis RCE via CONFIG SET |
| 2375 | Docker | Docker daemon API (container escape) |
| 502 | Modbus | Industrial SCADA protocol |
| 9527 / 8888 | DVR/NVR web | XiongMai / generic cheap DVR/NVR web ports |

---

## Dashboard Features

| Feature | Description |
|---------|-------------|
| Attack Map | Live Leaflet.js world map with severity markers |
| Metric Cards | Attacks, IPs, CVEs, botnets, malware, RTSP, ONVIF, ISAPI, and more |
| Live Log | Real-time attack stream with pause/resume |
| CVE Exploits | Tracks 20+ known vulnerability attempts |
| Credentials | Top username/password pairs captured |
| Malware URLs | wget/curl download captures |
| Honeytokens | Bait files and credentials with trigger alerts |
| Attacker Intel | Risk scoring, kill chain, multi-stage detection |
| Botnet Tracking | Named botnet identification with session history |
| Decoy Log | HIK-specific path probe tracking |
| Device Status | Fake camera status panel |
| Daily Report | Printable / emailed PDF threat intelligence report |

---

## Threat Intelligence Features

- **VirusTotal integration** — checks captured file hashes against VT API v3
- **AbuseIPDB integration** — lookups and optional auto-reporting of attacking IPs
- **Tor exit node detection** — auto-downloads and caches the Tor exit list
- **VPN range detection** — flags IPs from known VPN CIDR blocks
- **Botnet credential matching** — 80+ known Mirai/Satori/Okiru credential pairs
- **CVE pattern detection** — regex-matched CVE signatures across all HTTP payloads
- **Rate limiting** — per-IP connection rate limit with automatic ban
- **Telegram alerts** — real-time structured alerts with spam cooldown
- **Email alerts** — SMTP-based alert delivery
- **Daily PDF report** — multi-page intelligence PDF with charts, generated on schedule and sent via Telegram

---

## Quick Start

### Requirements

```bash
pip install -r requirements.txt
```

Core dependencies:
```
flask>=3.0.0
flask-cors>=4.0.0
requests>=2.31.0
geoip2>=4.7.0
paramiko        # SSH service
reportlab       # PDF daily reports
matplotlib      # Charts in daily reports
```

### GeoIP Database

Download the free MaxMind GeoLite2-City database and place it at the project root (or set `GEOIP_DB_PATH`):
```
GeoLite2-City.mmdb
```

### Run

```bash
# Start all services (dashboard + telnet)
bash start-all.sh

# Or start individually:
python3 dashboard.py          # Dashboard API + frontend (port 5001)
python3 honeypot.py           # All honeypot services

# Open browser
open http://localhost:5001
# Default credentials: admin / honeypot2024
```

---

## Project Structure

```
honeyPot/
├── honeypot.py              # Main orchestrator — starts all services
├── dashboard.py             # Flask API + dashboard server (port 5001)
├── dashboard.html           # Frontend dashboard UI
├── config.py                # All configuration (env-var driven)
├── db.py                    # SQLite database layer (WAL mode)
├── device_identity.py       # Single source of truth for device fingerprint
├── geo.py                   # GeoIP lookups
├── alerts.py                # Telegram alert module with cooldown
├── daily_report.py          # PDF threat intelligence report generator
├── tor_detector.py          # Tor exit node detection
├── vt_lookup.py             # VirusTotal hash lookup
├── malware_capture.py       # Malware URL / payload capture
├── fake_commands.py         # Fake shell command responses
│
├── http_service.py          # HTTP/HTTPS — ISAPI, CGI, web UI
├── rtsp_service.py          # RTSP — IP camera stream
├── onvif_service.py         # ONVIF — camera management
├── ssh_service.py           # SSH — BusyBox/Paramiko shell
├── ftp_service.py           # FTP
├── tftp_service.py          # TFTP (UDP)
├── mqtt_service.py          # MQTT broker
├── coap_service.py          # CoAP (UDP, RFC 7252)
├── ssdp_service.py          # SSDP/UPnP (UDP)
├── tr069_service.py         # TR-069 CWMP (Mirai Aidra target)
├── adb_service.py           # Android Debug Bridge
├── vnc_service.py           # VNC remote desktop
├── redis_service.py         # Redis RCE emulation
├── docker_service.py        # Docker daemon API
├── hik_sdk_service.py       # Hikvision iVMS SDK (port 8200)
├── dahua_service.py         # Dahua DVR protocol (port 37777)
├── xmeye_service.py         # XMEye / HiSilicon (port 34567)
│
├── src/
│   ├── honeypot.py          # Legacy service entry point
│   └── telnet_server.py     # Standalone Telnet server
│
├── data/
│   ├── honeypot.db          # SQLite database
│   └── GeoLite2-City.mmdb  # GeoIP database (not in git)
├── logs/                    # Runtime logs
├── requirements.txt
├── start-all.sh             # Launch script
├── deploy_report.sh         # Deploy daily report cron
└── .env.example             # Environment variable template
```

---

## Configuration

All settings are driven by environment variables. Copy `.env.example` and set your values:

```bash
# Core
SENSOR_NAME=honeyPot
HONEYPOT_DB_PATH=data/honeypot.db

# Dashboard auth (CHANGE BEFORE DEPLOYING)
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=honeypot2024
DASHBOARD_PORT=5001

# Device identity
DEVICE_SERIAL=DS-XXXXXXXXXXXX
DEVICE_IP=192.168.1.108

# Enable/disable individual services
ENABLE_SSH=true
ENABLE_TELNET=true
ENABLE_FTP=true
ENABLE_RTSP=true
ENABLE_ONVIF=true
ENABLE_MQTT=false
ENABLE_REDIS=false

# Threat intelligence APIs
VT_API_KEY=                    # VirusTotal
ABUSEIPDB_API_KEY=             # AbuseIPDB
ABUSEIPDB_AUTO_REPORT=false

# Telegram alerts
TELEGRAM_ENABLED=false
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Email alerts
EMAIL_ENABLED=false
EMAIL_FROM=honeypot@example.com
EMAIL_TO=admin@example.com
EMAIL_SMTP_SERVER=localhost
EMAIL_SMTP_PORT=587
```

---

## Daily PDF Report

Generate and send a multi-page threat intelligence PDF:

```bash
python3 daily_report.py
```

The report includes attack volume charts, top attacker IPs, CVE breakdown, credential analysis, botnet attribution, and malware URL captures. It is delivered via Telegram when `TELEGRAM_ENABLED=true`.

---

## Legal Notice

> Deploy only on systems you own or have explicit permission to monitor.
> This tool is for security research and education purposes only.

---

## License

MIT — see LICENSE file.
