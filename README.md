# 🍯 honeyPot — IoT Threat Intelligence Platform

Emulates a **Hikvision DS-2CD2043G2-I** IP camera. Logs every attacker. Shows everything in a real-time dark-theme dashboard. Sends Telegram alerts.

---

## Quick Start

```bash
# 1. Install dependencies
pip3 install flask flask-cors requests geoip2

# 2. Set Telegram alerts (optional — skip to disable)
export TELEGRAM_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"

# 3. Start everything (root needed for ports < 1024)
sudo ./START.sh
```

Dashboard → **http://localhost:5001** (or your server IP:5001)

---

## What It Emulates

A **Hikvision DS-2CD2043G2-I** IP camera running firmware V5.7.15.
Real Hikvision XML responses, realistic SSH/FTP/RTSP banners, camera admin panel HTML.

---

## Services (17 active)

| Port | Service | Purpose |
|------|---------|---------|
| 23 | Telnet | Full fake BusyBox shell — captures all commands |
| 22 | SSH | Banner grab, scanner detection |
| 21 | FTP | Credential capture, honeytoken files |
| 80 | HTTP | Camera web UI, CVE paths, admin panel |
| 443 | HTTPS | Same as HTTP |
| 8080 | HTTP-Alt | Secondary camera port |
| 554 | RTSP | IP camera stream (DESCRIBE/SETUP/PLAY) |
| 8000 | ONVIF | Camera management WS-Discovery |
| 1883 | MQTT | IoT broker (CONNECT/PUBLISH/SUBSCRIBE) |
| 6379 | Redis | RCE detection via CONFIG SET |
| 3306 | MySQL | Real handshake, username extraction |
| 2375 | Docker API | Container escape detection |
| 11211 | Memcached | stats/flush_all commands |
| 5900 | VNC | Full RFB handshake |
| 3389 | RDP | Negotiation response |
| 502 | Modbus | ICS/SCADA protocol |
| 25 | SMTP | EHLO/MAIL/RCPT/DATA |

---

## Features

### Intelligence
- **CVE Detection** — 12 CVEs: Hikvision auth bypass, Log4Shell, Shellshock, PAN-OS, Cisco IOS XE, Zyxel, Ivanti, Redis RCE, Docker escape
- **Botnet Detection** — 50+ Mirai/Gafgyt/Mozi/Sora/Muhstik credential pairs + family classification
- **Malware URL Capture** — Extracts URLs from wget/curl/tftp commands
- **Honeytoken System** — 16 fake files + 6 fake credentials. Any access = Telegram CRITICAL alert
- **Tor Detection** — Identifies Tor exit node connections

### Logging
- All attacks stored in **SQLite** with full metadata
- JSON logs: sessions, honeytokens
- Exportable to CSV from dashboard

### Alerts (Telegram)
| Alert | Trigger |
|-------|---------|
| 🌍 New Attacker | First connection from any IP |
| 🤖 Botnet Cred | Known Mirai/Gafgyt credentials used |
| 💀 CVE Exploit | Known vulnerability pattern matched |
| 🍯 Honeytoken | Fake file or credential accessed |
| 🐳 Docker Escape | Container breakout endpoint hit |
| ☣️ Malware Download | wget/curl payload URL captured |
| 🗄️ Redis RCE | CONFIG SET write attempted |

---

## Dashboard Panels

| Panel | What You See |
|-------|-------------|
| Overview | Metric cards, timeline, top countries/IPs, hourly heatmap, botnet chart |
| Attack Map | World map — colored by severity, real data only |
| Live Log | Real-time event stream (3s polling) |
| Sessions | Full attack table — filter, search, CSV export |
| CVE Exploits | CVE log with severity chart |
| Credentials | Username/password pairs with botnet flag |
| Malware URLs | Download URLs, family chart |
| Honeytokens | Trap trigger log |
| Services | Per-service hit counts |
| Report | Text report — printable |

---

## Telegram Setup

1. Message @BotFather → `/newbot` → copy token
2. Message @userinfobot → copy your chat ID
3. Run:
```bash
export TELEGRAM_TOKEN="123456789:AABBCCddeeff..."
export TELEGRAM_CHAT_ID="987654321"
sudo ./START.sh
```
Or set them directly in `config.py`.

---

## Cloud Deployment (Ubuntu)

```bash
# Open firewall ports (all honeypot ports + dashboard)
ufw allow 5001/tcp   # dashboard
ufw allow 23/tcp     # telnet
ufw allow 80/tcp     # http
ufw allow 554/tcp    # rtsp
# ... etc

# Install
pip3 install flask flask-cors requests geoip2

# Run persistently
export TELEGRAM_TOKEN="..."
export TELEGRAM_CHAT_ID="..."
sudo nohup python3 honeypot.py  > logs/honeypot.log  2>&1 &
     nohup python3 dashboard.py > logs/dashboard.log 2>&1 &

# Dashboard: http://YOUR_SERVER_IP:5001
```

---

## Config Reference (config.py)

| Setting | Default | Meaning |
|---------|---------|---------|
| `RATE_LIMIT_CONN_PER_MIN` | 120 | Max connections per IP per minute |
| `RATE_LIMIT_BAN_SECONDS` | 1800 | Auto-ban duration (30 min) |
| `ALERT_SPAM_COOLDOWN` | 30 | Seconds between same-IP alerts |
| `SERVICE_PORTS` | — | Set port to 0 to disable service |
| `HONEYTOKEN_FILES` | 16 files | Fake filesystem paths |
| `HONEYTOKEN_CREDS` | 6 pairs | Bait credentials |
| `CVE_PATTERNS` | 12 CVEs | Detection regex patterns |

---

## ⚠️ Legal

Only deploy on infrastructure you own. For research and education only.
