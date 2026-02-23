# 🍯 honeyPot — IoT Threat Intelligence Platform

Emulates a **Hikvision DS-2CD2043G2-I** IP camera. Logs every attacker. Shows everything in a real-time dark-theme dashboard. Sends Telegram alerts.

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip3 install -r requirements.txt
# or minimal:
# pip3 install flask flask-cors requests geoip2

# 2. Set Telegram alerts (optional — skip to disable)
export TELEGRAM_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"

# 3. Start everything
./START.sh
# (use sudo only if you really bind < 1024 ports)
```

Dashboard → **http://localhost:5001** (or `http://YOUR_SERVER_IP:5001`)

---

## 🎭 What It Emulates

A **Hikvision DS-2CD2043G2-I** IP camera running firmware `V5.7.15`.

- Realistic Hikvision-style XML responses
- Camera-like HTTP endpoints
- RTSP stream endpoints
- Admin-like web UI
- Fake filesystem and credentials for traps

---

## 🌐 Services (17 Active)

| Port | Service | Purpose |
|------|---------|---------|
| 23   | Telnet  | Fake BusyBox shell — captures all commands |
| 22   | SSH     | Banner grab, scanner detection |
| 21   | FTP     | Credential capture, honeytoken files |
| 80   | HTTP    | Camera web UI, CVE paths, admin panel |
| 443  | HTTPS   | Same as HTTP (if enabled) |
| 8080 | HTTP-Alt | Secondary camera port (ONVIF/REST) |
| 554  | RTSP    | IP camera stream (DESCRIBE/SETUP/PLAY) |
| 8000 | ONVIF   | Camera management / WS-Discovery |
| 1883 | MQTT    | IoT broker (CONNECT/PUBLISH/SUBSCRIBE) |
| 6379 | Redis   | RCE detection via CONFIG SET / EVAL |
| 3306 | MySQL   | Handshake + username extraction |
| 2375 | Docker API | Container escape detection |
| 11211| Memcached | stats/flush_all commands |
| 5900 | VNC     | RFB handshake |
| 3389 | RDP     | Negotiation response |
| 502  | Modbus  | ICS/SCADA protocol |
| 25   | SMTP    | EHLO/MAIL/RCPT/DATA |

> Exact ports are configurable in `config.py` via `SERVICE_PORTS`.

---

## 🧠 Features

### Threat Intelligence

- **CVE Detection**  
  Detects 12+ common CVEs:
  - Hikvision auth bypass
  - Log4Shell (CVE-2021-44228)
  - Shellshock
  - PAN-OS, Cisco IOS XE, Zyxel, Ivanti
  - Redis RCE
  - Docker escape

- **Botnet Detection**  
  - 50+ Mirai / Gafgyt / Mozi / Sora / Muhstik credential pairs
  - Simple family classification based on payload and behavior

- **Malware URL Capture**  
  - Extracts URLs from `wget`, `curl`, `tftp`, and similar commands
  - Logs URLs, IPs, and timestamps

- **Honeytoken System**  
  - 16 fake files + 6 fake credential pairs
  - Any access → **CRITICAL Telegram alert**
  - Confirms post-exploitation and credential theft

- **Tor Detection**  
  - Flags Tor exit node IPs
  - Can be used to bump risk score

### Logging

- All attacks stored in **SQLite** (see `honeypot.db`)
- JSON-style logs for:
  - Sessions
  - Honeytokens
  - Malware URLs
- Export to CSV from dashboard

---

## 📣 Alerts (Telegram)

| Alert           | Trigger                                      |
|----------------|----------------------------------------------|
| 🌍 New Attacker | First connection from any IP                |
| 🤖 Botnet Cred | Known Mirai/Gafgyt credential used          |
| 💀 CVE Exploit | Known vulnerability pattern matched         |
| 🍯 Honeytoken  | Fake file or credential accessed            |
| 🐳 Docker Escape | Container breakout endpoint hit          |
| ☣️ Malware Download | `wget`/`curl` URL captured           |
| 🗄️ Redis RCE  | Dangerous CONFIG/WRITE attempted on Redis   |

---

## 📊 Dashboard Panels

Dashboard is served by `dashboard.py` on port **5001**.

| Panel       | What You See                                             |
|-------------|----------------------------------------------------------|
| Overview    | Metric cards, timeline, top countries/IPs, heatmap, botnet chart |
| Attack Map  | World map — colored by severity, real data only         |
| Live Log    | Real-time event stream (short polling)                  |
| Sessions    | Full attack table — filter, search, CSV export          |
| CVE Exploits| CVE log with severity chart                             |
| Credentials | Username/password pairs with botnet flag                |
| Malware URLs| Download URLs + family chart                            |
| Honeytokens | Trap trigger log                                        |
| Services    | Per-service hit counts                                  |
| Report      | Text summary — printable / exportable                   |

---

## 📲 Telegram Setup

1. Talk to **@BotFather** → `/newbot` → copy token
2. Talk to **@userinfobot** → copy your chat ID
3. In your shell:

```bash
export TELEGRAM_TOKEN="123456789:AABBCCddeeff..."
export TELEGRAM_CHAT_ID="987654321"
./START.sh
```

Or set them directly inside `config.py`:

```python
TELEGRAM_TOKEN   = "..."
TELEGRAM_CHAT_ID = "..."
```

---

## ☁️ Cloud Deployment (Ubuntu Example)

```bash
# 1. Open firewall ports (honeypot + dashboard)
sudo ufw allow 5001/tcp   # dashboard
sudo ufw allow 23/tcp     # telnet
sudo ufw allow 80/tcp     # http
sudo ufw allow 554/tcp    # rtsp
# ... add any other ports you enable

# 2. Install Python deps
pip3 install -r requirements.txt

# 3. Set Telegram (optional)
export TELEGRAM_TOKEN="..."
export TELEGRAM_CHAT_ID="..."

# 4. Run persistently
nohup ./START.sh > logs/honeypot_stdout.log 2>&1 &
```

Dashboard: `http://YOUR_SERVER_IP:5001`

---

## ⚙️ Config Reference (`config.py`)

| Setting                    | Default      | Meaning                            |
|---------------------------|-------------|------------------------------------|
| `RATE_LIMIT_CONN_PER_MIN` | `120`       | Max connections/IP per minute      |
| `RATE_LIMIT_BAN_SECONDS`  | `1800`      | Auto-ban duration (30 min)         |
| `ALERT_SPAM_COOLDOWN`     | `30`        | Seconds between same-IP alerts     |
| `SERVICE_PORTS`           | dict        | Port per service (set to 0 = off)  |
| `HONEYTOKEN_FILES`        | 16 entries  | Fake filesystem paths              |
| `HONEYTOKEN_CREDS`        | 6 pairs     | Bait credentials                   |
| `CVE_PATTERNS`            | list        | Detection regex / signatures       |

---

## 🧪 Testing Locally

```bash
# Start honeypot
./START.sh

# In another terminal:
curl http://localhost:8080/onvif/device_service
curl http://localhost:5001/api/stats
```

You should see:
- Log entries in `logs/`
- DB entries in `honeypot.db`
- Data appear on the dashboard

---

## ⚠️ Legal & Safety

- Only deploy on infrastructure you **own** or are **authorized** to test.
- Isolate the honeypot from production systems.
- Intended for **research and education** only.
- The authors are **not responsible** for misuse.

---
