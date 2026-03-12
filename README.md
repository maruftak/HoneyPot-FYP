# 🍯 honeyPot — IoT Threat Intelligence Platform

A high-interaction honeypot masquerading as a **Hikvision DS-2CD2043G2-I** IP camera,
capturing real-world IoT attacks with a full threat intelligence dashboard.

![Dashboard](https://img.shields.io/badge/status-live-00ff88?style=flat-square)
![Python](https://img.shields.io/badge/python-3.9+-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## 🎯 What It Does

- Emulates a real Hikvision IP camera (HTTP, RTSP, ONVIF, ISAPI endpoints)
- Captures credentials, CVE exploits, malware URLs, botnet sessions
- Tracks attacker kill chains and multi-stage attack progressions
- Visualises everything on a real-time threat intelligence dashboard

---

## 📦 Features

| Feature | Description |
|---------|-------------|
| 🌍 Attack Map | Live Leaflet.js world map with severity markers |
| 📊 12 Metric Cards | Attacks, IPs, CVEs, Botnets, Malware, RTSP, ONVIF, ISAPI... |
| 📡 Live Log | Real-time attack stream with pause/resume |
| 💀 CVE Exploits | Tracks known vulnerability attempts |
| 🔑 Credentials | Top username/password pairs captured |
| ☣️ Malware URLs | wget/curl download captures |
| 🍯 Honeytokens | Bait files and credentials with trigger alerts |
| 🎯 Attacker Intel | Risk scoring, kill chain, multi-stage detection |
| 🎭 Decoy Log | HIK-specific path probe tracking |
| 📷 Device Status | Fake camera status panel |
| 📄 Report | Printable threat intelligence report |

---

## 🚀 Quick Start

### Requirements
```bash
pip install flask flask-cors geoip2 requests
```

### Run
```bash
# Start honeypot services
python3 src/honeypot.py

# Start dashboard (separate terminal)
python3 dashboard.py

# Open browser
open http://localhost:5001
```

---

## 📁 Project Structure

```
honeyPot/
├── src/
│   └── honeypot.py          # Honeypot service (HTTP/RTSP/Telnet/ONVIF)
├── dashboard.py             # Flask API + dashboard server
├── dashboard.html           # Frontend dashboard UI
├── db.py                    # SQLite database layer
├── config.py                # Configuration (ports, paths) — not in git
├── iot_profiles.py          # IoT device emulation profiles
├── protocol_analyzer.py     # Deep protocol analysis
├── threat_intel.py          # Threat intelligence scoring
├── ml_features.py           # ML feature extraction
├── ENHANCEMENTS.md          # Feature documentation
└── .gitignore
```

---

## ⚙️ Configuration

Create `config.py` (excluded from git):
```python
DB_PATH  = "honeypot.db"
LOG_DIR  = "logs/"
HTTP_PORT  = 80
HTTPS_PORT = 443
RTSP_PORT  = 554
TELNET_PORT = 23
ONVIF_PORT = 8000
DASHBOARD_PORT = 5001
```

---

## 🔒 Legal Notice

> Deploy only on systems you own or have explicit permission to monitor.
> This tool is for security research and education purposes only.

---

## 📜 License

MIT — see LICENSE file.
