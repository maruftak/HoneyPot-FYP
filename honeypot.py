#!/usr/bin/env python3
"""
honeyPot — Core Engine
Emulates a Hikvision IP camera. 17 services. Real logging. Telegram alerts.

Run as root:  sudo python3 honeypot.py
"""

import socket, threading, os, json, time, re, datetime
from collections import defaultdict

import config, db, geo, alerts
from fake_commands import FakeShell

# ─── State ────────────────────────────────────────────────────────────────────
_seen_ips    = set()
_rate_track  = defaultdict(list)   # ip -> [timestamps]
_banned      = {}                   # ip -> unban epoch
_session_n   = 0
_session_lk  = threading.Lock()
_stats_lk    = threading.Lock()

COUNTERS = {
    "sessions": 0, "commands": 0, "logins": 0,
    "botnets": 0, "cves": 0, "malware": 0,
    "honeytokens": 0, "tor": 0,
}

# ─── Helpers ──────────────────────────────────────────────────────────────────
def _ts():
    return datetime.datetime.utcnow().isoformat()

def _sid():
    global _session_n
    with _session_lk:
        _session_n += 1
        return f"HP{_session_n:06d}"

def _inc(key, n=1):
    with _stats_lk:
        COUNTERS[key] = COUNTERS.get(key, 0) + n

def _is_rate_limited(ip):
    if ip.startswith(("127.", "10.", "192.168.")):
        return False
    now = time.time()
    if ip in _banned:
        if now < _banned[ip]:
            return True
        del _banned[ip]
    window = config.RATE_LIMIT_CONN_PER_MIN
    _rate_track[ip] = [t for t in _rate_track[ip] if now - t < 60]
    if len(_rate_track[ip]) >= window:
        _banned[ip] = now + config.RATE_LIMIT_BAN_SECONDS
        print(f"[RATE] Banned {ip} for {config.RATE_LIMIT_BAN_SECONDS}s")
        return True
    _rate_track[ip].append(now)
    return False

def _geoip(ip):
    return geo.lookup(ip)

def _new_ip_alert(ip, country, city, service):
    if ip not in _seen_ips:
        _seen_ips.add(ip)
        alerts.new_attacker(ip, country, city, service)

def _check_cve(payload, service):
    for cve_id, cve in config.CVE_PATTERNS.items():
        if cve["pattern"] and re.search(cve["pattern"], payload, re.I):
            if cve.get("service") in (service, "any", None) or True:
                return cve_id, cve
    return None, None

def _check_botnet(username, password):
    return (username.strip(), password.strip()) in config.BOTNET_CREDS

def _check_honeytoken_file(path):
    for f in config.HONEYTOKEN_FILES:
        if f in path or path.endswith(f.split("/")[-1]):
            return True, f
    return False, None

def _check_honeytoken_cred(u, p):
    return (u, p) in config.HONEYTOKEN_CREDS, f"{u}/{p}"

def _detect_malware_url(cmd):
    patterns = [
        r"(https?://\S+\.(?:sh|elf|bin|arm|mips|x86|arm7|arm5|m68k|ppc|mpsl|mipsel))\b",
        r"(?:wget|curl|tftp\s+-g)\s+(https?://\S+)",
        r"(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:\d]*/\S+)",
    ]
    for pat in patterns:
        m = re.search(pat, cmd, re.I)
        if m:
            return m.group(1)
    return None

def _detect_arch(cmd_str):
    for a in ["arm7", "arm6", "arm5", "arm", "mips", "mipsel", "mpsl", "x86", "i686", "ppc", "m68k", "sh4"]:
        if a in cmd_str.lower():
            return a
    return "unknown"

def _detect_botnet_family(cmd_str):
    families = {
        "Mirai":   ["busybox", "ECCHI", "/bin/busybox", "cat /proc/cpuinfo", "cat /proc/mounts"],
        "Gafgyt":  ["HTTPFLOOD", "UDPFLOOD", "tftp -g", "PING", "HOLD", "JUNK"],
        "Sora":    ["SORA", "/bin/busybox SORA"],
        "Mozi":    ["mozi", "nttpd", "dht"],
        "Muhstik": ["muhstik", "JOIN #", "irc"],
        "Okiru":   ["Okiru", "bins/arm"],
    }
    s = cmd_str.lower()
    for fam, indicators in families.items():
        if any(ind.lower() in s for ind in indicators):
            return fam
    return "Unknown"

def _base_log(ip, service, gdata, sid, extra=None):
    """Log every connection hit to DB."""
    d = {
        "timestamp":  _ts(),
        "source_ip":  ip,
        "service":    service,
        "session_id": sid,
        "country":    gdata.get("country", "Unknown"),
        "city":       gdata.get("city", ""),
        "latitude":   gdata.get("latitude"),
        "longitude":  gdata.get("longitude"),
    }
    if extra:
        d.update(extra)
    db.log_attack(d)
    _new_ip_alert(ip, d["country"], d["city"], service)

# ─── TELNET (port 23) — full fake BusyBox shell ───────────────────────────────
_TELNET_BANNERS = [
    "\r\n\r\nHikvision DS-2CD2043G2-I\r\nFirmware: V5.7.15 build 230313\r\n\r\n(none) login: ",
    "\r\n\r\nBusyBox v1.31.1 (2021-10-19 08:36:54 UTC) built-in shell (ash)\r\n\r\nlogin: ",
    "\r\n\r\nWelcome to HiLinux.\r\n\r\n(none) login: ",
    "\r\n\r\nDVR-4CH Login\r\nKernel: 3.10.14\r\n\r\nlogin: ",
]

_PROMPTS = ["# ", "/ # ", "root@dvr:~# ", "[root@camera ~]# ", "root@(none):/# "]

def handle_telnet(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    sid   = _sid()
    shell = FakeShell(ip)
    prompt = _prompts = _PROMPTS[hash(ip) % len(_PROMPTS)]
    _inc("sessions")

    all_commands   = []
    login_attempts = []
    authenticated  = False

    try:
        conn.sendall(_TELNET_BANNERS[hash(ip) % len(_TELNET_BANNERS)].encode())

        for attempt in range(12):
            conn.settimeout(25)
            try:
                uraw = conn.recv(256)
            except socket.timeout:
                break
            if not uraw:
                break
            username = uraw.strip().decode(errors="ignore")

            conn.sendall(b"Password: ")
            try:
                praw = conn.recv(256)
            except socket.timeout:
                break
            password = praw.strip().decode(errors="ignore") if praw else ""

            is_bot     = _check_botnet(username, password)
            is_ht_c, ht_cv = _check_honeytoken_cred(username, password)
            login_attempts.append({"username": username, "password": password, "is_botnet": is_bot, "attempt": attempt + 1})
            _inc("logins")

            threat = "critical" if is_ht_c else ("high" if is_bot else "medium")
            db.log_attack({
                "timestamp": _ts(), "source_ip": ip, "source_port": port,
                "dest_port": 23, "service": "telnet", "protocol": "TCP",
                "username": username, "password": password,
                "country": gdata["country"], "city": gdata["city"],
                "latitude": gdata["latitude"], "longitude": gdata["longitude"],
                "attack_type": "brute_force", "threat_level": threat,
                "is_botnet": is_bot, "session_id": sid,
            })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "telnet")

            if is_bot:
                _inc("botnets")
                alerts.botnet_cred(ip, gdata["country"], "telnet", username, password)
            if is_ht_c:
                _inc("honeytokens")
                alerts.honeytoken(ip, gdata["country"], "CREDENTIAL", ht_cv, "telnet")
                db.log_honeytoken(_ts(), ip, "CREDENTIAL", ht_cv, "telnet", gdata["country"], gdata["city"])

            # Accept after 2nd attempt, or known botnet creds (let them in to observe)
            if attempt >= 1 or is_bot or is_ht_c:
                authenticated = True
                time.sleep(0.8)
                conn.sendall(b"\r\nLogin successful\r\n")
                conn.sendall(prompt.encode())
                break
            else:
                conn.sendall(b"Login incorrect\r\n")

        if not authenticated:
            return

        # ── Shell session ──────────────────────────────────────────────────
        for _ in range(150):
            try:
                conn.settimeout(120)
                raw = conn.recv(4096)
            except socket.timeout:
                break
            if not raw:
                break

            cmd = raw.strip().decode(errors="ignore")
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit", "logout"):
                break

            all_commands.append(cmd)
            _inc("commands")

            # Honeytoken file access
            ht_f, ht_fv = _check_honeytoken_file(cmd)
            if ht_f:
                _inc("honeytokens")
                alerts.honeytoken(ip, gdata["country"], "FILE_ACCESS", ht_fv, "telnet")
                db.log_honeytoken(_ts(), ip, "FILE_ACCESS", ht_fv, "telnet",
                                  gdata["country"], gdata["city"], all_commands[-5:])

            # Malware URL
            mal_url = _detect_malware_url(cmd)
            if mal_url:
                _inc("malware")
                arch   = _detect_arch(cmd)
                family = _detect_botnet_family(" ".join(all_commands))
                alerts.malware_download(ip, gdata["country"], mal_url, family, arch)
                db.log_malware(_ts(), ip, mal_url, cmd, family, arch, gdata["country"])

            # CVE
            cve_id, cve = _check_cve(cmd, "telnet")
            if cve_id:
                _inc("cves")
                alerts.cve_exploit(ip, gdata["country"], cve_id, cve["name"], cve["severity"], "telnet", cmd[:80])
                db.log_cve(_ts(), ip, cve_id, cve["name"], cve["severity"], "telnet", cmd, gdata["country"])

            out = shell.execute(cmd)
            time.sleep(0.1)
            if out:
                conn.sendall(out.encode())
            conn.sendall(prompt.encode())

    except Exception as e:
        pass
    finally:
        # Final session log with all commands
        if all_commands or login_attempts:
            db.log_attack({
                "timestamp": _ts(), "source_ip": ip, "source_port": port,
                "dest_port": 23, "service": "telnet", "protocol": "TCP",
                "country": gdata["country"], "city": gdata["city"],
                "latitude": gdata["latitude"], "longitude": gdata["longitude"],
                "attack_type": "session_complete", "threat_level": "high" if all_commands else "medium",
                "session_id": sid, "commands": all_commands,
                "is_botnet": any(la["is_botnet"] for la in login_attempts),
            })
        try: conn.close()
        except: pass

# ─── SSH (port 22) — banner + key exchange ────────────────────────────────────
_SSH_BANNERS = [
    b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
    b"SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1\r\n",
    b"SSH-2.0-dropbear_2022.82\r\n",
    b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\n",
]

def handle_ssh(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        banner = _SSH_BANNERS[hash(ip) % len(_SSH_BANNERS)]
        conn.sendall(banner)

        conn.settimeout(10)
        client_data = b""
        try:
            client_data = conn.recv(512)
        except socket.timeout:
            pass

        ua = client_data.decode(errors="ignore")[:200]
        scanner = ""
        for s in ["masscan", "zgrab", "shodan", "libssh", "paramiko", "python", "go/", "nmap"]:
            if s in ua.lower():
                scanner = s; break

        db.log_attack({
            "timestamp": _ts(), "source_ip": ip, "source_port": port,
            "dest_port": 22, "service": "ssh", "protocol": "TCP",
            "user_agent": ua, "attack_type": "banner_grab" if not scanner else "scanner",
            "threat_level": "medium", "country": gdata["country"], "city": gdata["city"],
            "latitude": gdata["latitude"], "longitude": gdata["longitude"],
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], "ssh")
        if scanner:
            print(f"  [SSH] Scanner detected: {scanner} from {ip}")

        # Keep alive briefly for scanners
        time.sleep(1.5)
        for _ in range(3):
            try:
                conn.settimeout(5)
                data = conn.recv(4096)
                if not data: break
                if b"SSH-" in data:
                    # Another banner — they're trying password auth
                    db.log_attack({
                        "timestamp": _ts(), "source_ip": ip,
                        "dest_port": 22, "service": "ssh",
                        "attack_type": "brute_force", "threat_level": "high",
                        "country": gdata["country"], "city": gdata["city"],
                        "latitude": gdata["latitude"], "longitude": gdata["longitude"],
                    })
            except: break

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── FTP (port 21) ────────────────────────────────────────────────────────────
_FTP_BANNERS = [
    "220 Hikvision DVR FTP Server V1.0\r\n",
    "220 (vsFTPd 3.0.5)\r\n",
    "220 FTP Server ready.\r\n",
    "220 DVR FTP Server Ready.\r\n",
]

def handle_ftp(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")
    username = ""
    authenticated = False

    try:
        conn.sendall(_FTP_BANNERS[hash(ip) % len(_FTP_BANNERS)].encode())

        for _ in range(30):
            conn.settimeout(20)
            try:
                line = conn.recv(512).decode(errors="ignore").strip()
            except socket.timeout:
                break
            if not line: break

            parts = line.split(" ", 1)
            cmd   = parts[0].upper()
            arg   = parts[1] if len(parts) > 1 else ""

            if cmd == "USER":
                username = arg
                conn.sendall(b"331 Password required.\r\n")

            elif cmd == "PASS":
                password = arg
                is_bot   = _check_botnet(username, password)
                is_ht_c, ht_cv = _check_honeytoken_cred(username, password)

                db.log_attack({
                    "timestamp": _ts(), "source_ip": ip, "source_port": port,
                    "dest_port": 21, "service": "ftp", "protocol": "TCP",
                    "username": username, "password": password,
                    "country": gdata["country"], "city": gdata["city"],
                    "latitude": gdata["latitude"], "longitude": gdata["longitude"],
                    "attack_type": "brute_force", "threat_level": "high" if is_bot else "medium",
                    "is_botnet": is_bot,
                })
                _new_ip_alert(ip, gdata["country"], gdata["city"], "ftp")
                _inc("logins")

                if is_bot:
                    _inc("botnets")
                    alerts.botnet_cred(ip, gdata["country"], "ftp", username, password)
                if is_ht_c:
                    _inc("honeytokens")
                    alerts.honeytoken(ip, gdata["country"], "FTP_CRED", ht_cv, "ftp")
                    db.log_honeytoken(_ts(), ip, "FTP_CRED", ht_cv, "ftp", gdata["country"])

                if is_bot or is_ht_c:
                    conn.sendall(b"230 Login successful.\r\n")
                    authenticated = True
                else:
                    conn.sendall(b"530 Login incorrect.\r\n")

            elif cmd == "SYST":
                conn.sendall(b"215 UNIX Type: L8\r\n")
            elif cmd == "FEAT":
                conn.sendall(b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")
            elif cmd == "PWD":
                conn.sendall(b'257 "/" is current directory.\r\n')
            elif cmd == "TYPE":
                conn.sendall(b"200 Switching to Binary mode.\r\n")
            elif cmd == "PASV" and authenticated:
                conn.sendall(b"227 Entering Passive Mode (192,168,1,108,195,215).\r\n")
            elif cmd == "LIST" and authenticated:
                conn.sendall(b"150 Here comes the directory listing.\r\n")
                conn.sendall(b"-rw-r--r-- 1 root root    4096 Feb 18 09:00 passwords.txt\r\n")
                conn.sendall(b"-rw-r--r-- 1 root root   65536 Feb 18 09:00 admin_backup.zip\r\n")
                conn.sendall(b"-rw-r--r-- 1 root root  131072 Feb 18 09:00 recordings.tar.gz\r\n")
                conn.sendall(b"226 Directory send OK.\r\n")
            elif cmd == "RETR" and authenticated:
                ht_f, ht_fv = _check_honeytoken_file(arg)
                if ht_f:
                    _inc("honeytokens")
                    alerts.honeytoken(ip, gdata["country"], "FTP_DOWNLOAD", arg, "ftp")
                    db.log_honeytoken(_ts(), ip, "FTP_DOWNLOAD", arg, "ftp", gdata["country"])
                conn.sendall(b"550 Failed to open file.\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye.\r\n"); break
            else:
                conn.sendall(b"500 Unknown command.\r\n")

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── SMTP (port 25) ───────────────────────────────────────────────────────────
def handle_smtp(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        conn.sendall(b"220 mail.camera-system.local ESMTP Postfix\r\n")
        for _ in range(20):
            conn.settimeout(15)
            try:
                line = conn.recv(1024).decode(errors="ignore").strip()
            except socket.timeout:
                break
            if not line: break

            db.log_attack({
                "timestamp": _ts(), "source_ip": ip, "dest_port": 25,
                "service": "smtp", "payload": line[:200],
                "attack_type": "smtp_probe", "threat_level": "low",
                "country": gdata["country"], "city": gdata["city"],
                "latitude": gdata["latitude"], "longitude": gdata["longitude"],
            })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "smtp")

            cmd = line.split()[0].upper() if line.split() else ""
            if cmd in ("EHLO", "HELO"):
                conn.sendall(b"250-mail.camera-system.local\r\n250-PIPELINING\r\n250-AUTH LOGIN PLAIN\r\n250 HELP\r\n")
            elif cmd == "AUTH":
                conn.sendall(b"535 5.7.8 Authentication credentials invalid\r\n")
            elif cmd in ("MAIL", "RCPT"):
                conn.sendall(b"250 OK\r\n")
            elif cmd == "DATA":
                conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"221 Bye\r\n"); break
            else:
                conn.sendall(b"500 Command not recognized\r\n")
    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── HTTP / HTTPS (ports 80, 443, 8080) ───────────────────────────────────────
# Rich set of paths that attackers scan for
HTTP_ROUTES = {
    "/": (200, "text/html", """<!DOCTYPE html>
<html><head><title>IP Camera Web Manager</title></head>
<body style="background:#111;color:#0f0;font-family:monospace;padding:40px;text-align:center">
<h1>&#127909; Hikvision DS-2CD2043G2-I</h1>
<p>Firmware: V5.7.15 build 230313 | MAC: 44:19:B6:7A:2C:D9</p>
<p style="margin-top:30px">
  <a href="/doc/page/login.asp" style="color:#0ff">Web Interface</a> &nbsp;|&nbsp;
  <a href="/ISAPI/System/deviceInfo" style="color:#0ff">Device Info</a> &nbsp;|&nbsp;
  <a href="/admin" style="color:#0ff">Admin Panel</a>
</p>
</body></html>"""),

    "/doc/page/login.asp": (200, "text/html", """<!DOCTYPE html>
<html><head><title>Hikvision — Login</title></head>
<body style="background:#1a1a1a;color:#ccc;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0">
<div style="background:#222;padding:40px;border-radius:8px;min-width:300px">
<h2 style="color:#fff;text-align:center">&#128247; Hikvision</h2>
<form method="POST" action="/doc/page/login.asp" style="display:flex;flex-direction:column;gap:12px">
  <input name="username" placeholder="Username" style="padding:10px;background:#333;border:1px solid #555;color:#fff;border-radius:4px">
  <input name="password" type="password" placeholder="Password" style="padding:10px;background:#333;border:1px solid #555;color:#fff;border-radius:4px">
  <button type="submit" style="padding:10px;background:#0066cc;color:#fff;border:none;border-radius:4px;cursor:pointer">Login</button>
</form>
</div></body></html>"""),

    "/admin": (200, "text/html", """<!DOCTYPE html>
<html><head><title>Admin Panel</title></head>
<body style="background:#1a1a1a;color:#ccc;font-family:sans-serif;padding:20px">
<h2>Administrator Login</h2>
<form method="POST"><input name="user" placeholder="Username"> <input type="password" name="pass" placeholder="Password"> <button>Login</button></form>
<p style="color:#555;font-size:12px">System: Hikvision V5.7.15 | <a href="/.env" style="color:#888">cfg</a></p>
</body></html>"""),

    "/ISAPI/System/deviceInfo": (200, "application/xml", """<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0">
  <deviceName>IPCamera</deviceName>
  <deviceID>44194e2a-5b9c-4c9a-9c4b-12ef8e4d5f6a</deviceID>
  <model>DS-2CD2043G2-I</model>
  <serialNumber>DS-2CD2043G2-I20230313CCCH012345678</serialNumber>
  <macAddress>44:19:B6:7A:2C:D9</macAddress>
  <firmwareVersion>V5.7.15 build 230313</firmwareVersion>
  <firmwareReleasedDate>build 230313</firmwareReleasedDate>
  <encoderVersion>V9.0</encoderVersion>
  <deviceType>IPCamera</deviceType>
  <telecontrolID>88</telecontrolID>
</DeviceInfo>"""),

    "/ISAPI/Security/userCheck": (200, "application/xml",
        "<?xml version=\"1.0\"?><userCheck><statusValue>200</statusValue><statusString>OK</statusString></userCheck>"),

    "/ISAPI/Security/sessionLogin/capabilities": (200, "application/xml",
        "<?xml version=\"1.0\"?><SessionLoginCap><sessionID>3D1633C7</sessionID><challenge>aK9Jxm3</challenge><iterations>100</iterations><isIrreversible>true</isIrreversible></SessionLoginCap>"),

    "/ISAPI/Security/users": (401, "application/xml",
        "<?xml version=\"1.0\"?><ResponseStatus><requestURL>/ISAPI/Security/users</requestURL><statusCode>401</statusCode><statusString>Unauthorized</statusString></ResponseStatus>"),

    "/.env": (200, "text/plain", """APP_ENV=production
DB_HOST=192.168.1.50
DB_PORT=5432
DB_NAME=camera_db
DB_USER=admin
DB_PASS=SuperSecret2024!
API_KEY=sk-proj-abc123xyz789def456ghi
JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZX0
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SMTP_PASS=MailPass2024!
"""),

    "/.aws/credentials": (200, "text/plain", """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[backup]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
"""),

    "/etc/passwd": (200, "text/plain",
        "root:x:0:0:root:/root:/bin/ash\nadmin:x:500:500:Administrator:/home/admin:/bin/ash\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n"),

    "/robots.txt": (200, "text/plain",
        "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /.env\nDisallow: /.git/\nDisallow: /ISAPI/\n"),

    "/wp-login.php": (200, "text/html", """<!DOCTYPE html>
<html><head><title>Log In &lsaquo; WordPress &mdash; WordPress</title></head>
<body class="login"><div id="login"><h1><a href="/">Site</a></h1>
<form method="post" action="/wp-login.php">
<label>Username or Email<input type="text" name="log" size="20"></label>
<label>Password<input type="password" name="pwd" size="20"></label>
<input type="submit" name="wp-submit" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
</form></div></body></html>"""),

    "/wp-config.php": (403, "text/plain", "403 Forbidden"),

    "/phpMyAdmin/": (200, "text/html",
        '<html><body style="background:#1a1a1a;color:#ccc;font-family:sans-serif;padding:20px"><h2>phpMyAdmin 5.2.1</h2><form method="post"><input name="pma_username" placeholder="Username" style="padding:5px"> <input type="password" name="pma_password" placeholder="Password" style="padding:5px"> <input type="submit" value="Go"></form></body></html>'),

    "/phpmyadmin/": (200, "text/html",
        '<html><body style="background:#1a1a1a;color:#ccc;padding:20px"><h2>phpMyAdmin 5.2.1</h2></body></html>'),

    "/actuator/env": (200, "application/json",
        '{"activeProfiles":["production"],"propertySources":[{"name":"applicationConfig","properties":{"spring.datasource.password":{"value":"Sup3rS3cret2024!"},"jwt.secret":{"value":"change-in-prod-please"},"api.key":{"value":"sk-api-EXAMPLE123"}}}]}'),

    "/actuator": (200, "application/json",
        '{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"},"env":{"href":"/actuator/env"},"metrics":{"href":"/actuator/metrics"},"heapdump":{"href":"/actuator/heapdump"}}}'),

    "/manager/html": (401, "text/html",
        '<html><head><title>Apache Tomcat Manager</title></head><body><h1>401 Unauthorized</h1><p>This server has a realm of "Tomcat Manager Application"</p></body></html>'),

    "/console": (200, "text/html",
        '<html><body style="background:#1a1a1a;color:#ccc;padding:20px"><h2>JBoss Management Console</h2><form method="post"><input name="j_username" placeholder="Username"> <input type="password" name="j_password" placeholder="Password"> <input type="submit" value="Login"></form></body></html>'),

    "/.git/config": (200, "text/plain",
        '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = https://github.com/internal/camera-firmware.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n'),

    "/docker-compose.yml": (200, "text/plain",
        'version: "3.8"\nservices:\n  camera:\n    image: hikvision/ipc:latest\n    ports:\n      - "80:80"\n      - "554:554"\n    environment:\n      - ADMIN_PASS=Admin@2024!\n      - DB_URL=postgresql://admin:Sup3rS3cret2024@db:5432/cameras\n'),

    "/api/v1/endpoints/activate": (200, "application/json",
        '{"status":"ok","endpoint":"activated","token":"eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZX0.INVALID"}'),

    "/ztp/cgi-bin/handler": (200, "application/json",
        '{"result":"ok","code":0}'),

    "/phpinfo.php": (200, "text/html",
        "<html><body style='font-family:sans-serif;background:#fff'><h1>PHP Version 7.4.33</h1><table><tr><td>System</td><td>Linux camera 5.4.0 #1 SMP</td></tr><tr><td>Build Date</td><td>Jan 10 2023</td></tr><tr><td>Server API</td><td>Apache 2.0 Handler</td></tr></table></body></html>"),

    "/backup/passwords.txt": (200, "text/plain",
        "== Device Admin Credentials ==\nadmin:Admin@2024\nroot:ProductionKey999\ndbuser:MyDB_P@ssw0rd\n"),

    "/install.php": (200, "text/html",
        "<html><body style='padding:20px;background:#1a1a1a;color:#ccc'><h2>Installation Wizard</h2><p>Step 1: Database Configuration</p><form><input name='db_host' value='localhost'> <input name='db_user' value='root'> <input type='password' name='db_pass'><button>Next</button></form></body></html>"),
}

_HTTP_SERVER_HEADERS = [
    "App-webs/",
    "Apache/2.4.41 (Ubuntu)",
    "nginx/1.18.0",
    "GoAhead-Webs",
    "Boa/0.94.14rc21",
]
_HTTP_SRV_HDR = _HTTP_SERVER_HEADERS[0]

def _http_resp(status, ct, body, extra=""):
    if isinstance(body, str): body = body.encode()
    status_map = {200:"OK",302:"Found",401:"Unauthorized",403:"Forbidden",404:"Not Found"}
    hdr = (f"HTTP/1.1 {status} {status_map.get(status,'OK')}\r\n"
           f"Server: {_HTTP_SRV_HDR}\r\n"
           f"Content-Type: {ct}\r\n"
           f"Content-Length: {len(body)}\r\n"
           f"Connection: close\r\n{extra}\r\n")
    return hdr.encode() + body

def handle_http(conn, addr, https=False):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")
    svc   = "https" if https else "http"
    dport = 443 if https else (8080 if port == 8080 else 80)

    try:
        conn.settimeout(8)
        raw = conn.recv(16384)
        if not raw: return
        raw_str = raw.decode(errors="ignore")
        lines   = raw_str.split("\n")
        req_ln  = lines[0].strip().split()
        method  = req_ln[0] if req_ln else "GET"
        full_path = req_ln[1] if len(req_ln) > 1 else "/"
        path    = full_path.split("?")[0]

        ua      = next((l.split(":",1)[1].strip() for l in lines if l.lower().startswith("user-agent:")), "")
        referer = next((l.split(":",1)[1].strip() for l in lines if l.lower().startswith("referer:")), "")

        # POST body (login attempts)
        post_body = ""
        if "\r\n\r\n" in raw_str:
            post_body = raw_str.split("\r\n\r\n", 1)[1][:500]

        # CVE check
        full_request = raw_str[:2000]
        cve_id, cve = _check_cve(full_request, svc)
        if cve_id:
            _inc("cves")
            alerts.cve_exploit(ip, gdata["country"], cve_id, cve["name"], cve["severity"], svc, path)
            db.log_cve(_ts(), ip, cve_id, cve["name"], cve["severity"], svc, full_request[:1000], gdata["country"])

        # Honeytoken file check
        ht_f, ht_fv = _check_honeytoken_file(path)
        if ht_f:
            _inc("honeytokens")
            alerts.honeytoken(ip, gdata["country"], "HTTP_GET", path, svc)
            db.log_honeytoken(_ts(), ip, "HTTP_GET", path, svc, gdata["country"], gdata["city"])

        threat = "critical" if cve_id or ht_f else ("high" if any(p in path for p in ["/admin", "/ISAPI/", "/actuator"]) else "low")
        db.log_attack({
            "timestamp":   _ts(), "source_ip": ip, "source_port": port,
            "dest_port":   dport, "service":   svc, "protocol": "TCP",
            "method":      method, "path": path, "user_agent": ua[:256],
            "payload":     post_body, "raw_payload": full_request[:512],
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
            "attack_type": "web_scan", "threat_level": threat,
            "cve_id":      cve_id or "",
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], svc)

        # Route response
        if path in HTTP_ROUTES:
            status, ct, body = HTTP_ROUTES[path]
            conn.sendall(_http_resp(status, ct, body))
        elif any(x in path for x in ["wp-", "wordpress"]):
            conn.sendall(_http_resp(200, "text/html", HTTP_ROUTES["/wp-login.php"][2]))
        elif any(x in path.lower() for x in ["phpmyadmin", "pma"]):
            conn.sendall(_http_resp(200, "text/html", HTTP_ROUTES["/phpMyAdmin/"][2]))
        elif "backup" in path.lower() or path.endswith((".sql", ".zip", ".tar.gz")):
            # Return forbidden but log it
            conn.sendall(_http_resp(403, "text/html", b"<h1>403 Forbidden</h1>"))
        elif path.startswith("/api"):
            conn.sendall(_http_resp(200, "application/json", b'{"status":"ok","version":"1.0.0"}'))
        elif path.startswith("/ISAPI"):
            conn.sendall(_http_resp(401, "application/xml",
                b"<?xml version=\"1.0\"?><ResponseStatus><statusCode>401</statusCode><statusString>Unauthorized</statusString></ResponseStatus>"))
        else:
            conn.sendall(_http_resp(404, "text/html", b"<html><body><h1>404 Not Found</h1></body></html>"))

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── RTSP (port 554) ──────────────────────────────────────────────────────────
def handle_rtsp(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        conn.settimeout(10)
        raw = conn.recv(2048).decode(errors="ignore")
        if not raw: return

        cseq = "1"
        for line in raw.split("\n"):
            if line.upper().startswith("CSEQ:"):
                cseq = line.split(":", 1)[1].strip()

        # Extract stream URL if present
        stream_url = ""
        for line in raw.split("\n"):
            if line.upper().startswith("DESCRIBE") or "RTSP" in line.upper():
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("rtsp://"):
                    stream_url = parts[1]

        db.log_attack({
            "timestamp":   _ts(), "source_ip": ip, "source_port": port,
            "dest_port":   554, "service": "rtsp", "protocol": "TCP",
            "method":      raw.split()[0] if raw.split() else "DESCRIBE",
            "path":        stream_url or raw[:100],
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
            "attack_type": "camera_access", "threat_level": "medium",
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], "rtsp")

        resp = (f"RTSP/1.0 401 Unauthorized\r\n"
                f"CSeq: {cseq}\r\n"
                f"WWW-Authenticate: Digest realm=\"Streaming Server\","
                f" nonce=\"{os.urandom(8).hex()}\","
                f" algorithm=\"MD5\"\r\n"
                f"Server: Hikvision RTSP Server\r\n\r\n")
        conn.sendall(resp.encode())

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── ONVIF (port 8000) ───────────────────────────────────────────────────────
_ONVIF_RESP = b"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
  xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
  xmlns:tt="http://www.onvif.org/ver10/schema">
<SOAP-ENV:Body>
<tds:GetCapabilitiesResponse>
<tds:Capabilities>
<tt:Analytics><tt:XAddr>http://192.168.1.108:8000/onvif/analytics</tt:XAddr></tt:Analytics>
<tt:Device><tt:XAddr>http://192.168.1.108:8000/onvif/device_service</tt:XAddr></tt:Device>
<tt:Events><tt:XAddr>http://192.168.1.108:8000/onvif/event</tt:XAddr></tt:Events>
<tt:Imaging><tt:XAddr>http://192.168.1.108:8000/onvif/imaging</tt:XAddr></tt:Imaging>
<tt:Media><tt:XAddr>http://192.168.1.108:8000/onvif/media</tt:XAddr></tt:Media>
</tds:Capabilities>
</tds:GetCapabilitiesResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

def handle_onvif(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        conn.settimeout(8)
        raw = conn.recv(4096)
        if not raw: return

        db.log_attack({
            "timestamp":   _ts(), "source_ip": ip, "dest_port": 8000,
            "service":     "onvif", "protocol": "TCP",
            "payload":     raw.decode(errors="ignore")[:200],
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
            "attack_type": "camera_discovery", "threat_level": "medium",
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], "onvif")

        hdr = (f"HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\n"
               f"Content-Length: {len(_ONVIF_RESP)}\r\n\r\n")
        conn.sendall(hdr.encode() + _ONVIF_RESP)

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── MQTT (port 1883) ─────────────────────────────────────────────────────────
def handle_mqtt(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    username = ""
    try:
        conn.settimeout(10)
        pkt = conn.recv(256)
        if not pkt: return

        if (pkt[0] & 0xF0) == 0x10:  # CONNECT
            # Try to extract username from variable header
            try:
                proto_len = int.from_bytes(pkt[4:6], "big")
                idx = 2 + 2 + proto_len + 1 + 1 + 2  # skip fixed, proto_name, level, flags, keepalive
                flags = pkt[9] if len(pkt) > 9 else 0
                # Skip client_id
                if idx + 2 <= len(pkt):
                    cid_len = int.from_bytes(pkt[idx:idx+2], "big")
                    idx += 2 + cid_len
                # Username
                if (flags & 0x80) and idx + 2 <= len(pkt):
                    ulen = int.from_bytes(pkt[idx:idx+2], "big")
                    username = pkt[idx+2:idx+2+ulen].decode(errors="ignore")
            except Exception:
                pass

            conn.sendall(b"\x20\x02\x00\x00")  # CONNACK — accepted

            db.log_attack({
                "timestamp":   _ts(), "source_ip": ip, "dest_port": 1883,
                "service":     "mqtt", "protocol": "TCP",
                "username":    username,
                "country":     gdata["country"], "city": gdata["city"],
                "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
                "attack_type": "iot_protocol", "threat_level": "medium",
            })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "mqtt")

            # Read more packets
            for _ in range(15):
                try:
                    conn.settimeout(8)
                    p = conn.recv(512)
                    if not p: break
                    t = (p[0] & 0xF0) >> 4
                    if t == 12: conn.sendall(b"\xd0\x00")   # PINGRESP
                    elif t == 8: conn.sendall(b"\x90\x03\x00\x01\x00")  # SUBACK
                    elif t == 14: break  # DISCONNECT
                except: break

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── Redis (port 6379) ────────────────────────────────────────────────────────
def handle_redis(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")
    commands_seen = []

    try:
        for _ in range(25):
            conn.settimeout(15)
            try:
                data = conn.recv(1024)
            except socket.timeout:
                break
            if not data: break

            raw = data.decode(errors="ignore").strip()
            commands_seen.append(raw[:100])
            cmd = raw.upper().split()[0] if raw.split() else ""

            # Detect CONFIG SET RCE
            if cmd == "CONFIG" and ("SET" in raw.upper()):
                _inc("cves")
                alerts.redis_rce(ip, gdata["country"], raw[:100])
                db.log_cve(_ts(), ip, "REDIS-RCE", "Redis CONFIG SET RCE", "critical", "redis", raw[:500], gdata["country"])
                db.log_attack({
                    "timestamp": _ts(), "source_ip": ip, "dest_port": 6379,
                    "service": "redis", "payload": raw[:200], "cve_id": "REDIS-RCE",
                    "attack_type": "rce_attempt", "threat_level": "critical",
                    "country": gdata["country"], "latitude": gdata["latitude"],
                    "longitude": gdata["longitude"],
                })
            else:
                db.log_attack({
                    "timestamp": _ts(), "source_ip": ip, "dest_port": 6379,
                    "service": "redis", "payload": raw[:200],
                    "attack_type": "nosql_probe", "threat_level": "high",
                    "country": gdata["country"], "city": gdata["city"],
                    "latitude": gdata["latitude"], "longitude": gdata["longitude"],
                })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "redis")

            if cmd == "PING":      conn.sendall(b"+PONG\r\n")
            elif cmd == "AUTH":    conn.sendall(b"-ERR invalid password\r\n")
            elif cmd == "INFO":    conn.sendall(b"$120\r\n# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\nos:Linux 5.15.0\r\narch_bits:64\r\nuptime_in_seconds:86400\r\n\r\n")
            elif cmd == "CONFIG":  conn.sendall(b"-ERR unknown command 'config', with args beginning with: 'set' 'dir' '/tmp' \r\n")
            elif cmd == "SLAVEOF": conn.sendall(b"+OK\r\n")
            elif cmd == "SAVE":    conn.sendall(b"+OK\r\n")
            elif cmd == "FLUSHALL":conn.sendall(b"+OK\r\n")
            elif cmd == "SET":     conn.sendall(b"+OK\r\n")
            elif cmd == "GET":     conn.sendall(b"$-1\r\n")
            elif cmd == "KEYS":    conn.sendall(b"*0\r\n")
            elif cmd in ("QUIT","EXIT"): conn.sendall(b"+OK\r\n"); break
            else:                  conn.sendall(b"-ERR unknown command\r\n")

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── MySQL (port 3306) ────────────────────────────────────────────────────────
_MYSQL_GREET = (
    b"\x4a\x00\x00\x00"
    b"\x0a"
    b"8.0.32\x00"
    b"\x08\x00\x00\x00"
    b"\x2a\x4b\x7c\x26\x31\x3e\x65\x77\x00"
    b"\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x4c\x4b\x6c\x41\x43\x37\x42\x42\x41\x74\x6f\x4e\x00"
    b"caching_sha2_password\x00"
)

def handle_mysql(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        conn.sendall(_MYSQL_GREET)
        conn.settimeout(10)
        data = conn.recv(4096)
        username = "root"
        if data:
            try:
                text  = data[4:].decode(errors="ignore")
                parts = [p for p in text.split("\x00") if 2 < len(p) < 40 and p.isprintable()]
                if parts:
                    username = parts[0]
            except Exception:
                pass

        db.log_attack({
            "timestamp":   _ts(), "source_ip": ip, "dest_port": 3306,
            "service":     "mysql", "username": username,
            "attack_type": "db_auth", "threat_level": "high",
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], "mysql")

        # Auth failure
        conn.sendall(
            b"\x2e\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30"
            b"Access denied for user 'root'@'10.0.0.1' (using password: YES)"
        )

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── Docker API (port 2375) ───────────────────────────────────────────────────
_DOCKER_VER = b'{"Version":"24.0.7","ApiVersion":"1.43","MinAPIVersion":"1.12","GitCommit":"af33977","GoVersion":"go1.20.10","Os":"linux","Arch":"amd64","KernelVersion":"5.15.0"}'

def handle_docker(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")
    _inc("cves")

    try:
        conn.settimeout(10)
        raw = conn.recv(8192)
        if not raw: return

        raw_str  = raw.decode(errors="ignore")
        req_line = raw_str.split("\n")[0].strip()
        path     = req_line.split()[1] if len(req_line.split()) > 1 else "/"

        # Always alert Docker — it's always critical
        alerts.docker_escape(ip, gdata["country"], path)
        db.log_cve(_ts(), ip, "DOCKER-ESCAPE", "Docker API Container Escape", "critical", "docker", raw_str[:500], gdata["country"])
        db.log_attack({
            "timestamp":   _ts(), "source_ip": ip, "dest_port": 2375,
            "service":     "docker", "method": req_line.split()[0] if req_line.split() else "",
            "path":        path, "payload": raw_str[:300],
            "attack_type": "container_escape", "threat_level": "critical",
            "cve_id":      "DOCKER-ESCAPE",
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], "docker")

        if "version" in path.lower() or path in ("/", ""):
            body = _DOCKER_VER
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nApi-Version: 1.43\r\n"
                         + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        elif "/containers/json" in path:
            body = b'[{"Id":"4f2a8b1cabc123","Names":["/webapp"],"Image":"nginx:1.24","Status":"Up 14 hours","Ports":[{"PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]}]'
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        else:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── Memcached (port 11211) ───────────────────────────────────────────────────
def handle_memcached(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        for _ in range(10):
            conn.settimeout(10)
            try:
                data = conn.recv(512)
            except socket.timeout:
                break
            if not data: break
            raw = data.decode(errors="ignore").strip()
            cmd = raw.split()[0].lower() if raw.split() else ""

            db.log_attack({
                "timestamp": _ts(), "source_ip": ip, "dest_port": 11211,
                "service": "memcached", "payload": raw[:100],
                "attack_type": "nosql_probe", "threat_level": "medium",
                "country": gdata["country"], "city": gdata["city"],
                "latitude": gdata["latitude"], "longitude": gdata["longitude"],
            })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "memcached")

            if cmd == "stats":    conn.sendall(b"STAT version 1.6.17\r\nSTAT uptime 86400\r\nSTAT curr_items 0\r\nSTAT bytes_read 1024\r\nEND\r\n")
            elif cmd == "version":conn.sendall(b"VERSION 1.6.17\r\n")
            elif cmd == "flush_all": conn.sendall(b"OK\r\n")
            elif cmd == "set":    conn.sendall(b"STORED\r\n")
            elif cmd == "get":    conn.sendall(b"END\r\n")
            elif cmd == "quit":   break
            else:                 conn.sendall(b"ERROR\r\n")
    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── VNC (port 5900) ─────────────────────────────────────────────────────────
def handle_vnc(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        conn.sendall(b"RFB 003.008\n")
        conn.settimeout(8)
        conn.recv(12)                    # Client version
        conn.sendall(b"\x01\x02")        # Security: VNC Auth
        conn.recv(1)                     # Client picks type 2
        conn.sendall(os.urandom(16))     # Challenge
        conn.recv(16)                    # Client response
        conn.sendall(b"\x00\x00\x00\x01")  # Auth failed
        reason = b"Authentication failed"
        conn.sendall(len(reason).to_bytes(4, "big") + reason)

        db.log_attack({
            "timestamp": _ts(), "source_ip": ip, "dest_port": 5900,
            "service": "vnc", "attack_type": "remote_access", "threat_level": "high",
            "country": gdata["country"], "city": gdata["city"],
            "latitude": gdata["latitude"], "longitude": gdata["longitude"],
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], "vnc")
    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── RDP (port 3389) ─────────────────────────────────────────────────────────
def handle_rdp(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        conn.settimeout(8)
        conn.recv(512)
        conn.sendall(b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x08\x00\x00\x00\x00\x00")
        db.log_attack({
            "timestamp": _ts(), "source_ip": ip, "dest_port": 3389,
            "service": "rdp", "attack_type": "remote_access", "threat_level": "high",
            "country": gdata["country"], "city": gdata["city"],
            "latitude": gdata["latitude"], "longitude": gdata["longitude"],
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], "rdp")
    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── Modbus ICS (port 502) ───────────────────────────────────────────────────
def handle_modbus(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        conn.settimeout(8)
        data = conn.recv(256)
        if data and len(data) >= 6:
            txid = data[0:2]
            unit = data[6:7] if len(data) > 6 else b"\x01"
            # Exception: Illegal function
            conn.sendall(txid + b"\x00\x00\x00\x03" + unit + b"\x81\x01")

        db.log_attack({
            "timestamp": _ts(), "source_ip": ip, "dest_port": 502,
            "service": "modbus", "attack_type": "ics_scada", "threat_level": "critical",
            "country": gdata["country"], "city": gdata["city"],
            "latitude": gdata["latitude"], "longitude": gdata["longitude"],
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], "modbus")
        alerts.generic("MODBUS", "Modbus/ICS Probe", [
            ("IP", ip), ("Country", gdata["country"]),
        ], ip=ip, cooldown_key=f"MODBUS:{ip}")

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

# ─── Service launcher ─────────────────────────────────────────────────────────
def _start_tcp(handler, port, name):
    def _inner():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((config.HONEYPOT_HOST, port))
            srv.listen(256)
            print(f"  [+] {name:<22} :{port}")
            while True:
                try:
                    cli, addr = srv.accept()
                    t = threading.Thread(target=handler, args=(cli, addr), daemon=True)
                    t.start()
                except Exception as e:
                    print(f"  [!] {name} accept: {e}")
        except OSError as e:
            print(f"  [✗] {name:<22} :{port} — {e}")
    threading.Thread(target=_inner, daemon=True, name=name).start()

# ─── Services map ─────────────────────────────────────────────────────────────
_SERVICES = [
    (handle_telnet,                        config.SERVICE_PORTS["telnet"],    "Telnet"),
    (handle_ssh,                           config.SERVICE_PORTS["ssh"],       "SSH"),
    (handle_ftp,                           config.SERVICE_PORTS["ftp"],       "FTP"),
    (handle_smtp,                          config.SERVICE_PORTS["smtp"],      "SMTP"),
    (handle_http,                          config.SERVICE_PORTS["http"],      "HTTP"),
    (lambda c,a: handle_http(c,a,True),    config.SERVICE_PORTS["https"],     "HTTPS"),
    (handle_http,                          config.SERVICE_PORTS["http_alt"],  "HTTP-Alt"),
    (handle_rtsp,                          config.SERVICE_PORTS["rtsp"],      "RTSP"),
    (handle_onvif,                         config.SERVICE_PORTS["onvif"],     "ONVIF"),
    (handle_mqtt,                          config.SERVICE_PORTS["mqtt"],      "MQTT"),
    (handle_redis,                         config.SERVICE_PORTS["redis"],     "Redis"),
    (handle_mysql,                         config.SERVICE_PORTS["mysql"],     "MySQL"),
    (handle_docker,                        config.SERVICE_PORTS["docker"],    "Docker API"),
    (handle_memcached,                     config.SERVICE_PORTS["memcached"], "Memcached"),
    (handle_vnc,                           config.SERVICE_PORTS["vnc"],       "VNC"),
    (handle_rdp,                           config.SERVICE_PORTS["rdp"],       "RDP"),
    (handle_modbus,                        config.SERVICE_PORTS["modbus"],    "Modbus/ICS"),
]

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    db.init()

    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║  honeyPot v{config.VERSION}  —  IoT Threat Intelligence Honeypot              ║
║  Device: {config.DEVICE_VENDOR} {config.DEVICE_MODEL}                    ║
║  Firmware: {config.DEVICE_FIRMWARE}                              ║
╠══════════════════════════════════════════════════════════════════════╣
║  Telegram: {'ENABLED ✓' if config.TELEGRAM_ENABLED else 'disabled (set TELEGRAM_TOKEN + TELEGRAM_CHAT_ID)'}                                   ║
║  GeoIP:    {'ENABLED ✓' if os.path.exists(config.GEOIP_DB) else 'disabled (GeoLite2-City.mmdb missing)'}                                      ║
╚══════════════════════════════════════════════════════════════════════╝""")

    print("\n[*] Starting services:")
    active = 0
    for handler, port, name in _SERVICES:
        if port:
            _start_tcp(handler, port, name)
            active += 1
            time.sleep(0.05)

    print(f"\n[✓] {active} services active | DB: {config.DB_PATH}")
    print(f"[✓] Dashboard: python3 dashboard.py\n")

    if config.TELEGRAM_ENABLED:
        alerts.startup(active, f"{config.DEVICE_VENDOR} {config.DEVICE_MODEL}", config.DEVICE_FIRMWARE)
    else:
        print("[!] Telegram disabled — set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID env vars")

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print(f"\n[!] Stopped | Sessions: {COUNTERS['sessions']} | Unique IPs: {len(_seen_ips)}")
        if config.TELEGRAM_ENABLED:
            alerts.shutdown(COUNTERS["sessions"], len(_seen_ips))

if __name__ == "__main__":
    main()
