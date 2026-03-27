#!/usr/bin/env python3
"""
honeyPot — Core Engine
Emulates a Hikvision IP camera. 18 services. Real logging. Telegram alerts.

Run as root:  sudo python3 honeypot.py
"""

import socket, threading, os, json, time, re, datetime, urllib.request
from collections import defaultdict
import random

import ssl, certifi
os.environ["SSL_CERT_FILE"] = certifi.where()

import config, db, geo, alerts
from fake_commands import FakeShell
import rtsp_service
import onvif_service
import ssh_service
import ftp_service
import vnc_service
import mqtt_service
import coap_service
import hik_sdk_service
import tftp_service
import ssdp_service
import http_service
import dahua_service         # Dahua DVR proprietary protocol (port 37777)
import xmeye_service         # HiSilicon/XMEye DVR protocol (port 34567)
import tr069_service         # TR-069 CWMP ISP router management (port 7547)
import adb_service           # Android Debug Bridge (port 5555)
import redis_service          # Redis RCE honeypot (port 6379)
import docker_service         # Docker daemon API honeypot (port 2375)

# ─── State ────────────────────────────────────────────────────────────────────
_seen_ips    = set()
_rate_track  = defaultdict(list)   # ip -> [timestamps]
_banned      = {}                   # ip -> unban epoch
_cred_track  = defaultdict(list)   # ip -> [timestamps] for brute force detection
_session_n  = 0
_session_lk = threading.Lock()
_stats_lk   = threading.Lock()

COUNTERS = {
    "sessions":    0,
    "commands":    0,
    "logins":      0,
    "botnets":     0,
    "cves":        0,
    "malware":     0,
    "honeytokens": 0,
    "tor":         0,
    "vpn":         0,
    "proxy":       0,
    "brute_force": 0,
}

# ─── Randomisation helpers ────────────────────────────────────────────────────
def _random_mac():
    return "44:%02X:%02X:%02X:%02X:%02X" % tuple(random.randint(0, 255) for _ in range(5))

def _random_session_id():
    return "".join(random.choices("ABCDEF0123456789", k=8))

def _random_delay(min_ms=80, max_ms=220):
    time.sleep(random.uniform(min_ms, max_ms) / 1000)

# ─── Core helpers ─────────────────────────────────────────────────────────────
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
    if ip.startswith(("127.", "10.", "192.168.", "::1")):
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


# ─── Brute-force burst detection ──────────────────────────────────────────────
_BRUTE_WINDOW  = 60    # seconds
_BRUTE_THRESH  = 10    # attempts within window before alert fires
_brute_alerted = {}    # ip -> last alert epoch (so we don't spam)
_brute_lk      = threading.Lock()

def _track_cred_attempt(ip: str, service: str):
    """Call on every login attempt. Fires Telegram alert on burst."""
    now = time.time()
    with _brute_lk:
        _cred_track[ip] = [t for t in _cred_track[ip] if now - t < _BRUTE_WINDOW]
        _cred_track[ip].append(now)
        count = len(_cred_track[ip])
        last_alert = _brute_alerted.get(ip, 0)
        if count >= _BRUTE_THRESH and now - last_alert > 300:  # re-alert every 5 min max
            _brute_alerted[ip] = now
            _inc("brute_force")
            gdata = _geoip(ip)
            db.log_attack({
                "timestamp":   _ts(),
                "source_ip":   ip,
                "dest_port":   {"ssh": 2222, "ftp": 21, "telnet": 23}.get(service, 0),
                "service":     service,
                "protocol":    "TCP",
                "attack_type": "BRUTE_FORCE_BURST",
                "threat_level": "high",
                "country":     gdata.get("country", "Unknown"),
                "city":        gdata.get("city", ""),
                "latitude":    gdata.get("latitude", 0),
                "longitude":   gdata.get("longitude", 0),
                "payload":     f"{count} attempts in {_BRUTE_WINDOW}s",
                **_intel_fields(gdata),
            })
            try:
                alerts.brute_force_burst(
                    ip, gdata.get("country", "Unknown"),
                    service, count, _BRUTE_WINDOW,
                )
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
#  TOR EXIT NODE DETECTION
# ══════════════════════════════════════════════════════════════════════════════

_tor_exit_nodes: set = set()
_tor_list_loaded     = False
_tor_list_lock       = threading.Lock()


def _load_tor_exit_nodes():
    global _tor_exit_nodes, _tor_list_loaded
    with _tor_list_lock:
        if _tor_list_loaded:
            return

        import ssl, certifi
        ctx = ssl.create_default_context(cafile=certifi.where())

        sources = [
            "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst",
            "https://check.torproject.org/torbulkexitlist",
            "https://www.dan.me.uk/torlist/",
        ]
        for url in sources:
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "security-research-honeypot/1.0"}
                )
                with urllib.request.urlopen(req, timeout=12, context=ctx) as r:
                    raw = r.read().decode("utf-8", errors="ignore")
                ips = {
                    line.strip()
                    for line in raw.splitlines()
                    if line.strip()
                    and not line.startswith("#")
                    and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line.strip())
                }
                if ips:
                    _tor_exit_nodes = ips
                    print(f"  [+] Tor exit nodes: {len(ips):,} loaded")
                    break
            except Exception as e:
                print(f"  [!] Tor list fetch failed ({url}): {e}")
        _tor_list_loaded = True


def _tor_refresh_worker():
    """Background thread: reload Tor exit list every 6 hours."""
    global _tor_list_loaded
    while True:
        time.sleep(6 * 3600)
        _tor_list_loaded = False
        _load_tor_exit_nodes()


def _is_tor_exit(ip: str) -> bool:
    if not _tor_list_loaded:
        _load_tor_exit_nodes()
    return ip in _tor_exit_nodes


# ══════════════════════════════════════════════════════════════════════════════
#  VPN / PROXY / DATACENTER PROVIDER IDENTIFICATION
# ══════════════════════════════════════════════════════════════════════════════

_VPN_SIGNATURES: dict = {
    "NordVPN":               ["nordvpn", "nord vpn", "tefincom"],
    "ExpressVPN":            ["expressvpn", "express vpn", "kape technologies"],
    "Mullvad":               ["mullvad", "amagicom"],
    "ProtonVPN":             ["protonvpn", "proton vpn", "proton ag"],
    "Surfshark":             ["surfshark"],
    "IPVanish":              ["ipvanish"],
    "PrivateInternetAccess": ["privateinternetaccess", "pia vpn", "london trust media"],
    "HideMyAss":             ["hidemyass", "hma vpn"],
    "CyberGhost":            ["cyberghost"],
    "Windscribe":            ["windscribe"],
    "TorGuard":              ["torguard"],
    "AirVPN":                ["airvpn"],
    "PureVPN":               ["purevpn", "gaditek"],
    "Hotspot Shield":        ["hotspot shield", "anchorage"],
    "hide.me":               ["hide.me vpn"],
    "Hola VPN":              ["hola networks"],
    "IVPN":                  ["ivpn"],
    "VyprVPN":               ["vyprvpn", "golden frog"],
    "Private VPN":           ["privatevpn", "privax"],
    "AWS":                   ["amazon", "aws", "amazon.com", "amazon technologies"],
    "DigitalOcean":          ["digitalocean"],
    "Linode/Akamai":         ["linode", "akamai"],
    "Vultr":                 ["vultr", "choopa"],
    "Hetzner":               ["hetzner"],
    "OVH":                   ["ovh", "ovhcloud", "ovh sas"],
    "Contabo":               ["contabo"],
    "Frantech/BuyVM":        ["frantech", "ponynet", "buyvm"],
    "M247":                  ["m247"],
    "Serverius":             ["serverius"],
    "Psychz":                ["psychz"],
    "HostWinds":             ["hostwinds"],
    "Google Cloud":          ["google cloud", "gcp", "google llc"],
    "Azure":                 ["microsoft azure", "azure"],
    "Cloudflare":            ["cloudflare"],
    "Leaseweb":              ["leaseweb"],
    "Zenlayer":              ["zenlayer"],
    "Sharktech":             ["sharktech"],
    "DataPacket":            ["datapacket"],
}

_PROXY_TYPE_LABELS: dict = {
    "corporate":   "Corporate Proxy",
    "residential": "Residential Proxy",
    "cellular":    "Mobile/Cellular",
    "hosting":     "Datacenter/Hosting",
    "anonymous":   "Anonymous Proxy",
    "satellite":   "Satellite",
    "education":   "Education Network",
}


def _identify_vpn_provider(org: str, asn_org: str = "", isp: str = "") -> str | None:
    combined = " ".join(filter(None, [org, asn_org, isp])).lower()
    if not combined.strip():
        return None
    for provider, keywords in _VPN_SIGNATURES.items():
        if any(kw in combined for kw in keywords):
            return provider
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  ENRICHED GEOIP
# ══════════════════════════════════════════════════════════════════════════════

def _geoip(ip: str) -> dict:
    g: dict = {
        "country":              "Unknown",
        "city":                 "",
        "latitude":             0.0,
        "longitude":            0.0,
        "asn":                  None,
        "asn_org":              None,
        "org":                  None,
        "isp":                  None,
        "is_vpn":               False,
        "is_tor":               False,
        "is_proxy":             False,
        "proxy":                False,
        "vpn_provider":         None,
        "vpn_exit_country":     None,
        "tor_exit_node":        False,
        "tor_exit_ip":          None,
        "proxy_type":           None,
        "anonymized":           False,
        "anonymization_method": None,
    }

    if not ip.startswith(("127.", "10.", "192.168.", "::1")):
        try:
            g.update(geo.lookup(ip) or {})
        except Exception:
            pass
        try:
            if hasattr(geo, "asn_lookup"):
                g.update(geo.asn_lookup(ip) or {})
        except Exception:
            pass
        try:
            if hasattr(geo, "privacy_lookup"):
                priv = geo.privacy_lookup(ip) or {}
                g.update(priv)
                g["is_vpn"]   = bool(priv.get("is_vpn"))
                g["is_tor"]   = bool(priv.get("is_tor") or priv.get("is_tor_exit_node"))
                g["is_proxy"] = bool(priv.get("is_proxy") or priv.get("is_anonymous_proxy"))
                raw_ptype     = priv.get("connection_type") or priv.get("user_type") or ""
                g["proxy_type"] = _PROXY_TYPE_LABELS.get(raw_ptype.lower(), raw_ptype or None)
        except Exception:
            pass

        # Use proxy/hosting flags returned directly from ip-api.com enrichment
        geo_proxy   = g.get("is_proxy", False)
        geo_hosting = g.get("is_hosting", False)

        if g["is_tor"] or _is_tor_exit(ip):
            g["is_tor"]        = True
            g["tor_exit_node"] = True
            g["tor_exit_ip"]   = ip

        # VPN provider matching against org/isp/asn strings (named providers)
        vpn_provider = _identify_vpn_provider(
            g.get("org", "") or "",
            g.get("asn_org", "") or "",
            g.get("isp", "") or "",
        )
        if vpn_provider:
            g["is_vpn"]       = True
            g["vpn_provider"] = vpn_provider

        # ip-api.com proxy=true means the IP is a VPN exit / proxy node
        # Use the org name as the provider so the dashboard shows who it is
        if geo_proxy and not g["is_tor"]:
            g["is_vpn"]       = True
            org_label = g.get("org") or g.get("asn_org") or g.get("isp") or "Unknown VPN"
            if not g["vpn_provider"]:
                g["vpn_provider"] = org_label
            g["vpn_exit_country"] = g.get("country")

        # hosting=true but proxy=false = pure datacenter server (not a VPN user)
        if geo_hosting and not geo_proxy and not g["is_vpn"]:
            g["is_proxy"]   = True
            g["proxy_type"] = "datacenter"

        g["vpn_exit_country"] = g.get("country") if g["is_vpn"] else None

    methods = []
    if g["is_tor"]:
        methods.append("Tor")
    if g["is_vpn"]:
        label = f"VPN ({g['vpn_provider']})" if g["vpn_provider"] else "VPN"
        methods.append(label)
    if g["is_proxy"]:
        pt = g.get("proxy_type")
        methods.append(f"Proxy ({pt})" if pt else "Proxy")

    g["anonymized"]           = bool(methods)
    g["anonymization_method"] = " + ".join(methods) if methods else None

    return g


def _intel_fields(g: dict) -> dict:
    g = g or {}
    return {
        "asn":                  g.get("asn") or g.get("asn_org") or g.get("org"),
        "org":                  g.get("org") or g.get("isp") or g.get("asn_org"),
        "is_vpn":               g.get("is_vpn", False),
        "is_tor":               g.get("is_tor", False),
        "is_proxy":             g.get("is_proxy", False) or g.get("proxy", False),
        "vpn_provider":         g.get("vpn_provider"),
        "vpn_exit_country":     g.get("vpn_exit_country"),
        "tor_exit_node":        g.get("tor_exit_node", False),
        "tor_exit_ip":          g.get("tor_exit_ip"),
        "proxy_type":           g.get("proxy_type"),
        "anonymized":           g.get("anonymized", False),
        "anonymization_method": g.get("anonymization_method"),
    }


# ─── New-IP alert ─────────────────────────────────────────────────────────────
def _new_ip_alert(ip: str, country: str, city: str, service: str):
    if ip not in _seen_ips:
        _seen_ips.add(ip)
        alerts.new_attacker(ip, country, city, service)

        gdata = _geoip(ip)
        if gdata.get("is_tor"):
            _inc("tor")
            try:
                alerts.tor_attacker(ip, country, service, gdata.get("tor_exit_ip"))
            except AttributeError:
                pass
        elif gdata.get("is_vpn"):
            _inc("vpn")
            try:
                alerts.vpn_attacker(
                    ip, country, service,
                    gdata.get("vpn_provider"),
                    gdata.get("vpn_exit_country"),
                )
            except AttributeError:
                pass
        elif gdata.get("is_proxy"):
            _inc("proxy")


# ══════════════════════════════════════════════════════════════════════════════
#  SCANNER / TOOL DETECTION
# ══════════════════════════════════════════════════════════════════════════════

_SCANNER_SIGNATURES = {
    "masscan":         ["masscan"],
    "nmap":            ["nmap", "nmapscript"],
    "zgrab":           ["zgrab"],
    "zgrab2":          ["zgrab2"],
    "shodan":          ["shodan"],
    "censys":          ["censys"],
    "nikto":           ["nikto"],
    "sqlmap":          ["sqlmap"],
    "wpscan":          ["wpscan"],
    "nuclei":          ["nuclei", "projectdiscovery"],
    "burpsuite":       ["burp", "burpsuite"],
    "metasploit":      ["metasploit", "msfconsole", "meterpreter"],
    "cobalt_strike":   ["cobalt strike", "cobaltstrike"],
    "hydra":           ["hydra", "thc-hydra"],
    "medusa":          ["medusa"],
    "ncrack":          ["ncrack"],
    "curl":            ["curl/"],
    "wget":            ["wget/"],
    "python_requests": ["python-requests", "python-urllib"],
    "go_http":         ["go-http-client"],
    "java_http":       ["java/", "jakarta"],
    "mirai_scanner":   ["hello world", "busybox", "bin/busybox"],
    "iot_reaper":      ["iot_reaper", "reaper"],
    "libssh":          ["libssh"],
    "paramiko":        ["paramiko"],
    "putty":           ["putty"],
    "dropbear":        ["dropbear"],
}

def _detect_scanner(text: str) -> str:
    t = text.lower()
    for tool, sigs in _SCANNER_SIGNATURES.items():
        if any(s.lower() in t for s in sigs):
            return tool
    return ""


# ══════════════════════════════════════════════════════════════════════════════
#  THREAT INTELLIGENCE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

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
    for a in ["arm7","arm6","arm5","arm","mips","mipsel","mpsl","x86","i686","ppc","m68k","sh4"]:
        if a in cmd_str.lower():
            return a
    return "unknown"

def _detect_botnet_family(cmd_str):
    families = {
        "Mirai":   ["busybox","ECCHI","/bin/busybox","cat /proc/cpuinfo","cat /proc/mounts"],
        "Gafgyt":  ["HTTPFLOOD","UDPFLOOD","tftp -g","PING","HOLD","JUNK"],
        "Sora":    ["SORA","/bin/busybox SORA"],
        "Mozi":    ["mozi","nttpd","dht"],
        "Muhstik": ["muhstik","JOIN #","irc"],
        "Okiru":   ["Okiru","bins/arm"],
    }
    s = cmd_str.lower()
    for fam, indicators in families.items():
        if any(ind.lower() in s for ind in indicators):
            return fam
    return "Unknown"


# ══════════════════════════════════════════════════════════════════════════════
#  TELNET (port 23)
# ══════════════════════════════════════════════════════════════════════════════

# Telnet IAC sequences for echo control
_IAC       = bytes([255])
_WILL      = bytes([251])
_WONT      = bytes([252])
_DO        = bytes([253])
_DONT      = bytes([254])
_ECHO      = bytes([1])
_SGA       = bytes([3])   # Suppress Go Ahead — needed for character mode

# Sent at connection: server will echo + suppress go-ahead (line mode → char mode)
_TELNET_INIT  = _IAC + _WILL + _ECHO + _IAC + _WILL + _SGA + _IAC + _DO + _SGA
# Before password prompt: server stops echoing so password is hidden
_ECHO_OFF     = _IAC + _WONT + _ECHO
# After password received: server resumes echoing
_ECHO_ON      = _IAC + _WILL + _ECHO

_TELNET_BANNERS = [
    # Hikvision IP cameras — consistent with device identity
    "\r\n\r\nHikvision DS-2CD2043G2-I\r\nFirmware: V5.7.15 build 230313\r\n\r\n(none) login: ",
    "\r\n\r\nWelcome to HiLinux.\r\n\r\n(none) login: ",
    "\r\n\r\nHikvision DS-2CD2085G1-I\r\nFirmware: V5.5.800 build 210628\r\n\r\n(none) login: ",
    # HiSilicon SoC — the chip inside Hikvision/Dahua/XMEye cameras
    "\r\n\r\nHi3518 family \r\nBusyBox v1.16.1\r\n\r\nlogin: ",
    "\r\n\r\nHi3520D family\r\nBusyBox v1.19.4 (2013-08-12 12:00:00 CST) built-in shell (ash)\r\n\r\nlogin: ",
    # BusyBox on embedded camera Linux — old versions targeted by Mirai
    "\r\n\r\nBusyBox v1.16.1 (2009-10-01 23:34:21 CST) built-in shell (ash)\r\n\r\nlogin: ",
    "\r\n\r\nBusyBox v1.19.4 (2013-08-12 12:00:00 CST) built-in shell (ash)\r\n\r\nlogin: ",
    "\r\n\r\nBusyBox v1.31.1 (2021-10-19 08:36:54 UTC) built-in shell (ash)\r\n\r\nlogin: ",
    # DVR/NVR units
    "\r\n\r\nDVR-4CH Login\r\nKernel: 3.10.14\r\n\r\nlogin: ",
    "\r\n\r\nDahua Technology DVR\r\nFirmware: 2.460.0000.14.R\r\n\r\nlogin: ",
    # XMEye/generic embedded Linux (millions of budget cameras)
    "\r\n\r\nlinux\r\nBusyBox v1.01 (2015.08.10-08:30+0000) Built-in shell (ash)\r\n\r\nlogin: ",
    "\r\n\r\nXMeye Security\r\nFirmware: V4.02.R11.00000117.10001.131900\r\n\r\nlogin: ",
]
_PROMPTS = ["# ", "/ # ", "root@dvr:~# ", "[root@camera ~]# ", "root@(none):/# "]

def handle_telnet(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata  = _geoip(ip)
    sid    = _sid()
    shell  = FakeShell(ip)
    prompt = _PROMPTS[hash(ip) % len(_PROMPTS)]
    _inc("sessions")

    all_commands   = []
    login_attempts = []
    authenticated  = False

    try:
        _random_delay(100, 400)
        # Send IAC negotiation then banner — puts client into char mode with server echo
        conn.sendall(_TELNET_INIT + random.choice(_TELNET_BANNERS).encode())

        def _sanitize_cred(s):
            """Strip IAC/control bytes, keep printable ASCII + tab."""
            return "".join(c for c in s if ord(c) >= 32 or c == "\t").strip()

        # Shared byte buffer — persists across _recv_line calls AND the shell loop.
        # Critical for bots that send "user\r\npassword\r\ncmd\r\n" all at once:
        # without this, recv reads everything but _recv_line only consumes up to
        # the first \r\n, silently dropping the rest.
        _sock_buf = bytearray()

        def _recv_line(timeout=25, server_echo=True):
            """Buffer chars until newline — handles char-mode telnet (each keystroke = separate recv).
            Bots sending full lines work too since \\r/\\n flushes immediately.
            Returns (line_str, ok) where ok=False means the connection closed."""
            buf = ""
            while True:
                if _sock_buf:
                    chunk = bytes(_sock_buf)
                    _sock_buf.clear()
                else:
                    try:
                        conn.settimeout(timeout)
                        chunk = conn.recv(64)
                    except socket.timeout:
                        return buf, bool(buf)
                if not chunk:
                    return buf, False   # connection closed
                i = 0
                while i < len(chunk):
                    b = chunk[i]
                    if b >= 240:           # IAC — skip this byte + next 2 option bytes
                        i += 3
                        continue
                    if b == 13:            # CR — consume trailing LF/NUL if present
                        if i + 1 < len(chunk) and chunk[i + 1] in (0, 10):
                            i += 1
                        _sock_buf.extend(chunk[i + 1:])  # save remaining bytes
                        conn.sendall(b"\r\n")
                        return buf, True
                    if b == 10:            # bare LF
                        _sock_buf.extend(chunk[i + 1:])  # save remaining bytes
                        conn.sendall(b"\r\n")
                        return buf, True
                    elif b in (127, 8):    # backspace / DEL
                        if buf:
                            buf = buf[:-1]
                            if server_echo:
                                conn.sendall(b"\x08 \x08")
                    elif b >= 32:          # printable char
                        buf += chr(b)
                        if server_echo:
                            conn.sendall(bytes([b]))
                    i += 1

        # Valid credentials: known botnet defaults (BOTNET_CREDS) + explicit honeypot login
        _VALID_CREDS = {("admin", "1234567890")}

        for attempt in range(3):
            _random_delay(80, 200)

            # Show login prompt on retries (banner already ends with "login: " on first attempt)
            if attempt > 0:
                conn.sendall(b"\r\nlogin: ")

            uraw, u_ok = _recv_line(timeout=25, server_echo=True)
            username   = _sanitize_cred(uraw)
            if not u_ok and not username:
                break   # connection closed before any printable input

            # Ask for password — do NOT send IAC WONT ECHO (that would make the
            # client re-enable its own local echo). We already negotiated
            # IAC WILL ECHO at init, so just silently stop echoing server-side.
            conn.sendall(b"Password: ")
            praw, _    = _recv_line(timeout=25, server_echo=False)
            password   = _sanitize_cred(praw)

            is_bot         = _check_botnet(username, password)
            is_ht_c, ht_cv = _check_honeytoken_cred(username, password)
            is_valid       = is_bot or is_ht_c or (username, password) in _VALID_CREDS

            login_attempts.append({"username": username, "password": password,
                                    "is_botnet": is_bot, "attempt": attempt + 1})
            _inc("logins")
            _track_cred_attempt(ip, "telnet")

            threat = "critical" if is_ht_c else ("high" if is_bot else "medium")
            db.log_attack({
                "timestamp":   _ts(), "source_ip": ip, "source_port": port,
                "dest_port":   23,    "service": "telnet", "protocol": "TCP",
                "username":    username, "password": password,
                "country":     gdata["country"], "city": gdata["city"],
                "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
                "attack_type": "brute_force", "threat_level": threat,
                "is_botnet":   is_bot, "session_id": sid,
                **_intel_fields(gdata),
            })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "telnet")

            if is_bot:
                _inc("botnets")
                alerts.botnet_cred(ip, gdata["country"], "telnet", username, password)
            if is_ht_c:
                _inc("honeytokens")
                alerts.honeytoken(ip, gdata["country"], "CREDENTIAL", ht_cv, "telnet")
                db.log_honeytoken(_ts(), ip, "CREDENTIAL", ht_cv, "telnet",
                                  gdata["country"], gdata["city"])

            if is_valid:
                authenticated = True
                time.sleep(0.8)
                conn.sendall(b"\r\nLogin successful\r\n")
                conn.sendall(prompt.encode())
                break
            else:
                conn.sendall(b"\r\nLogin incorrect\r\n")
                if attempt == 2:
                    conn.sendall(b"Maximum authentication attempts exceeded.\r\n")

        if not authenticated:
            return

        # Shell loop — accumulate chars into a line buffer so that character-mode
        # telnet clients (each keystroke is a separate recv) work correctly.
        # Bots send whole commands at once and also work because \n flushes the buffer.
        _cmd_buf  = ""
        _cmd_done = False

        # Login-response strings that bleed into the shell buffer when bots pipeline
        # credentials and the first attempt fails ("Login incorrect" → "ncorrect").
        _GARBAGE_CMDS = frozenset([
            "ncorrect", "incorrect", "login incorrect", "wrong password",
            "authentication failed", "access denied",
        ])

        def _run_cmd(cmd):
            """Process one complete shell command. Returns False to end session."""
            if cmd.lower() in ("exit", "quit", "logout"):
                return False
            if not cmd:
                conn.sendall(prompt.encode())
                return True
            # Drop garbage artifacts from pipelined login-failure responses
            if cmd.lower().strip() in _GARBAGE_CMDS:
                conn.sendall(prompt.encode())
                return True

            all_commands.append(cmd)
            _inc("commands")

            ht_f, ht_fv = _check_honeytoken_file(cmd)
            if ht_f:
                _inc("honeytokens")
                alerts.honeytoken(ip, gdata["country"], "FILE_ACCESS", ht_fv, "telnet")
                db.log_honeytoken(_ts(), ip, "FILE_ACCESS", ht_fv, "telnet",
                                  gdata["country"], gdata["city"], all_commands[-5:])

            mal_url = _detect_malware_url(cmd)
            if mal_url:
                _inc("malware")
                arch   = _detect_arch(cmd)
                family = _detect_botnet_family(" ".join(all_commands))
                alerts.malware_download(ip, gdata["country"], mal_url, family, arch)
                db.log_malware(_ts(), ip, mal_url, cmd, family, arch, gdata["country"])

            cve_id, cve = _check_cve(cmd, "telnet")
            if cve_id:
                _inc("cves")
                alerts.cve_exploit(ip, gdata["country"], cve_id, cve["name"],
                                   cve["severity"], "telnet", cmd[:80])
                db.log_cve(_ts(), ip, cve_id, cve["name"], cve["severity"],
                           "telnet", cmd, gdata["country"])

            # ECCHI — definitive Mirai botnet confirmation marker
            if "ECCHI" in cmd.upper():
                _inc("botnets")
                alerts.mirai_confirmed(ip, gdata["country"], "telnet", cmd)
                db.log_attack({
                    "timestamp":    _ts(), "source_ip": ip, "source_port": port,
                    "dest_port":    23,    "service": "telnet", "protocol": "TCP",
                    "attack_type":  "mirai_ecchi_confirmed", "threat_level": "critical",
                    "payload":      cmd,   "country": gdata["country"],
                    "city":         gdata["city"], "latitude": gdata["latitude"],
                    "longitude":    gdata["longitude"], "session_id": sid,
                    **_intel_fields(gdata),
                })

            out = shell.execute(cmd)
            time.sleep(0.1)
            if out:
                conn.sendall(out.encode())
            conn.sendall(prompt.encode())
            return True

        _last_activity = time.time()
        for _ in range(2000):
            # Simulate embedded device command latency (50-200 ms per cycle)
            _random_delay(50, 200)
            # Idle timeout — real cameras drop telnet after ~5 min with no input
            if time.time() - _last_activity > 300:
                break
            if _sock_buf:
                raw = bytes(_sock_buf)
                _sock_buf.clear()
            else:
                try:
                    conn.settimeout(120)
                    raw = conn.recv(256)
                except socket.timeout:
                    break
            _last_activity = time.time()
            if not raw:
                break

            for b in raw:
                if b >= 240:
                    # IAC byte — skip the option negotiation byte
                    continue
                if b in (10, 13):
                    # Newline / CR — flush buffer as a command
                    conn.sendall(b"\r\n")
                    cmd = "".join(
                        c for c in _cmd_buf if ord(c) >= 32 or c == "\t"
                    ).strip()
                    _cmd_buf = ""
                    if not _run_cmd(cmd):
                        _cmd_done = True
                        break
                elif b in (127, 8):
                    # DEL / Backspace — erase last char
                    if _cmd_buf:
                        _cmd_buf = _cmd_buf[:-1]
                        conn.sendall(b"\x08 \x08")
                elif b >= 32:
                    # Printable char — echo it and add to buffer
                    _cmd_buf += chr(b)
                    conn.sendall(bytes([b]))

            if _cmd_done:
                break

    except Exception:
        pass
    finally:
        # Only log session_complete when the attacker actually ran commands —
        # pure credential-spray connections already have a brute_force entry,
        # no need for a second blank row in the dashboard.
        if all_commands:
            last = login_attempts[-1] if login_attempts else {}
            db.log_attack({
                "timestamp":    _ts(), "source_ip": ip, "source_port": port,
                "dest_port":    23, "service": "telnet", "protocol": "TCP",
                "username":     last.get("username", ""),
                "password":     last.get("password", ""),
                "country":      gdata["country"], "city": gdata["city"],
                "latitude":     gdata["latitude"], "longitude": gdata["longitude"],
                "attack_type":  "session_complete",
                "threat_level": "critical",
                "session_id":   sid, "commands": all_commands,
                "is_botnet":    any(la["is_botnet"] for la in login_attempts),
                **_intel_fields(gdata),
            })

            # Kill-chain alert — fire when attacker ran real commands including downloads
            mal_urls = [u for u in (_detect_malware_url(c) for c in all_commands) if u]
            family   = _detect_botnet_family(" ".join(all_commands))
            arch     = next((_detect_arch(c) for c in all_commands
                             if _detect_arch(c) != "unknown"), "unknown")
            if len(all_commands) >= 2 and (mal_urls or family != "Unknown"):
                la = login_attempts[-1] if login_attempts else {}
                steps = [f"telnet_login({la.get('username','?')}/{la.get('password','?')})"]
                steps += [c[:60] for c in all_commands[:5]]
                alerts.kill_chain(ip, gdata["country"], "telnet",
                                  steps, family, arch, mal_urls)

        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  SSH (port 2222)
# ══════════════════════════════════════════════════════════════════════════════

def ssh_log_attack(ip, port, event_type, details):
    try:
        gdata = _geoip(ip)
        log_entry = {
            "timestamp":   _ts(), "source_ip": ip,
            "dest_port":   port,  "service": "ssh", "protocol": "TCP",
            "attack_type": event_type,
            "threat_level": "medium",
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
            **_intel_fields(gdata),
        }
        if isinstance(details, str):
            try: details = json.loads(details)
            except Exception: details = {"raw": details}
        if isinstance(details, dict):
            log_entry.update(details)
        # SSH logs "command" (singular) per event — map it to payload+commands columns
        if log_entry.get("command") and not log_entry.get("payload"):
            log_entry["payload"]  = log_entry["command"]
        if log_entry.get("command") and not log_entry.get("commands"):
            log_entry["commands"] = [log_entry["command"]]
        # Classify threat level from event type
        if event_type in ("SSH_MALWARE", "SSH_HONEYTOKEN"):
            log_entry["threat_level"] = "critical"
        elif event_type in ("SSH_AUTH_SUCCESS", "SSH_COMMAND"):
            log_entry["threat_level"] = "high"
        elif event_type in ("SSH_AUTH_ATTEMPT", "SSH_BANNER_EXCHANGE"):
            log_entry["threat_level"] = "medium"
        elif event_type in ("SSH_CONNECT", "SSH_SESSION_END"):
            log_entry["threat_level"] = "low"
        db.log_attack(log_entry)
    except Exception as e:
        print(f"[!] SSH log error: {e}")

def handle_ssh(conn, addr):
    try:
        _random_delay(80, 200)
        _inc("sessions")
        ssh_service.handle_ssh(
            conn, addr,
            log_attack=ssh_log_attack,
            geoip_func=_geoip,
            intel_fields_func=_intel_fields,
            new_ip_alert=_new_ip_alert,
            track_cred_attempt=_track_cred_attempt,
            log_malware=db.log_malware,
            log_honeytoken=db.log_honeytoken,
        )
    except Exception as e:
        print(f"[!] SSH handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  HIKVISION SDK (port 8200)
# ══════════════════════════════════════════════════════════════════════════════

def handle_hik_sdk(conn, addr):
    try:
        _random_delay(80, 200)
        _inc("sessions")
        hik_sdk_service.handle_hik_sdk(
            conn, addr,
            log_attack            = db.log_attack,
            geoip_func            = _geoip,
            intel_fields_func     = _intel_fields,
            new_ip_alert          = _new_ip_alert,
            check_botnet          = _check_botnet,
            check_honeytoken_cred = _check_honeytoken_cred,
            check_cve             = _check_cve,
            inc_counter           = _inc,
            alert_funcs           = {
                "cve_exploit": alerts.cve_exploit,
                "botnet_cred": alerts.botnet_cred,
                "honeytoken":  alerts.honeytoken,
            },
        )
    except Exception as e:
        print(f"[!] Hik-SDK handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  FTP (port 21)
# ══════════════════════════════════════════════════════════════════════════════

def ftp_log_attack(ip, port, event_type, details):
    try:
        details_dict = json.loads(details) if isinstance(details, str) else details
        gdata = _geoip(ip)
        log_entry = {
            "timestamp":    _ts(), "source_ip": ip, "dest_port": port,
            "service":      "ftp", "protocol": "TCP",
            "attack_type":  event_type,
            "threat_level": details_dict.get("threat_level", "medium"),
            "country":      gdata["country"], "city": gdata["city"],
            "latitude":     gdata["latitude"], "longitude": gdata["longitude"],
            **_intel_fields(gdata),
        }
        log_entry.update(details_dict)
        db.log_attack(log_entry)
    except Exception as e:
        print(f"[!] FTP log error: {e}")

def handle_ftp(conn, addr):
    try:
        _random_delay(80, 200)
        _inc("sessions")
        ftp_service.handle_ftp(
            conn, addr,
            log_attack=ftp_log_attack,
            geoip_func=_geoip,
            intel_fields_func=lambda ip: _intel_fields(_geoip(ip)),
            new_ip_alert=_new_ip_alert,
            check_honeytoken_file=_check_honeytoken_file,
            check_botnet=_check_botnet,
            check_honeytoken_cred=_check_honeytoken_cred,
            track_cred_attempt=_track_cred_attempt,
            log_honeytoken=db.log_honeytoken,
        )
    except Exception as e:
        print(f"[!] FTP handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP / HTTPS (ports 80, 443, 8080)  ← delegated to http_service.py
# ══════════════════════════════════════════════════════════════════════════════

# Bundle all injected helpers once so the lambda stays clean
_HTTP_KWARGS = dict(
    ts_func                    = _ts,
    geoip_func                 = _geoip,
    intel_fields_func          = _intel_fields,
    new_ip_alert_func          = _new_ip_alert,
    log_attack_func            = db.log_attack,
    check_cve_func             = _check_cve,
    check_honeytoken_file_func = _check_honeytoken_file,
    check_botnet_func          = _check_botnet,
    check_honeytoken_cred_func = _check_honeytoken_cred,
    log_cve_func               = db.log_cve,
    log_honeytoken_func        = db.log_honeytoken,
    log_malware_func           = db.log_malware,
    inc_counter_func           = _inc,
    alert_funcs                = {
        "cve_exploit": alerts.cve_exploit,
        "honeytoken":  alerts.honeytoken,
        "botnet_cred": alerts.botnet_cred,
    },
    is_rate_limited_func       = _is_rate_limited,
)

def handle_http(conn, addr, https=False):
    try:
        _random_delay(40, 120)
        http_service.handle_http(conn, addr, https, **_HTTP_KWARGS)
    except Exception as e:
        print(f"[!] HTTP handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  RTSP (port 554)
# ══════════════════════════════════════════════════════════════════════════════

def rtsp_log_attack(entry_or_ip, port=None, event_type=None, details=None):
    try:
        if isinstance(entry_or_ip, dict):
            db.log_attack(entry_or_ip)
            return
        # legacy positional call (kept for safety)
        ip = entry_or_ip
        details_dict = json.loads(details) if isinstance(details, str) else (details or {})
        gdata = _geoip(ip)
        log_entry = {
            "timestamp":    _ts(), "source_ip": ip,
            "source_port":  details_dict.get("source_port", 0),
            "dest_port":    port, "service": "rtsp", "protocol": "TCP",
            "attack_type":  event_type,
            "threat_level": details_dict.get("threat_level", "medium"),
            "country":      gdata["country"], "city": gdata["city"],
            "latitude":     gdata["latitude"], "longitude": gdata["longitude"],
            **_intel_fields(gdata),
        }
        log_entry.update(details_dict)
        db.log_attack(log_entry)
    except Exception as e:
        print(f"[!] RTSP log error: {e}")

def rtsp_intel_fields(ip_or_gdata):
    try:
        gdata = ip_or_gdata if isinstance(ip_or_gdata, dict) else _geoip(ip_or_gdata)
        return _intel_fields(gdata)
    except Exception:
        return {"asn":None,"org":None,"is_vpn":False,"is_tor":False,"is_proxy":False,
                "vpn_provider":None,"anonymized":False,"anonymization_method":None}

def handle_rtsp(conn, addr):
    try:
        _random_delay(80, 200)
        _inc("sessions")
        rtsp_service.handle_rtsp(
            conn, addr,
            log_attack=rtsp_log_attack,
            geoip_func=_geoip,
            intel_fields_func=rtsp_intel_fields,
            new_ip_alert=_new_ip_alert,
        )
    except Exception as e:
        print(f"[!] RTSP handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  ONVIF (port 8000)
# ══════════════════════════════════════════════════════════════════════════════

def onvif_log_attack(entry_or_ip, port=None, event_type=None, details=None):
    try:
        if isinstance(entry_or_ip, dict):
            db.log_attack(entry_or_ip)
            return
        # legacy positional call
        ip = entry_or_ip
        details_dict = json.loads(details) if isinstance(details, str) else (details or {})
        gdata = _geoip(ip)
        log_entry = {
            "timestamp":    _ts(), "source_ip": ip, "dest_port": port,
            "service":      "onvif", "protocol": "TCP",
            "attack_type":  event_type,
            "threat_level": details_dict.get("threat_level", "medium"),
            "country":      gdata["country"], "city": gdata["city"],
            "latitude":     gdata["latitude"], "longitude": gdata["longitude"],
            **_intel_fields(gdata),
        }
        log_entry.update(details_dict)
        db.log_attack(log_entry)
    except Exception as e:
        print(f"[!] ONVIF log error: {e}")

def handle_onvif(conn, addr):
    try:
        _random_delay(80, 200)
        _inc("sessions")
        onvif_service.handle_onvif(
            conn, addr,
            log_attack=onvif_log_attack,
            geoip_func=_geoip,
            intel_fields_func=_intel_fields,
            new_ip_alert=_new_ip_alert,
        )
    except Exception as e:
        print(f"[!] ONVIF handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  MQTT (port 1883)
# ══════════════════════════════════════════════════════════════════════════════

def handle_mqtt(conn, addr):
    threading.Thread(
        target=mqtt_service.handle_mqtt,
        args=(conn, addr),
        kwargs=dict(
            log_attack        = db.log_attack,
            server_port       = 1883,
            geoip_func        = _geoip,
            intel_fields_func = _intel_fields,
            new_ip_alert      = _new_ip_alert,
        ),
        daemon=True,
    ).start()


# ══════════════════════════════════════════════════════════════════════════════
#  VNC (port 5900)
# ══════════════════════════════════════════════════════════════════════════════

def vnc_log_attack(entry_or_ip, port=None, event_type=None, details=None):
    try:
        if isinstance(entry_or_ip, dict):
            db.log_attack(entry_or_ip)
            return
        # legacy positional call (kept for safety)
        ip = entry_or_ip
        gdata = _geoip(ip)
        log_entry = {
            "timestamp":   _ts(), "source_ip": ip, "dest_port": port,
            "service":     "vnc", "protocol": "TCP",
            "attack_type": event_type,
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
            **_intel_fields(gdata),
        }
        if isinstance(details, dict):
            log_entry.update(details)
        db.log_attack(log_entry)
    except Exception as e:
        print(f"[!] VNC log error: {e}")

def handle_vnc(conn, addr):
    try:
        _random_delay(80, 200)
        _inc("sessions")
        vnc_service.handle_vnc(
            conn, addr,
            log_attack=vnc_log_attack,
            geoip_func=_geoip,
            intel_fields_func=_intel_fields,
            new_ip_alert=_new_ip_alert,
        )
    except Exception as e:
        print(f"[!] VNC handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  Modbus / ICS (port 502)
# ══════════════════════════════════════════════════════════════════════════════

_MODBUS_FC = {
    0x01: ("read_coils",             "medium"),
    0x02: ("read_discrete_inputs",   "medium"),
    0x03: ("read_holding_registers", "medium"),
    0x04: ("read_input_registers",   "medium"),
    0x05: ("write_single_coil",      "high"),
    0x06: ("write_single_register",  "high"),
    0x0F: ("write_multiple_coils",   "critical"),
    0x10: ("write_multiple_registers","critical"),
    0x11: ("report_server_id",       "medium"),
    0x2B: ("read_device_id",         "medium"),
}

def _modbus_response(tid: bytes, fc: int, req_data: bytes) -> bytes:
    """Build a realistic Modbus TCP response for common function codes."""
    unit = req_data[6:7] if len(req_data) > 6 else b"\x01"
    if fc == 0x01:   # Read Coils — return 2 bytes of coil status
        body = bytes([fc, 2, 0xAA, 0x55])
    elif fc == 0x02: # Read Discrete Inputs
        body = bytes([fc, 2, 0b10101010, 0b01010101])
    elif fc == 0x03: # Read Holding Registers — 4 regs of camera-ish values
        regs = [0x0001, 0x270F, 0x03E8, 0x0064]  # mode, temp*10, pressure, pct
        payload = b"".join(r.to_bytes(2, "big") for r in regs)
        body = bytes([fc, len(payload)]) + payload
    elif fc == 0x04: # Read Input Registers
        regs = [0x0064, 0x0001, 0x01F4]
        payload = b"".join(r.to_bytes(2, "big") for r in regs)
        body = bytes([fc, len(payload)]) + payload
    elif fc in (0x05, 0x06, 0x0F, 0x10):  # Write — echo back address+value
        body = bytes([fc]) + (req_data[8:12] if len(req_data) >= 12 else b"\x00\x00\x00\x00")
    elif fc == 0x11: # Report Server ID
        server_id = b"Hikvision DS-2CD2043G2-I\xFF"
        body = bytes([fc, len(server_id)]) + server_id
    elif fc == 0x2B: # Read Device ID
        obj = b"\x00\x0eHikvision"
        body = bytes([fc, 0x0E, 0x01, 0x83, 0x00, 0x00, 0x01, len(obj)]) + obj
    else:           # Unknown — return exception
        body = bytes([fc | 0x80, 0x01])
    mbap = tid + b"\x00\x00" + len(body + unit).to_bytes(2, "big") + unit
    return mbap + body

def handle_modbus(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    fc_seen = set()
    try:
        conn.settimeout(10)
        for _ in range(20):
            try: data = conn.recv(512)
            except socket.timeout: break
            if not data or len(data) < 8: break

            tid = data[0:2]
            fc  = data[7] if len(data) > 7 else 0
            fc_seen.add(fc)

            op_name, threat = _MODBUS_FC.get(fc, ("ics_unknown_fc", "critical"))
            if len(fc_seen) > 5:
                op_name, threat = "ics_function_scan", "critical"

            db.log_attack({
                "timestamp":     _ts(), "source_ip": ip, "dest_port": 502,
                "service":       "modbus", "protocol": "TCP",
                "payload":       data[:100].hex(),
                "function_code": fc,
                "attack_type":   op_name, "threat_level": threat,
                "country":       gdata["country"], "city": gdata["city"],
                "latitude":      gdata["latitude"], "longitude": gdata["longitude"],
                **_intel_fields(gdata),
            })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "modbus")

            conn.sendall(_modbus_response(tid, fc, data))

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  CoAP (port 5683 UDP)
# ══════════════════════════════════════════════════════════════════════════════

def handle_coap(srv_sock, addr, data=b""):
    ip, _ = addr
    if _is_rate_limited(ip):
        return
    _inc("sessions")
    try:
        coap_service.handle_coap(
            srv_sock, addr,
            data=data,
            log_attack            = db.log_attack,
            geoip_func            = _geoip,
            intel_fields_func     = _intel_fields,
            new_ip_alert          = _new_ip_alert,
            check_honeytoken_file = _check_honeytoken_file,
            inc_counter           = _inc,
        )
    except Exception as e:
        print(f"[!] CoAP handler error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  TFTP (port 69 UDP)
# ══════════════════════════════════════════════════════════════════════════════

def handle_tftp(srv_sock, addr, data=b""):
    ip, _ = addr
    if _is_rate_limited(ip):
        return
    _inc("sessions")
    try:
        tftp_service.handle_tftp(
            srv_sock, addr,
            data=data,
            log_attack            = db.log_attack,
            geoip_func            = _geoip,
            intel_fields_func     = _intel_fields,
            new_ip_alert          = _new_ip_alert,
            check_honeytoken_file = _check_honeytoken_file,
            inc_counter           = _inc,
            log_honeytoken        = db.log_honeytoken,
        )
    except Exception as e:
        print(f"[!] TFTP handler error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  SSDP/UPnP (port 1900 UDP)
# ══════════════════════════════════════════════════════════════════════════════

def handle_ssdp(srv_sock, addr, data=b""):
    ip, _ = addr
    if _is_rate_limited(ip):
        return
    _inc("sessions")
    try:
        ssdp_service.handle_ssdp(
            srv_sock, addr,
            data          = data,
            log_attack    = db.log_attack,
            geoip_func    = _geoip,
            intel_fields_func = _intel_fields,
            new_ip_alert  = _new_ip_alert,
            check_cve     = _check_cve,
            inc_counter   = _inc,
            alert_funcs   = {
                "cve_exploit": alerts.cve_exploit,
            },
            local_ip      = config.DEVICE_IP or "192.168.1.108",
        )
    except Exception as e:
        print(f"[!] SSDP handler error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  SERVICE LAUNCHERS
# ══════════════════════════════════════════════════════════════════════════════

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
                    threading.Thread(target=handler, args=(cli, addr), daemon=True).start()
                except Exception as e:
                    print(f"  [!] {name} accept: {e}")
        except OSError as e:
            print(f"  [✗] {name:<22} :{port} — {e}")
    threading.Thread(target=_inner, daemon=True, name=name).start()


def _start_udp(handler, port, name):
    def _inner():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # SO_REUSEPORT lets us share the port with other processes (e.g. Spotify on 1900)
            if hasattr(socket, "SO_REUSEPORT"):
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            srv.bind((config.HONEYPOT_HOST, port))
            print(f"  [+] {name:<22} :{port} (UDP)")
            while True:
                try:
                    data, addr = srv.recvfrom(4096)
                    threading.Thread(
                        target=handler,
                        args=(srv, addr, data),
                        daemon=True,
                    ).start()
                except Exception as e:
                    print(f"  [!] {name} recvfrom: {e}")
        except OSError as e:
            print(f"  [✗] {name:<22} :{port} (UDP) — {e}")
    threading.Thread(target=_inner, daemon=True, name=name).start()


# ══════════════════════════════════════════════════════════════════════════════
#  NEW IoT SERVICE HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

def handle_dahua(conn, addr):
    try:
        dahua_service.handle_dahua(
            conn, addr,
            log_attack=db.log_attack,
            geoip_func=_geoip,
            intel_fields_func=_intel_fields,
            new_ip_alert=_new_ip_alert,
            inc_counter=_inc,
            log_honeytoken=db.log_honeytoken,
        )
    except Exception as e:
        print(f"[!] Dahua handler error: {e}")
        try: conn.close()
        except: pass


def handle_xmeye(conn, addr):
    try:
        xmeye_service.handle_xmeye(
            conn, addr,
            log_attack=db.log_attack,
            geoip_func=_geoip,
            intel_fields_func=_intel_fields,
            new_ip_alert=_new_ip_alert,
            inc_counter=_inc,
            log_honeytoken=db.log_honeytoken,
        )
    except Exception as e:
        print(f"[!] XMEye handler error: {e}")
        try: conn.close()
        except: pass


def handle_tr069(conn, addr):
    try:
        tr069_service.handle_tr069(
            conn, addr,
            log_attack=db.log_attack,
            geoip_func=_geoip,
            intel_fields_func=_intel_fields,
            new_ip_alert=_new_ip_alert,
            inc_counter=_inc,
        )
    except Exception as e:
        print(f"[!] TR-069 handler error: {e}")
        try: conn.close()
        except: pass


def handle_adb(conn, addr):
    try:
        adb_service.handle_adb(
            conn, addr,
            log_attack=db.log_attack,
            geoip_func=_geoip,
            intel_fields_func=_intel_fields,
            new_ip_alert=_new_ip_alert,
            inc_counter=_inc,
            log_honeytoken=db.log_honeytoken,
        )
    except Exception as e:
        print(f"[!] ADB handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  REDIS (port 6379)
# ══════════════════════════════════════════════════════════════════════════════

def handle_redis(conn, addr):
    try:
        _inc("sessions")
        redis_service.handle_redis(
            conn, addr,
            log_attack=db.log_attack,
            inc_counter=_inc,
        )
    except Exception as e:
        print(f"[!] Redis handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  DOCKER API (port 2375)
# ══════════════════════════════════════════════════════════════════════════════

def handle_docker(conn, addr):
    try:
        _inc("sessions")
        docker_service.handle_docker(
            conn, addr,
            log_attack=db.log_attack,
            inc_counter=_inc,
        )
    except Exception as e:
        print(f"[!] Docker handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  SERVICES MAP
# ══════════════════════════════════════════════════════════════════════════════

_SERVICES = [
    (handle_telnet,                     config.SERVICE_PORTS["telnet"],      "Telnet",        "tcp"),
    (handle_telnet,                     config.SERVICE_PORTS["telnet_alt"],  "Telnet-2323",   "tcp"),
    (handle_ssh,                        config.SERVICE_PORTS["ssh"],         "SSH",           "tcp"),
    (handle_ftp,                        config.SERVICE_PORTS["ftp"],       "FTP",           "tcp"),
    (handle_http,                       config.SERVICE_PORTS["http"],      "HTTP",          "tcp"),
    (lambda c,a: handle_http(c,a,True), config.SERVICE_PORTS["https"],     "HTTPS",         "tcp"),
    (handle_http,                       config.SERVICE_PORTS["http_alt"],  "HTTP-Alt",      "tcp"),
    (handle_rtsp,                       config.SERVICE_PORTS["rtsp"],      "RTSP",          "tcp"),
    (handle_onvif,                      config.SERVICE_PORTS["onvif"],     "ONVIF",         "tcp"),
    (handle_mqtt,                       config.SERVICE_PORTS["mqtt"],      "MQTT",          "tcp"),
    (handle_vnc,                        config.SERVICE_PORTS["vnc"],       "VNC",           "tcp"),
    (handle_modbus,                     config.SERVICE_PORTS["modbus"],    "Modbus/ICS",    "tcp"),
    (handle_coap,                       config.SERVICE_PORTS["coap"],      "CoAP",          "udp"),
    (handle_hik_sdk,                    config.SERVICE_PORTS["hik_sdk"],   "Hikvision-SDK", "tcp"),
    (handle_dahua,                      config.SERVICE_PORTS["dahua"],     "Dahua-DVR",     "tcp"),
    (handle_xmeye,                      config.SERVICE_PORTS["xmeye"],     "XMEye-DVR",     "tcp"),
    (handle_tr069,                      config.SERVICE_PORTS["tr069"],     "TR-069/CWMP",   "tcp"),
    (handle_adb,                        config.SERVICE_PORTS["adb"],       "Android-ADB",   "tcp"),
    (handle_tftp,                       config.SERVICE_PORTS["tftp"],      "TFTP",          "udp"),
    (handle_ssdp,                       config.SERVICE_PORTS["ssdp"],      "SSDP/UPnP",     "udp"),
    (handle_redis,                      config.SERVICE_PORTS["redis"],     "Redis",         "tcp"),
    (handle_docker,                     config.SERVICE_PORTS["docker"],    "Docker-API",    "tcp"),
    (handle_http,                       config.SERVICE_PORTS["dvr_web"],   "XiongMai-DVR",  "tcp"),
    (handle_http,                       config.SERVICE_PORTS["nvr_web"],   "NVR-Web",       "tcp"),
]


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

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

    print("\n[*] Loading threat intelligence feeds:")
    _load_tor_exit_nodes()
    threading.Thread(target=_tor_refresh_worker, daemon=True, name="TorExitRefresh").start()

    print("\n[*] Starting services:")
    active = 0
    for handler, port, name, proto in _SERVICES:
        if port:
            if proto == "udp":
                _start_udp(handler, port, name)
            else:
                _start_tcp(handler, port, name)
            active += 1
            time.sleep(0.05)

    print(f"\n[✓] {active} services active | DB: {config.DB_PATH}")
    print(f"[✓] Dashboard: python3 dashboard.py\n")

    # Start SSDP multicast NOTIFY sender — advertises device on the LAN
    ssdp_location = f"http://{config.DEVICE_IP or '192.168.1.108'}:80/upnp/basicDevice.xml"
    ssdp_service.start_notify_sender(ssdp_location)

    if config.TELEGRAM_ENABLED:
        alerts.startup(active, f"{config.DEVICE_VENDOR} {config.DEVICE_MODEL}", config.DEVICE_FIRMWARE)
    else:
        print("[!] Telegram disabled — set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID env vars")

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print(
            f"\n[!] Stopped"
            f" | Sessions: {COUNTERS['sessions']}"
            f" | Unique IPs: {len(_seen_ips)}"
            f" | Tor: {COUNTERS['tor']}"
            f" | VPN: {COUNTERS['vpn']}"
            f" | Proxy: {COUNTERS['proxy']}"
        )
        if config.TELEGRAM_ENABLED:
            alerts.shutdown(COUNTERS["sessions"], len(_seen_ips))


if __name__ == "__main__":
    main()