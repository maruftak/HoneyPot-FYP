#!/usr/bin/env python3
"""
honeyPot — Core Engine
Emulates a Hikvision IP camera. 17 services. Real logging. Telegram alerts.

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

# ─── State ────────────────────────────────────────────────────────────────────
_seen_ips   = set()
_rate_track = defaultdict(list)   # ip -> [timestamps]
_banned     = {}                   # ip -> unban epoch
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
    "tor":         0,   # NEW: connections from Tor exit nodes
    "vpn":         0,   # NEW: connections from known VPN providers
    "proxy":       0,   # NEW: connections from proxy/datacenter IPs
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


# ══════════════════════════════════════════════════════════════════════════════
#  TOR EXIT NODE DETECTION
#  Live list fetched from torproject.org, refreshed every 6 hours.
#  Used by _geoip() so every single service gets Tor detection automatically.
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
#  Matches ASN org/ISP strings against known provider keywords.
#  Returns a human-readable provider name or None.
# ══════════════════════════════════════════════════════════════════════════════

# Each key is the display name; value is a list of lowercase substrings
# to match against the combined org + asn_org + isp string.
_VPN_SIGNATURES: dict = {
    # ── Commercial VPN providers ─────────────────────────────────────────────
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
    # ── Datacenter / hosting providers (common attacker infrastructure) ───────
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

# MaxMind connection_type / user_type → human label
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
    """Return the best-match VPN/datacenter provider name, or None."""
    combined = " ".join(filter(None, [org, asn_org, isp])).lower()
    if not combined.strip():
        return None
    for provider, keywords in _VPN_SIGNATURES.items():
        if any(kw in combined for kw in keywords):
            return provider
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  ENRICHED GEOIP  ← single entry point for ALL 17 services
#
#  Every service calls _geoip(ip).  The returned dict always contains:
#    Standard geo fields:  country, city, latitude, longitude, asn, org, isp
#    Anonymization flags:  is_tor, is_vpn, is_proxy
#    Detail fields:        tor_exit_node, tor_exit_ip
#                          vpn_provider, vpn_exit_country
#                          proxy_type
#    Aggregate:            anonymized (bool), anonymization_method (str)
# ══════════════════════════════════════════════════════════════════════════════

def _geoip(ip: str) -> dict:
    g: dict = {
        # Geo
        "country":   "Unknown",
        "city":      "",
        "latitude":  0.0,
        "longitude": 0.0,
        "asn":       None,
        "asn_org":   None,
        "org":       None,
        "isp":       None,
        # Anonymization (defaults — overwritten below for real IPs)
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
        # ── Standard geo lookup ───────────────────────────────────────────────
        try:
            g.update(geo.lookup(ip) or {})
        except Exception:
            pass
        try:
            if hasattr(geo, "asn_lookup"):
                g.update(geo.asn_lookup(ip) or {})
        except Exception:
            pass
        # ── MaxMind privacy / anonymization data ──────────────────────────────
        try:
            if hasattr(geo, "privacy_lookup"):
                priv = geo.privacy_lookup(ip) or {}
                g.update(priv)
                g["is_vpn"]   = bool(priv.get("is_vpn"))
                g["is_tor"]   = bool(
                    priv.get("is_tor") or priv.get("is_tor_exit_node")
                )
                g["is_proxy"] = bool(
                    priv.get("is_proxy") or priv.get("is_anonymous_proxy")
                )
                raw_ptype     = priv.get("connection_type") or priv.get("user_type") or ""
                g["proxy_type"] = _PROXY_TYPE_LABELS.get(raw_ptype.lower(), raw_ptype or None)
        except Exception:
            pass

        # ── Tor cross-reference against live exit list ────────────────────────
        if g["is_tor"] or _is_tor_exit(ip):
            g["is_tor"]        = True
            g["tor_exit_node"] = True
            g["tor_exit_ip"]   = ip

        # ── VPN provider identification ───────────────────────────────────────
        vpn_provider = _identify_vpn_provider(
            g.get("org", "") or "",
            g.get("asn_org", "") or "",
            g.get("isp", "") or "",
        )
        g["vpn_provider"]     = vpn_provider
        g["vpn_exit_country"] = g.get("country") if g["is_vpn"] else None

    # ── Human-readable anonymization summary ─────────────────────────────────
    methods = []
    if g["is_tor"]:
        methods.append("Tor")
    if g["is_vpn"]:
        label = f"VPN ({g['vpn_provider']})" if g["vpn_provider"] else "VPN"
        methods.append(label)
    if g["is_proxy"]:
        pt = g.get("proxy_type")
        methods.append(f"Proxy ({pt})" if pt else "Proxy")

    g["anonymized"]            = bool(methods)
    g["anonymization_method"]  = " + ".join(methods) if methods else None

    return g


def _intel_fields(g: dict) -> dict:
    """
    Flatten all intelligence + anonymization fields into a flat dict.
    Merged into every db.log_attack() call across all services.
    """
    g = g or {}
    return {
        # Network identity
        "asn":                  g.get("asn") or g.get("asn_org") or g.get("org"),
        "org":                  g.get("org") or g.get("isp") or g.get("asn_org"),
        # Anonymization flags
        "is_vpn":               g.get("is_vpn", False),
        "is_tor":               g.get("is_tor", False),
        "is_proxy":             g.get("is_proxy", False) or g.get("proxy", False),
        # VPN detail
        "vpn_provider":         g.get("vpn_provider"),
        "vpn_exit_country":     g.get("vpn_exit_country"),
        # Tor detail
        "tor_exit_node":        g.get("tor_exit_node", False),
        "tor_exit_ip":          g.get("tor_exit_ip"),
        # Proxy detail
        "proxy_type":           g.get("proxy_type"),
        # Convenience aggregate
        "anonymized":           g.get("anonymized", False),
        "anonymization_method": g.get("anonymization_method"),
    }


# ─── New-IP alert (fires once per unique IP) ──────────────────────────────────
def _new_ip_alert(ip: str, country: str, city: str, service: str):
    if ip not in _seen_ips:
        _seen_ips.add(ip)
        alerts.new_attacker(ip, country, city, service)

        # Fire anonymization-specific Telegram alerts
        gdata = _geoip(ip)
        if gdata.get("is_tor"):
            _inc("tor")
            try:
                alerts.tor_attacker(ip, country, service, gdata.get("tor_exit_ip"))
            except AttributeError:
                pass   # alerts.tor_attacker not yet added — safe to skip
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
#  TELNET (port 23) — full fake BusyBox shell
# ══════════════════════════════════════════════════════════════════════════════

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
        conn.sendall(random.choice(_TELNET_BANNERS).encode())

        for attempt in range(12):
            _random_delay(80, 200)
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

            is_bot        = _check_botnet(username, password)
            is_ht_c, ht_cv = _check_honeytoken_cred(username, password)
            login_attempts.append({"username": username, "password": password,
                                    "is_botnet": is_bot, "attempt": attempt + 1})
            _inc("logins")

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

        for _ in range(150):
            _random_delay(30, 120)
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

            out = shell.execute(cmd)
            time.sleep(0.1)
            if out:
                conn.sendall(out.encode())
            conn.sendall(prompt.encode())

    except Exception:
        pass
    finally:
        if all_commands or login_attempts:
            db.log_attack({
                "timestamp":   _ts(), "source_ip": ip, "source_port": port,
                "dest_port":   23, "service": "telnet", "protocol": "TCP",
                "country":     gdata["country"], "city": gdata["city"],
                "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
                "attack_type": "session_complete",
                "threat_level": "high" if all_commands else "medium",
                "session_id":  sid, "commands": all_commands,
                "is_botnet":   any(la["is_botnet"] for la in login_attempts),
                **_intel_fields(gdata),
            })
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  SSH (port 22)
# ══════════════════════════════════════════════════════════════════════════════

def ssh_log_attack(ip, port, event_type, details):
    try:
        gdata = _geoip(ip)
        log_entry = {
            "timestamp":   _ts(), "source_ip": ip,
            "dest_port":   port,  "service": "ssh", "protocol": "TCP",
            "attack_type": event_type,
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
            **_intel_fields(gdata),
        }
        if isinstance(details, dict):
            log_entry.update(details)
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
        )
    except Exception as e:
        print(f"[!] SSH handler error: {e}")
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
        )
    except Exception as e:
        print(f"[!] FTP handler error: {e}")
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  SMTP (port 25)
# ══════════════════════════════════════════════════════════════════════════════

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
                "timestamp":   _ts(), "source_ip": ip, "dest_port": 25,
                "service":     "smtp", "payload": line[:200],
                "attack_type": "smtp_probe", "threat_level": "low",
                "country":     gdata["country"], "city": gdata["city"],
                "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
                **_intel_fields(gdata),
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


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP / HTTPS (ports 80, 443, 8080)
# ══════════════════════════════════════════════════════════════════════════════

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
</p></body></html>"""),

    "/doc/page/login.asp": (200, "text/html", """<!DOCTYPE html>
<html><head><title>Hikvision — Login</title></head>
<body style="background:#1a1a1a;color:#ccc;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0">
<div style="background:#222;padding:40px;border-radius:8px;min-width:300px">
<h2 style="color:#fff;text-align:center">&#128247; Hikvision</h2>
<form method="POST" action="/doc/page/login.asp" style="display:flex;flex-direction:column;gap:12px">
  <input name="username" placeholder="Username" style="padding:10px;background:#333;border:1px solid #555;color:#fff;border-radius:4px">
  <input name="password" type="password" placeholder="Password" style="padding:10px;background:#333;border:1px solid #555;color:#fff;border-radius:4px">
  <button type="submit" style="padding:10px;background:#0066cc;color:#fff;border:none;border-radius:4px;cursor:pointer">Login</button>
</form></div></body></html>"""),

    "/admin": (200, "text/html", """<!DOCTYPE html>
<html><head><title>Hikvision Admin Panel</title></head>
<body style="background:#1a1a1a;color:#ccc;font-family:sans-serif;padding:30px">
<h2 style="color:#fff">&#9881; Hikvision Administrator Panel</h2>
<p style="color:#888">Device: DS-2CD2043G2-I | Firmware: V5.7.15 build 230313</p>
<hr style="border-color:#333">
<form method="POST" action="/admin" style="max-width:300px">
  <div style="margin-bottom:12px"><label>Username</label><br>
    <input name="user" value="admin" style="width:100%;padding:8px;background:#333;border:1px solid #555;color:#fff;border-radius:4px;margin-top:4px">
  </div>
  <div style="margin-bottom:12px"><label>Password</label><br>
    <input type="password" name="pass" style="width:100%;padding:8px;background:#333;border:1px solid #555;color:#fff;border-radius:4px;margin-top:4px">
  </div>
  <button type="submit" style="padding:10px 20px;background:#cc3300;color:#fff;border:none;border-radius:4px;cursor:pointer">Login</button>
</form>
<p style="color:#444;font-size:11px;margin-top:20px">
  <a href="/.env" style="color:#555">config</a> |
  <a href="/backup/passwords.txt" style="color:#555">backup</a> |
  <a href="/ISAPI/System/deviceInfo" style="color:#555">device info</a>
</p></body></html>"""),

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
        '<?xml version="1.0"?><userCheck><statusValue>200</statusValue><statusString>OK</statusString></userCheck>'),

    "/ISAPI/Security/sessionLogin/capabilities": (200, "application/xml",
        '<?xml version="1.0"?><SessionLoginCap><sessionID>3D1633C7</sessionID><challenge>aK9Jxm3</challenge><iterations>100</iterations><isIrreversible>true</isIrreversible></SessionLoginCap>'),

    "/ISAPI/Security/users": (401, "application/xml",
        '<?xml version="1.0"?><ResponseStatus><requestURL>/ISAPI/Security/users</requestURL><statusCode>401</statusCode><statusString>Unauthorized</statusString></ResponseStatus>'),

    "/ISAPI/Security/users/1": (200, "application/xml",
        '<?xml version="1.0" encoding="UTF-8"?><User version="2.0"><id>1</id><userName>admin</userName><userLevel>Administrator</userLevel></User>'),

    "/ISAPI/System/Network/interfaces/1/ipAddress": (200, "application/xml", """<?xml version="1.0" encoding="UTF-8"?>
<IPAddress version="2.0">
  <ipVersion>v4</ipVersion><addressingType>static</addressingType>
  <ipAddress>192.168.1.108</ipAddress><subnetMask>255.255.255.0</subnetMask>
  <DefaultGateway><ipAddress>192.168.1.1</ipAddress></DefaultGateway>
</IPAddress>"""),

    "/ISAPI/ContentMgmt/StreamingProxy": (200, "application/xml", """<?xml version="1.0" encoding="UTF-8"?>
<StreamingProxyChannelStatus version="2.0">
  <id>1</id>
  <sourceInputPortDescriptor>
    <proxyProtocol>RTSP</proxyProtocol>
    <sourceInputPort>rtsp://192.168.1.108:554/Streaming/Channels/101</sourceInputPort>
    <streamType>main</streamType>
  </sourceInputPortDescriptor>
  <online>true</online>
</StreamingProxyChannelStatus>"""),

    "/ISAPI/System/Video/inputs/channels/1/status": (200, "application/xml", """<?xml version="1.0" encoding="UTF-8"?>
<VideoInputChannelStatus version="2.0">
  <id>1</id><videoInputStatusDescription>OK</videoInputStatusDescription>
  <resolution><width>2688</width><height>1520</height></resolution>
</VideoInputChannelStatus>"""),

    "/ISAPI/System/capabilities": (200, "application/xml", """<?xml version="1.0" encoding="UTF-8"?>
<SystemCap version="2.0">
  <isSupportDDNS>true</isSupportDDNS><isSupportNFS>true</isSupportNFS>
  <isSupportConfigEncrypt>true</isSupportConfigEncrypt>
  <NetworkCap><isSupportWireless>false</isSupportWireless></NetworkCap>
</SystemCap>"""),

    "/.env": (200, "text/plain", """APP_ENV=production
DB_HOST=192.168.1.50\nDB_PORT=5432\nDB_NAME=camera_db
DB_USER=admin\nDB_PASS=SuperSecret2024!
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
<html><head><title>Log In &lsaquo; WordPress</title></head>
<body class="login"><div id="login"><h1><a href="/">Site</a></h1>
<form method="post" action="/wp-login.php">
<label>Username or Email<input type="text" name="log" size="20"></label>
<label>Password<input type="password" name="pwd" size="20"></label>
<input type="submit" name="wp-submit" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
</form></div></body></html>"""),

    "/wp-config.php":  (403, "text/plain", "403 Forbidden"),

    "/phpMyAdmin/": (200, "text/html",
        '<html><body style="background:#1a1a1a;color:#ccc;padding:20px"><h2>phpMyAdmin 5.2.1</h2>'
        '<form method="post"><input name="pma_username" placeholder="Username" style="padding:5px"> '
        '<input type="password" name="pma_password" placeholder="Password" style="padding:5px"> '
        '<input type="submit" value="Go"></form></body></html>'),

    "/phpmyadmin/": (200, "text/html",
        '<html><body style="background:#1a1a1a;color:#ccc;padding:20px"><h2>phpMyAdmin 5.2.1</h2></body></html>'),

    "/actuator/env": (200, "application/json",
        '{"activeProfiles":["production"],"propertySources":[{"name":"applicationConfig","properties":'
        '{"spring.datasource.password":{"value":"Sup3rS3cret2024!"},"jwt.secret":{"value":"change-in-prod"},'
        '"api.key":{"value":"sk-api-EXAMPLE123"}}}]}'),

    "/actuator": (200, "application/json",
        '{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"},'
        '"env":{"href":"/actuator/env"},"metrics":{"href":"/actuator/metrics"}}}'),

    "/manager/html": (401, "text/html",
        '<html><head><title>Apache Tomcat Manager</title></head>'
        '<body><h1>401 Unauthorized</h1><p>Realm: "Tomcat Manager Application"</p></body></html>'),

    "/console": (200, "text/html",
        '<html><body style="background:#1a1a1a;color:#ccc;padding:20px"><h2>JBoss Management Console</h2>'
        '<form method="post"><input name="j_username" placeholder="Username"> '
        '<input type="password" name="j_password" placeholder="Password"> '
        '<input type="submit" value="Login"></form></body></html>'),

    "/.git/config": (200, "text/plain",
        '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n'
        '[remote "origin"]\n\turl = https://github.com/internal/camera-firmware.git\n'
        '\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
        '[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n'),

    "/docker-compose.yml": (200, "text/plain",
        'version: "3.8"\nservices:\n  camera:\n    image: hikvision/ipc:latest\n'
        '    ports:\n      - "80:80"\n      - "554:554"\n    environment:\n'
        '      - ADMIN_PASS=Admin@2024!\n      - DB_URL=postgresql://admin:Sup3rS3cret2024@db:5432/cameras\n'),

    "/phpinfo.php": (200, "text/html",
        "<html><body style='font-family:sans-serif'><h1>PHP Version 7.4.33</h1>"
        "<table><tr><td>System</td><td>Linux camera 5.4.0</td></tr>"
        "<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr></table></body></html>"),

    "/backup/passwords.txt": (200, "text/plain",
        "== Device Admin Credentials ==\nadmin:Admin@2024\nroot:ProductionKey999\ndbuser:MyDB_P@ssw0rd\n"),

    "/install.php": (200, "text/html",
        "<html><body style='padding:20px;background:#1a1a1a;color:#ccc'>"
        "<h2>Installation Wizard</h2><p>Step 1: Database Configuration</p>"
        "<form><input name='db_host' value='localhost'> <input name='db_user' value='root'> "
        "<input type='password' name='db_pass'><button>Next</button></form></body></html>"),

    "/System/configurationFile": (200, "application/octet-stream",
        "HIKVISION_CONFIG_V5.7.15\nadmin:Admin@2024\nrtsp_pass:RtspP@ss123\n"),

    "/cgi-bin/admin/param.cgi": (200, "text/html",
        '<html><body style="background:#111;color:#ccc;font-family:monospace;padding:20px">'
        '<h3>Hikvision CGI Interface</h3>'
        '<form method="POST">User: <input name="usr"> Pass: <input type="password" name="pwd">'
        '<input type="submit" value="Submit"></form></body></html>'),

    "/web/login": (200, "text/html", """<!DOCTYPE html>
<html><head><title>Hikvision — Web Login</title></head>
<body style="background:#1a1a1a;color:#ccc;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0">
<div style="background:#222;padding:40px;border-radius:8px;min-width:320px">
<h2 style="color:#fff;text-align:center">&#128247; Hikvision Web Interface</h2>
<p style="color:#888;text-align:center;font-size:12px">DS-2CD2043G2-I | V5.7.15</p>
<form method="POST" action="/web/login" style="display:flex;flex-direction:column;gap:12px;margin-top:20px">
  <input name="username" placeholder="Username" value="admin" style="padding:10px;background:#333;border:1px solid #555;color:#fff;border-radius:4px">
  <input name="password" type="password" placeholder="Password" style="padding:10px;background:#333;border:1px solid #555;color:#fff;border-radius:4px">
  <button type="submit" style="padding:10px;background:#0066cc;color:#fff;border:none;border-radius:4px;cursor:pointer">Login</button>
</form>
<p style="color:#555;font-size:11px;text-align:center;margin-top:16px">Default: admin / 12345</p>
</div></body></html>"""),

    "/onvif/device_service": (200, "application/soap+xml", """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
  xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
  xmlns:tt="http://www.onvif.org/ver10/schema">
<SOAP-ENV:Body><tds:GetCapabilitiesResponse><tds:Capabilities>
<tt:Analytics><tt:XAddr>http://192.168.1.108:8000/onvif/analytics</tt:XAddr></tt:Analytics>
<tt:Device><tt:XAddr>http://192.168.1.108:8000/onvif/device_service</tt:XAddr></tt:Device>
<tt:Media><tt:XAddr>http://192.168.1.108:8000/onvif/media</tt:XAddr></tt:Media>
</tds:Capabilities></tds:GetCapabilitiesResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""),

    "/api/v1/endpoints/activate": (200, "application/json",
        '{"status":"ok","endpoint":"activated","token":"eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZX0.INVALID"}'),

    "/ztp/cgi-bin/handler": (200, "application/json", '{"result":"ok","code":0}'),

    "/v1/about": (200, "application/json",
        f'{{"name":"{getattr(config,"PROJECT_NAME","honeyPot")}",'
        f'"status":"running","device":"Hikvision DS-2CD2043G2-I","firmware":"V5.7.15 build 230313"}}'),
}

_HTTP_SERVER_HEADERS = [
    "App-webs/", "Apache/2.4.41 (Ubuntu)",
    "nginx/1.18.0", "GoAhead-Webs", "Boa/0.94.14rc21",
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
        raw_str   = raw.decode(errors="ignore")
        lines     = raw_str.split("\n")
        req_ln    = lines[0].strip().split()
        method    = req_ln[0] if req_ln else "GET"
        full_path = req_ln[1] if len(req_ln) > 1 else "/"
        path      = full_path.split("?")[0]
        query     = full_path.split("?")[1] if "?" in full_path else ""

        ua      = next((l.split(":",1)[1].strip() for l in lines if l.lower().startswith("user-agent:")), "")
        referer = next((l.split(":",1)[1].strip() for l in lines if l.lower().startswith("referer:")), "")
        host    = next((l.split(":",1)[1].strip() for l in lines if l.lower().startswith("host:")), "")
        origin  = next((l.split(":",1)[1].strip() for l in lines if l.lower().startswith("origin:")), "")
        post_body = raw_str.split("\r\n\r\n", 1)[1][:1000] if "\r\n\r\n" in raw_str else ""

        attack_patterns = []
        threat_level = "low"

        # Attack pattern detection
        if any(x in full_path for x in ["../","..\\","%2e%2e","....//","..;/"]):
            attack_patterns.append("directory_traversal"); threat_level = "high"
        if any(x in full_path or x in post_body for x in ["|",";","`","$","&&","||","\n","$(","${"]):
            attack_patterns.append("command_injection"); threat_level = "critical"
        if any(x in full_path.lower() or x in post_body.lower()
               for x in ["'","union","select","insert","delete","drop","exec","1=1","' or '"]):
            attack_patterns.append("sql_injection"); threat_level = "high"
        if any(x in full_path.lower() or x in post_body.lower()
               for x in ["<script","javascript:","onerror=","onload="]):
            attack_patterns.append("xss"); threat_level = "medium"

        for pattern, name in {
            "/cgi-bin/":"cgi_exploit", "/shell?":"web_shell",
            "/api/jsonws/invoke":"liferay_rce", "/vendor/phpunit":"phpunit_rce",
            "/.aws/":"aws_creds_leak", "/.kube/":"kubernetes_creds",
            "/actuator/":"spring_boot_exposure", "/solr/":"apache_solr_exploit",
            "/console/":"jboss_exploit", "/manager/":"tomcat_exploit",
            "/goform/":"dlink_tplink_exploit",
        }.items():
            if pattern in path.lower():
                attack_patterns.append(name); threat_level = "critical"

        if method == "POST" and any(x in path.lower() for x in ["/login","/admin","/auth","/signin"]):
            attack_patterns.append("credential_harvest"); threat_level = "high"
        if any(x in ua.lower() for x in ["xmrig","miner","stratum","nicehash"]):
            attack_patterns.append("cryptominer"); threat_level = "critical"
        if any(x in ua.lower() for x in ["masscan","zgrab","shodan","censys","nmap","nikto","sqlmap","metasploit","burp"]):
            attack_patterns.append("automated_scanner"); threat_level = "medium"
        if any(sf in path.lower() for sf in ["/.env","/wp-config.php","/.git/config","/id_rsa","/.ssh/","/.aws/credentials"]):
            attack_patterns.append("sensitive_file_access"); threat_level = "critical"

        full_request = raw_str[:2000]
        cve_id, cve = _check_cve(full_request, svc)
        if cve_id:
            _inc("cves"); attack_patterns.append(f"cve_{cve_id}"); threat_level = "critical"
            alerts.cve_exploit(ip, gdata["country"], cve_id, cve["name"], cve["severity"], svc, path)
            db.log_cve(_ts(), ip, cve_id, cve["name"], cve["severity"], svc, full_request[:1000], gdata["country"])

        ht_f, ht_fv = _check_honeytoken_file(path)
        if ht_f:
            _inc("honeytokens"); attack_patterns.append("honeytoken_file"); threat_level = "critical"
            alerts.honeytoken(ip, gdata["country"], "HTTP_GET", path, svc)
            db.log_honeytoken(_ts(), ip, "HTTP_GET", path, svc, gdata["country"], gdata["city"])

        username = ""; password = ""
        if method == "POST" and post_body:
            for part in post_body.replace("&", "\n").splitlines():
                if "=" in part:
                    k, v = part.split("=", 1)
                    if k.lower() in ("username","user","usr","log","j_username","login","email"):
                        username = v[:50]
                    if k.lower() in ("password","pass","pwd","j_password","passwd"):
                        password = v[:50]
            if username or password:
                is_bot = _check_botnet(username, password)
                is_ht_c, ht_cv = _check_honeytoken_cred(username, password)
                if is_bot:
                    _inc("botnets"); attack_patterns.append("botnet_credential"); threat_level = "critical"
                    alerts.botnet_cred(ip, gdata["country"], svc, username, password)
                if is_ht_c:
                    _inc("honeytokens"); attack_patterns.append("honeytoken_credential"); threat_level = "critical"
                    alerts.honeytoken(ip, gdata["country"], "HTTP_CRED", ht_cv, svc)
                    db.log_honeytoken(_ts(), ip, "HTTP_CRED", ht_cv, svc, gdata["country"])

        scanner_tool = _detect_scanner(ua + " " + full_request[:500])

        db.log_attack({
            "timestamp":       _ts(),     "source_ip":    ip,
            "source_port":     port,       "dest_port":    dport,
            "service":         svc,        "protocol":     "TCP",
            "method":          method,     "path":         path[:500],
            "query_string":    query[:500],"user_agent":   ua[:256],
            "referer":         referer[:256], "host_header": host[:256],
            "origin":          origin[:256],  "username":   username,
            "password":        password,   "payload":      post_body[:500],
            "raw_payload":     full_request[:1000],
            "attack_patterns": ",".join(attack_patterns) if attack_patterns else "",
            "country":         gdata["country"], "city":   gdata["city"],
            "latitude":        gdata["latitude"],"longitude": gdata["longitude"],
            "attack_type":     attack_patterns[0] if attack_patterns else "web_scan",
            "threat_level":    threat_level, "cve_id":     cve_id or "",
            "scanner_tool":    scanner_tool,
            **_intel_fields(gdata),
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], svc)

        # Response routing
        if path in HTTP_ROUTES:
            status, ct, body = HTTP_ROUTES[path]
            if method == "POST" and path in ("/web/login","/doc/page/login.asp","/admin","/cgi-bin/admin/param.cgi"):
                conn.sendall(_http_resp(401, "text/html",
                    b"<html><body style='background:#1a1a1a;color:#f55;padding:20px'>"
                    b"<p>Invalid username or password.</p>"
                    b"<a href='javascript:history.back()' style='color:#0af'>Back</a></body></html>"))
                return
            conn.sendall(_http_resp(status, ct, body))
        elif any(x in path for x in ["wp-","wordpress"]):
            conn.sendall(_http_resp(200, "text/html", HTTP_ROUTES["/wp-login.php"][2]))
        elif any(x in path.lower() for x in ["phpmyadmin","pma"]):
            conn.sendall(_http_resp(200, "text/html", HTTP_ROUTES["/phpMyAdmin/"][2]))
        elif "backup" in path.lower() or path.endswith((".sql",".zip",".tar.gz")):
            conn.sendall(_http_resp(403, "text/html", b"<h1>403 Forbidden</h1>"))
        elif path.startswith("/api"):
            intel = _intel_fields(gdata)
            body  = json.dumps({
                "status": "ok", "version": "1.0.0", "ip": ip,
                "country": gdata["country"], "city": gdata["city"],
                "latitude": gdata["latitude"], "longitude": gdata["longitude"],
                "asn": intel["asn"], "org": intel["org"],
                "is_vpn": intel["is_vpn"],
                "vpn_provider": intel["vpn_provider"],
                "vpn_exit_country": intel["vpn_exit_country"],
                "is_tor": intel["is_tor"],
                "tor_exit_node": intel["tor_exit_node"],
                "is_proxy": intel["is_proxy"],
                "proxy_type": intel["proxy_type"],
                "anonymized": intel["anonymized"],
                "anonymization_method": intel["anonymization_method"],
            }).encode()
            conn.sendall(_http_resp(200, "application/json", body))
        elif path.startswith("/ISAPI"):
            conn.sendall(_http_resp(401, "application/xml",
                b'<?xml version="1.0"?><ResponseStatus><statusCode>401</statusCode>'
                b'<statusString>Unauthorized</statusString></ResponseStatus>'))
        else:
            conn.sendall(_http_resp(404, "text/html", b"<html><body><h1>404 Not Found</h1></body></html>"))

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  RTSP (port 554)
# ══════════════════════════════════════════════════════════════════════════════

def rtsp_log_attack(ip, port, event_type, details):
    try:
        details_dict = json.loads(details) if isinstance(details, str) else details
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

def rtsp_intel_fields(ip):
    try:
        return _intel_fields(_geoip(ip))
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

def onvif_log_attack(ip, port, event_type, details):
    try:
        details_dict = json.loads(details) if isinstance(details, str) else details
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
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")
    username = ""

    try:
        conn.settimeout(10)
        pkt = conn.recv(256)
        if not pkt: return

        if (pkt[0] & 0xF0) == 0x10:
            try:
                proto_len = int.from_bytes(pkt[4:6], "big")
                idx = 2 + 2 + proto_len + 1 + 1 + 2
                flags = pkt[9] if len(pkt) > 9 else 0
                if idx + 2 <= len(pkt):
                    cid_len = int.from_bytes(pkt[idx:idx+2], "big")
                    idx += 2 + cid_len
                if (flags & 0x80) and idx + 2 <= len(pkt):
                    ulen = int.from_bytes(pkt[idx:idx+2], "big")
                    username = pkt[idx+2:idx+2+ulen].decode(errors="ignore")
            except Exception:
                pass

            conn.sendall(b"\x20\x02\x00\x00")  # CONNACK accepted
            db.log_attack({
                "timestamp":   _ts(), "source_ip": ip, "dest_port": 1883,
                "service":     "mqtt", "protocol": "TCP",
                "username":    username,
                "country":     gdata["country"], "city": gdata["city"],
                "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
                "attack_type": "iot_protocol", "threat_level": "medium",
                **_intel_fields(gdata),
            })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "mqtt")

            for _ in range(15):
                try:
                    conn.settimeout(8)
                    p = conn.recv(512)
                    if not p: break
                    t = (p[0] & 0xF0) >> 4
                    if t == 12:   conn.sendall(b"\xd0\x00")
                    elif t == 8:  conn.sendall(b"\x90\x03\x00\x01\x00")
                    elif t == 14: break
                except: break

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  Redis (port 6379)
# ══════════════════════════════════════════════════════════════════════════════

def handle_redis(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        for _ in range(25):
            conn.settimeout(15)
            try:
                data = conn.recv(1024)
            except socket.timeout:
                break
            if not data: break
            raw = data.decode(errors="ignore").strip()
            cmd = raw.upper().split()[0] if raw.split() else ""

            if cmd == "CONFIG" and "SET" in raw.upper():
                _inc("cves")
                alerts.redis_rce(ip, gdata["country"], raw[:100])
                db.log_cve(_ts(), ip, "REDIS-RCE", "Redis CONFIG SET RCE", "critical",
                           "redis", raw[:500], gdata["country"])
                db.log_attack({
                    "timestamp": _ts(), "source_ip": ip, "dest_port": 6379,
                    "service": "redis", "payload": raw[:200], "cve_id": "REDIS-RCE",
                    "attack_type": "rce_attempt", "threat_level": "critical",
                    "country": gdata["country"], "latitude": gdata["latitude"],
                    "longitude": gdata["longitude"], **_intel_fields(gdata),
                })
            else:
                db.log_attack({
                    "timestamp": _ts(), "source_ip": ip, "dest_port": 6379,
                    "service": "redis", "payload": raw[:200],
                    "attack_type": "nosql_probe", "threat_level": "high",
                    "country": gdata["country"], "city": gdata["city"],
                    "latitude": gdata["latitude"], "longitude": gdata["longitude"],
                    **_intel_fields(gdata),
                })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "redis")

            if cmd == "PING":       conn.sendall(b"+PONG\r\n")
            elif cmd == "AUTH":     conn.sendall(b"-ERR invalid password\r\n")
            elif cmd == "INFO":     conn.sendall(b"$120\r\n# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\nos:Linux 5.15.0\r\narch_bits:64\r\nuptime_in_seconds:86400\r\n\r\n")
            elif cmd == "CONFIG":   conn.sendall(b"-ERR unknown command 'config'\r\n")
            elif cmd == "SLAVEOF":  conn.sendall(b"+OK\r\n")
            elif cmd == "SAVE":     conn.sendall(b"+OK\r\n")
            elif cmd == "FLUSHALL": conn.sendall(b"+OK\r\n")
            elif cmd == "SET":      conn.sendall(b"+OK\r\n")
            elif cmd == "GET":      conn.sendall(b"$-1\r\n")
            elif cmd == "KEYS":     conn.sendall(b"*0\r\n")
            elif cmd in ("QUIT","EXIT"): conn.sendall(b"+OK\r\n"); break
            else:                   conn.sendall(b"-ERR unknown command\r\n")

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  MySQL (port 3306)
# ══════════════════════════════════════════════════════════════════════════════

_MYSQL_GREET = (
    b"\x4a\x00\x00\x00\x0a" b"8.0.32\x00"
    b"\x08\x00\x00\x00\x2a\x4b\x7c\x26\x31\x3e\x65\x77\x00"
    b"\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
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
                if parts: username = parts[0]
            except Exception:
                pass

        db.log_attack({
            "timestamp":   _ts(), "source_ip": ip, "dest_port": 3306,
            "service":     "mysql", "username": username,
            "attack_type": "db_auth", "threat_level": "high",
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
            **_intel_fields(gdata),
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], "mysql")
        conn.sendall(
            b"\x2e\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30"
            b"Access denied for user 'root'@'10.0.0.1' (using password: YES)"
        )
    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  Docker API (port 2375)
# ══════════════════════════════════════════════════════════════════════════════

_DOCKER_VER = b'{"Version":"24.0.7","ApiVersion":"1.43","MinAPIVersion":"1.12","GitCommit":"af33977","GoVersion":"go1.20.10","Os":"linux","Arch":"amd64","KernelVersion":"5.15.0"}'

def handle_docker(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions"); _inc("cves")

    try:
        conn.settimeout(10)
        raw = conn.recv(8192)
        if not raw: return
        raw_str  = raw.decode(errors="ignore")
        req_line = raw_str.split("\n")[0].strip()
        path     = req_line.split()[1] if len(req_line.split()) > 1 else "/"

        alerts.docker_escape(ip, gdata["country"], path)
        db.log_cve(_ts(), ip, "DOCKER-ESCAPE", "Docker API Container Escape",
                   "critical", "docker", raw_str[:500], gdata["country"])
        db.log_attack({
            "timestamp":   _ts(), "source_ip": ip, "dest_port": 2375,
            "service":     "docker",
            "method":      req_line.split()[0] if req_line.split() else "",
            "path":        path, "payload": raw_str[:300],
            "attack_type": "container_escape", "threat_level": "critical",
            "cve_id":      "DOCKER-ESCAPE",
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
            **_intel_fields(gdata),
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


# ══════════════════════════════════════════════════════════════════════════════
#  Memcached (port 11211)
# ══════════════════════════════════════════════════════════════════════════════

def handle_memcached(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        for _ in range(10):
            conn.settimeout(10)
            try: data = conn.recv(512)
            except socket.timeout: break
            if not data: break
            raw = data.decode(errors="ignore").strip()
            cmd = raw.split()[0].lower() if raw.split() else ""

            db.log_attack({
                "timestamp": _ts(), "source_ip": ip, "dest_port": 11211,
                "service": "memcached", "payload": raw[:100],
                "attack_type": "nosql_probe", "threat_level": "medium",
                "country": gdata["country"], "city": gdata["city"],
                "latitude": gdata["latitude"], "longitude": gdata["longitude"],
                **_intel_fields(gdata),
            })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "memcached")

            if cmd == "stats":       conn.sendall(b"STAT version 1.6.17\r\nSTAT uptime 86400\r\nSTAT curr_items 0\r\nEND\r\n")
            elif cmd == "version":   conn.sendall(b"VERSION 1.6.17\r\n")
            elif cmd == "flush_all": conn.sendall(b"OK\r\n")
            elif cmd == "set":       conn.sendall(b"STORED\r\n")
            elif cmd == "get":       conn.sendall(b"END\r\n")
            elif cmd == "quit":      break
            else:                    conn.sendall(b"ERROR\r\n")
    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  VNC (port 5900)
# ══════════════════════════════════════════════════════════════════════════════

def vnc_log_attack(ip, port, event_type, details):
    try:
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
#  RDP (port 3389)
# ══════════════════════════════════════════════════════════════════════════════

def handle_rdp(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        conn.settimeout(8)
        pkt = conn.recv(1024)
        if not pkt: return

        # X.224 Connection Confirm
        conn.sendall(
            b"\x03\x00\x00\x13"
            b"\x0e\xd0\x00\x00"
            b"\x12\x34\x00\x00"
            b"\x00"
            b"\x02\x01\x08"
            b"\x00\x00\x00\x00"
        )

        db.log_attack({
            "timestamp":   _ts(), "source_ip": ip, "dest_port": 3389,
            "service":     "rdp", "protocol": "TCP",
            "payload":     pkt[:200].hex(),
            "attack_type": "rdp_probe", "threat_level": "high",
            "country":     gdata["country"], "city": gdata["city"],
            "latitude":    gdata["latitude"], "longitude": gdata["longitude"],
            **_intel_fields(gdata),
        })
        _new_ip_alert(ip, gdata["country"], gdata["city"], "rdp")

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  Modbus / ICS (port 502)
# ══════════════════════════════════════════════════════════════════════════════

def handle_modbus(conn, addr):
    ip, port = addr
    if _is_rate_limited(ip): conn.close(); return
    gdata = _geoip(ip)
    _inc("sessions")

    try:
        conn.settimeout(10)
        for _ in range(10):
            try: data = conn.recv(512)
            except socket.timeout: break
            if not data or len(data) < 6: break

            transaction_id = data[0:2]
            function_code  = data[7] if len(data) > 7 else 0

            db.log_attack({
                "timestamp":     _ts(), "source_ip": ip, "dest_port": 502,
                "service":       "modbus", "protocol": "TCP",
                "payload":       data[:100].hex(),
                "function_code": function_code,
                "attack_type":   "ics_probe", "threat_level": "critical",
                "country":       gdata["country"], "city": gdata["city"],
                "latitude":      gdata["latitude"], "longitude": gdata["longitude"],
                **_intel_fields(gdata),
            })
            _new_ip_alert(ip, gdata["country"], gdata["city"], "modbus")

            # Modbus exception: ILLEGAL_FUNCTION
            resp = transaction_id + b"\x00\x00\x00\x03\x01" + bytes([function_code | 0x80, 0x01])
            conn.sendall(resp)

    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  SERVICE LAUNCHER
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


# ══════════════════════════════════════════════════════════════════════════════
#  SERVICES MAP
# ══════════════════════════════════════════════════════════════════════════════

_SERVICES = [
    (handle_telnet,                     config.SERVICE_PORTS["telnet"],    "Telnet"),
    (handle_ssh,                        2222,                             "SSH"),  # Changed from config.SERVICE_PORTS["ssh"] to 2222
    (handle_ftp,                        config.SERVICE_PORTS["ftp"],       "FTP"),
    (handle_smtp,                       config.SERVICE_PORTS["smtp"],      "SMTP"),
    (handle_http,                       config.SERVICE_PORTS["http"],      "HTTP"),
    (lambda c,a: handle_http(c,a,True), config.SERVICE_PORTS["https"],     "HTTPS"),
    (handle_http,                       config.SERVICE_PORTS["http_alt"],  "HTTP-Alt"),
    (handle_rtsp,                       config.SERVICE_PORTS["rtsp"],      "RTSP"),
    (handle_onvif,                      config.SERVICE_PORTS["onvif"],     "ONVIF"),
    (handle_mqtt,                       config.SERVICE_PORTS["mqtt"],      "MQTT"),
    (handle_redis,                      config.SERVICE_PORTS["redis"],     "Redis"),
    (handle_mysql,                      config.SERVICE_PORTS["mysql"],     "MySQL"),
    (handle_docker,                     config.SERVICE_PORTS["docker"],    "Docker API"),
    (handle_memcached,                  config.SERVICE_PORTS["memcached"], "Memcached"),
    (handle_vnc,                        config.SERVICE_PORTS["vnc"],       "VNC"),
    (handle_rdp,                        config.SERVICE_PORTS["rdp"],       "RDP"),
    (handle_modbus,                     config.SERVICE_PORTS["modbus"],    "Modbus/ICS"),
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

    # ── Load Tor exit list + start background refresh ─────────────────────────
    print("\n[*] Loading threat intelligence feeds:")
    _load_tor_exit_nodes()
    threading.Thread(target=_tor_refresh_worker, daemon=True, name="TorExitRefresh").start()

    # ── Start all services ────────────────────────────────────────────────────
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