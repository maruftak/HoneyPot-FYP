#!/usr/bin/env python3
"""
honeyPot — SSDP/UPnP Service (RFC 2931 / UDA 1.0 + 1.1)
Emulates a Hikvision IP camera advertising itself via SSDP on UDP port 1900.

Protocol overview:
  - SSDP (Simple Service Discovery Protocol) is the discovery layer of UPnP
  - Devices advertise via multicast NOTIFY to 239.255.255.250:1900
  - Clients discover devices via unicast/multicast M-SEARCH to port 1900
  - After discovery, clients fetch the device description XML via HTTP
    (LOCATION header → our HTTP service handles that hit)

Attack patterns captured:
  - M-SEARCH broadcast sweeps (mass recon, botnet discovery)
  - Targeted M-SEARCH for InternetGatewayDevice (IGD) — router/NAT exploit
  - CVE-2020-12695 CallStranger (SUBSCRIBE with external callback URL → SSRF)
  - CVE-2012-5958/5959/5960/5961 (libupnp stack overflows via SSDP)
  - SSDP amplification DDoS probes (attacker forges victim IP as source)
  - EternalSilence UPnP botnet lateral-movement probes (Akamai 2020)
  - Spoofed NOTIFY packets used to poison UPnP tables

Design rule: handle_ssdp() never calls recv/recvfrom on the shared srv_sock.
The datagram is already read by _start_udp in honeypot.py and passed as `data`.
Outbound NOTIFY packets are sent from a separate multicast socket.
"""

import datetime
import random
import re
import socket
import struct
import threading
import time

# ─── UPnP / SSDP Constants ───────────────────────────────────────────────────

SSDP_MULTICAST  = "239.255.255.250"
SSDP_PORT       = 1900

# Fake Hikvision device identity — matches the rest of the honeypot
_DEVICE_UUID     = "44194e2a-5b9c-4c9a-9c4b-12ef8e4d5f6a"
_DEVICE_USN_ROOT = f"uuid:{_DEVICE_UUID}"
_DEVICE_TYPE     = "urn:schemas-upnp-org:device:Basic:1"
_SERVER_HEADER   = "Linux/3.10.108 UPnP/1.0 Hikvision/V5.7.15"
_FRIENDLY_NAME   = "Hikvision DS-2CD2043G2-I"
_MANUFACTURER    = "Hikvision Digital Technology Co., Ltd."
_MODEL_NUMBER    = "DS-2CD2043G2-I"
_SERIAL          = "DS-2CD2043G2-I20230313CCCH012345678"
_FIRMWARE        = "V5.7.15 build 230313"
_MAC             = "44:19:B6:7A:2C:D9"

# URL served for device description (our HTTP service handles the actual request)
_DESCRIPTION_PATH = "/upnp/basicDevice.xml"

# Services this fake device advertises
_UPNP_SERVICES = [
    "upnp:rootdevice",
    _DEVICE_TYPE,
    f"uuid:{_DEVICE_UUID}",
    "urn:schemas-upnp-org:service:ConnectionManager:1",
    "urn:schemas-upnp-org:service:AVTransport:1",
]

# ─── Device description XML ───────────────────────────────────────────────────

_DESCRIPTION_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
    <friendlyName>Hikvision DS-2CD2043G2-I</friendlyName>
    <manufacturer>Hikvision Digital Technology Co., Ltd.</manufacturer>
    <manufacturerURL>http://www.hikvision.com</manufacturerURL>
    <modelDescription>2MP AcuSense Fixed Dome Network Camera</modelDescription>
    <modelName>DS-2CD2043G2-I</modelName>
    <modelNumber>DS-2CD2043G2-I</modelNumber>
    <modelURL>http://www.hikvision.com</modelURL>
    <serialNumber>DS-2CD2043G2-I20230313CCCH012345678</serialNumber>
    <UDN>uuid:44194e2a-5b9c-4c9a-9c4b-12ef8e4d5f6a</UDN>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:ConnectionManager:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:ConnectionManager</serviceId>
        <SCPDURL>/upnp/connectionManager.xml</SCPDURL>
        <controlURL>/upnp/control/connectionManager</controlURL>
        <eventSubURL>/upnp/event/connectionManager</eventSubURL>
      </service>
      <service>
        <serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:AVTransport</serviceId>
        <SCPDURL>/upnp/avTransport.xml</SCPDURL>
        <controlURL>/upnp/control/avTransport</controlURL>
        <eventSubURL>/upnp/event/avTransport</eventSubURL>
      </service>
    </serviceList>
    <presentationURL>http://192.168.1.108:80/</presentationURL>
  </device>
</root>"""

# ─── CVE / Attack patterns ────────────────────────────────────────────────────

_CVE_PATTERNS = {
    "CVE-2020-12695": {
        "name":     "CallStranger UPnP SUBSCRIBE SSRF",
        "severity": "critical",
        "pattern":  re.compile(
            rb"SUBSCRIBE|callback\s*=\s*<http://|NT:\s*upnp:event",
            re.IGNORECASE,
        ),
    },
    "CVE-2012-5958": {
        "name":     "libupnp Stack Overflow (Broadcom/Portable SDK)",
        "severity": "critical",
        "pattern":  re.compile(
            rb"urn:schemas-upnp-org:device:InternetGatewayDevice|"
            rb"urn:schemas-upnp-org:service:WANIPConn|"
            rb"urn:schemas-upnp-org:service:WANPPPConn",
            re.IGNORECASE,
        ),
    },
    "SSDP-AMPLIFY": {
        "name":     "SSDP Amplification DDoS Probe",
        "severity": "high",
        "pattern":  re.compile(
            rb"M-SEARCH \* HTTP.*MAN.*ssdp:discover",
            re.IGNORECASE | re.DOTALL,
        ),
    },
    "UPNP-IGD-EXPLOIT": {
        "name":     "UPnP IGD Port Mapping / AddPortMapping Exploit",
        "severity": "critical",
        "pattern":  re.compile(
            rb"AddPortMapping|NewInternalClient|NewExternalPort|"
            rb"WANIPConnection|WANPPPConnection|DeletePortMapping",
            re.IGNORECASE,
        ),
    },
    "ETERNAL-SILENCE": {
        "name":     "EternalSilence UPnP Botnet Probe (Akamai)",
        "severity": "critical",
        "pattern":  re.compile(
            rb"NewRemoteHost.*NewExternalPort.*NewInternalClient|"
            rb"urn:schemas-upnp-org:service:WANIPConn.*AddPortMapping",
            re.IGNORECASE | re.DOTALL,
        ),
    },
    "CVE-2019-17621": {
        "name":     "D-Link UPnP RCE (HNAP/UPnP command injection)",
        "severity": "critical",
        "pattern":  re.compile(
            rb"NewInternalClient.*<\s*script|NewInternalClient.*\$\(",
            re.IGNORECASE | re.DOTALL,
        ),
    },
}

# Known scanner / tool fingerprints in the User-Agent or payload
_TOOL_FINGERPRINTS = {
    b"masscan":           "masscan",
    b"nmap":              "nmap",
    b"python-requests":   "Python-requests scanner",
    b"python-urllib":     "Python-urllib scanner",
    b"zgrab":             "zgrab",
    b"nuclei":            "Nuclei scanner",
    b"curl/":             "curl",
    b"go-http-client":    "Go HTTP scanner",
    b"upnp-inspector":    "UPnP Inspector",
    b"miranda":           "Miranda UPnP tool",
    b"cybergarage":       "CyberGarage UPnP",
    b"platinum":          "Platinum UPnP SDK",
    b"intel sdk":         "Intel UPnP SDK",
    b"libupnp":           "libupnp client",
    b"miniupnp":          "miniUPnP client",
    b"upnpc":             "upnpc (miniUPnP CLI)",
}

# ─── SSDP message parser ──────────────────────────────────────────────────────

class SSDPMessage:
    """
    Parses a raw SSDP datagram into method, headers, and body.
    SSDP messages look like HTTP/1.1 but have custom methods.
    """

    def __init__(self):
        self.method  = ""        # M-SEARCH, NOTIFY, SUBSCRIBE, etc.
        self.headers = {}        # lowercased header name → value
        self.body    = b""
        self.valid   = False
        self.raw     = b""

    @classmethod
    def parse(cls, data: bytes) -> "SSDPMessage":
        msg = cls()
        msg.raw = data
        try:
            text = data.decode("utf-8", errors="ignore")
            lines = text.replace("\r\n", "\n").split("\n")
            if not lines:
                return msg

            first = lines[0].strip()
            # Request line: METHOD * HTTP/1.1
            if first.startswith("M-SEARCH"):
                msg.method = "M-SEARCH"
            elif first.startswith("NOTIFY"):
                msg.method = "NOTIFY"
            elif first.startswith("SUBSCRIBE"):
                msg.method = "SUBSCRIBE"
            elif first.startswith("UNSUBSCRIBE"):
                msg.method = "UNSUBSCRIBE"
            else:
                msg.method = first.split()[0] if first.split() else "UNKNOWN"

            in_body = False
            body_lines = []
            for line in lines[1:]:
                if in_body:
                    body_lines.append(line)
                    continue
                if line.strip() == "":
                    in_body = True
                    continue
                if ":" in line:
                    k, _, v = line.partition(":")
                    msg.headers[k.strip().lower()] = v.strip()

            msg.body  = "\n".join(body_lines).encode()
            msg.valid = bool(msg.method)
        except Exception:
            pass
        return msg

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


# ─── Threat classifier ────────────────────────────────────────────────────────

def _classify(msg: SSDPMessage) -> tuple[str, str, str | None, dict | None]:
    """
    Returns (attack_type, threat_level, cve_id, cve_info).
    """
    raw = msg.raw

    # CVE scan — check all patterns
    for cve_id, info in _CVE_PATTERNS.items():
        if info["pattern"].search(raw):
            return f"ssdp_cve_{cve_id.lower().replace('-','_')}", \
                   info["severity"], cve_id, info

    st  = msg.header("st").lower()
    nt  = msg.header("nt").lower()
    nts = msg.header("nts").lower()

    if msg.method == "M-SEARCH":
        if st in ("ssdp:all", "upnp:rootdevice"):
            return "ssdp_discovery_sweep", "medium", None, None
        if "internetgatewaydevice" in st or "wanipconn" in st:
            return "ssdp_igd_probe", "high", None, None
        if "schemas-upnp-org" in st:
            return "ssdp_service_probe", "medium", None, None
        return "ssdp_msearch", "low", None, None

    if msg.method == "NOTIFY":
        if nts == "ssdp:byebye":
            return "ssdp_byebye", "low", None, None
        # Unexpected NOTIFY (attacker sending forged alive packets)
        return "ssdp_notify_probe", "medium", None, None

    if msg.method == "SUBSCRIBE":
        return "ssdp_subscribe_abuse", "high", None, None

    return "ssdp_probe", "low", None, None


def _detect_tool(raw: bytes) -> str:
    rl = raw.lower()
    for sig, name in _TOOL_FINGERPRINTS.items():
        if sig in rl:
            return name
    return ""


# ─── SSDP response builders ───────────────────────────────────────────────────

def _msearch_response(location: str, st: str) -> bytes:
    """
    Unicast HTTP 200 OK response to an M-SEARCH request.
    st is echoed back so the client knows which service responded.
    """
    now  = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    resp = (
        "HTTP/1.1 200 OK\r\n"
        f"CACHE-CONTROL: max-age=1800\r\n"
        f"DATE: {now}\r\n"
        "EXT:\r\n"
        f"LOCATION: {location}\r\n"
        f"SERVER: {_SERVER_HEADER}\r\n"
        f"ST: {st}\r\n"
        f"USN: {_DEVICE_USN_ROOT}::{st}\r\n"
        f"BOOTID.UPNP.ORG: 1\r\n"
        f"CONFIGID.UPNP.ORG: 1337\r\n"
        "\r\n"
    )
    return resp.encode()


def _notify_alive(nt: str, location: str) -> bytes:
    """
    Multicast NOTIFY ssdp:alive for one NT/USN pair.
    Real Hikvision firmware sends several of these on boot and every 15 min.
    """
    pkt = (
        "NOTIFY * HTTP/1.1\r\n"
        f"HOST: {SSDP_MULTICAST}:{SSDP_PORT}\r\n"
        f"CACHE-CONTROL: max-age=1800\r\n"
        f"LOCATION: {location}\r\n"
        f"NT: {nt}\r\n"
        "NTS: ssdp:alive\r\n"
        f"SERVER: {_SERVER_HEADER}\r\n"
        f"USN: {_DEVICE_USN_ROOT}::{nt}\r\n"
        f"BOOTID.UPNP.ORG: 1\r\n"
        f"CONFIGID.UPNP.ORG: 1337\r\n"
        "\r\n"
    )
    return pkt.encode()


def _notify_byebye(nt: str) -> bytes:
    pkt = (
        "NOTIFY * HTTP/1.1\r\n"
        f"HOST: {SSDP_MULTICAST}:{SSDP_PORT}\r\n"
        f"NT: {nt}\r\n"
        "NTS: ssdp:byebye\r\n"
        f"USN: {_DEVICE_USN_ROOT}::{nt}\r\n"
        "\r\n"
    )
    return pkt.encode()


# ─── Background NOTIFY sender ─────────────────────────────────────────────────

_notify_thread_started = False
_notify_lock           = threading.Lock()


def _send_notify_burst(location: str):
    """
    Send a burst of NOTIFY ssdp:alive packets to the multicast group.
    Real Hikvision cameras send one per advertised NT, three times in a row
    with a short delay — as specified in UDA 1.1.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        dest = (SSDP_MULTICAST, SSDP_PORT)
        for nt in _UPNP_SERVICES:
            for _ in range(3):          # UDA 1.1 §1.2.2: send 3 times
                pkt = _notify_alive(nt, location)
                sock.sendto(pkt, dest)
                time.sleep(random.uniform(0.05, 0.2))
            time.sleep(random.uniform(0.1, 0.4))
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _notify_worker(location: str, interval: int = 840):
    """
    Daemon thread: advertise the device on the LAN every `interval` seconds.
    840 s ≈ 14 min — slightly under the 15-min CACHE-CONTROL max-age=1800/2
    so the device stays "alive" in neighbour tables.
    """
    # Initial delay so the main process finishes binding all ports first
    time.sleep(5)
    while True:
        _send_notify_burst(location)
        time.sleep(interval + random.randint(-30, 30))


def start_notify_sender(location: str, interval: int = 840):
    """
    Called once from honeypot.py after all services are bound.
    Starts the background multicast NOTIFY thread.
    """
    global _notify_thread_started
    with _notify_lock:
        if _notify_thread_started:
            return
        _notify_thread_started = True
    threading.Thread(
        target  = _notify_worker,
        args    = (location, interval),
        daemon  = True,
        name    = "SSDP-Notify",
    ).start()


# ─── Main handler ─────────────────────────────────────────────────────────────

def handle_ssdp(
    srv_sock,
    addr,
    data:                  bytes,
    log_attack             = None,
    geoip_func             = None,
    intel_fields_func      = None,
    new_ip_alert           = None,
    check_cve              = None,
    inc_counter            = None,
    alert_funcs            = None,
    local_ip:              str = "192.168.1.108",
):
    """
    Handle a single SSDP datagram.

    Parameters
    ----------
    srv_sock : socket.socket
        Shared UDP socket on port 1900. We call sendto() on it to reply
        to unicast M-SEARCH requests.  We NEVER call recv/recvfrom here.
    addr : (str, int)
        Sender (ip, port).
    data : bytes
        Raw datagram already read by _start_udp in honeypot.py.
    local_ip : str
        The IP address to advertise in LOCATION URLs.
    """
    ip, port  = addr
    alert_funcs = alert_funcs or {}

    # ── GeoIP ─────────────────────────────────────────────────────────────────
    gdata: dict = {}
    if geoip_func:
        try:
            gdata = geoip_func(ip) or {}
        except Exception:
            pass

    intel: dict = {}
    if intel_fields_func:
        try:
            intel = intel_fields_func(gdata) or {}
        except Exception:
            pass

    # ── Parse ─────────────────────────────────────────────────────────────────
    msg = SSDPMessage.parse(data)

    location = f"http://{local_ip}:80{_DESCRIPTION_PATH}"

    if not msg.valid:
        _log(log_attack, {
            "timestamp":    _ts(), "source_ip":  ip,
            "source_port":  port,  "dest_port":  1900,
            "service":      "ssdp", "protocol":  "UDP",
            "attack_type":  "ssdp_malformed",
            "threat_level": "low",
            "payload":      data[:128].decode("latin-1", errors="ignore"),
            "raw_payload":  data[:64].hex(),
            "country":      gdata.get("country", "Unknown"),
            "city":         gdata.get("city", ""),
            "latitude":     gdata.get("latitude", 0.0),
            "longitude":    gdata.get("longitude", 0.0),
            **intel,
        })
        if new_ip_alert:
            try: new_ip_alert(ip, gdata.get("country","Unknown"),
                              gdata.get("city",""), "ssdp")
            except Exception: pass
        return

    # ── Classify threat ───────────────────────────────────────────────────────
    attack_type, threat_level, cve_id, cve_info = _classify(msg)

    # Let the injected CVE checker have a pass too (uses global CVE_PATTERNS)
    if check_cve and not cve_id:
        try:
            cve_id2, cve_info2 = check_cve(data, "ssdp")
            if cve_id2:
                cve_id       = cve_id2
                cve_info     = cve_info2
                threat_level = "critical"
                attack_type  = f"ssdp_cve_{cve_id2.lower().replace('-','_')}"
        except Exception:
            pass

    # ── CVE alert ─────────────────────────────────────────────────────────────
    if cve_id:
        if inc_counter:
            try: inc_counter("cves")
            except Exception: pass
        cve_alert = alert_funcs.get("cve_exploit")
        if cve_alert and cve_info:
            try:
                cve_alert(
                    ip, gdata.get("country", ""),
                    cve_id,
                    cve_info.get("name", cve_id),
                    cve_info.get("severity", "high"),
                    "ssdp",
                    data[:80].decode("latin-1", errors="ignore"),
                )
            except Exception:
                pass

    tool = _detect_tool(data)
    st   = msg.header("st")
    nt   = msg.header("nt")
    nts  = msg.header("nts")
    mx   = msg.header("mx")

    # ── Log ───────────────────────────────────────────────────────────────────
    _log(log_attack, {
        "timestamp":    _ts(),
        "source_ip":    ip,
        "source_port":  port,
        "dest_port":    1900,
        "service":      "ssdp",
        "protocol":     "UDP",
        "method":       msg.method,
        "path":         st or nt or "",
        "payload":      data[:500].decode("latin-1", errors="ignore"),
        "raw_payload":  data[:128].hex(),
        "attack_type":  attack_type,
        "threat_level": threat_level,
        "cve_id":       cve_id or "",
        "user_agent":   tool,
        "country":      gdata.get("country", "Unknown"),
        "city":         gdata.get("city", ""),
        "latitude":     gdata.get("latitude", 0.0),
        "longitude":    gdata.get("longitude", 0.0),
        **intel,
    })

    if new_ip_alert:
        try: new_ip_alert(ip, gdata.get("country","Unknown"),
                          gdata.get("city",""), "ssdp")
        except Exception: pass

    # ── Respond to M-SEARCH ───────────────────────────────────────────────────
    if msg.method == "M-SEARCH":
        # Honour MX delay (UDA spec: server must wait 0..MX seconds before reply)
        try:
            mx_val = float(mx) if mx else 1.0
            mx_val = max(0.0, min(mx_val, 5.0))
            if mx_val > 0:
                time.sleep(random.uniform(0, mx_val))
        except Exception:
            pass

        st_lower = st.lower()

        # Decide which ST values we respond to
        respond_to = []
        if st_lower in ("ssdp:all", "upnp:rootdevice"):
            respond_to = _UPNP_SERVICES        # reply for all our services
        else:
            # Respond to anything — even probes for other device types
            # (real scanners don't need an exact match to log the probe)
            respond_to = [st if st else _DEVICE_TYPE]

        try:
            for svc_st in respond_to:
                resp = _msearch_response(location, svc_st)
                srv_sock.sendto(resp, addr)
                time.sleep(random.uniform(0.02, 0.08))
        except Exception:
            pass

    # ── Respond to SUBSCRIBE (CVE-2020-12695 style) ───────────────────────────
    elif msg.method == "SUBSCRIBE":
        # Fake a 200 OK subscription response to keep the attacker engaged
        callback = msg.header("callback")
        sid      = f"uuid:{_random_uuid()}"
        try:
            resp = (
                "HTTP/1.1 200 OK\r\n"
                f"DATE: {datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\n"
                f"SERVER: {_SERVER_HEADER}\r\n"
                f"SID: {sid}\r\n"
                "CONTENT-LENGTH: 0\r\n"
                "TIMEOUT: Second-1800\r\n"
                "\r\n"
            ).encode()
            srv_sock.sendto(resp, addr)
        except Exception:
            pass


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.datetime.utcnow().isoformat()


def _random_uuid() -> str:
    return "-".join([
        "%08x" % random.randint(0, 0xFFFFFFFF),
        "%04x" % random.randint(0, 0xFFFF),
        "%04x" % random.randint(0, 0xFFFF),
        "%04x" % random.randint(0, 0xFFFF),
        "%012x" % random.randint(0, 0xFFFFFFFFFFFF),
    ])


def _log(fn, entry: dict):
    if fn is None:
        return
    try:
        fn(entry)
    except Exception:
        pass


# ─── Device description XML accessor (used by HTTP service) ──────────────────

def get_description_xml() -> str:
    """Return the UPnP device description XML string."""
    return _DESCRIPTION_XML
