#!/usr/bin/env python3
"""
hik_sdk_service.py  —  Hikvision Private SDK (port 8200) Honeypot Service

Emulates the Hikvision NET_DVR / SADP proprietary binary protocol used by:
  - iVMS-4200 client software
  - Hikvision HikCentral
  - Third-party NVR/VMS integrations
  - Automated scanners targeting CVE-2021-36260, CVE-2017-7921, CVE-2023-28808

Protocol overview (simplified):
  → Client sends a SADP/SDK handshake (magic header 0x4849 'HI' + cmd byte)
  → Server responds with device info + session token
  → Client may then send auth, config-read, or exploit payloads
  → All traffic is logged and analysed for CVE patterns

Real Hikvision SDK magic bytes:
  0x20 0x00  – SADP discovery probe
  0x48 0x49  – 'HI' SDK session initiation
  0x00 0x00  – ping / keepalive
  Various length-prefixed binary frames

This module is imported by honeypot.py; the thin wrapper there injects
all helper functions (geoip, logging, alerts, etc.).
"""

import socket
import struct
import time
import re
import random
import threading
import datetime
import device_identity as _dev

# ─── SDK Protocol Constants ───────────────────────────────────────────────────

MAGIC_SADP   = b"\x20\x00"           # SADP UDP discovery probe (also seen on TCP)
MAGIC_SDK    = b"\x48\x49"           # 'HI' — SDK session open
MAGIC_PING   = b"\x00\x00\x00\x00"  # Keepalive
MAGIC_AUTH   = b"\x48\x49\x00\x01"  # Auth command
MAGIC_CFG    = b"\x48\x49\x00\x03"  # Config read
MAGIC_CMD    = b"\x48\x49\x00\x0a"  # PTZ / control command

# Command codes embedded in SDK frames
CMD_LOGIN       = 0x01
CMD_LOGOUT      = 0x02
CMD_KEEPALIVE   = 0x03
CMD_GET_CONFIG  = 0x08
CMD_SET_CONFIG  = 0x09
CMD_START_RTSP  = 0x0a
CMD_UPGRADE_FW  = 0x0b
CMD_REBOOT      = 0x0c
CMD_GET_USERS   = 0x0d
CMD_ADD_USER    = 0x0e
CMD_DEL_USER    = 0x0f

# CVE patterns seen in the wild against Hikvision SDK port
_CVE_PATTERNS = {
    "CVE-2021-36260": {
        "pattern": rb"PUT /SDK/webLanguage|webLanguage.*\.xml|mxml|<language>",
        "name":    "Hikvision Command Injection via webLanguage",
        "severity":"critical",
    },
    "CVE-2017-7921": {
        "pattern": rb"backdoor|auth=YWRtaW4|snapshot\.jpg\?auth=|/onvif-http/snapshot",
        "name":    "Hikvision Auth Bypass (Backdoor Account)",
        "severity":"critical",
    },
    "CVE-2023-28808": {
        "pattern": rb"diag\x00|/ISAPI/System/upgradeStatus|cmd=shell|/SDK/webLanguage",
        "name":    "Hikvision Unauthenticated RCE",
        "severity":"critical",
    },
    "CVE-2022-28171": {
        "pattern": rb"GET /ptz|setPreset|goPreset|ISAPI/PTZCtrl.*inject",
        "name":    "Hikvision PTZ Command Injection",
        "severity":"high",
    },
    "HIK-SDK-OVERFLOW": {
        "pattern": rb".{2048,}",               # Huge payload → buffer overflow attempt
        "name":    "Hikvision SDK Buffer Overflow Attempt",
        "severity":"high",
    },
}

# Known exploit tool fingerprints in the SDK payload
_TOOL_FINGERPRINTS = {
    b"Hikexploit":      "HikExploit scanner",
    b"hikpwn":          "hikpwn tool",
    b"python-requests": "Python scanner",
    b"Metasploit":      "Metasploit Framework",
    b"masscan":         "masscan",
    b"nmap":            "nmap",
    b"nuclei":          "Nuclei scanner",
    b"go-http-client":  "Go HTTP client",
    b"curl/":           "curl",
    b"zgrab":           "zgrab",
}

# ─── Realistic binary response builders ──────────────────────────────────────

_DEVICE_SERIAL   = _dev.HIK["serial"]
_DEVICE_MODEL    = _dev.HIK["model"]
_DEVICE_FIRMWARE = _dev.HIK["firmware"]
_DEVICE_MAC      = _dev.HIK["mac_upper"]
_SDK_VERSION     = _dev.HIK["sdk_version"]

def _random_session_token():
    return "".join(random.choices("0123456789ABCDEF", k=32))

def _ts():
    return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def _ts_iso():
    return datetime.datetime.utcnow().isoformat()


def _build_sdk_hello(session_token: str) -> bytes:
    """
    Fake SDK session-open response.
    Real format: magic(2) + version(2) + cmd(2) + length(4) + payload

    0x4849 'HI' | version 0x0601 | cmd 0x0001 LOGIN_ACK | len | body
    """
    body = (
        f"<?xml version='1.0' encoding='utf-8'?>"
        f"<SessionLoginCap version='2.0'>"
        f"<sessionID>{session_token}</sessionID>"
        f"<challenge>{random.randint(100000000, 999999999)}</challenge>"
        f"<iterations>100</iterations>"
        f"<isIrreversible>true</isIrreversible>"
        f"<sessionIDVersion>2</sessionIDVersion>"
        f"</SessionLoginCap>"
    ).encode()

    header = struct.pack(
        ">2sHHI",
        b"HI",      # magic
        0x0601,     # SDK version 6.1
        0x0001,     # CMD: SESSION_OPEN ACK
        len(body),
    )
    return header + body


def _build_device_info_xml() -> bytes:
    """Realistic Hikvision DeviceInfo XML response body."""
    xml = (
        f"<?xml version='1.0' encoding='utf-8'?>"
        f"<DeviceInfo version='2.0'>"
        f"<deviceName>IPCamera</deviceName>"
        f"<deviceID>44194e2a-5b9c-4c9a-9c4b-12ef8e4d5f6a</deviceID>"
        f"<model>{_DEVICE_MODEL}</model>"
        f"<serialNumber>{_DEVICE_SERIAL}</serialNumber>"
        f"<macAddress>{_DEVICE_MAC}</macAddress>"
        f"<firmwareVersion>{_DEVICE_FIRMWARE}</firmwareVersion>"
        f"<firmwareReleasedDate>build 230313</firmwareReleasedDate>"
        f"<encoderVersion>V9.0 build 230109</encoderVersion>"
        f"<encoderReleasedDate>build 230109</encoderReleasedDate>"
        f"<bootVersion>V1.3.4 build 190906</bootVersion>"
        f"<bootReleasedDate>build 190906</bootReleasedDate>"
        f"<hardwareVersion>0x0</hardwareVersion>"
        f"<deviceType>IPCamera</deviceType>"
        f"<telecontrolID>88</telecontrolID>"
        f"<supportBeep>false</supportBeep>"
        f"<supportVideoLoss>false</supportVideoLoss>"
        f"<firmwareVersionInfo>B-R6-0</firmwareVersionInfo>"
        f"<sdkVersion>{_SDK_VERSION}</sdkVersion>"
        f"<sdkCapabilities>0x00000001</sdkCapabilities>"
        f"</DeviceInfo>"
    ).encode()
    return xml


def _build_sdk_response(cmd: int, body: bytes, status: int = 0) -> bytes:
    """
    Generic SDK response frame.
    Header: magic(2) + version(2) + cmd(2) + status(2) + length(4)
    """
    header = struct.pack(
        ">2sHHHI",
        b"HI",
        0x0601,
        cmd,
        status,
        len(body),
    )
    return header + body


def _build_auth_fail() -> bytes:
    body = (
        b"<?xml version='1.0' encoding='utf-8'?>"
        b"<ResponseStatus version='1.0'>"
        b"<requestURL>/SDK/webLanguage</requestURL>"
        b"<statusCode>401</statusCode>"
        b"<statusString>Unauthorized</statusString>"
        b"<subStatusCode>notAuthenticated</subStatusCode>"
        b"</ResponseStatus>"
    )
    return _build_sdk_response(CMD_LOGIN, body, status=0x0010)


def _build_auth_ok(session_token: str) -> bytes:
    body = (
        f"<?xml version='1.0' encoding='utf-8'?>"
        f"<UserSessionCap version='2.0'>"
        f"<sessionID>{session_token}</sessionID>"
        f"<userID>1</userID>"
        f"<userName>admin</userName>"
        f"<userLevel>Administrator</userLevel>"
        f"<loginDate>{_ts()}</loginDate>"
        f"</UserSessionCap>"
    ).encode()
    return _build_sdk_response(CMD_LOGIN, body, status=0x0000)


def _build_config_response() -> bytes:
    body = (
        b"<?xml version='1.0' encoding='utf-8'?>"
        b"<NetworkInterfaceList version='2.0'>"
        b"<NetworkInterface>"
        b"<id>1</id><IPAddress version='2.0'>"
        b"<ipVersion>v4</ipVersion>"
        b"<addressingType>static</addressingType>"
        b"<ipAddress>192.168.1.108</ipAddress>"
        b"<subnetMask>255.255.255.0</subnetMask>"
        b"<DefaultGateway><ipAddress>192.168.1.1</ipAddress></DefaultGateway>"
        b"<PrimaryDNS><ipAddress>8.8.8.8</ipAddress></PrimaryDNS>"
        b"</IPAddress></NetworkInterface>"
        b"</NetworkInterfaceList>"
    )
    return _build_sdk_response(CMD_GET_CONFIG, body, status=0x0000)


def _build_keepalive_ack() -> bytes:
    return _build_sdk_response(CMD_KEEPALIVE, b"", status=0x0000)


def _build_sadp_response() -> bytes:
    """
    SADP (Search Active Devices Protocol) response.
    This is what Hikvision tools broadcast to discover cameras on a subnet.
    Realistic SADP XML probe response.
    """
    xml = (
        f"<?xml version='1.0' encoding='utf-8'?>"
        f"<Probe version='1.0'>"
        f"<Uuid>44194E2A5B9C4C9A9C4B12EF8E4D5F6A</Uuid>"
        f"<Types>inquiry</Types>"
        f"<DeviceType>IPCamera</DeviceType>"
        f"<DeviceDescription>Hikvision IP Camera</DeviceDescription>"
        f"<DeviceSN>{_DEVICE_SERIAL}</DeviceSN>"
        f"<CommandPort>8000</CommandPort>"
        f"<HttpPort>80</HttpPort>"
        f"<MAC>{_DEVICE_MAC}</MAC>"
        f"<IPv4Address>192.168.1.108</IPv4Address>"
        f"<IPv4SubnetMask>255.255.255.0</IPv4SubnetMask>"
        f"<IPv4Gateway>192.168.1.1</IPv4Gateway>"
        f"<IPv6Address>::</IPv6Address>"
        f"<IPv6Gateway>::</IPv6Gateway>"
        f"<IPv6MaskLen>0</IPv6MaskLen>"
        f"<DHCP>false</DHCP>"
        f"<AnalogChannelNum>0</AnalogChannelNum>"
        f"<DigitalChannelNum>1</DigitalChannelNum>"
        f"<SoftwareVersion>{_DEVICE_FIRMWARE}</SoftwareVersion>"
        f"<DSPVersion>V9.0 build 230109</DSPVersion>"
        f"<BootTime>2024-12-01T08:00:00</BootTime>"
        f"<ResetAbility>false</ResetAbility>"
        f"<DiskNumber>0</DiskNumber>"
        f"<Activated>true</Activated>"
        f"</Probe>"
    ).encode()
    # SADP responses are prefixed with a 20-byte fixed header in real firmware
    header = struct.pack(">BBHI8s", 0x20, 0x00, 0x0001, len(xml), b"\x00" * 8)
    return header + xml


# ─── CVE / exploit detection ─────────────────────────────────────────────────

def _detect_cve(raw: bytes):
    for cve_id, info in _CVE_PATTERNS.items():
        if re.search(info["pattern"], raw, re.IGNORECASE | re.DOTALL):
            return cve_id, info
    return None, None


def _detect_tool(raw: bytes) -> str:
    for sig, name in _TOOL_FINGERPRINTS.items():
        if sig.lower() in raw.lower():
            return name
    return ""


def _classify_payload(raw: bytes) -> dict:
    """
    Classify what the connecting client is actually doing.
    Returns a dict with attack_type, threat_level, notes.
    """
    result = {
        "attack_type":  "hik_sdk_probe",
        "threat_level": "medium",
        "notes":        [],
        "username":     "",
        "password":     "",
        "cmd_code":     None,
    }

    # Try to parse binary header
    if len(raw) >= 10 and raw[:2] == b"HI":
        try:
            _, version, cmd, length = struct.unpack(">2sHHI", raw[:10])
            result["cmd_code"] = cmd
            payload_body = raw[10:10 + length]

            if cmd == CMD_LOGIN:
                result["attack_type"]  = "hik_sdk_auth"
                result["threat_level"] = "high"
                result["notes"].append(f"SDK LOGIN attempt (cmd=0x{cmd:04x})")
                # Try to extract credentials from XML body
                um = re.search(rb"<userName>(.*?)</userName>", payload_body, re.DOTALL)
                pm = re.search(rb"<password>(.*?)</password>",  payload_body, re.DOTALL)
                if um: result["username"] = um.group(1).decode(errors="ignore")[:64]
                if pm: result["password"] = pm.group(1).decode(errors="ignore")[:64]

            elif cmd == CMD_UPGRADE_FW:
                result["attack_type"]  = "hik_sdk_firmware_inject"
                result["threat_level"] = "critical"
                result["notes"].append("SDK FIRMWARE UPGRADE attempted — possible implant")

            elif cmd == CMD_SET_CONFIG:
                result["attack_type"]  = "hik_sdk_config_write"
                result["threat_level"] = "critical"
                result["notes"].append("SDK SET_CONFIG — possible persistent backdoor")

            elif cmd == CMD_REBOOT:
                result["attack_type"]  = "hik_sdk_reboot"
                result["threat_level"] = "high"
                result["notes"].append("SDK REBOOT command sent")

            elif cmd == CMD_ADD_USER:
                result["attack_type"]  = "hik_sdk_add_user"
                result["threat_level"] = "critical"
                result["notes"].append("SDK ADD_USER — backdoor account creation attempt")

        except struct.error:
            pass

    # SADP probe
    elif len(raw) >= 2 and raw[:2] == b"\x20\x00":
        result["attack_type"]  = "sadp_discovery"
        result["threat_level"] = "low"
        result["notes"].append("SADP device discovery probe")

    # HTTP-style exploit embedded in SDK port (CVE-2021-36260 style)
    elif raw[:3] in (b"GET", b"PUT", b"POS", b"DEL"):
        result["attack_type"]  = "hik_http_on_sdk_port"
        result["threat_level"] = "critical"
        result["notes"].append("HTTP exploit attempt on SDK port")

    # Auth bypass probe (CVE-2017-7921)
    if b"YWRtaW4" in raw or b"auth=0" in raw or b"backdoor" in raw.lower():
        result["attack_type"]  = "hik_auth_bypass"
        result["threat_level"] = "critical"
        result["notes"].append("CVE-2017-7921 auth bypass token detected")

    # webLanguage RCE (CVE-2021-36260)
    if b"webLanguage" in raw or b"mxml" in raw or b"<language>" in raw:
        result["attack_type"]  = "hik_weblanguage_rce"
        result["threat_level"] = "critical"
        result["notes"].append("CVE-2021-36260 webLanguage RCE payload detected")

    # Fuzzing / overflow
    if len(raw) > 2048:
        result["notes"].append(f"Oversized payload ({len(raw)} bytes) — possible overflow")
        result["threat_level"] = "critical"

    return result


# ─── Fake credentials that are accepted (honeytoken bait) ───────────────────

_BAIT_CREDS = {
    ("admin", "12345"),
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "Admin@2024"),
    ("root",  "root"),
    ("guest", "guest"),
}

def _credential_accepted(username: str, password: str) -> bool:
    return (username, password) in _BAIT_CREDS


# ─── Main handler ────────────────────────────────────────────────────────────

def handle_hik_sdk(
    conn,
    addr,
    log_attack,
    geoip_func,
    intel_fields_func,
    new_ip_alert,
    check_botnet=None,
    check_honeytoken_cred=None,
    check_cve=None,
    inc_counter=None,
    alert_funcs=None,
    dest_port=8200,             # FIX: accept dest_port so it is not hardcoded
):
    """
    Full Hikvision SDK / SADP honeypot handler.

    Called by the thin wrapper in honeypot.py which injects all helper
    functions. conn is an accepted TCP socket.
    """
    ip, port = addr
    gdata    = geoip_func(ip)
    session_token = _random_session_token()
    alert_funcs   = alert_funcs or {}

    # FIX: _ts_iso defined BEFORE _log so the closure reference is clear
    # (Python late-binding makes the original work, but this is less confusing)
    def _ts_iso():
        return datetime.datetime.utcnow().isoformat()

    def _log(attack_type, threat_level, extra=None):
        entry = {
            "timestamp":    _ts_iso(),
            "source_ip":    ip,
            "source_port":  port,
            "dest_port":    dest_port,   # FIX: was hardcoded 8200
            "service":      "hik_sdk",
            "protocol":     "TCP",
            "attack_type":  attack_type,
            "threat_level": threat_level,
            "country":      gdata.get("country", "Unknown"),
            "city":         gdata.get("city", ""),
            "latitude":     gdata.get("latitude", 0.0),
            "longitude":    gdata.get("longitude", 0.0),
            **intel_fields_func(gdata),
        }
        if extra:
            entry.update(extra)
        log_attack(entry)

    authenticated    = False
    frames_received  = 0
    all_payloads     = []

    try:
        # ── Phase 1: Banner / Greeting ────────────────────────────────────
        # Real Hikvision SDK servers send nothing first — they wait for the
        # client's probe. Some older firmware sends a 4-byte version banner.
        # We mimic the older style to attract more scanners.
        time.sleep(random.uniform(0.05, 0.15))   # realistic processing delay
        banner = struct.pack(">4sHH", b"HISC", 0x0601, 0x0001)  # version banner
        conn.sendall(banner)

        conn.settimeout(20)

        while frames_received < 30:
            # ── Phase 2: Receive client frame ─────────────────────────────
            try:
                raw = conn.recv(8192)
            except socket.timeout:
                break
            if not raw:
                break

            frames_received += 1
            all_payloads.append(raw[:512])

            # ── Phase 3: Classify & detect ────────────────────────────────
            classification = _classify_payload(raw)

            # FIX: use injected check_cve if available, fall back to local _detect_cve
            if check_cve:
                cve_id, cve_info = check_cve(raw, "hik_sdk")
                # check_cve returns (id, dict) where dict has "name"/"severity" keys
                # but honeypot.py's _check_cve returns (id, cve) where cve has those.
                # Normalise to the same shape _detect_cve returns.
                if cve_id and cve_info and "name" not in cve_info:
                    cve_info = {
                        "name":     cve_info.get("description", cve_id),
                        "severity": cve_info.get("severity", "high"),
                    }
            else:
                cve_id, cve_info = _detect_cve(raw)

            tool = _detect_tool(raw)

            attack_type  = classification["attack_type"]
            threat_level = classification["threat_level"]
            cmd_code     = classification["cmd_code"]
            username     = classification.get("username", "")
            password     = classification.get("password", "")
            notes        = "; ".join(classification["notes"])

            # ── CVE hit ───────────────────────────────────────────────────
            if cve_id:
                threat_level = "critical"
                if inc_counter:
                    inc_counter("cves")
                _log(f"cve_{cve_id}", "critical", {
                    "cve_id":   cve_id,
                    "payload":  raw[:300].hex(),
                    "notes":    cve_info["name"] if cve_info else cve_id,
                })
                cve_alert = alert_funcs.get("cve_exploit")
                if cve_alert and cve_info:
                    cve_alert(
                        ip, gdata.get("country", ""), cve_id,
                        cve_info.get("name", cve_id),
                        cve_info.get("severity", "high"),
                        "hik_sdk", raw[:80].hex(),
                    )

            # ── Botnet credential check ───────────────────────────────────
            is_bot = False
            if username and check_botnet:
                is_bot = check_botnet(username, password)
                if is_bot:
                    if inc_counter:
                        inc_counter("botnets")
                    botnet_alert = alert_funcs.get("botnet_cred")
                    if botnet_alert:
                        botnet_alert(ip, gdata.get("country", ""), "hik_sdk", username, password)

            # ── Honeytoken credential check ───────────────────────────────
            is_ht, ht_val = False, ""
            if check_honeytoken_cred and username:
                is_ht, ht_val = check_honeytoken_cred(username, password)
                if is_ht:
                    if inc_counter:
                        inc_counter("honeytokens")
                    ht_alert = alert_funcs.get("honeytoken")
                    if ht_alert:
                        ht_alert(ip, gdata.get("country", ""), "SDK_CRED", ht_val, "hik_sdk")
                    threat_level = "critical"

            # ── Main log entry ────────────────────────────────────────────
            _log(attack_type, threat_level, {
                "payload":      raw[:300].hex(),
                "raw_text":     raw[:300].decode(errors="replace"),
                "username":     username,
                "password":     password,
                "scanner_tool": tool,
                "notes":        notes,
                "sdk_cmd":      f"0x{cmd_code:04x}" if cmd_code is not None else "",
                "is_botnet":    is_bot,
                "cve_id":       cve_id or "",
            })
            new_ip_alert(ip, gdata.get("country", "Unknown"), gdata.get("city", ""), "hik_sdk")

            # ── Phase 4: Respond realistically ───────────────────────────
            time.sleep(random.uniform(0.03, 0.12))  # simulate processing

            # SADP discovery probe → send SADP XML response
            if attack_type == "sadp_discovery":
                conn.sendall(_build_sadp_response())
                break  # SADP is one-shot

            # If client sent 'HI' SDK open → respond with session hello
            if raw[:2] == b"HI" and cmd_code is None:
                conn.sendall(_build_sdk_hello(session_token))
                continue

            # Auth / login attempt
            if cmd_code == CMD_LOGIN or attack_type == "hik_sdk_auth":
                if inc_counter:
                    inc_counter("logins")
                if _credential_accepted(username, password) or is_ht or is_bot:
                    # Appear to accept — then ghost after a few frames
                    authenticated = True
                    conn.sendall(_build_auth_ok(session_token))
                else:
                    # Realistic multi-attempt: reject first, then accept on retry
                    if frames_received <= 2:
                        conn.sendall(_build_auth_fail())
                    else:
                        authenticated = True
                        conn.sendall(_build_auth_ok(session_token))
                continue

            # Keepalive
            if cmd_code == CMD_KEEPALIVE or raw == MAGIC_PING:
                conn.sendall(_build_keepalive_ack())
                continue

            # Config read
            if cmd_code == CMD_GET_CONFIG:
                if authenticated:
                    conn.sendall(_build_config_response())
                else:
                    conn.sendall(_build_auth_fail())
                continue

            # Device info requests (HTTP-style on SDK port)
            if b"deviceInfo" in raw or b"DeviceInfo" in raw:
                body = _build_device_info_xml()
                resp = _build_sdk_response(CMD_GET_CONFIG, body)
                conn.sendall(resp)
                continue

            # Firmware upgrade attempt → log as critical, stall attacker
            if cmd_code == CMD_UPGRADE_FW or b"upgrade" in raw.lower():
                # Stall to waste attacker time, then send a fake busy response
                time.sleep(random.uniform(1.5, 3.0))
                body = (
                    b"<?xml version='1.0'?><ResponseStatus>"
                    b"<statusCode>406</statusCode>"
                    b"<statusString>Device Busy</statusString>"
                    b"<subStatusCode>upgrading</subStatusCode>"
                    b"</ResponseStatus>"
                )
                conn.sendall(_build_sdk_response(CMD_UPGRADE_FW, body, status=0x0006))
                continue

            # Reboot command
            if cmd_code == CMD_REBOOT:
                body = (
                    b"<?xml version='1.0'?><ResponseStatus>"
                    b"<statusCode>200</statusCode>"
                    b"<statusString>OK</statusString>"
                    b"</ResponseStatus>"
                )
                conn.sendall(_build_sdk_response(CMD_REBOOT, body))
                time.sleep(0.5)
                break  # close after fake reboot

            # Add-user backdoor attempt
            if cmd_code == CMD_ADD_USER:
                body = (
                    b"<?xml version='1.0'?><ResponseStatus>"
                    b"<statusCode>403</statusCode>"
                    b"<statusString>Forbidden</statusString>"
                    b"<subStatusCode>lowPrivilege</subStatusCode>"
                    b"</ResponseStatus>"
                )
                conn.sendall(_build_sdk_response(CMD_ADD_USER, body, status=0x0403))
                continue

            # CVE-2021-36260 webLanguage payload → respond like vulnerable firmware
            if b"webLanguage" in raw or b"mxml" in raw:
                # Vulnerable firmware would return 200 OK; we mimic it to capture the payload
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n"
                    b"Content-Length: 82\r\n\r\n"
                    b"<?xml version='1.0'?><ResponseStatus><statusCode>200</statusCode>"
                    b"<statusString>OK</statusString></ResponseStatus>"
                )
                continue

            # HTTP GET/PUT on wrong port (common scanner mistake)
            if raw[:3] in (b"GET", b"PUT", b"POS", b"DEL"):
                conn.sendall(
                    b"HTTP/1.1 401 Unauthorized\r\n"
                    b'WWW-Authenticate: Digest realm="DS-2CD2043G2-I"\r\n'
                    b"Content-Length: 0\r\n\r\n"
                )
                continue

            # Fallback: generic SDK error
            body = (
                b"<?xml version='1.0' encoding='utf-8'?>"
                b"<ResponseStatus version='1.0'>"
                b"<statusCode>500</statusCode>"
                b"<statusString>Bad Request</statusString>"
                b"<subStatusCode>unknownCommand</subStatusCode>"
                b"</ResponseStatus>"
            )
            conn.sendall(_build_sdk_response(0xFFFF, body, status=0x0500))

    except (ConnectionResetError, BrokenPipeError, socket.timeout):
        pass
    except Exception:
        # Swallow silently — honeypot must never crash on attacker input
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass