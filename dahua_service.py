#!/usr/bin/env python3
"""
dahua_service.py — Dahua DVR/NVR proprietary protocol honeypot (port 37777)

Emulates the Dahua private protocol used by millions of DVRs and NVRs worldwide.
Targeted by:
  - CVE-2021-33044  Unauthenticated RCE (auth bypass via NULL username)
  - CVE-2021-33045  Username enumeration / credential bypass
  - CVE-2022-30563  Authentication replay attack
  - Dedicated Dahua scanners (dhscan, dahua-pwn, Satori variant)

Protocol: binary header (20 bytes) + JSON body
  Header layout (little-endian):
    0xFF 0x01       magic
    session_id[4]   assigned by server on login
    unknown[4]      always 0x00 in responses
    sequence[4]     echoed from request
    total_len[4]    length of JSON body
  Body: UTF-8 JSON
"""

import socket
import struct
import json
import random
import datetime
import re

_DEVICE_MODEL   = "DHI-NVR4104HS-P-4KS2/L"
_DEVICE_SERIAL  = "2L0610DAZ00002A"
_FIRMWARE       = "V2.820.0000000.18.R, Build Date: 2021-08-18"
_DEVICE_TYPE    = "NVR"
_VENDOR         = "Dahua"
_MAC            = "3c:ef:8c:4a:1b:22"

_DAHUA_MAGIC    = bytes([0xFF, 0x01])

# Weak credentials that the device accepts (honeytoken bait)
_WEAK_CREDS = {
    ("admin",   ""),
    ("admin",   "admin"),
    ("admin",   "12345"),
    ("admin",   "888888"),
    ("admin",   "Admin@2024"),
    ("default", "tluafed"),
    ("888888",  "888888"),
    ("666666",  "666666"),
}


def _ts():
    return datetime.datetime.utcnow().isoformat()


def _session_id():
    return random.randint(0x10000000, 0x7FFFFFFF)


def _build_response(session: int, sequence: int, body: dict) -> bytes:
    """Pack a Dahua binary header + JSON body."""
    body_bytes = json.dumps(body, separators=(',', ':')).encode()
    header = struct.pack(
        "<2sIIII",
        _DAHUA_MAGIC,
        session,
        0x00000000,   # unknown
        sequence,
        len(body_bytes),
    )
    return header + body_bytes


def _parse_frame(data: bytes):
    """
    Parse one Dahua frame from raw bytes.
    Returns (session, sequence, body_dict) or None.
    """
    if len(data) < 20:
        return None
    try:
        magic, session, unknown, sequence, body_len = struct.unpack_from("<2sIIII", data, 0)
        if magic != _DAHUA_MAGIC:
            # Also handle 0xFF 0x00 variant
            if data[:2] != bytes([0xFF, 0x00]):
                return None
        body_raw = data[20: 20 + body_len]
        if not body_raw:
            return session, sequence, {}
        # JSON may be padded with NULLs
        body_str = body_raw.rstrip(b"\x00").decode(errors="ignore")
        body = json.loads(body_str) if body_str.strip() else {}
        return session, sequence, body
    except Exception:
        return None


def handle_dahua(conn, addr, log_attack=None, geoip_func=None,
                 intel_fields_func=None, new_ip_alert=None, inc_counter=None,
                 log_honeytoken=None):
    ip, src_port = addr
    gdata   = geoip_func(ip) if geoip_func else {}
    country = gdata.get("country", "Unknown")
    city    = gdata.get("city", "")
    session = _session_id()
    seq     = 0

    def _log(attack_type, threat="medium", extra=None):
        if not log_attack:
            return
        entry = {
            "timestamp":    _ts(),
            "source_ip":    ip,
            "source_port":  src_port,
            "dest_port":    37777,
            "service":      "dahua",
            "protocol":     "TCP",
            "attack_type":  attack_type,
            "threat_level": threat,
            "country":      country,
            "city":         city,
            "latitude":     gdata.get("latitude", 0.0),
            "longitude":    gdata.get("longitude", 0.0),
        }
        if intel_fields_func:
            entry.update(intel_fields_func(gdata))
        if extra:
            entry.update(extra)
        try:
            log_attack(entry)
        except Exception:
            pass

    if new_ip_alert:
        try:
            new_ip_alert(ip, country, city, "dahua")
        except Exception:
            pass
    if inc_counter:
        try:
            inc_counter("sessions")
        except Exception:
            pass

    _log("dahua_connect", "low")

    try:
        conn.settimeout(30)
        authenticated = False

        # Real Dahua scanners (dhscan, dahua-pwn, Satori) send the login frame
        # immediately on connect WITHOUT waiting for a server greeting.
        # Strategy: peek for an incoming frame within 2s; if nothing arrives,
        # fall back to sending our greeting (for tools that do wait for server-first).
        greeting = _build_response(session, 0, {
            "Ret": 100,
            "SessionID": f"0x{session:08X}",
            "AliveInterval": 20,
            "ChannelNum": 4,
            "DeviceType ": _DEVICE_TYPE,
            "ExtraChannel": 0,
        })
        conn.settimeout(2)
        try:
            first = conn.recv(8192)
        except socket.timeout:
            first = None
        conn.settimeout(30)

        # Send greeting regardless — real devices also send it
        conn.sendall(greeting)

        # Re-inject the first frame if we got one so the main loop processes it
        pending = [first] if first else []

        while True:
            if pending:
                raw = pending.pop(0)
            else:
                try:
                    raw = conn.recv(8192)
                except socket.timeout:
                    break
            if not raw:
                break

            parsed = _parse_frame(raw)
            if parsed is None:
                # Might be a plain-text or HTTP probe
                text = raw[:8].decode(errors="ignore")
                if text.startswith(("GET ", "POST", "HEAD")):
                    conn.sendall(
                        b"HTTP/1.1 401 Unauthorized\r\n"
                        b"WWW-Authenticate: Digest realm=\"Dahua NVR\"\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    _log("dahua_http_probe", "low")
                break

            client_session, client_seq, body = parsed
            cmd = body.get("LoginType") or body.get("Name") or body.get("OPTalk") or body.get("OPTimeSetting") or ""

            # ── LOGIN ──────────────────────────────────────────────────────
            if "UserName" in body or "Name" in body:
                username = body.get("UserName") or body.get("Name") or ""
                password = body.get("PassWord") or body.get("Password") or ""
                enc_type = body.get("EncryptType", "")

                # CVE-2021-33044: NULL byte auth bypass
                if "\x00" in username or username.strip() == "":
                    authenticated = True
                    _log("dahua_cve_2021_33044", "critical", {
                        "username": repr(username),
                        "password": repr(password),
                        "cve_id":   "CVE-2021-33044",
                        "payload":  f"NULL-byte auth bypass user={repr(username)} enc={enc_type}",
                    })
                elif (username, password) in _WEAK_CREDS or (username, "") in _WEAK_CREDS:
                    authenticated = True
                    _log("dahua_login_success", "high", {
                        "username": username,
                        "password": password,
                        "payload":  f"login_ok user={username} pass={password} enc={enc_type}",
                    })
                else:
                    _log("dahua_login_fail", "medium", {
                        "username": username,
                        "password": password,
                        "payload":  f"login_fail user={username} pass={password} enc={enc_type}",
                    })

                if authenticated:
                    conn.sendall(_build_response(session, client_seq, {
                        "Ret": 100,
                        "SessionID": f"0x{session:08X}",
                        "AliveInterval": 20,
                        "ChannelNum": 4,
                        "DeviceType ": _DEVICE_TYPE,
                        "ExtraChannel": 0,
                        "Ret": 100,
                    }))

                    # Send device info follow-up
                    info = _build_response(session, client_seq + 1, {
                        "Ret": 100,
                        "AlarmChnNum": 0,
                        "BuildDate": "2021-08-18",
                        "DeviceRunTime": "0x0012b5c0",
                        "DeviceType ": _DEVICE_TYPE,
                        "HardWareVersion": "V1.00",
                        "MACADDR": _MAC,
                        "NFONum": 0,
                        "ProductDefinition": "StandardDigital",
                        "SerialNo": _DEVICE_SERIAL,
                        "SoftWareVersion": _FIRMWARE,
                        "SystemName": "IPC",
                    })
                    conn.sendall(info)
                else:
                    conn.sendall(_build_response(session, client_seq, {
                        "Ret": 205,  # Wrong password
                        "SessionID": "0x00000000",
                    }))

            # ── CONFIG READ (CVE-2022-30563 replay style) ─────────────────
            elif "OPMachine" in body or "SystemInfo" in body:
                if authenticated:
                    conn.sendall(_build_response(session, client_seq, {
                        "Ret": 100,
                        "OPMachine": {
                            "Action": "Get",
                            "Machine": {
                                "DeviceID": _DEVICE_SERIAL,
                                "DeviceName": "NVR4104HS",
                                "Note": "",
                                "Language": "English",
                                "VideoStandard": "PAL",
                            }
                        }
                    }))
                    _log("dahua_config_read", "high")
                else:
                    conn.sendall(_build_response(session, client_seq, {"Ret": 401}))

            # ── FIRMWARE UPGRADE ──────────────────────────────────────────
            elif "OPSystemUpgrade" in body or "Upgrade" in str(body):
                _log("dahua_firmware_upgrade", "critical", {
                    "notes": "Firmware upgrade attempted — possible implant injection",
                })
                conn.sendall(_build_response(session, client_seq, {
                    "Ret": 100,
                    "OPSystemUpgrade": {"Action": "Start", "State": "Upgrading"},
                }))

            # ── KEEPALIVE ─────────────────────────────────────────────────
            elif "OPKeepAlive" in body:
                conn.sendall(_build_response(session, client_seq, {
                    "Ret": 100,
                    "OPKeepAlive": {"Action": "Keep", "Param": {"SessionID": f"0x{session:08X}"}},
                }))

            # ── LOGOUT ────────────────────────────────────────────────────
            elif "OPLogout" in body:
                conn.sendall(_build_response(session, client_seq, {"Ret": 100}))
                break

            # ── UNKNOWN ───────────────────────────────────────────────────
            else:
                conn.sendall(_build_response(session, client_seq, {"Ret": 100}))
                _log("dahua_unknown_cmd", "medium", {"payload": str(body)[:200]})

            seq += 1

    except (ConnectionResetError, BrokenPipeError, socket.timeout):
        pass
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
