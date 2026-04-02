#!/usr/bin/env python3
"""
xmeye_service.py — HiSilicon/XMEye DVR protocol honeypot (port 34567)

Emulates the XMEye/CamHi/Sofia protocol used by tens of millions of cheap
OEM IP cameras, NVRs, and DVRs built on HiSilicon chips.
Common brands: Annke, ZOSI, Reolink OEM, LaView, etc.

Targeted by:
  - Satori botnet (HiSilicon exploit)
  - CVE-2018-10088  Stack overflow in XMEye login
  - CVE-2020-25173  Unauthenticated remote code execution
  - Generic DVR scanners (dvr-scan, xmeye-pwn)

Protocol: 20-byte binary header + JSON body
  Header (little-endian):
    flag[2]        0xFF 0x01
    version[1]     0x00
    session[4]     server-assigned session ID
    sequence[4]    echoed
    channel[1]     0x00
    end_flag[1]    0x00
    msg_id[2]      command identifier
    data_len[4]    JSON body length
"""

import socket
import struct
import json
import random
import datetime
import hashlib

# XMEye message IDs
MSG_LOGIN_REQ   = 1000
MSG_LOGIN_RESP  = 1000
MSG_LOGOUT      = 1001
MSG_KEEPALIVE   = 1006
MSG_SYSINFO_REQ = 1020
MSG_SYSINFO_RSP = 1020
MSG_CONFIG_GET  = 1042
MSG_CONFIG_SET  = 1040
MSG_UPGRADE     = 0x5F5

_DEVICE_MODEL   = "HI3518E_50H10L_S38"
_DEVICE_SERIAL  = "66H25856YADFF1234"
_FIRMWARE       = "V4.02.R11.00000117.10010.040.0000000"
_HARDWARE       = "1.00"
_DEVICE_NAME    = "IPC"
_MAC            = "1c:c0:e1:55:30:ab"

_HEADER_MAGIC   = bytes([0xFF, 0x01])

# Weak credentials
_WEAK_CREDS = {
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "xmeyeadmin"),
    ("default", ""),
    ("888888", "888888"),
    ("666666", "666666"),
    ("admin", "12345"),
}


def _ts():
    return datetime.datetime.utcnow().isoformat()


def _sofia_md5(password: str) -> str:
    """Sofia/XMEye password hashing (MD5 with specific uppercase truncation)."""
    raw = hashlib.md5(password.encode()).hexdigest().upper()
    # Sofia uses first 8 chars of every other pair
    return "".join(raw[i] for i in range(0, 16, 2))


def _build_frame(session: int, sequence: int, msg_id: int, body: dict) -> bytes:
    body_bytes = json.dumps(body, separators=(',', ':')).encode() + b"\x0a\x00"
    header = struct.pack(
        "<2sBIIBBHI",
        _HEADER_MAGIC,  # flag
        0x00,           # version
        session,        # session id
        sequence,       # sequence
        0x00,           # channel
        0x00,           # end flag
        msg_id,         # message id
        len(body_bytes),
    )
    return header + body_bytes


def _parse_frame(data: bytes):
    """Parse XMEye frame. Returns (session, sequence, msg_id, body_dict) or None."""
    if len(data) < 20:
        return None
    try:
        flag, version, session, sequence, channel, end, msg_id, data_len = struct.unpack_from(
            "<2sBIIBBHI", data, 0
        )
        if flag != _HEADER_MAGIC:
            return None
        body_raw = data[20: 20 + data_len]
        body_str = body_raw.rstrip(b"\x00\x0a").decode(errors="ignore")
        body = json.loads(body_str) if body_str.strip() else {}
        return session, sequence, msg_id, body
    except Exception:
        return None


def handle_xmeye(conn, addr, log_attack=None, geoip_func=None,
                 intel_fields_func=None, new_ip_alert=None, inc_counter=None,
                 log_honeytoken=None):
    ip, src_port = addr
    gdata   = geoip_func(ip) if geoip_func else {}
    country = gdata.get("country", "Unknown")
    city    = gdata.get("city", "")
    session = random.randint(0x1000, 0x7FFF)

    def _log(attack_type, threat="medium", extra=None):
        if not log_attack:
            return
        entry = {
            "timestamp":    _ts(),
            "source_ip":    ip,
            "source_port":  src_port,
            "dest_port":    34567,
            "service":      "xmeye",
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
            new_ip_alert(ip, country, city, "xmeye")
        except Exception:
            pass
    if inc_counter:
        try:
            inc_counter("sessions")
        except Exception:
            pass

    _log("xmeye_connect", "low")

    try:
        conn.settimeout(30)
        authenticated = False
        seq = 0

        # XMeye/Sofia scanners send MSG_LOGIN_REQ immediately on connect.
        # Some tools wait for a server banner first — peek for 2s; if nothing
        # arrives send a challenge frame so they respond with credentials.
        _challenge = _build_frame(session, 0, MSG_LOGIN_REQ, {
            "EncryptType": "MD5",
            "LoginType":   "DVRIP-Web",
            "PassWord":    "",
            "UserName":    "",
        })
        conn.settimeout(2)
        try:
            first = conn.recv(8192)
        except socket.timeout:
            first = None
        conn.settimeout(30)
        conn.sendall(_challenge)
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

            # Handle HTTP probes on wrong port
            if raw[:3] in (b"GET", b"POS", b"HEA"):
                conn.sendall(
                    b"HTTP/1.1 404 Not Found\r\n"
                    b"Server: XMEye-Webs/3.0\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                _log("xmeye_http_probe", "low")
                break

            parsed = _parse_frame(raw)
            if parsed is None:
                # Log raw bytes for unknown/partial frames
                _log("xmeye_raw_probe", "low", {
                    "payload": raw[:200].hex(),
                    "raw_payload": raw[:200].decode(errors="replace"),
                })
                break

            client_session, client_seq, msg_id, body = parsed

            # ── LOGIN ─────────────────────────────────────────────────────
            if msg_id == MSG_LOGIN_REQ and ("UserName" in body or "Name" in body):
                username = body.get("UserName") or body.get("Name") or ""
                password = body.get("PassWord") or body.get("Password") or ""
                enc_type = body.get("EncryptType", "")
                login_type = body.get("LoginType", "")
                guid = body.get("GUID", "")

                # Accept weak creds and empty password (massive class of vulnerable devices)
                if (username, password) in _WEAK_CREDS or (username, "") in _WEAK_CREDS:
                    authenticated = True
                    conn.sendall(_build_frame(session, client_seq, MSG_LOGIN_RESP, {
                        "AliveInterval": 20,
                        "ChannelNum": 4,
                        "DataUseAES": False,
                        "DeviceType": _DEVICE_NAME,
                        "ExtraChannel": 0,
                        "Ret": 100,
                        "SessionID": f"0x{session:08X}",
                    }))
                    _log("xmeye_login_success", "high", {
                        "username":   username,
                        "password":   password,
                        "payload":    f"login_ok user={username} pass={password} type={login_type} enc={enc_type}",
                    })
                else:
                    # Log and reject — keep connection open for continued attempts
                    conn.sendall(_build_frame(session, client_seq, MSG_LOGIN_RESP, {
                        "Ret": 205,
                        "SessionID": "0x00000000",
                    }))
                    _log("xmeye_login_fail", "medium", {
                        "username":   username,
                        "password":   password,
                        "payload":    f"login_fail user={username} pass={password} enc={enc_type}",
                    })

            # ── SYSTEM INFO ───────────────────────────────────────────────
            elif msg_id == MSG_SYSINFO_REQ and ("OPMachine" in body or "SystemFunction" in body):
                if authenticated:
                    conn.sendall(_build_frame(session, client_seq, MSG_SYSINFO_RSP, {
                        "Ret": 100,
                        "OPMachine": {
                            "AlarmInChannel": 4,
                            "AlarmOutChannel": 1,
                            "AudioInChannel": 1,
                            "BuildDate": "2021-03-11",
                            "CombineSwitch": 0,
                            "DeviceID": _DEVICE_SERIAL,
                            "DeviceName": _DEVICE_NAME,
                            "DeviceRunTime": "0x00189640",
                            "DeviceType": 50,
                            "DigChannel": 0,
                            "EncryptVersion": "Initial",
                            "ExtraChannel": 0,
                            "HardWareVersion": _HARDWARE,
                            "MACADDR": _MAC,
                            "NFONum": 0,
                            "NorChannel": 4,
                            "OtherFunction": "",
                            "ProductDefinition": "Xmeye",
                            "SerialNo": _DEVICE_SERIAL,
                            "SoftWareVersion": _FIRMWARE,
                            "UpdataTime": "2021-03-11 08:00:00",
                            "UpdataType": "0x00000001",
                            "VideoInChannel": 4,
                            "VideoOutChannel": 1,
                        }
                    }))
                    _log("xmeye_sysinfo", "medium")
                else:
                    conn.sendall(_build_frame(session, client_seq, MSG_SYSINFO_RSP, {"Ret": 401}))

            # ── CONFIG GET ────────────────────────────────────────────────
            elif msg_id == MSG_CONFIG_GET:
                if authenticated:
                    conn.sendall(_build_frame(session, client_seq, MSG_CONFIG_GET + 1, {
                        "Ret": 100,
                        "Name": body.get("Name", ""),
                        "OPNetWork.NetCommon": {
                            "DomainName2": "www.xmeye.net",
                            "GateWay": "192.168.1.1",
                            "HostIP": "192.168.1.108",
                            "HostName": "LocalHost",
                            "HttpPort": 80,
                            "MAC": _MAC,
                            "MediaPort": 34568,
                            "SSLPort": 443,
                            "SubMask": "255.255.255.0",
                            "TCPMaxConn": 128,
                            "TCPPort": 34567,
                            "UDPPort": 34568,
                        },
                    }))
                    _log("xmeye_config_read", "medium")
                else:
                    conn.sendall(_build_frame(session, client_seq, MSG_CONFIG_GET + 1, {"Ret": 401}))

            # ── CONFIG SET ────────────────────────────────────────────────
            elif msg_id == MSG_CONFIG_SET:
                conn.sendall(_build_frame(session, client_seq, MSG_CONFIG_SET + 1, {"Ret": 100}))
                _log("xmeye_config_write", "critical", {
                    "notes": "Config write — possible backdoor installation",
                    "payload": str(body)[:200],
                })

            # ── FIRMWARE UPGRADE ──────────────────────────────────────────
            elif msg_id == MSG_UPGRADE or "Upgrade" in str(body):
                conn.sendall(_build_frame(session, client_seq, MSG_UPGRADE, {
                    "Ret": 100,
                    "Status": "Upgrading",
                }))
                _log("xmeye_firmware_upgrade", "critical", {
                    "notes": "Firmware upgrade — possible implant injection",
                })

            # ── KEEPALIVE ─────────────────────────────────────────────────
            elif msg_id == MSG_KEEPALIVE:
                conn.sendall(_build_frame(session, client_seq, MSG_KEEPALIVE, {
                    "Ret": 100,
                    "Name": "KeepAlive",
                }))

            # ── LOGOUT ────────────────────────────────────────────────────
            elif msg_id == MSG_LOGOUT:
                conn.sendall(_build_frame(session, client_seq, MSG_LOGOUT, {"Ret": 100}))
                break

            # ── UNKNOWN ───────────────────────────────────────────────────
            else:
                conn.sendall(_build_frame(session, client_seq, msg_id, {"Ret": 100}))
                _log("xmeye_unknown", "low", {
                    "msg_id": msg_id,
                    "payload": str(body)[:200],
                })

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
