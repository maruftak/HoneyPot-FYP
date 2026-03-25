#!/usr/bin/env python3
"""
honeyPot — CoAP Service (RFC 7252)
Emulates a CoAP endpoint on an IoT/camera device (UDP port 5683).

Key design rule: this module NEVER calls settimeout() on the shared UDP
server socket.  The datagram has already been read by _start_udp in
honeypot.py and is passed in as the `data` parameter.  We only ever call
srv.sendto() on the socket — never recv/recvfrom.
"""

import datetime
import json
import struct
import random
import threading

# ─── CoAP constants (RFC 7252) ────────────────────────────────────────────────

COAP_VERSION      = 0x01

# Message types
TYPE_CON  = 0   # Confirmable
TYPE_NON  = 1   # Non-confirmable
TYPE_ACK  = 2   # Acknowledgement
TYPE_RST  = 3   # Reset

# Response codes  (class * 32 + detail)
CODE_EMPTY          = 0x00   # 0.00  Empty
CODE_GET            = 0x01   # 0.01
CODE_POST           = 0x02   # 0.02
CODE_PUT            = 0x03   # 0.03
CODE_DELETE         = 0x04   # 0.04

CODE_CONTENT        = 0x45   # 2.05
CODE_CHANGED        = 0x44   # 2.04
CODE_CREATED        = 0x41   # 2.01
CODE_DELETED        = 0x42   # 2.02
CODE_NOT_FOUND      = 0x84   # 4.04
CODE_METHOD_NA      = 0x85   # 4.05
CODE_UNAUTHORIZED   = 0x81   # 4.01
CODE_BAD_REQUEST    = 0x80   # 4.00
CODE_FORBIDDEN      = 0x83   # 4.03
CODE_INTERNAL_ERR   = 0xA0   # 5.00

# Content-Format option values
CF_TEXT_PLAIN       = 0
CF_LINK_FORMAT      = 40
CF_XML              = 41
CF_OCTET_STREAM     = 42
CF_EXI              = 47
CF_JSON             = 50
CF_CBOR             = 60

# Option numbers
OPT_IF_MATCH        = 1
OPT_URI_HOST        = 3
OPT_ETAG            = 4
OPT_IF_NONE_MATCH   = 5
OPT_OBSERVE         = 6
OPT_URI_PORT        = 7
OPT_LOCATION_PATH   = 8
OPT_URI_PATH        = 11
OPT_CONTENT_FORMAT  = 12
OPT_MAX_AGE         = 14
OPT_URI_QUERY       = 15
OPT_ACCEPT          = 17
OPT_LOCATION_QUERY  = 20
OPT_PROXY_URI       = 35
OPT_PROXY_SCHEME    = 39
OPT_SIZE1           = 60

# ─── Fake IoT resources ───────────────────────────────────────────────────────

# Resource link format for .well-known/core
_WELL_KNOWN_CORE = (
    '</>;rt="oma.lwm2m",</1/0>;rt="oma.lwm2m.server",'
    '</3/0>;rt="oma.lwm2m.device",</3303/0>;rt="oma.lwm2m.temperature",'
    '</3304/0>;rt="oma.lwm2m.humidity",</3312/0>;rt="oma.lwm2m.power",'
    '</camera/status>;rt="camera.status";ct=50,'
    '</camera/config>;rt="camera.config";ct=50,'
    '</camera/stream>;rt="camera.stream",'
    '</firmware/version>;rt="firmware",'
    '</sys/info>;rt="sys.info";ct=50'
)

_RESOURCES: dict = {
    "/.well-known/core": (CF_LINK_FORMAT, _WELL_KNOWN_CORE),

    "/camera/status": (CF_JSON, json.dumps({
        "device":   "DS-2CD2043G2-I",
        "firmware": "V5.7.15 build 230313",
        "status":   "online",
        "uptime":   86423,
        "stream":   "rtsp://192.168.1.108:554/Streaming/Channels/101",
        "motion":   False,
        "ir_cut":   True,
    })),

    "/camera/config": (CF_JSON, json.dumps({
        "resolution": "2688x1520",
        "fps":        20,
        "bitrate":    4096,
        "codec":      "H.265+",
        "auth":       "digest",
        "admin_user": "admin",
    })),

    "/camera/stream": (CF_TEXT_PLAIN,
        "rtsp://192.168.1.108:554/Streaming/Channels/101"),

    "/firmware/version": (CF_TEXT_PLAIN, "V5.7.15 build 230313"),

    "/sys/info": (CF_JSON, json.dumps({
        "model":     "DS-2CD2043G2-I",
        "mac":       "44:19:B6:7A:2C:D9",
        "serial":    "DS-2CD2043G2-I20230313CCCH012345678",
        "cpu_load":  12,
        "mem_free":  62144,
    })),

    # LwM2M-style object paths
    "/1/0": (CF_TEXT_PLAIN, "LwM2M Server Object"),
    "/3/0": (CF_JSON, json.dumps({
        "manufacturer":   "Hikvision",
        "model_number":   "DS-2CD2043G2-I",
        "serial_number":  "DS-2CD2043G2-I20230313CCCH012345678",
        "firmware":       "V5.7.15 build 230313",
        "power_sources":  [0],
        "battery_level":  100,
        "memory_free":    62144,
    })),
    "/3303/0": (CF_JSON, json.dumps({"sensor_value": 28.4, "units": "Cel"})),
    "/3304/0": (CF_JSON, json.dumps({"sensor_value": 55.2, "units": "%RH"})),
    "/3312/0": (CF_JSON, json.dumps({"on_off": True,  "dimmer": 100})),
}

# Paths that should trigger honeytoken alerts
_SENSITIVE_PATHS = {
    "/camera/config",
    "/sys/info",
    "/firmware/update",
    "/admin",
    "/config",
    "/.env",
    "/credentials",
    "/backup",
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.datetime.utcnow().isoformat()


def _code_str(code: int) -> str:
    c = (code >> 5) & 0x07
    d = code & 0x1F
    return f"{c}.{d:02d}"


def _type_str(t: int) -> str:
    return {TYPE_CON: "CON", TYPE_NON: "NON",
            TYPE_ACK: "ACK", TYPE_RST: "RST"}.get(t, f"T{t}")


def _method_str(code: int) -> str:
    return {0x01: "GET", 0x02: "POST",
            0x03: "PUT", 0x04: "DELETE"}.get(code, f"0x{code:02X}")


# ─── Packet parser ────────────────────────────────────────────────────────────

class CoapPacket:
    """Minimal CoAP packet parser — tolerant of malformed data."""

    def __init__(self):
        self.version    = 1
        self.msg_type   = TYPE_NON
        self.token_len  = 0
        self.code       = 0
        self.msg_id     = 0
        self.token      = b""
        self.options    = {}        # option_number -> [bytes, ...]
        self.payload    = b""
        self.uri_path   = ""
        self.uri_query  = ""
        self.valid      = False

    @classmethod
    def parse(cls, data: bytes) -> "CoapPacket":
        pkt = cls()
        if len(data) < 4:
            return pkt

        try:
            byte0 = data[0]
            pkt.version   = (byte0 >> 6) & 0x03
            pkt.msg_type  = (byte0 >> 4) & 0x03
            pkt.token_len = byte0 & 0x0F
            pkt.code      = data[1]
            pkt.msg_id    = struct.unpack_from("!H", data, 2)[0]

            offset = 4
            if pkt.token_len > 0 and offset + pkt.token_len <= len(data):
                pkt.token = data[offset: offset + pkt.token_len]
                offset   += pkt.token_len

            # Parse options
            opt_num = 0
            while offset < len(data):
                b = data[offset]
                if b == 0xFF:           # payload marker
                    offset += 1
                    pkt.payload = data[offset:]
                    break

                delta  = (b >> 4) & 0x0F
                length =  b & 0x0F
                offset += 1

                if delta == 13:
                    if offset >= len(data): break
                    delta   = data[offset] + 13;  offset += 1
                elif delta == 14:
                    if offset + 1 >= len(data): break
                    delta   = struct.unpack_from("!H", data, offset)[0] + 269; offset += 2
                elif delta == 15:
                    break   # reserved / error

                if length == 13:
                    if offset >= len(data): break
                    length  = data[offset] + 13;  offset += 1
                elif length == 14:
                    if offset + 1 >= len(data): break
                    length  = struct.unpack_from("!H", data, offset)[0] + 269; offset += 2
                elif length == 15:
                    break

                opt_num += delta
                val      = data[offset: offset + length]
                offset  += length
                pkt.options.setdefault(opt_num, []).append(val)

            # Build URI path
            path_parts = pkt.options.get(OPT_URI_PATH, [])
            pkt.uri_path = "/" + "/".join(
                p.decode("utf-8", errors="ignore") for p in path_parts
            )
            if pkt.uri_path == "/":
                pkt.uri_path = "/"

            # Build URI query string
            query_parts = pkt.options.get(OPT_URI_QUERY, [])
            pkt.uri_query = "&".join(
                q.decode("utf-8", errors="ignore") for q in query_parts
            )

            pkt.valid = True
        except Exception:
            pass

        return pkt


# ─── Packet builder ───────────────────────────────────────────────────────────

def _build_response(
    msg_type:   int,
    code:       int,
    msg_id:     int,
    token:      bytes,
    payload:    bytes = b"",
    content_fmt: int  = None,
) -> bytes:
    """Build a minimal CoAP response packet."""
    token_len = len(token)
    header = bytes([
        (COAP_VERSION << 6) | (msg_type << 4) | (token_len & 0x0F),
        code & 0xFF,
        (msg_id >> 8) & 0xFF,
        msg_id & 0xFF,
    ]) + token

    options = b""
    if content_fmt is not None and payload:
        # Option delta=12 (Content-Format), single-byte value for values < 256
        if content_fmt <= 0xFF:
            options = bytes([0xC1, content_fmt & 0xFF])
        else:
            options = bytes([0xC2,
                             (content_fmt >> 8) & 0xFF,
                              content_fmt & 0xFF])

    if payload:
        return header + options + b"\xFF" + payload
    return header + options


def _ack(msg_id: int, token: bytes, code: int,
         payload: bytes = b"", content_fmt: int = None) -> bytes:
    return _build_response(TYPE_ACK, code, msg_id, token, payload, content_fmt)


def _non(msg_id: int, token: bytes, code: int,
         payload: bytes = b"", content_fmt: int = None) -> bytes:
    return _build_response(TYPE_NON, code, msg_id, token, payload, content_fmt)


def _rst(msg_id: int) -> bytes:
    return _build_response(TYPE_RST, CODE_EMPTY, msg_id, b"")


# ─── Attack-pattern detection ─────────────────────────────────────────────────

_SUSPICIOUS_PATHS = {
    "/efi/",        "/admin",       "/root",
    "/etc/passwd",  "/.env",        "/credentials",
    "/backup",      "/firmware/update",
    "/shell",       "/cmd",         "/exec",
    "/cgi-bin",     "/system",      "/config",
}

_PAYLOAD_PATTERNS = [
    b"busybox", b"/bin/sh", b"wget ", b"curl ",
    b"chmod", b"AAAAAAAA",          # buffer-overflow padding
    b"SELECT", b"UNION",            # SQL injection attempts
    b"../", b"..\\",                # path traversal
    b"<script", b"javascript:",     # XSS
    b"\x00" * 8,                    # null-byte flooding
]


def _classify_threat(pkt: CoapPacket, payload_str: str) -> tuple[str, str]:
    """Return (attack_type, threat_level)."""
    path = pkt.uri_path.lower()
    pl   = payload_str.lower()

    if any(p.lower().decode("utf-8", errors="ignore") in pl
           for p in _PAYLOAD_PATTERNS if isinstance(p, bytes)):
        return "coap_payload_injection", "critical"

    if any(s in path for s in _SUSPICIOUS_PATHS):
        return "coap_sensitive_path", "high"

    if pkt.code in (CODE_PUT, CODE_POST, CODE_DELETE):
        if path in ("/firmware/update", "/admin", "/config"):
            return "coap_device_manipulation", "critical"
        return "coap_write_attempt", "high"

    if OPT_PROXY_URI in pkt.options or OPT_PROXY_SCHEME in pkt.options:
        return "coap_proxy_abuse", "high"

    if pkt.code == CODE_GET and path in _SENSITIVE_PATHS:
        return "coap_info_disclosure", "high"

    return "coap_probe", "low"


# ─── Main handler ─────────────────────────────────────────────────────────────

def handle_coap(
    srv_sock,
    addr,
    data:                 bytes,        # datagram already read by _start_udp
    log_attack            = None,
    geoip_func            = None,
    intel_fields_func     = None,
    new_ip_alert          = None,
    check_honeytoken_file = None,
    inc_counter           = None,
):
    """
    Handle a single CoAP datagram.

    Parameters
    ----------
    srv_sock : socket.socket
        The shared UDP server socket.  We ONLY call sendto() on it —
        never recv/recvfrom and never settimeout().
    addr : (str, int)
        Sender's (ip, port).
    data : bytes
        The datagram payload, already read by the caller.
    """
    ip, port = addr

    # ── GeoIP & counters ──────────────────────────────────────────────────────
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
    pkt = CoapPacket.parse(data)

    # If the packet is too broken to be CoAP, just drop it
    if not pkt.valid:
        _log(log_attack, {
            "timestamp":   _ts(),        "source_ip":  ip,
            "source_port": port,         "dest_port":  5683,
            "service":     "coap",       "protocol":   "UDP",
            "attack_type": "coap_malformed", "threat_level": "low",
            "payload":     data[:64].hex(),
            "country":     gdata.get("country", "Unknown"),
            "city":        gdata.get("city", ""),
            "latitude":    gdata.get("latitude", 0.0),
            "longitude":   gdata.get("longitude", 0.0),
            **intel,
        })
        if new_ip_alert:
            try: new_ip_alert(ip, gdata.get("country","Unknown"),
                              gdata.get("city",""), "coap")
            except Exception: pass
        return

    method      = _method_str(pkt.code)
    uri_path    = pkt.uri_path
    payload_str = pkt.payload.decode("utf-8", errors="ignore")
    msg_type    = pkt.msg_type
    msg_id      = pkt.msg_id
    token       = pkt.token

    attack_type, threat_level = _classify_threat(pkt, payload_str)

    # ── Honeytoken check ──────────────────────────────────────────────────────
    is_ht = False
    ht_val = None
    if check_honeytoken_file:
        try:
            is_ht, ht_val = check_honeytoken_file(uri_path)
        except Exception:
            pass
    if is_ht:
        threat_level = "critical"
        attack_type  = "coap_honeytoken"
        if inc_counter:
            try: inc_counter("honeytokens")
            except Exception: pass

    # ── Log ───────────────────────────────────────────────────────────────────
    _log(log_attack, {
        "timestamp":     _ts(),
        "source_ip":     ip,
        "source_port":   port,
        "dest_port":     5683,
        "service":       "coap",
        "protocol":      "UDP",
        "method":        method,
        "path":          uri_path[:500],
        "query_string":  pkt.uri_query[:200],
        "payload":       payload_str[:500],
        "raw_payload":   data[:256].hex(),
        "msg_type":      _type_str(msg_type),
        "msg_id":        msg_id,
        "token":         token.hex() if token else "",
        "attack_type":   attack_type,
        "threat_level":  threat_level,
        "honeytoken":    ht_val or "",
        "country":       gdata.get("country", "Unknown"),
        "city":          gdata.get("city", ""),
        "latitude":      gdata.get("latitude", 0.0),
        "longitude":     gdata.get("longitude", 0.0),
        **intel,
    })

    if new_ip_alert:
        try: new_ip_alert(ip, gdata.get("country","Unknown"),
                          gdata.get("city",""), "coap")
        except Exception: pass

    # ── RST for non-CoAP garbage or RST messages ──────────────────────────────
    if msg_type == TYPE_RST:
        return

    # ── Build and send response ───────────────────────────────────────────────
    resp = _make_response(pkt, uri_path, method, payload_str, msg_type, msg_id, token)
    if resp:
        try:
            srv_sock.sendto(resp, addr)
        except Exception:
            pass


# ─── Response logic ───────────────────────────────────────────────────────────

def _make_response(
    pkt:         CoapPacket,
    uri_path:    str,
    method:      str,
    payload_str: str,
    msg_type:    int,
    msg_id:      int,
    token:       bytes,
) -> bytes | None:
    """Return the bytes to send, or None to send nothing."""

    resp_type = TYPE_ACK if msg_type == TYPE_CON else TYPE_NON

    # ── Empty ACK for ping (0.00 CON) ────────────────────────────────────────
    if pkt.code == CODE_EMPTY and msg_type == TYPE_CON:
        return _ack(msg_id, token, CODE_EMPTY)

    # ── Non-request code — ignore ─────────────────────────────────────────────
    if pkt.code not in (CODE_GET, CODE_POST, CODE_PUT, CODE_DELETE):
        if msg_type == TYPE_CON:
            return _ack(msg_id, token, CODE_EMPTY)
        return None

    # ── GET ───────────────────────────────────────────────────────────────────
    if method == "GET":
        resource = _RESOURCES.get(uri_path)

        if resource:
            cf, body = resource
            return _build_response(resp_type, CODE_CONTENT, msg_id, token,
                                   body.encode() if isinstance(body, str) else body, cf)

        # Unknown path → 4.04 Not Found
        body = json.dumps({"error": "not found", "path": uri_path}).encode()
        return _build_response(resp_type, CODE_NOT_FOUND, msg_id, token,
                               body, CF_JSON)

    # ── POST ──────────────────────────────────────────────────────────────────
    if method == "POST":
        # Firmware update endpoint — pretend to accept but do nothing
        if uri_path in ("/firmware/update",):
            body = b'{"status":"queued","job_id":"fw-2024-0042"}'
            return _build_response(resp_type, CODE_CHANGED, msg_id, token,
                                   body, CF_JSON)

        # Generic writable resource
        body = json.dumps({"status": "created", "path": uri_path}).encode()
        return _build_response(resp_type, CODE_CREATED, msg_id, token,
                               body, CF_JSON)

    # ── PUT ───────────────────────────────────────────────────────────────────
    if method == "PUT":
        body = json.dumps({"status": "changed", "path": uri_path}).encode()
        return _build_response(resp_type, CODE_CHANGED, msg_id, token,
                               body, CF_JSON)

    # ── DELETE ────────────────────────────────────────────────────────────────
    if method == "DELETE":
        body = json.dumps({"status": "deleted", "path": uri_path}).encode()
        return _build_response(resp_type, CODE_DELETED, msg_id, token,
                               body, CF_JSON)

    # Fallback
    return _build_response(resp_type, CODE_METHOD_NA, msg_id, token)


# ─── Safe log wrapper ─────────────────────────────────────────────────────────

def _log(log_attack, entry: dict):
    if log_attack is None:
        return
    try:
        log_attack(entry)
    except Exception:
        pass