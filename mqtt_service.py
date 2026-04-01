import ssl
import struct
import time
import random
import threading
import json
import logging
import socket
import datetime

logger = logging.getLogger("honeypot.mqtt")

# ─────────────────────────────────────────────────────────────────────────────
# Global session store  (clean_session=False persistence)
# ─────────────────────────────────────────────────────────────────────────────
_session_store: dict = {}
_session_lock = threading.Lock()

# Open broker — accept everything to attract bots and log all activity
BLOCKED_CREDENTIALS: set = set()

# Never randomly reject — we want to capture all connections
AUTH_RANDOM_REJECT_RATE = 0.00


# ─────────────────────────────────────────────────────────────────────────────
# Fake retained topic store
# ─────────────────────────────────────────────────────────────────────────────
def _fake_retained_store() -> dict:
    def rtemp():   return json.dumps({"value": round(random.uniform(18.0, 24.0), 1), "unit": "C", "sensor": "DHT22"})
    def rhumid():  return json.dumps({"value": round(random.uniform(40.0, 65.0), 1), "unit": "%"})
    def rrouter(): return json.dumps({"status": "online", "ip": "192.168.1.1", "clients": random.randint(3, 12)})
    def rcam1():   return json.dumps({"status": "recording", "fps": 25, "resolution": "1080p"})
    def rftemp():  return str(round(random.uniform(60.0, 90.0), 2))
    def rfpres():  return str(round(random.uniform(1.0, 5.0), 3))
    def rconn():   return str(random.randint(3, 20))
    def rmsg():    return str(random.randint(10_000, 999_999))

    return {
        "home/temperature":                        rtemp,
        "home/humidity":                           rhumid,
        "home/livingroom/light":                   lambda: random.choice(["ON", "OFF"]),
        "home/bedroom/light":                      lambda: random.choice(["ON", "OFF"]),
        "home/door/front":                         lambda: random.choice(["locked", "unlocked"]),
        "home/door/back":                          lambda: "locked",
        "home/alarm":                              lambda: "disarmed",
        "home/garage":                             lambda: "closed",
        "home/camera/motion":                      lambda: "false",
        "devices/router/status":                   rrouter,
        "devices/camera/1/status":                 rcam1,
        "devices/camera/2/status":                 lambda: json.dumps({"status": "idle"}),
        "devices/thermostat/setpoint":             lambda: str(random.randint(19, 23)),
        "devices/thermostat/current":              lambda: str(round(random.uniform(18.5, 22.5), 1)),
        "factory/sensor/temp/1":                   rftemp,
        "factory/sensor/temp/2":                   lambda: str(round(random.uniform(55.0, 85.0), 2)),
        "factory/sensor/pressure/1":               rfpres,
        "factory/plc/status":                      lambda: "RUNNING",
        "factory/plc/mode":                        lambda: "AUTO",
        "factory/plc/error_code":                  lambda: "0",
        "$SYS/broker/version":                     lambda: "mosquitto version 2.0.15",
        "$SYS/broker/uptime":                      lambda: f"{random.randint(100_000, 900_000)} seconds",
        "$SYS/broker/clients/connected":           rconn,
        "$SYS/broker/clients/total":               lambda: str(random.randint(20, 200)),
        "$SYS/broker/messages/received":           rmsg,
        "$SYS/broker/messages/sent":               rmsg,
        "$SYS/broker/publish/messages/received":   lambda: str(random.randint(5_000, 500_000)),
        "$SYS/broker/subscriptions/count":         lambda: str(random.randint(10, 80)),
        "$SYS/broker/load/messages/received/1min": lambda: str(round(random.uniform(10, 200), 2)),
    }


HIGH_VALUE_TOPICS = {
    "home/alarm", "home/door/front", "home/door/back",
    "home/garage", "factory/plc/status", "factory/plc/mode",
    "factory/plc/error_code", "devices/camera/1/status",
}


# ─────────────────────────────────────────────────────────────────────────────
# Variable-length integer codec (MQTT remaining-length + v5 Properties Length)
# ─────────────────────────────────────────────────────────────────────────────
def _decode_varint(data: bytes, offset: int):
    multiplier, value = 1, 0
    while offset < len(data):
        byte = data[offset]; offset += 1
        value += (byte & 0x7F) * multiplier
        multiplier *= 128
        if not (byte & 0x80): break
        if multiplier > 128 ** 3:
            raise ValueError("Malformed varint")
    return value, offset


def _encode_varint(n: int) -> bytes:
    result = bytearray()
    while True:
        byte = n % 128; n //= 128
        if n: byte |= 0x80
        result.append(byte)
        if not n: break
    return bytes(result)


# ─────────────────────────────────────────────────────────────────────────────
# String / bytes field helpers
# ─────────────────────────────────────────────────────────────────────────────
def _read_utf8(data: bytes, offset: int):
    if offset + 2 > len(data): return "", offset
    length = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2
    return data[offset:offset + length].decode(errors="ignore"), offset + length


def _read_bytes_field(data: bytes, offset: int):
    if offset + 2 > len(data): return b"", offset
    length = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2
    return data[offset:offset + length], offset + length


# ─────────────────────────────────────────────────────────────────────────────
# MQTT v5 Properties parser
# ─────────────────────────────────────────────────────────────────────────────
_V5_PROP_TYPES = {
    0x01: ("payload_format_indicator",           "u8"),
    0x02: ("message_expiry_interval",            "u32"),
    0x03: ("content_type",                       "utf8"),
    0x08: ("response_topic",                     "utf8"),
    0x09: ("correlation_data",                   "bytes"),
    0x0B: ("subscription_identifier",            "varint"),
    0x11: ("session_expiry_interval",            "u32"),
    0x12: ("assigned_client_identifier",         "utf8"),
    0x13: ("server_keep_alive",                  "u16"),
    0x15: ("authentication_method",              "utf8"),
    0x16: ("authentication_data",                "bytes"),
    0x17: ("request_problem_information",        "u8"),
    0x18: ("will_delay_interval",                "u32"),
    0x19: ("request_response_information",       "u8"),
    0x1A: ("response_information",               "utf8"),
    0x1C: ("server_reference",                   "utf8"),
    0x1F: ("reason_string",                      "utf8"),
    0x21: ("receive_maximum",                    "u16"),
    0x22: ("topic_alias_maximum",                "u16"),
    0x23: ("topic_alias",                        "u16"),
    0x24: ("maximum_qos",                        "u8"),
    0x25: ("retain_available",                   "u8"),
    0x26: ("user_property",                      "utf8pair"),
    0x27: ("maximum_packet_size",                "u32"),
    0x28: ("wildcard_subscription_available",    "u8"),
    0x29: ("subscription_identifier_available",  "u8"),
    0x2A: ("shared_subscription_available",      "u8"),
}


def _parse_v5_properties(data: bytes, offset: int):
    props_len, offset = _decode_varint(data, offset)
    end   = offset + props_len
    props: dict = {}
    try:
        while offset < end and offset < len(data):
            prop_id = data[offset]; offset += 1
            if prop_id not in _V5_PROP_TYPES: break
            name, ptype = _V5_PROP_TYPES[prop_id]
            if   ptype == "u8":      val = data[offset]; offset += 1
            elif ptype == "u16":     val = int.from_bytes(data[offset:offset+2], "big"); offset += 2
            elif ptype == "u32":     val = int.from_bytes(data[offset:offset+4], "big"); offset += 4
            elif ptype == "utf8":    val, offset = _read_utf8(data, offset)
            elif ptype == "bytes":   val, offset = _read_bytes_field(data, offset); val = val.hex()
            elif ptype == "varint":  val, offset = _decode_varint(data, offset)
            elif ptype == "utf8pair":
                k, offset = _read_utf8(data, offset)
                v, offset = _read_utf8(data, offset)
                props.setdefault("user_properties", {})[k] = v
                continue
            else: break
            props[name] = val
    except Exception:
        pass
    return props, max(offset, end)


# ─────────────────────────────────────────────────────────────────────────────
# Packet builders
# ─────────────────────────────────────────────────────────────────────────────
def _build_connack(session_present: bool = False,
                   return_code: int = 0,
                   mqtt_version: int = 4) -> bytes:
    if mqtt_version == 5:
        props = bytes([0x00])
        body  = bytes([0x01 if session_present else 0x00, return_code]) + props
        return bytes([0x20]) + _encode_varint(len(body)) + body
    return bytes([0x20, 0x02, 0x01 if session_present else 0x00, return_code])


def _build_publish(topic: str, payload, qos: int = 0,
                   retain: bool = False, packet_id: int = None) -> bytes:
    if isinstance(payload, str): payload = payload.encode()
    if isinstance(topic,   str): topic   = topic.encode()
    flags  = 0x30 | (0x01 if retain else 0)
    flags |= (qos & 0x03) << 1
    body   = struct.pack("!H", len(topic)) + topic
    if qos > 0 and packet_id is not None:
        body += struct.pack("!H", packet_id)
    body += payload
    return bytes([flags]) + _encode_varint(len(body)) + body


def _build_suback(packet_id: int, return_codes: list) -> bytes:
    body = struct.pack("!H", packet_id) + bytes(return_codes)
    return b"\x90" + _encode_varint(len(body)) + body


def _build_unsuback(packet_id: int) -> bytes:
    return struct.pack("!BBH", 0xB0, 0x02, packet_id)


def _build_puback(packet_id: int)  -> bytes:
    return struct.pack("!BBH", 0x40, 0x02, packet_id)


def _build_pubrec(packet_id: int)  -> bytes:
    return struct.pack("!BBH", 0x50, 0x02, packet_id)


def _build_pubcomp(packet_id: int) -> bytes:
    return struct.pack("!BBH", 0x70, 0x02, packet_id)


PINGRESP = b"\xD0\x00"


# ─────────────────────────────────────────────────────────────────────────────
# Socket reader
# ─────────────────────────────────────────────────────────────────────────────
def _recv_packet(conn, timeout: float = 30):
    conn.settimeout(timeout)
    try:
        header = conn.recv(1)
        if not header: return None
        rem_len, multiplier = 0, 1
        for _ in range(4):
            b = conn.recv(1)
            if not b: return None
            byte = b[0]
            rem_len += (byte & 0x7F) * multiplier
            multiplier *= 128
            if not (byte & 0x80): break
        body, remaining = b"", rem_len
        while remaining > 0:
            chunk = conn.recv(min(remaining, 4096))
            if not chunk: return None
            body += chunk; remaining -= len(chunk)
        return header + _encode_varint(rem_len) + body
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# CONNECT parser
# ─────────────────────────────────────────────────────────────────────────────
def _parse_connect(pkt: bytes) -> dict:
    info = {
        "mqtt_version": 4,    "protocol_name": "",  "client_id":    "",
        "username":     "",   "password":      "",  "will_topic":   "",
        "will_payload": "",   "will_qos":      0,   "will_retain":  False,
        "clean_session": True,"keepalive":      0,  "flags":        0,
        "v5_properties": {},  "will_properties":{},
    }
    try:
        _rem, idx                  = _decode_varint(pkt, 1)
        info["protocol_name"], idx = _read_utf8(pkt, idx)
        info["mqtt_version"]       = pkt[idx]; idx += 1
        if idx >= len(pkt): return info
        flags                      = pkt[idx]; idx += 1
        info["flags"]              = flags
        info["clean_session"]      = bool(flags & 0x02)
        has_will                   = bool(flags & 0x04)
        info["will_qos"]           = (flags & 0x18) >> 3
        info["will_retain"]        = bool(flags & 0x20)
        has_password               = bool(flags & 0x40)
        has_username               = bool(flags & 0x80)
        info["keepalive"]          = int.from_bytes(pkt[idx:idx+2], "big"); idx += 2

        if info["mqtt_version"] == 5:
            info["v5_properties"], idx = _parse_v5_properties(pkt, idx)

        info["client_id"], idx = _read_utf8(pkt, idx)

        if has_will:
            if info["mqtt_version"] == 5:
                info["will_properties"], idx = _parse_v5_properties(pkt, idx)
            info["will_topic"],   idx = _read_utf8(pkt, idx)
            will_bytes,           idx = _read_bytes_field(pkt, idx)
            info["will_payload"]      = will_bytes.decode(errors="ignore")

        if has_username: info["username"], idx = _read_utf8(pkt, idx)
        if has_password:
            pwd, idx        = _read_bytes_field(pkt, idx)
            info["password"]= pwd.decode(errors="ignore")

    except Exception as e:
        logger.debug(f"CONNECT parse error: {e}")
    return info


def _parse_subscribe(body: bytes):
    if len(body) < 2: return 0, []
    packet_id = int.from_bytes(body[0:2], "big"); idx = 2
    topics = []
    while idx < len(body):
        if idx + 2 > len(body): break
        tlen  = int.from_bytes(body[idx:idx+2], "big"); idx += 2
        topic = body[idx:idx+tlen].decode(errors="ignore"); idx += tlen
        qos   = body[idx] & 0x03 if idx < len(body) else 0; idx += 1
        topics.append((topic, qos))
    return packet_id, topics


def _parse_unsubscribe(body: bytes):
    if len(body) < 2: return 0, []
    packet_id = int.from_bytes(body[0:2], "big"); idx = 2
    topics = []
    while idx < len(body):
        if idx + 2 > len(body): break
        tlen  = int.from_bytes(body[idx:idx+2], "big"); idx += 2
        topic = body[idx:idx+tlen].decode(errors="ignore"); idx += tlen
        topics.append(topic)
    return packet_id, topics


def _parse_publish(pkt: bytes, fixed_byte: int) -> dict:
    qos    = (fixed_byte & 0x06) >> 1
    retain = bool(fixed_byte & 0x01)
    dup    = bool(fixed_byte & 0x08)
    try:
        _rem, idx  = _decode_varint(pkt, 1)
        topic, idx = _read_utf8(pkt, idx)
        packet_id  = None
        if qos > 0:
            packet_id = int.from_bytes(pkt[idx:idx+2], "big"); idx += 2
        payload = pkt[idx:].decode(errors="ignore")
        return {"topic": topic, "payload": payload, "qos": qos,
                "retain": retain, "dup": dup, "packet_id": packet_id}
    except Exception:
        return {"topic": "", "payload": "", "qos": qos,
                "retain": retain, "dup": dup, "packet_id": None}


# ─────────────────────────────────────────────────────────────────────────────
# Topic matching
# ─────────────────────────────────────────────────────────────────────────────
def _topic_matches(filt: str, topic: str) -> bool:
    fp = filt.split("/"); tp = topic.split("/")
    for i, f in enumerate(fp):
        if f == "#": return True
        if i >= len(tp): return False
        if f != "+" and f != tp[i]: return False
    return len(fp) == len(tp)


# ─────────────────────────────────────────────────────────────────────────────
# Auth decision
# ─────────────────────────────────────────────────────────────────────────────
def _auth_decision(username: str, password: str):
    """
    Returns (accepted: bool, connack_return_code: int).
    Codes: 0x00 = accepted, 0x04 = bad credentials, 0x05 = not authorised.
    """
    if (username.lower(), password) in BLOCKED_CREDENTIALS:
        time.sleep(random.uniform(0.1, 0.4))
        return False, random.choice([0x04, 0x05])
    if random.random() < AUTH_RANDOM_REJECT_RATE:
        time.sleep(random.uniform(0.05, 0.3))
        return False, 0x04
    return True, 0x00


# ─────────────────────────────────────────────────────────────────────────────
# Retained message push
# ─────────────────────────────────────────────────────────────────────────────
def _push_retained(conn, subscriptions: list, retained: dict):
    """Push matching retained messages to newly-subscribed client."""
    for topic, gen in retained.items():
        for (filt, qos) in subscriptions:
            if _topic_matches(filt, topic):
                try:
                    pkt = _build_publish(topic, gen(), qos=min(qos, 1), retain=True)
                    conn.sendall(pkt)
                    time.sleep(0.015)
                except Exception:
                    return
                break   # one retained message per topic, no duplicates


# ─────────────────────────────────────────────────────────────────────────────
# Background live sensor publisher
# ─────────────────────────────────────────────────────────────────────────────
_LIVE_TOPICS = [
    "home/temperature", "home/humidity", "factory/sensor/temp/1",
    "factory/sensor/temp/2", "factory/sensor/pressure/1",
    "devices/router/status", "devices/thermostat/current",
    "$SYS/broker/clients/connected", "$SYS/broker/messages/received",
    "$SYS/broker/load/messages/received/1min",
]


def _live_publisher(conn, subscriptions: list, retained: dict,
                    stop: threading.Event):
    while not stop.is_set():
        stop.wait(random.uniform(12, 30))
        if stop.is_set(): break
        topic = random.choice(_LIVE_TOPICS)
        gen   = retained.get(topic)
        if gen is None: continue
        for (filt, qos) in subscriptions:
            if _topic_matches(filt, topic):
                try:
                    conn.sendall(_build_publish(topic, gen(), qos=min(qos, 1)))
                except Exception:
                    stop.set(); return
                break


# ─────────────────────────────────────────────────────────────────────────────
# Optional TLS upgrade
# ─────────────────────────────────────────────────────────────────────────────
def upgrade_tls(conn: socket.socket, certfile: str, keyfile: str):
    """
    Wrap socket with server-side TLS.  Returns wrapped socket or original.

    Generate self-signed cert:
        openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \\
                -days 365 -nodes -subj '/CN=localhost'
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx.wrap_socket(conn, server_side=True)
    except ssl.SSLError as e:
        logger.debug(f"TLS upgrade failed: {e}")
        return conn


# ─────────────────────────────────────────────────────────────────────────────
# Structured event logger
#
# FIX: geoip_func and intel_fields_func are now OPTIONAL.
#      Only log_attack is required.  If the others are absent we still log
#      with empty geo/intel fields so username/password always reach the DB.
# ─────────────────────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def _log_event(log_attack, geoip_func, intel_fields_func,
               ip, dest_port, gdata, session, attack_type,
               extra=None, threat_level="medium"):
    """
    Build a log record and call log_attack().

    log_attack      — required; if None nothing is logged.
    geoip_func      — optional; if None geo fields are empty.
    intel_fields_func — optional; if None intel fields are omitted.
    """
    if not log_attack:
        return

    # Geo fields — degrade gracefully when geoip_func is missing
    country  = gdata.get("country",   "Unknown") if gdata else "Unknown"
    city     = gdata.get("city",      "")        if gdata else ""
    latitude = gdata.get("latitude",  0.0)       if gdata else 0.0
    longitude= gdata.get("longitude", 0.0)       if gdata else 0.0

    record = {
        "timestamp":    _now_iso(),
        "source_ip":    ip,
        "dest_port":    dest_port,         # ← FIX: server listen port, not client port
        "service":      "mqtt",
        "protocol":     "TCP",
        "username":     session.get("username",     ""),
        "password":     session.get("password",     ""),
        "client_id":    session.get("client_id",    ""),
        "mqtt_version": session.get("mqtt_version", 4),
        "attack_type":  attack_type,
        "threat_level": threat_level,
        "country":      country,
        "city":         city,
        "latitude":     latitude,
        "longitude":    longitude,
    }

    # Intel fields — only merged when callback exists
    if intel_fields_func and gdata:
        try:
            record.update(intel_fields_func(gdata))
        except Exception:
            pass

    if extra:
        record.update(extra)

    try:
        log_attack(record)
    except Exception as e:
        logger.error(f"log_attack() raised: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Main handler
# ─────────────────────────────────────────────────────────────────────────────
def handle_mqtt(conn, addr,
                log_attack=None,
                geoip_func=None,
                intel_fields_func=None,
                new_ip_alert=None,
                tls_certfile: str = None,
                tls_keyfile:  str = None,
                server_port:  int = 1883):
    """
    Entry point — drop into your honeypot dispatcher.

    Parameters
    ----------
    conn               Raw socket from accept()
    addr               (client_ip, client_port) from accept()
    log_attack         Callable(dict) → None  [required for logging]
    geoip_func         Callable(ip_str) → dict  [optional]
    intel_fields_func  Callable(gdata) → dict   [optional]
    new_ip_alert       Callable(ip, country, city, service) → None  [optional]
    tls_certfile       Path to PEM cert  (enables TLS when both given)
    tls_keyfile        Path to PEM key
    server_port        The port YOUR server is listening on (1883 or 8883).
                       This is what gets stored as dest_port in the DB.
                       FIX: addr[1] is the CLIENT's ephemeral port — never use
                       it as dest_port.
    """
    client_ip, _client_port = addr   # _client_port intentionally unused

    # Optional TLS upgrade
    if tls_certfile and tls_keyfile:
        conn = upgrade_tls(conn, tls_certfile, tls_keyfile)

    retained   = _fake_retained_store()
    stop_evt   = threading.Event()
    pub_thread = None
    gdata      = {}

    session: dict = {
        "client_id":     "",
        "username":      "",
        "password":      "",
        "will_topic":    "",
        "will_payload":  "",
        "mqtt_version":  4,
        "keepalive":     0,
        "subscriptions": [],      # [(filter, qos), ...]
        "publishes":     [],      # [{topic, payload, qos, retain}, ...]
        "unsubscribes":  [],
        "packet_count":  0,
        "auth_accepted": False,
        "auth_rejected": False,
        "v5_properties": {},
        "session_start": time.time(),
        "pending_qos2":  {},      # {packet_id -> "pubrec_sent" | "pubcomp_sent"}
    }

    try:
        # ── 1. Receive CONNECT ────────────────────────────────────────────
        pkt = _recv_packet(conn, timeout=15)
        if not pkt:
            return

        if (pkt[0] & 0xF0) != 0x10:
            # Not a CONNECT — send a polite refusal and bail
            conn.sendall(_build_connack(return_code=1))
            return

        info = _parse_connect(pkt)
        session.update({
            "client_id":     info["client_id"],
            "username":      info["username"],
            "password":      info["password"],
            "will_topic":    info["will_topic"],
            "will_payload":  info["will_payload"],
            "mqtt_version":  info["mqtt_version"],
            "keepalive":     info["keepalive"],
            "v5_properties": info.get("v5_properties", {}),
        })
        session["packet_count"] += 1
        mv = info["mqtt_version"]

        # ── 2. GeoIP lookup (optional) ────────────────────────────────────
        if geoip_func:
            try:
                gdata = geoip_func(client_ip) or {}
            except Exception:
                gdata = {}

        # ── 3. Auth decision ──────────────────────────────────────────────
        time.sleep(random.uniform(0.05, 0.15))   # simulate real broker latency
        accepted, rc = _auth_decision(info["username"], info["password"])

        if not accepted:
            session["auth_rejected"] = True
            conn.sendall(_build_connack(return_code=rc, mqtt_version=mv))

            # FIX: log rejected connections too — username/password still captured
            _log_event(log_attack, geoip_func, intel_fields_func,
                       client_ip, server_port, gdata, session,
                       "mqtt_auth_failure",
                       extra={
                           "connack_code":  rc,
                           "will_topic":    info["will_topic"],
                           "v5_properties": info.get("v5_properties", {}),
                       },
                       threat_level="medium")

            if new_ip_alert:
                try:
                    new_ip_alert(client_ip,
                                 gdata.get("country", "Unknown"),
                                 gdata.get("city", ""),
                                 "mqtt_auth_failure")
                except Exception:
                    pass
            return

        session["auth_accepted"] = True

        # ── Client ID botnet fingerprinting ───────────────────────────────
        _BOTNET_CLIENT_PATTERNS = [
            ("Mirai",    ["mirai", "iot_", "bot_", "mozi"]),
            ("Gafgyt",   ["gafgyt", "bashlite", "qbot"]),
            ("EasyCash", ["ESP8266", "ESP32", "MQTT_FX"]),
            ("Scanner",  ["mqtt-spy", "mosquitto", "pahomqtt", "mqttfx"]),
            ("Randbot",  ["ffffffff", "00000000", "aaaaaaaa"]),  # hex random IDs
        ]
        cid_lower = (info["client_id"] or "").lower()
        _cid_family = "Unknown"
        for _fam, _pats in _BOTNET_CLIENT_PATTERNS:
            if any(p in cid_lower for p in _pats):
                _cid_family = _fam
                break
        # Also flag suspiciously short (1-2 char) or pure-hex client IDs (scripted bots)
        if _cid_family == "Unknown" and len(cid_lower) in (1, 2):
            _cid_family = "MinimalBot"
        if _cid_family not in ("Unknown", "EasyCash", "Scanner"):
            session["botnet_family"] = _cid_family

        # ── 4. Session persistence (clean_session=False) ──────────────────
        session_present = False
        cid = info["client_id"]
        if not info["clean_session"] and cid:
            with _session_lock:
                stored = _session_store.get(cid)
                if stored:
                    session["subscriptions"] = stored.get("subscriptions", [])
                    session["pending_qos2"]  = stored.get("pending_qos2",  {})
                    session_present          = True

        # ── 5. CONNACK ────────────────────────────────────────────────────
        conn.sendall(_build_connack(session_present=session_present,
                                    return_code=0, mqtt_version=mv))

        # ── 6. Initial connection log ─────────────────────────────────────
        _log_event(log_attack, geoip_func, intel_fields_func,
                   client_ip, server_port, gdata, session,
                   "mqtt_connect",
                   extra={
                       "will_topic":      info["will_topic"],
                       "will_payload":    info["will_payload"],
                       "clean_session":   info["clean_session"],
                       "session_present": session_present,
                       "v5_properties":   info.get("v5_properties", {}),
                   })

        if new_ip_alert:
            try:
                new_ip_alert(client_ip,
                             gdata.get("country", "Unknown"),
                             gdata.get("city", ""),
                             "mqtt")
            except Exception:
                pass

        # ── 7. Session loop ───────────────────────────────────────────────
        keepalive_timeout = (max(session["keepalive"] * 1.5, 30)
                             if session["keepalive"] else 60)

        for _ in range(500):
            pkt = _recv_packet(conn, timeout=keepalive_timeout)
            if pkt is None:
                break
            session["packet_count"] += 1
            ptype = pkt[0] & 0xF0

            # ── SUBSCRIBE (0x80) ──────────────────────────────────────────
            if ptype == 0x80:
                _, bstart    = _decode_varint(pkt, 1)
                pid, topics  = _parse_subscribe(pkt[bstart:])
                new_subs, return_codes = [], []
                for (filt, qos) in topics:
                    granted = min(qos, 2)
                    return_codes.append(granted)
                    entry = (filt, granted)
                    if entry not in session["subscriptions"]:
                        session["subscriptions"].append(entry)
                        new_subs.append(entry)
                conn.sendall(_build_suback(pid, return_codes))

                # Push retained messages for new subscriptions
                if new_subs:
                    _push_retained(conn, new_subs, retained)

                # Start background publisher once subscriptions exist
                if new_subs and pub_thread is None:
                    pub_thread = threading.Thread(
                        target=_live_publisher,
                        args=(conn, session["subscriptions"], retained, stop_evt),
                        daemon=True)
                    pub_thread.start()

                # Classify subscribe intent
                _sub_topics = [t for t, _ in topics]
                _sub_event  = "mqtt_subscribe"
                _sub_threat = "medium"
                if any(t.startswith("$SYS") for t in _sub_topics):
                    _sub_event  = "mqtt_sys_enumeration"   # broker intelligence gathering
                    _sub_threat = "high"
                elif any(t in ("#", "+") for t in _sub_topics):
                    _sub_event  = "mqtt_wildcard_subscribe"  # full broker dump
                    _sub_threat = "high"
                elif any("cmd" in t.lower() or "exec" in t.lower()
                         or "control" in t.lower() for t in _sub_topics):
                    _sub_event  = "mqtt_c2_subscribe"      # C2 command channel
                    _sub_threat = "critical"

                _log_event(log_attack, geoip_func, intel_fields_func,
                           client_ip, server_port, gdata, session,
                           _sub_event,
                           extra={"topics": _sub_topics,
                                  "botnet_family": session.get("botnet_family", "")},
                           threat_level=_sub_threat)

            # ── PUBLISH (0x30) ────────────────────────────────────────────
            elif ptype == 0x30:
                pub = _parse_publish(pkt, pkt[0])
                session["publishes"].append(pub)
                qos = pub["qos"]
                pid = pub["packet_id"]

                if qos == 1 and pid is not None:
                    conn.sendall(_build_puback(pid))
                elif qos == 2 and pid is not None:
                    session["pending_qos2"][pid] = "pubrec_sent"
                    conn.sendall(_build_pubrec(pid))

                # Update retained store if attacker publishes with retain flag
                if pub["retain"] and pub["topic"]:
                    val = pub["payload"]
                    retained[pub["topic"]] = lambda v=val: v

                threat = "high" if pub["topic"] in HIGH_VALUE_TOPICS else "medium"
                topic_str   = pub["topic"] or "(empty)"
                payload_str = pub["payload"][:512] if pub["payload"] else "(empty)"
                _log_event(log_attack, geoip_func, intel_fields_func,
                           client_ip, server_port, gdata, session,
                           "mqtt_publish",
                           extra={
                               # Store topic+payload in the DB payload column so dashboard shows it
                               "payload":     f"topic={topic_str} payload={payload_str}",
                               "raw_payload": payload_str,
                               "path":        topic_str,   # topic in path column for table display
                               "qos":         qos,
                               "retain":      pub["retain"],
                           },
                           threat_level=threat)

            # ── PUBREL (0x62) — QoS 2 phase 2 ────────────────────────────
            elif pkt[0] == 0x62:
                if len(pkt) >= 4:
                    pid = int.from_bytes(pkt[2:4], "big")
                    session["pending_qos2"].pop(pid, None)
                    conn.sendall(_build_pubcomp(pid))

            # ── UNSUBSCRIBE (0xA0) ────────────────────────────────────────
            elif ptype == 0xA0:
                _, bstart   = _decode_varint(pkt, 1)
                pid, topics = _parse_unsubscribe(pkt[bstart:])
                session["unsubscribes"].extend(topics)
                session["subscriptions"] = [
                    (f, q) for (f, q) in session["subscriptions"]
                    if f not in topics
                ]
                conn.sendall(_build_unsuback(pid))

            # ── PINGREQ (0xC0) ────────────────────────────────────────────
            elif ptype == 0xC0:
                conn.sendall(PINGRESP)

            # ── AUTH (0xF0) — MQTT v5 extended authentication ─────────────
            elif pkt[0] == 0xF0 and mv == 5:
                conn.sendall(bytes([0xF0, 0x02, 0x00, 0x00]))
                _log_event(log_attack, geoip_func, intel_fields_func,
                           client_ip, server_port, gdata, session,
                           "mqtt_v5_auth",
                           extra={"raw_hex": pkt.hex()[:64]},
                           threat_level="medium")

            # ── DISCONNECT (0xE0) ─────────────────────────────────────────
            elif ptype == 0xE0:
                break

    except Exception as e:
        logger.debug(f"MQTT session error from {client_ip}: {e}")

    finally:
        stop_evt.set()
        duration = round(time.time() - session["session_start"], 2)

        # Persist session for clean_session=False reconnects
        cid = session["client_id"]
        if cid and not session["auth_rejected"]:
            with _session_lock:
                _session_store[cid] = {
                    "subscriptions": session["subscriptions"],
                    "pending_qos2":  session["pending_qos2"],
                }

        logger.info(
            f"[MQTT] closed | ip={client_ip} port={server_port} "
            f"cid={cid!r} user={session['username']!r} "
            f"pass={session['password']!r} v={session['mqtt_version']} "
            f"pkts={session['packet_count']} "
            f"subs={len(session['subscriptions'])} "
            f"pubs={len(session['publishes'])} dur={duration}s "
            f"auth={'OK' if session['auth_accepted'] else 'FAIL'}"
        )
        try:
            conn.close()
        except Exception:
            pass