import os
import time
import socket
import struct
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# VNC Security Types
SEC_NONE = 1
SEC_VNC_AUTH = 2

# VNC Message Types (client -> server)
MSG_SET_PIXEL_FORMAT = 0
MSG_SET_ENCODINGS = 2
MSG_FRAMEBUFFER_UPDATE_REQUEST = 3
MSG_KEY_EVENT = 4
MSG_POINTER_EVENT = 5
MSG_CLIENT_CUT_TEXT = 6

def _parse_client_message(data):
    """Parse incoming VNC client messages and return structured info."""
    if not data:
        return None
    msg_type = data[0]

    if msg_type == MSG_SET_PIXEL_FORMAT and len(data) >= 20:
        return {
            "type": "SET_PIXEL_FORMAT",
            "bits_per_pixel": data[4],
            "depth": data[5],
            "big_endian": data[6],
            "true_colour": data[7],
        }
    elif msg_type == MSG_SET_ENCODINGS and len(data) >= 4:
        num_encodings = struct.unpack(">H", data[2:4])[0]
        encodings = []
        for i in range(min(num_encodings, 16)):
            offset = 4 + i * 4
            if offset + 4 <= len(data):
                enc = struct.unpack(">i", data[offset:offset+4])[0]
                encodings.append(enc)
        return {"type": "SET_ENCODINGS", "encodings": encodings}
    elif msg_type == MSG_FRAMEBUFFER_UPDATE_REQUEST and len(data) >= 10:
        return {
            "type": "FB_UPDATE_REQUEST",
            "incremental": data[1],
            "x": struct.unpack(">H", data[2:4])[0],
            "y": struct.unpack(">H", data[4:6])[0],
            "width": struct.unpack(">H", data[6:8])[0],
            "height": struct.unpack(">H", data[8:10])[0],
        }
    elif msg_type == MSG_KEY_EVENT and len(data) >= 8:
        keysym = struct.unpack(">I", data[4:8])[0]
        return {
            "type": "KEY_EVENT",
            "down": data[1],
            "keysym": keysym,
            "keysym_hex": hex(keysym),
        }
    elif msg_type == MSG_POINTER_EVENT and len(data) >= 6:
        return {
            "type": "POINTER_EVENT",
            "button_mask": data[1],
            "x": struct.unpack(">H", data[2:4])[0],
            "y": struct.unpack(">H", data[4:6])[0],
        }
    elif msg_type == MSG_CLIENT_CUT_TEXT and len(data) >= 8:
        length = struct.unpack(">I", data[4:8])[0]
        text = data[8:8+length].decode("latin-1", errors="replace") if len(data) >= 8+length else ""
        return {"type": "CLIENT_CUT_TEXT", "text": text}
    return {"type": "UNKNOWN", "msg_type": msg_type}


def _build_server_init():
    """
    Build a realistic ServerInit message.
    Pretends to be a 1280x800 desktop named 'desktop'.
    """
    width = 1280
    height = 800
    # PixelFormat: 32bpp, 24 depth, big-endian=0, true-colour=1
    pixel_format = struct.pack(
        ">BBBBHHHBBBBBB",
        32,    # bits-per-pixel
        24,    # depth
        0,     # big-endian-flag
        1,     # true-colour-flag
        255,   # red-max
        255,   # green-max
        255,   # blue-max
        16,    # red-shift
        8,     # green-shift
        0,     # blue-shift
        0, 0, 0  # padding
    )
    name = b"desktop"
    return struct.pack(">HH", width, height) + pixel_format + struct.pack(">I", len(name)) + name


def _build_fake_framebuffer_update(width=1280, height=800):
    """
    Send a single raw framebuffer update rectangle filled with a dark colour.
    Looks like a real (blank/locked) desktop screen.
    """
    # FramebufferUpdate header: type=0, padding, num_rects=1
    header = struct.pack(">BBH", 0, 0, 1)
    # Rectangle header: x, y, w, h, encoding=0 (raw)
    rect_header = struct.pack(">HHHHi", 0, 0, width, height, 0)
    # Raw pixel data: 4 bytes per pixel (32bpp), dark grey
    pixel = b"\x30\x30\x30\xff"
    # Limit size — send a small 64x64 tile to avoid huge payloads
    tile_w, tile_h = 64, 64
    rect_header = struct.pack(">HHHHi", 0, 0, tile_w, tile_h, 0)
    pixels = pixel * (tile_w * tile_h)
    return header + rect_header + pixels


def handle_vnc(conn, addr, log_attack=None, geoip_func=None, intel_fields_func=None, new_ip_alert=None):
    ip, port = addr
    gdata = geoip_func(ip) if geoip_func else {}
    session_data = {
        "key_events": [],
        "pointer_events": [],
        "client_cut_texts": [],
        "encodings": [],
        "pixel_format": None,
        "fb_requests": 0,
        "auth_attempts": 0,
        "start_time": datetime.utcnow().isoformat(),
    }

    def _log(event_type, extra=None):
        if log_attack:
            payload = {
                "event": event_type,
                "country": gdata.get("country", "Unknown"),
                "city": gdata.get("city", ""),
            }
            if extra:
                payload.update(extra)
            log_attack(ip, 5900, f"VNC_{event_type.upper()}", payload)

    try:
        _log("connect")

        # ── Phase 1: Version handshake ──────────────────────────────────────
        conn.sendall(b"RFB 003.008\n")
        conn.settimeout(10)

        try:
            client_version = conn.recv(12).decode("ascii", errors="replace").strip()
        except Exception:
            client_version = "unknown"
        _log("version", {"client_version": client_version})

        # ── Phase 2: Security negotiation ──────────────────────────────────
        # Offer both None (1) and VNC Auth (2) so attacker can choose
        conn.sendall(struct.pack(">BB", 2, SEC_NONE, SEC_VNC_AUTH) if False
                     else b"\x02\x01\x02")  # 2 security types: None=1, VNCAuth=2

        try:
            sec_choice = conn.recv(1)
        except Exception:
            return

        chosen = sec_choice[0] if sec_choice else 2
        _log("security_choice", {"chosen_type": chosen})

        if chosen == SEC_NONE:
            # No auth — let them straight in (rare but some clients try)
            conn.sendall(b"\x00\x00\x00\x00")  # SecurityResult OK
        else:
            # VNC Auth challenge/response
            challenge = os.urandom(16)
            conn.sendall(challenge)

            try:
                response = conn.recv(16)
            except Exception:
                response = b""

            session_data["auth_attempts"] += 1
            _log("auth_attempt", {
                "challenge_hex": challenge.hex(),
                "response_hex": response.hex() if response else "",
            })

            # Always fail auth — but delay slightly to feel real
            time.sleep(0.3)
            conn.sendall(b"\x00\x00\x00\x01")  # SecurityResult: failed
            reason = b"Authentication failed"
            conn.sendall(struct.pack(">I", len(reason)) + reason)
            _log("auth_failed")
            return  # Real VNC closes here after failed auth

        # ── Phase 3: ClientInit ─────────────────────────────────────────────
        try:
            client_init = conn.recv(1)
            shared = client_init[0] if client_init else 0
            _log("client_init", {"shared_flag": shared})
        except Exception:
            pass

        # ── Phase 4: ServerInit ─────────────────────────────────────────────
        conn.sendall(_build_server_init())

        # ── Phase 5: Main message loop ──────────────────────────────────────
        conn.settimeout(30)
        interaction_count = 0
        max_interactions = 200  # Cap to avoid infinite loops

        while interaction_count < max_interactions:
            try:
                # Peek at message type first (1 byte)
                header = conn.recv(1)
                if not header:
                    break

                msg_type = header[0]

                # Read remaining bytes based on message type
                if msg_type == MSG_SET_PIXEL_FORMAT:
                    rest = conn.recv(19)
                    data = header + rest
                elif msg_type == MSG_SET_ENCODINGS:
                    rest2 = conn.recv(3)
                    num_enc = struct.unpack(">H", rest2[1:3])[0] if len(rest2) >= 3 else 0
                    enc_data = conn.recv(num_enc * 4) if num_enc else b""
                    data = header + rest2 + enc_data
                elif msg_type == MSG_FRAMEBUFFER_UPDATE_REQUEST:
                    rest = conn.recv(9)
                    data = header + rest
                elif msg_type == MSG_KEY_EVENT:
                    rest = conn.recv(7)
                    data = header + rest
                elif msg_type == MSG_POINTER_EVENT:
                    rest = conn.recv(5)
                    data = header + rest
                elif msg_type == MSG_CLIENT_CUT_TEXT:
                    rest = conn.recv(7)
                    if len(rest) >= 7:
                        length = struct.unpack(">I", rest[3:7])[0]
                        text_data = conn.recv(min(length, 4096))
                        data = header + rest + text_data
                    else:
                        data = header + rest
                else:
                    # Unknown type — drain a small buffer and continue
                    conn.recv(64)
                    interaction_count += 1
                    continue

                parsed = _parse_client_message(data)
                if not parsed:
                    break

                # Log and respond per message type
                if parsed["type"] == "SET_PIXEL_FORMAT":
                    session_data["pixel_format"] = parsed
                    _log("pixel_format", parsed)

                elif parsed["type"] == "SET_ENCODINGS":
                    session_data["encodings"] = parsed["encodings"]
                    _log("encodings", {"encodings": parsed["encodings"]})

                elif parsed["type"] == "FB_UPDATE_REQUEST":
                    session_data["fb_requests"] += 1
                    # Send a fake framebuffer response so client keeps going
                    conn.sendall(_build_fake_framebuffer_update())

                elif parsed["type"] == "KEY_EVENT":
                    session_data["key_events"].append(parsed)
                    _log("key_event", parsed)

                elif parsed["type"] == "POINTER_EVENT":
                    session_data["pointer_events"].append(parsed)
                    # Only log every 20th pointer event to avoid flooding
                    if len(session_data["pointer_events"]) % 20 == 1:
                        _log("pointer_event", parsed)

                elif parsed["type"] == "CLIENT_CUT_TEXT":
                    session_data["client_cut_texts"].append(parsed["text"])
                    _log("client_cut_text", {"text": parsed["text"]})

                interaction_count += 1

            except socket.timeout:
                break
            except Exception:
                break

        # ── Phase 6: Session summary ────────────────────────────────────────
        _log("session_end", {
            "duration_s": round(
                (datetime.utcnow() - datetime.fromisoformat(session_data["start_time"])).total_seconds(), 2
            ),
            "key_events": len(session_data["key_events"]),
            "pointer_events": len(session_data["pointer_events"]),
            "fb_requests": session_data["fb_requests"],
            "client_cut_texts": session_data["client_cut_texts"],
            "encodings": session_data["encodings"],
        })

        if new_ip_alert:
            new_ip_alert(ip, gdata.get("country", ""), gdata.get("city", ""), "vnc")

    except Exception as e:
        logger.debug(f"VNC handler error from {ip}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass