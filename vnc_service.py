#!/usr/bin/env python3
"""
honeyPot — VNC Service (RFB Protocol 3.8)
Emulates a VNC server on an IoT/camera device (TCP port 5900).

Key changes over the original:
  - Auth ACCEPTS common weak passwords so attackers reach the session stage
    and we capture rich post-auth behaviour (keyboard, clipboard, screen grabs)
  - Keysym → character decoding so typed text is readable in the DB
  - Full clipboard analysis (URLs, credentials, shell commands)
  - CVE / exploit encoding detection
  - Tool fingerprinting from RFB version strings
  - All button-click pointer events logged (not just 1-in-20)
  - Proper db.log_attack dict format with all standard fields
"""

import os
import re
import json
import struct
import time
import datetime
import socket
import random

# ─── RFB Constants ───────────────────────────────────────────────────────────

RFB_VERSION_SERVER = b"RFB 003.008\n"

SEC_NONE     = 1
SEC_VNC_AUTH = 2

MSG_SET_PIXEL_FORMAT          = 0
MSG_SET_ENCODINGS             = 2
MSG_FRAMEBUFFER_UPDATE_REQUEST = 3
MSG_KEY_EVENT                 = 4
MSG_POINTER_EVENT             = 5
MSG_CLIENT_CUT_TEXT           = 6

# ─── Known weak VNC passwords (used to decide if we "accept" the auth) ───────
# VNC uses DES-encrypted challenge/response — we can't verify without DES.
# We deliberately accept almost all auth to maximise post-auth intelligence.
# The challenge + response hex are logged so offline cracking is possible.
_WEAK_CREDS_NOTE = (
    "VNC auth accepted (honeypot policy: accept to capture session)"
)

# ─── Tool / client fingerprints from RFB version string ──────────────────────

_CLIENT_FINGERPRINTS = {
    "RFB 003.003": "legacy VNC 3.3 client (very old, likely scanner)",
    "RFB 003.007": "RealVNC 3.x client",
    "RFB 003.008": "standard VNC client (RealVNC 4+, TigerVNC, UltraVNC)",
    "RFB 004.001": "RealVNC 5+ / Enterprise",
    "RFB 004.002": "RealVNC 6+ / Enterprise",
    "rfb 003.008": "LibVNCClient (lower-case = unusual client)",
}

# ─── CVE patterns — specific encoding/feature combinations ───────────────────

# Encoding IDs that are associated with known vulnerabilities
_CVE_ENCODINGS = {
    -239: ("CVE-2019-15681", "LibVNCServer memory leak via CopyRect encoding",  "high"),
    -232: ("CVE-2020-14397", "LibVNCServer NULL deref via RRE sub-encoding",     "high"),
    -240: ("CVE-2020-25708", "LibVNCServer infinite loop via ZRLE encoding",     "high"),
    16:   ("CVE-2022-23967",  "TurboVNC ZRLE buffer overflow",                  "critical"),
}

# Clipboard patterns that indicate malicious intent
# Most specific patterns FIRST — first match wins
_CLIPBOARD_PATTERNS = [
    (re.compile(r"\$\{jndi:"),                                      "log4shell_pasted",     "critical"),
    (re.compile(r"(wget|curl)\s+https?://", re.I),                  "download_cmd_pasted",  "critical"),
    (re.compile(r"(bash|sh|python|perl)\s+-[ci]\s+", re.I),         "shell_cmd_pasted",     "critical"),
    (re.compile(r"chmod\s+[0-7]{3,4}\s", re.I),                     "chmod_pasted",         "high"),
    (re.compile(r"(password|passwd|secret)\s*[=:]\s*\S+", re.I),    "credential_pasted",    "critical"),
    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),                       "base64_blob_pasted",   "medium"),
    (re.compile(r"https?://\S+"),                                    "url_in_clipboard",     "medium"),
]

# ─── X11 keysym → character mapping ──────────────────────────────────────────

def _keysym_to_char(keysym: int) -> str:
    """Convert an X11 keysym to a printable character or control-key name."""
    # Printable Latin-1 range
    if 0x0020 <= keysym <= 0x007e:
        return chr(keysym)
    if 0x00a0 <= keysym <= 0x00ff:
        return chr(keysym)

    _SPECIAL = {
        0xff08: "[BS]",   0xff09: "[TAB]",  0xff0d: "[ENTER]",
        0xff1b: "[ESC]",  0xff50: "[HOME]", 0xff51: "[LEFT]",
        0xff52: "[UP]",   0xff53: "[RIGHT]",0xff54: "[DOWN]",
        0xff55: "[PGUP]", 0xff56: "[PGDN]", 0xff57: "[END]",
        0xff63: "[INS]",  0xffff: "[DEL]",
        0xffe1: "[LSHIFT]", 0xffe2: "[RSHIFT]",
        0xffe3: "[LCTRL]",  0xffe4: "[RCTRL]",
        0xffe5: "[CAPSLOCK]",
        0xffe9: "[LALT]",   0xffea: "[RALT]",
        0xffeb: "[LSUPER]", 0xffec: "[RSUPER]",
        # Function keys
        0xffbe: "[F1]",  0xffbf: "[F2]",  0xffc0: "[F3]",
        0xffc1: "[F4]",  0xffc2: "[F5]",  0xffc3: "[F6]",
        0xffc4: "[F7]",  0xffc5: "[F8]",  0xffc6: "[F9]",
        0xffc7: "[F10]", 0xffc8: "[F11]", 0xffc9: "[F12]",
    }
    return _SPECIAL.get(keysym, f"[0x{keysym:04x}]")


def _decode_keystream(key_events: list[dict]) -> str:
    """
    Reconstruct typed text from a list of key-event dicts.
    Only processes key-down events; handles backspace.
    """
    chars = []
    for ev in key_events:
        if not ev.get("down"):
            continue
        keysym = ev.get("keysym", 0)
        ch = _keysym_to_char(keysym)
        if ch == "[BS]" and chars:
            chars.pop()
        else:
            chars.append(ch)
    return "".join(chars)


# ─── Packet builders ──────────────────────────────────────────────────────────

def _build_server_init(desktop_name: bytes = b"DS-2CD2043G2-I") -> bytes:
    """
    Realistic ServerInit pretending to be a Hikvision camera desktop.
    1920x1080 resolution (typical IP camera web interface).
    """
    pixel_format = struct.pack(
        ">BBBBHHHBBBBBB",
        32, 24, 0, 1,       # bpp, depth, big-endian=no, true-colour=yes
        255, 255, 255,       # R/G/B max
        16, 8, 0,            # R/G/B shift
        0, 0, 0              # padding
    )
    return (
        struct.pack(">HH", 1920, 1080)
        + pixel_format
        + struct.pack(">I", len(desktop_name))
        + desktop_name
    )


def _build_framebuffer_update() -> bytes:
    """
    Send a realistic Hikvision camera login screen framebuffer.
    Layout: dark navy background (#1a1a2e) with a lighter login panel strip in the center.
    Full 1920x1080 resolution split into 3 horizontal rects to keep payload manageable.
    """
    rects = []

    # Top band: dark navy (#1a1a2e) — 1920×400
    rects.append(struct.pack(">HHHHi", 0, 0, 1920, 400, 0))
    rects.append(b"\x1a\x1a\x2e\xff" * (1920 * 400))

    # Middle band: slightly lighter panel (#242442) — 1920×280 — simulates login box area
    rects.append(struct.pack(">HHHHi", 0, 400, 1920, 280, 0))
    rects.append(b"\x24\x24\x42\xff" * (1920 * 280))

    # Bottom band: dark navy (#1a1a2e) — 1920×400
    rects.append(struct.pack(">HHHHi", 0, 680, 1920, 400, 0))
    rects.append(b"\x1a\x1a\x2e\xff" * (1920 * 400))

    num_rects = 3
    header = struct.pack(">BBH", 0, 0, num_rects)
    return header + b"".join(rects)


def _build_server_cut_text(text: str) -> bytes:
    """ServerCutText — pushes text to client clipboard on connect."""
    encoded = text.encode("latin-1", errors="replace")
    return struct.pack(">BBBBBI", 3, 0, 0, 0, 0, len(encoded)) + encoded


def _build_security_result_ok() -> bytes:
    return b"\x00\x00\x00\x00"


def _build_security_result_fail(reason: str = "Authentication failed") -> bytes:
    encoded = reason.encode()
    return b"\x00\x00\x00\x01" + struct.pack(">I", len(encoded)) + encoded


# ─── Clipboard analysis ───────────────────────────────────────────────────────

def _analyse_clipboard(text: str) -> tuple[str, str]:
    """
    Returns (attack_type, threat_level) for clipboard content.
    Checks for malicious patterns: commands, creds, exploits.
    """
    for pattern, atype, level in _CLIPBOARD_PATTERNS:
        if pattern.search(text):
            return atype, level
    return "vnc_clipboard_paste", "low"


# ─── Main handler ─────────────────────────────────────────────────────────────

def handle_vnc(
    conn,
    addr,
    log_attack        = None,
    geoip_func        = None,
    intel_fields_func = None,
    new_ip_alert      = None,
):
    ip, src_port = addr
    gdata = geoip_func(ip) if geoip_func else {}
    intel = intel_fields_func(gdata) if intel_fields_func else {}

    session = {
        "start":        _ts(),
        "key_events":   [],       # list of decoded chars
        "clipboard":    [],
        "fb_requests":  0,
        "clicks":       [],
        "encodings":    [],
        "cve_hits":     [],
        "authenticated": False,
        "auth_challenge": "",
        "auth_response":  "",
        "client_version": "",
        "client_tool":    "",
    }

    def _log(attack_type: str, threat_level: str = "low", extra: dict = None):
        if not log_attack:
            return
        entry = {
            "timestamp":    _ts(),
            "source_ip":    ip,
            "source_port":  src_port,
            "dest_port":    5900,
            "service":      "vnc",
            "protocol":     "TCP",
            "attack_type":  attack_type,
            "threat_level": threat_level,
            "country":      gdata.get("country", "Unknown"),
            "city":         gdata.get("city", ""),
            "latitude":     gdata.get("latitude", 0.0),
            "longitude":    gdata.get("longitude", 0.0),
            **intel,
        }
        if extra:
            entry.update(extra)
        try:
            log_attack(entry)
        except Exception:
            pass

    try:
        conn.settimeout(15)

        # ── Phase 1: Version handshake ─────────────────────────────────────
        conn.sendall(RFB_VERSION_SERVER)
        raw_ver = conn.recv(12)
        client_ver = raw_ver.decode("ascii", errors="replace").strip()
        session["client_version"] = client_ver
        session["client_tool"]    = _CLIENT_FINGERPRINTS.get(client_ver, "unknown VNC client")

        # ── Phase 2: Security type negotiation ────────────────────────────
        # Offer None(1) and VNCAuth(2) — realistic for unpatched devices
        conn.sendall(b"\x02\x01\x02")
        sec_choice = conn.recv(1)
        chosen = sec_choice[0] if sec_choice else SEC_VNC_AUTH

        # ── Phase 3: Authentication ────────────────────────────────────────
        if chosen == SEC_NONE:
            # Direct access — no auth at all (old firmware / misconfigured device)
            conn.sendall(_build_security_result_ok())
            session["authenticated"] = True
            _log("vnc_auth_bypass", "critical", {
                "payload":      "SEC_NONE: no authentication required — direct access",
                "scanner_tool": session["client_tool"],
                "username":     client_ver,
            })

        else:
            # VNC Challenge/Response (DES-based)
            challenge = os.urandom(16)
            conn.sendall(challenge)
            response = conn.recv(16)

            session["auth_challenge"] = challenge.hex()
            session["auth_response"]  = response.hex() if response else ""

            # ACCEPT authentication — we cannot verify DES without the password,
            # and accepting maximises post-auth intelligence collected.
            # The challenge+response pair is logged for offline cracking.
            conn.sendall(_build_security_result_ok())
            session["authenticated"] = True

            _log("vnc_auth_attempt", "high", {
                # Map into real DB columns so dashboard can display them
                "payload":       f"challenge:{session['auth_challenge']} response:{session['auth_response']}",
                "raw_payload":   f"{session['auth_challenge']}:{session['auth_response']}",
                "scanner_tool":  session["client_tool"],
                "username":      client_ver,   # store RFB version as username for display
            })

        # ── Phase 4: Client init ───────────────────────────────────────────
        client_init = conn.recv(1)
        shared = client_init[0] if client_init else 0

        # ── Phase 5: Server init ───────────────────────────────────────────
        conn.sendall(_build_server_init())

        # ── Push device info to client clipboard (real Hikvision cameras do this) ──
        # Human operators who follow up on scanner hits see this immediately
        cut_text = "Hikvision DS-2CD2043G2-I | FW:V5.7.15 | http://192.168.1.108"
        conn.sendall(_build_server_cut_text(cut_text))

        # ── Phase 6: Message loop ──────────────────────────────────────────
        conn.settimeout(30)
        interactions = 0

        while interactions < 300:
            try:
                hdr = conn.recv(1)
            except socket.timeout:
                break
            if not hdr:
                break

            msg_type = hdr[0]

            # ── SetPixelFormat ─────────────────────────────────────────────
            if msg_type == MSG_SET_PIXEL_FORMAT:
                rest = conn.recv(19)
                data = hdr + rest
                if len(data) >= 20:
                    bpp   = data[4]
                    depth = data[5]
                    _log("vnc_pixel_format", "low", {
                        "payload": f"SetPixelFormat bpp={bpp} depth={depth}",
                    })

            # ── SetEncodings ───────────────────────────────────────────────
            elif msg_type == MSG_SET_ENCODINGS:
                rest     = conn.recv(3)
                num_enc  = struct.unpack(">H", rest[1:3])[0] if len(rest) >= 3 else 0
                enc_data = conn.recv(num_enc * 4) if num_enc else b""
                session["encodings"] = []
                for i in range(num_enc):
                    off = i * 4
                    if off + 4 <= len(enc_data):
                        enc_id = struct.unpack(">i", enc_data[off:off+4])[0]
                        session["encodings"].append(enc_id)
                        # CVE check on encoding ID
                        if enc_id in _CVE_ENCODINGS:
                            cve_id, cve_name, sev = _CVE_ENCODINGS[enc_id]
                            session["cve_hits"].append(cve_id)
                            _log(f"vnc_cve_{cve_id.lower().replace('-','_')}", sev, {
                                "cve_id":  cve_id,
                                "payload": f"{cve_name} — encoding id {enc_id}",
                            })

                _log("vnc_encodings", "low", {
                    "payload": f"SetEncodings: {session['encodings'][:10]}",
                })

            # ── FramebufferUpdateRequest ───────────────────────────────────
            elif msg_type == MSG_FRAMEBUFFER_UPDATE_REQUEST:
                rest = conn.recv(9)
                session["fb_requests"] += 1
                # Send a fake framebuffer to keep client alive
                conn.sendall(_build_framebuffer_update())

            # ── KeyEvent ──────────────────────────────────────────────────
            elif msg_type == MSG_KEY_EVENT:
                rest = conn.recv(7)
                data = hdr + rest
                if len(data) >= 8:
                    down   = data[1]
                    keysym = struct.unpack(">I", data[4:8])[0]
                    ch     = _keysym_to_char(keysym)
                    session["key_events"].append({"down": down, "keysym": keysym, "ch": ch})

                    if down:
                        _log("vnc_key_press", "medium", {
                            "payload":   ch,
                            "keysym":    hex(keysym),
                            "keystroke": ch,
                        })

            # ── PointerEvent ──────────────────────────────────────────────
            elif msg_type == MSG_POINTER_EVENT:
                rest = conn.recv(5)
                data = hdr + rest
                if len(data) >= 6:
                    btn_mask = data[1]
                    x = struct.unpack(">H", data[2:4])[0]
                    y = struct.unpack(">H", data[4:6])[0]
                    # Log every button click (mask != 0), not mouse moves
                    if btn_mask != 0:
                        _log("vnc_mouse_click", "low", {
                            "payload": f"click btn={btn_mask} x={x} y={y}",
                        })

            # ── ClientCutText (clipboard paste) ───────────────────────────
            elif msg_type == MSG_CLIENT_CUT_TEXT:
                rest = conn.recv(7)
                if len(rest) >= 7:
                    length    = struct.unpack(">I", rest[3:7])[0]
                    text_data = conn.recv(min(length, 8192))
                    text      = text_data.decode("latin-1", errors="replace")
                    session["clipboard"].append(text)

                    attack_type, threat_level = _analyse_clipboard(text)
                    _log(attack_type, threat_level, {
                        "payload":   text[:500],
                        "clipboard": text[:200],
                    })

            else:
                conn.recv(64)   # drain unknown

            interactions += 1

        # ── Phase 7: Session summary ───────────────────────────────────────
        typed_text = _decode_keystream(session["key_events"])
        duration   = round(
            (datetime.datetime.utcnow()
             - datetime.datetime.fromisoformat(session["start"])).total_seconds(), 2
        )

        clipboard_str = " | ".join(session["clipboard"])[:300]
        cve_str       = ",".join(session["cve_hits"])

        # Build a human-readable summary for the dashboard payload column
        summary_parts = []
        if typed_text:
            summary_parts.append(f"typed:{typed_text[:200]}")
        if clipboard_str:
            summary_parts.append(f"clipboard:{clipboard_str[:200]}")
        if cve_str:
            summary_parts.append(f"cves:{cve_str}")
        summary_parts.append(f"fb_requests:{session['fb_requests']} keys:{len(session['key_events'])} dur:{duration}s")

        _log("vnc_session_end", "medium" if typed_text or clipboard_str else "low", {
            "payload":      " | ".join(summary_parts),
            "raw_payload":  typed_text[:500] if typed_text else clipboard_str[:500],
            "commands":     json.dumps({
                "typed":       typed_text[:300],
                "clipboard":   clipboard_str,
                "fb_requests": session["fb_requests"],
                "key_count":   len(session["key_events"]),
                "encodings":   session["encodings"][:10],
                "cves":        session["cve_hits"],
                "duration_s":  duration,
                "client":      session["client_tool"],
                "rfb_version": session["client_version"],
            }),
            "scanner_tool": session["client_tool"],
            "username":     session["client_version"],
        })

        if new_ip_alert:
            try:
                new_ip_alert(ip, gdata.get("country", ""), gdata.get("city", ""), "vnc")
            except Exception:
                pass

    except (ConnectionResetError, BrokenPipeError, socket.timeout):
        pass
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ─── Helper ───────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.datetime.utcnow().isoformat()
