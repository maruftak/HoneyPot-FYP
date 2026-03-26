#!/usr/bin/env python3
"""
adb_service.py — Android Debug Bridge (ADB) honeypot (port 5555)

ADB is the Android developer debugging protocol. Port 5555 is the default
TCP port for wireless ADB. It's massively targeted on IoT devices because:

  - Android-based smart TVs, set-top boxes, streaming sticks, NVRs, kiosks
    often ship with ADB enabled and exposed on the network
  - The Fbot botnet (Mirai variant) specifically scans port 5555
  - Satori botnet variant targeted ADB for cryptominer installation
  - ADB gives full unauthenticated shell access on unpatched devices

Attack pattern:
  1. Connect → receive CNXN handshake
  2. Send OPEN shell: → get a shell
  3. Run: am start ... / pm install ... / shell commands (rm -rf, wget, etc.)

ADB protocol:
  Packet header (24 bytes):
    command  [4]  CNXN / OPEN / CLSE / WRTE / OKAY / SYNC
    arg0     [4]  e.g., host version or local_id
    arg1     [4]  e.g., remote_id
    data_len [4]
    data_crc [4]  CRC32 of data
    magic    [4]  command ^ 0xFFFFFFFF
"""

import socket
import struct
import random
import datetime
import re

# ADB command constants
CMD_SYNC  = 0x434e5953
CMD_CNXN  = 0x4e584e43
CMD_OPEN  = 0x4e45504f
CMD_OKAY  = 0x59414b4f
CMD_CLSE  = 0x45534c43
CMD_WRTE  = 0x45545257
CMD_AUTH  = 0x48545541

ADB_VERSION      = 0x01000000
ADB_MAX_DATA     = 4096

# Fake device properties
_DEVICE_MODEL    = "AndroidTV"
_DEVICE_SERIAL   = "emulator-5554"
_ANDROID_VERSION = "9"
_SDK_VERSION     = "28"
_BUILD_ID        = "PI/android-build/generic_x86:9/PSR1.180720.094"


def _ts():
    return datetime.datetime.utcnow().isoformat()


def _crc32(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = (crc + b) & 0xFFFFFFFF
    return crc


def _build_packet(command: int, arg0: int, arg1: int, data: bytes = b"") -> bytes:
    header = struct.pack(
        "<IIIIII",
        command,
        arg0,
        arg1,
        len(data),
        _crc32(data),
        command ^ 0xFFFFFFFF,
    )
    return header + data


def _parse_packet(raw: bytes):
    if len(raw) < 24:
        return None
    try:
        command, arg0, arg1, data_len, data_crc, magic = struct.unpack_from("<IIIIII", raw, 0)
        if (command ^ 0xFFFFFFFF) != magic:
            return None
        data = raw[24: 24 + data_len]
        return command, arg0, arg1, data
    except Exception:
        return None


def handle_adb(conn, addr, log_attack=None, geoip_func=None,
               intel_fields_func=None, new_ip_alert=None, inc_counter=None,
               log_honeytoken=None):
    ip, src_port = addr
    gdata   = geoip_func(ip) if geoip_func else {}
    country = gdata.get("country", "Unknown")
    city    = gdata.get("city", "")
    local_id  = random.randint(1, 0x7FFFFFFF)
    remote_id = 0

    def _log(attack_type, threat="medium", extra=None):
        if not log_attack:
            return
        entry = {
            "timestamp":    _ts(),
            "source_ip":    ip,
            "source_port":  src_port,
            "dest_port":    5555,
            "service":      "adb",
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
            new_ip_alert(ip, country, city, "adb")
        except Exception:
            pass
    if inc_counter:
        try:
            inc_counter("sessions")
        except Exception:
            pass

    _log("adb_connect", "high")

    try:
        conn.settimeout(30)

        # ADB server speaks first: send CNXN
        device_banner = (
            f"device::{_DEVICE_SERIAL};"
            f"model:{_DEVICE_MODEL};"
            f"product:sdk_phone_x86;"
            f"ro.build.version.release:{_ANDROID_VERSION};"
            f"ro.build.version.sdk:{_SDK_VERSION};"
            f"features=shell_v2,cmd"
        ).encode()
        conn.sendall(_build_packet(CMD_CNXN, ADB_VERSION, ADB_MAX_DATA, device_banner))

        shell_open = False
        shell_buffer = b""
        commands_seen = []

        while True:
            try:
                raw = conn.recv(8192)
            except socket.timeout:
                break
            if not raw:
                break

            parsed = _parse_packet(raw)
            if parsed is None:
                # May be AUTH or garbage
                # Some clients send raw shell text after CNXN
                text = raw.decode(errors="ignore").strip()
                if text:
                    commands_seen.append(text[:80])
                    _log("adb_raw_cmd", "high", {"command": text[:200]})
                continue

            command, arg0, arg1, data = parsed

            # ── CNXN (client hello) ──────────────────────────────────────
            if command == CMD_CNXN:
                # Client introduces itself — log its banner
                banner = data.decode(errors="ignore")
                _log("adb_handshake", "high", {"client_banner": banner[:200]})
                # Respond with our CNXN again (re-confirm)
                conn.sendall(_build_packet(CMD_CNXN, ADB_VERSION, ADB_MAX_DATA, device_banner))

            # ── AUTH ─────────────────────────────────────────────────────
            elif command == CMD_AUTH:
                # Skip auth — just send CNXN to accept
                conn.sendall(_build_packet(CMD_CNXN, ADB_VERSION, ADB_MAX_DATA, device_banner))
                _log("adb_auth_bypass", "high")

            # ── OPEN (shell / file sync) ──────────────────────────────────
            elif command == CMD_OPEN:
                remote_id = arg0
                service = data.rstrip(b"\x00").decode(errors="ignore")

                # Accept the channel
                conn.sendall(_build_packet(CMD_OKAY, local_id, remote_id))

                threat = "critical"
                attack_type = "adb_shell_open"

                if service.startswith("shell:"):
                    cmd_text = service[6:].strip()
                    commands_seen.append(cmd_text)

                    # Detect high-value commands
                    if any(kw in cmd_text.lower() for kw in ["wget", "curl", "chmod", "busybox", "/tmp/"]):
                        attack_type = "adb_malware_download"
                    elif "am start" in cmd_text or "pm install" in cmd_text:
                        attack_type = "adb_apk_install"
                    elif "getprop" in cmd_text or "dumpsys" in cmd_text:
                        attack_type = "adb_recon"
                    elif not cmd_text:
                        attack_type = "adb_interactive_shell"

                    # Send fake shell output then close
                    fake_output = _fake_shell_output(cmd_text)
                    if fake_output:
                        conn.sendall(_build_packet(CMD_WRTE, local_id, remote_id, fake_output))
                        conn.sendall(_build_packet(CMD_OKAY, local_id, remote_id))

                    _log(attack_type, threat, {
                        "service":  service[:100],
                        "command":  cmd_text[:200],
                        "notes":    "ADB shell command — full device access",
                    })

                elif service.startswith("sync:") or service == "sync:":
                    attack_type = "adb_file_sync"
                    _log(attack_type, "critical", {
                        "notes": "ADB file sync — attacker pushing/pulling files",
                    })
                else:
                    _log("adb_service_open", "high", {"service": service[:100]})

                shell_open = True

            # ── WRTE (data on open shell) ─────────────────────────────────
            elif command == CMD_WRTE:
                conn.sendall(_build_packet(CMD_OKAY, local_id, remote_id))
                text = data.decode(errors="ignore").strip()
                if text:
                    commands_seen.append(text[:80])
                    fake_out = _fake_shell_output(text)
                    if fake_out:
                        conn.sendall(_build_packet(CMD_WRTE, local_id, remote_id, fake_out))
                        conn.sendall(_build_packet(CMD_OKAY, local_id, remote_id))
                    _log("adb_shell_cmd", "critical", {"command": text[:200]})

            # ── CLSE (channel close) ──────────────────────────────────────
            elif command == CMD_CLSE:
                conn.sendall(_build_packet(CMD_CLSE, local_id, remote_id))
                break

            # ── OKAY ──────────────────────────────────────────────────────
            elif command == CMD_OKAY:
                pass  # ACK, no response needed

    except (ConnectionResetError, BrokenPipeError, socket.timeout):
        pass
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _fake_shell_output(cmd: str) -> bytes:
    """Return believable shell output for common attacker commands."""
    cmd = cmd.strip()
    if not cmd:
        return b""
    c = cmd.lower().split()[0] if cmd.split() else ""

    if c in ("id", "whoami"):
        return b"uid=0(root) gid=0(root) groups=0(root)\n"
    if c == "uname":
        return b"Linux localhost 3.18.91-perf #1 SMP PREEMPT Fri Jan 12 11:28:43 CST 2018 armv7l Android\n"
    if cmd.startswith("getprop"):
        return (
            b"[ro.build.version.release]: [9]\n"
            b"[ro.product.model]: [AndroidTV]\n"
            b"[ro.serialno]: [emulator-5554]\n"
            b"[ro.product.manufacturer]: [Android]\n"
        )
    if c == "ls":
        return b"/\ndata\ndev\nproc\nsys\nsystem\ncache\nmnt\nvendor\nconfig\n"
    if c in ("cat",):
        return b""
    if c in ("pwd",):
        return b"/\n"
    if c in ("ps",):
        return (
            b"USER     PID   PPID  VSIZE  RSS   WCHAN    PC         NAME\n"
            b"root      1     0     5496   692   SyS_epoll_wait 0 S /init\n"
            b"root      2     0     0      0     kthreadd 0 S kthreadd\n"
            b"u0_a55    1234  312   1085M  52M   SyS_epoll_wait 0 S com.android.tv\n"
        )
    if c in ("rm", "kill", "chmod", "mkdir", "touch"):
        return b""
    if "wget" in c or "curl" in c:
        return b"Connecting...\nHTTP request sent, awaiting response... 200 OK\nSaved\n"
    if "pm install" in cmd:
        return b"pkg: /data/local/tmp/a.apk\nSuccess\n"
    if "am start" in cmd:
        return b"Starting: Intent { ... }\n"
    if "reboot" in cmd:
        return b""
    return b""
