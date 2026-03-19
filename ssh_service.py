import random
import time
import socket
import os
import hashlib
import json
import re
from collections import defaultdict
import base64

# ═══════════════════════════════════════════════════════════════════════════
# ULTIMATE SSH HONEYPOT - Advanced IoT Camera Simulation
# ═══════════════════════════════════════════════════════════════════════════

# ─── Rate Limiting & Tarpit ───────────────────────────────────────────────
_connection_tracker = defaultdict(list)  # IP -> [timestamps]
_failed_auth_tracker = defaultdict(int)  # IP -> failed count
_tarpit_ips = {}  # IP -> tarpit_until_timestamp

RATE_LIMIT_WINDOW = 60  # seconds
MAX_CONNECTIONS_PER_MINUTE = 10
MAX_FAILED_AUTH_BEFORE_TARPIT = 5
TARPIT_DURATION = 300  # 5 minutes
TARPIT_DELAY_PER_PACKET = 2.0  # seconds

def _should_tarpit(ip):
    """Check if IP should be tarpitted (slowed down)"""
    now = time.time()
    
    # Check if currently tarpitted
    if ip in _tarpit_ips:
        if now < _tarpit_ips[ip]:
            return True
        else:
            del _tarpit_ips[ip]
            _failed_auth_tracker[ip] = 0
    
    # Check failed auth count
    if _failed_auth_tracker[ip] >= MAX_FAILED_AUTH_BEFORE_TARPIT:
        _tarpit_ips[ip] = now + TARPIT_DURATION
        return True
    
    # Check connection rate
    _connection_tracker[ip] = [t for t in _connection_tracker[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_connection_tracker[ip]) >= MAX_CONNECTIONS_PER_MINUTE:
        _tarpit_ips[ip] = now + TARPIT_DURATION
        return True
    
    _connection_tracker[ip].append(now)
    return False

# ─── SSH Host Key Fingerprinting ──────────────────────────────────────────
# Generate consistent host keys per honeypot instance
_HOST_KEY_RSA = os.urandom(32)
_HOST_KEY_FINGERPRINT_MD5 = hashlib.md5(_HOST_KEY_RSA).hexdigest()
_HOST_KEY_FINGERPRINT_SHA256 = base64.b64encode(hashlib.sha256(_HOST_KEY_RSA).digest()).decode().rstrip('=')

def _get_ssh_host_key_fingerprint():
    """Return SSH host key fingerprint (like real SSH server)"""
    # Format like real SSH: "2048 SHA256:abc123... root@hostname (RSA)"
    return f"2048 SHA256:{_HOST_KEY_FINGERPRINT_SHA256} root@camera (RSA)"

# ─── SSH Banners (IoT-specific versions) ──────────────────────────────────
_SSH_BANNERS = [
    b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
    b"SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1\r\n",
    b"SSH-2.0-dropbear_2022.82\r\n",
    b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\n",
    b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n",
    b"SSH-2.0-ROSSSH\r\n",  # Hikvision custom SSH
]

# ─── Weak Credentials (expanded) ──────────────────────────────────────────
WEAK_CREDENTIALS = {
    "root": ["root", "toor", "admin", "password", "12345", "123456", "rootroot", "raspberry", "alpine", "vizxv", "xc3511", "juantech", "anko", "Zte521", ""],
    "admin": ["admin", "password", "12345", "123456", "admin123", "administrator", "smcadmin", "1234", ""],
    "pi": ["raspberry", "pi", "123456", "password", ""],
    "user": ["user", "password", "12345", ""],
    "ubuntu": ["ubuntu", "password", "123456", ""],
    "support": ["support", "password", "12345", ""],
    "service": ["service", "12345", "password", ""],
    "guest": ["guest", "password", "12345", ""],
    "hikvision": ["hikvision", "12345", ""],
    "default": ["default", "12345", ""],
}

# ─── Shell Prompts (IoT-specific) ─────────────────────────────────────────
_PROMPTS = [
    "# ",
    "root@DVR:~# ",
    "root@IPC:~# ",
    "/ # ",
    "[root@camera]# ",
    "root@(none):/# ",
    "HiLinux # ",
]

# ═══════════════════════════════════════════════════════════════════════════
# IoT-Specific File System & Commands
# ═══════════════════════════════════════════════════════════════════════════

# IoT device configuration files (honeytokens)
_IOT_FILES = {
    "/.dvr_config": """[System]
DeviceType=NVR
Model=DS-2CD2043G2-I
SerialNumber=DS-2CD2043G2-I20230313BBRR012345
FirmwareVersion=V5.7.15 build 230313

[Network]
IP=192.168.1.108
MAC=44:19:B6:7A:2C:D9
Gateway=192.168.1.1
DNS1=8.8.8.8

[Admin]
Username=admin
Password=Admin@2024!
EnableSSH=true
""",
    
    "/etc/hikvision.conf": """DEVICE_MODEL=DS-2CD2043G2-I
FIRMWARE=V5.7.15
ADMIN_USER=admin
ADMIN_PASS=Admin@2024!
RTSP_PORT=554
HTTP_PORT=80
ONVIF_PORT=8000
""",
    
    "/etc/passwd": """root:x:0:0:root:/root:/bin/ash
daemon:x:1:1:daemon:/usr/sbin:/bin/false
bin:x:2:2:bin:/bin:/bin/false
sys:x:3:3:sys:/dev:/bin/false
admin:x:500:500:System Administrator:/home/admin:/bin/ash
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
""",
    
    "/etc/shadow": """root:$1$abc123$hashhashhashhash:18000:0:99999:7:::
admin:$1$xyz789$hashhashhashhash:18000:0:99999:7:::
""",
    
    "/mnt/dvr/recordings/": """total 0
drwxr-xr-x 2 root root 4096 Mar 19 10:00 .
drwxr-xr-x 3 root root 4096 Mar 19 10:00 ..
-rw-r--r-- 1 root root 2147483648 Mar 19 10:00 record_20260319_100000.mp4
-rw-r--r-- 1 root root 2147483648 Mar 19 09:00 record_20260319_090000.mp4
""",
    
    "/tmp/": """total 0
drwxrwxrwt 2 root root 4096 Mar 19 10:00 .
drwxr-xr-x 3 root root 4096 Mar 19 10:00 ..
""",
}

# Expanded shell commands (IoT-specific)
_COMMAND_RESPONSES = {
    "uname": "Linux\r\n",
    "uname -a": "Linux IPC 3.10.14 #1 SMP PREEMPT Mon Oct 19 08:36:54 UTC 2021 armv7l GNU/Linux\r\n",
    "uname -r": "3.10.14\r\n",
    "uname -m": "armv7l\r\n",
    
    "cat /proc/cpuinfo": """processor\t: 0
model name\t: ARMv7 Processor rev 4 (v7l)
BogoMIPS\t: 1600.00
Features\t: swp half thumb fastmult vfp edsp neon vfpv3
CPU implementer\t: 0x41
CPU architecture: 7
CPU variant\t: 0x0
CPU part\t: 0xc07
CPU revision\t: 4

Hardware\t: Hikvision IPCamera
Revision\t: 0000
Serial\t\t: 0000000000000000
""",
    
    "cat /proc/meminfo": """MemTotal:         524288 kB
MemFree:          128000 kB
MemAvailable:     256000 kB
Buffers:           16384 kB
Cached:            98304 kB
SwapCached:            0 kB
Active:           163840 kB
Inactive:          81920 kB
""",
    
    "cat /proc/mounts": """/dev/root / ext4 ro,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /tmp tmpfs rw,relatime 0 0
/dev/mtdblock5 /mnt/dvr ext4 rw,relatime 0 0
""",
    
    "cat /proc/version": "Linux version 3.10.14 (builder@hikvision) (gcc version 4.8.3 20140320 (prerelease)) #1 SMP PREEMPT Mon Oct 19 08:36:54 UTC 2021\r\n",
    
    "id": "uid=0(root) gid=0(root) groups=0(root)\r\n",
    "whoami": "root\r\n",
    "pwd": "/root\r\n",
    
    "ls": "bin  dev  etc  home  lib  mnt  proc  root  sbin  sys  tmp  usr  var\r\n",
    "ls -l": """total 0
drwxr-xr-x  2 root root  4096 Oct 19  2021 bin
drwxr-xr-x  4 root root  4096 Mar 19 10:00 dev
drwxr-xr-x  5 root root  4096 Oct 19  2021 etc
drwxr-xr-x  3 root root  4096 Oct 19  2021 home
drwxr-xr-x  5 root root  4096 Oct 19  2021 lib
drwxr-xr-x  3 root root  4096 Mar 19 10:00 mnt
dr-xr-xr-x 78 root root     0 Mar 19 10:00 proc
drwx------  2 root root  4096 Oct 19  2021 root
drwxr-xr-x  2 root root  4096 Oct 19  2021 sbin
dr-xr-xr-x 13 root root     0 Mar 19 10:00 sys
drwxrwxrwt  2 root root  4096 Mar 19 10:00 tmp
drwxr-xr-x  7 root root  4096 Oct 19  2021 usr
drwxr-xr-x  5 root root  4096 Oct 19  2021 var
""",
    
    "ls /": "bin  dev  etc  home  lib  mnt  proc  root  sbin  sys  tmp  usr  var\r\n",
    "ls /mnt": "dvr\r\n",
    "ls /mnt/dvr": "recordings  config\r\n",
    
    "ps": """  PID USER       VSZ STAT COMMAND
    1 root      1040 S    init
  123 root      2048 S    /sbin/syslogd
  234 root      3072 S    /usr/sbin/sshd
  345 root      4096 S    /usr/sbin/httpd
  456 root      8192 S    /usr/bin/ipc_server
  567 root     16384 S    /usr/bin/rtsp_server
  678 root      2048 S    /bin/sh
""",
    
    "ps aux": """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1   1040   256 ?        S    Oct19   0:00 init
root       123  0.0  0.2   2048   512 ?        S    Oct19   0:00 /sbin/syslogd
root       234  0.1  0.3   3072   768 ?        S    Oct19   0:12 /usr/sbin/sshd
root       345  0.2  0.4   4096  1024 ?        S    Oct19   0:34 /usr/sbin/httpd
root       456  1.2  1.6   8192  4096 ?        S    Oct19   5:67 /usr/bin/ipc_server
root       567  0.8  3.2  16384  8192 ?        S    Oct19   3:45 /usr/bin/rtsp_server
""",
    
    "ps -ef": """UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 Oct19 ?        00:00:00 init
root       123     1  0 Oct19 ?        00:00:00 /sbin/syslogd
root       234     1  0 Oct19 ?        00:00:12 /usr/sbin/sshd
root       345     1  0 Oct19 ?        00:00:34 /usr/sbin/httpd
root       456     1  1 Oct19 ?        05:67:89 /usr/bin/ipc_server
root       567     1  0 Oct19 ?        03:45:12 /usr/bin/rtsp_server
""",
    
    "ifconfig": """eth0      Link encap:Ethernet  HWaddr 44:19:B6:7A:2C:D9
          inet addr:192.168.1.108  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:123456 errors:0 dropped:0 overruns:0 frame:0
          TX packets:654321 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:98765432 (94.1 MiB)  TX bytes:12345678 (11.7 MiB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
""",
    
    "ip addr": """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 44:19:b6:7a:2c:d9 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.108/24 brd 192.168.1.255 scope global eth0
""",
    
    "netstat -an": """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:554             0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.108:22        192.168.1.1:54321       ESTABLISHED
""",
    
    "free": """             total       used       free     shared    buffers     cached
Mem:        524288     396288     128000          0      16384      98304
-/+ buffers/cache:     281600     242688
Swap:            0          0          0
""",
    
    "df": """Filesystem           1K-blocks      Used Available Use% Mounted on
/dev/root               524288    393216    131072  75% /
tmpfs                   262144      1024    261120   1% /tmp
/dev/mtdblock5         2097152   1048576   1048576  50% /mnt/dvr
""",
    
    "df -h": """Filesystem                Size      Used Available Use% Mounted on
/dev/root               512.0M    384.0M    128.0M  75% /
tmpfs                   256.0M      1.0M    255.0M   1% /tmp
/dev/mtdblock5            2.0G      1.0G      1.0G  50% /mnt/dvr
""",
    
    "mount": """/dev/root on / type ext4 (ro,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /tmp type tmpfs (rw,relatime)
/dev/mtdblock5 on /mnt/dvr type ext4 (rw,relatime)
""",
    
    "dmesg | tail": """[    0.000000] Linux version 3.10.14 (builder@hikvision)
[    0.000000] CPU: ARMv7 Processor [410fc075] revision 5 (ARMv7), cr=10c5387d
[    1.234567] Hikvision IPCamera platform initialized
[    2.345678] eth0: link up, 100Mbps, full-duplex
[    3.456789] RTSP server starting on port 554
[    4.567890] HTTP server starting on port 80
[    5.678901] Camera module initialized: DS-2CD2043G2-I
[    6.789012] Recording service started
[    7.890123] ONVIF service ready on port 8000
""",
    
    "uptime": " 10:00:00 up 45 days,  3:21,  1 user,  load average: 0.12, 0.08, 0.05\r\n",
    
    "date": time.strftime("%a %b %d %H:%M:%S UTC %Y\r\n", time.gmtime()),
    
    "hostname": "IPC\r\n",
    
    "busybox": "BusyBox v1.31.1 (2021-10-19 08:36:54 UTC) multi-call binary.\r\nBusyBox is copyrighted by many authors between 1998-2015.\r\n",
    
    "cat /etc/motd": "Welcome to Hikvision IP Camera\r\nFirmware: V5.7.15 build 230313\r\n",
    
    "cat /etc/issue": "Hikvision Embedded Linux\r\n",
    
    "cat /etc/hostname": "IPC\r\n",
    
    "env": """HOME=/root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SHELL=/bin/ash
TERM=xterm
USER=root
LOGNAME=root
PWD=/root
DEVICE_MODEL=DS-2CD2043G2-I
FIRMWARE_VERSION=V5.7.15
""",
    
    "printenv": """HOME=/root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SHELL=/bin/ash
USER=root
""",
}

# ─── Session Replay Database ──────────────────────────────────────────────
_session_replay_db = []  # List of previous attack sessions
MAX_REPLAY_SESSIONS = 50

def _save_session_for_replay(session_data):
    """Save interesting attack sessions for replay"""
    if len(session_data.get("commands", [])) >= 3:  # Only save sessions with 3+ commands
        _session_replay_db.append({
            "username": session_data.get("username"),
            "password": session_data.get("password"),
            "commands": session_data.get("commands", []),
            "timestamp": time.time(),
        })
        
        # Keep only last N sessions
        if len(_session_replay_db) > MAX_REPLAY_SESSIONS:
            _session_replay_db.pop(0)

def _should_replay_session():
    """Randomly decide if we should replay a previous session (5% chance)"""
    return _session_replay_db and random.random() < 0.05

def _get_replay_session():
    """Get a random previous session to replay"""
    if _session_replay_db:
        return random.choice(_session_replay_db)
    return None

# ═══════════════════════════════════════════════════════════════════════════
# SSH Protocol Implementation
# ═══════════════════════════════════════════════════════════════════════════

def _ssh_packet(payload):
    """Build SSH protocol packet"""
    packet_len = len(payload) + 1
    padding_len = 8 - (packet_len % 8) if packet_len % 8 else 8
    padding = os.urandom(padding_len)
    
    packet = (
        (packet_len + padding_len).to_bytes(4, 'big') +
        padding_len.to_bytes(1, 'big') +
        payload +
        padding
    )
    return packet

def _ssh_kex_init():
    """SSH Key Exchange Init packet"""
    cookie = os.urandom(16)
    payload = (
        b'\x14' +
        cookie +
        b'\x00\x00\x00\x45' + b'diffie-hellman-group14-sha1,diffie-hellman-group1-sha1' +
        b'\x00\x00\x00\x07' + b'ssh-rsa' +
        b'\x00\x00\x00\x0d' + b'aes128-cbc' +
        b'\x00\x00\x00\x0d' + b'aes128-cbc' +
        b'\x00\x00\x00\x09' + b'hmac-sha1' +
        b'\x00\x00\x00\x09' + b'hmac-sha1' +
        b'\x00\x00\x00\x04' + b'none' +
        b'\x00\x00\x00\x04' + b'none' +
        b'\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00' +
        b'\x00' +
        b'\x00\x00\x00\x00'
    )
    return _ssh_packet(payload)

def _ssh_service_accept(service_name):
    """SSH Service Accept"""
    payload = b'\x06' + len(service_name).to_bytes(4, 'big') + service_name
    return _ssh_packet(payload)

def _ssh_userauth_failure(methods=b"password,publickey"):
    """SSH UserAuth Failure"""
    payload = b'\x33' + len(methods).to_bytes(4, 'big') + methods + b'\x00'
    return _ssh_packet(payload)

def _ssh_userauth_success():
    """SSH UserAuth Success"""
    return _ssh_packet(b'\x34')

def _ssh_channel_open_confirmation(recipient_channel, sender_channel):
    """SSH Channel Open Confirmation"""
    payload = (
        b'\x5b' +
        recipient_channel.to_bytes(4, 'big') +
        sender_channel.to_bytes(4, 'big') +
        (32768).to_bytes(4, 'big') +
        (16384).to_bytes(4, 'big')
    )
    return _ssh_packet(payload)

def _ssh_channel_success(recipient_channel):
    """SSH Channel Success"""
    payload = b'\x63' + recipient_channel.to_bytes(4, 'big')
    return _ssh_packet(payload)

def _ssh_channel_data(recipient_channel, data):
    """SSH Channel Data"""
    if isinstance(data, str):
        data = data.encode()
    payload = (
        b'\x5e' +
        recipient_channel.to_bytes(4, 'big') +
        len(data).to_bytes(4, 'big') +
        data
    )
    return _ssh_packet(payload)

def _parse_ssh_packet(data):
    """Parse SSH packet"""
    if len(data) < 5:
        return None, None
    
    packet_len = int.from_bytes(data[0:4], 'big')
    padding_len = data[4]
    
    if len(data) < packet_len + 4:
        return None, None
    
    payload_len = packet_len - padding_len - 1
    payload = data[5:5+payload_len]
    
    if not payload:
        return None, None
    
    msg_type = payload[0]
    msg_data = payload[1:]
    
    return msg_type, msg_data

def _extract_string(data, offset=0):
    """Extract SSH string"""
    if len(data) < offset + 4:
        return None, offset
    
    str_len = int.from_bytes(data[offset:offset+4], 'big')
    if len(data) < offset + 4 + str_len:
        return None, offset
    
    string = data[offset+4:offset+4+str_len]
    return string, offset + 4 + str_len

# ═══════════════════════════════════════════════════════════════════════════
# Command Execution Engine (Expanded)
# ═══════════════════════════════════════════════════════════════════════════

def _execute_command(cmd):
    """Execute fake shell command with IoT-specific responses"""
    cmd = cmd.strip()
    
    if not cmd:
        return ""
    
    # Check exact matches first
    if cmd in _COMMAND_RESPONSES:
        return _COMMAND_RESPONSES[cmd]
    
    # Extract command name
    cmd_parts = cmd.split()
    cmd_name = cmd_parts[0] if cmd_parts else cmd
    
    # cat commands - check for IoT files
    if cmd_name == "cat":
        for filepath in _IOT_FILES:
            if filepath in cmd:
                return _IOT_FILES[filepath]
    
    # ls commands with paths
    if cmd_name in ["ls", "ll", "dir"]:
        if "/mnt/dvr/recordings" in cmd:
            return _IOT_FILES["/mnt/dvr/recordings/"]
        elif "/tmp" in cmd:
            return _IOT_FILES["/tmp/"]
        return _COMMAND_RESPONSES.get("ls -l", _COMMAND_RESPONSES["ls"])
    
    # wget/curl - simulate download
    if cmd_name in ["wget", "curl", "tftp"]:
        return ""  # Silent success
    
    # chmod/chown - accept silently
    if cmd_name in ["chmod", "chown", "chgrp"]:
        return ""
    
    # cd - accept silently
    if cmd_name == "cd":
        return ""
    
    # echo
    if cmd_name == "echo":
        if len(cmd_parts) > 1:
            return " ".join(cmd_parts[1:]).replace('"', '').replace("'", '') + "\r\n"
        return "\r\n"
    
    # kill - accept silently
    if cmd_name == "kill":
        return ""
    
    # reboot/poweroff
    if cmd_name in ["reboot", "poweroff", "halt", "shutdown"]:
        return "The system is going down for reboot NOW!\r\n"
    
    # Unknown command
    return f"{cmd_name}: command not found\r\n"

# ═══════════════════════════════════════════════════════════════════════════
# Scanner & Tool Detection
# ═══════════════════════════════════════════════════════════════════════════

_SCANNER_SIGNATURES = {
    "masscan": ["masscan"],
    "nmap": ["nmap"],
    "zgrab": ["zgrab"],
    "shodan": ["shodan"],
    "hydra": ["hydra"],
    "medusa": ["medusa"],
    "metasploit": ["metasploit"],
    "paramiko": ["paramiko"],
    "putty": ["putty"],
    "libssh": ["libssh"],
}

def _detect_scanner(text):
    """Detect scanner from SSH client string"""
    t = text.lower()
    for tool, signatures in _SCANNER_SIGNATURES.items():
        if any(sig in t for sig in signatures):
            return tool
    return ""

# ═══════════════════════════════════════════════════════════════════════════
# Credential & Malware Detection
# ═══════════════════════════════════════════════════════════════════════════

def _validate_credentials(username, password):
    """Check credentials"""
    if username in WEAK_CREDENTIALS:
        if password in WEAK_CREDENTIALS[username]:
            return True
    return False

def _detect_malware_url(cmd):
    """Detect malware download URLs"""
    patterns = [
        r"(https?://\S+\.(?:sh|elf|bin|arm|mips|x86|arm7|arm5|m68k|ppc|mpsl|mipsel))\b",
        r"(?:wget|curl|tftp\s+-g)\s+(https?://\S+)",
        r"(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:\d]*/\S+)",
    ]
    for pat in patterns:
        m = re.search(pat, cmd, re.I)
        if m:
            return m.group(1)
    return None

def _detect_arch(cmd_str):
    """Detect architecture"""
    for a in ["arm7", "arm6", "arm5", "arm", "mips", "mipsel", "mpsl", "x86", "i686", "ppc", "m68k", "sh4"]:
        if a in cmd_str.lower():
            return a
    return "unknown"

def _detect_botnet_family(cmd_str):
    """Detect botnet family"""
    families = {
        "Mirai":   ["busybox", "ECCHI", "/bin/busybox"],
        "Gafgyt":  ["HTTPFLOOD", "tftp -g"],
        "Mozi":    ["mozi", "nttpd"],
        "Muhstik": ["muhstik", "irc"],
    }
    s = cmd_str.lower()
    for fam, indicators in families.items():
        if any(ind.lower() in s for ind in indicators):
            return fam
    return "Unknown"

# ═══════════════════════════════════════════════════════════════════════════
# Main SSH Handler (ULTIMATE VERSION)
# ═══════════════════════════════════════════════════════════════════════════

def handle_ssh(conn, addr, log_attack=None, geoip_func=None, intel_fields_func=None, new_ip_alert=None):
    """
    ULTIMATE SSH honeypot handler with advanced IoT features
    """
    ip, port = addr
    
    # ─── Rate Limiting / Tarpit ───────────────────────────────────────────
    is_tarpitted = _should_tarpit(ip)
    
    if is_tarpitted and log_attack:
        log_attack(ip, 22, "SSH_TARPIT", json.dumps({
            "event": "tarpitted",
            "reason": "excessive_connections_or_failed_auth",
        }))
    
    # Session tracking
    session = {
        "authenticated": False,
        "username": "",
        "password": "",
        "auth_attempts": 0,
        "commands": [],
        "start_time": time.time(),
        "client_version": "",
        "channel_open": False,
        "recipient_channel": 0,
        "is_tarpitted": is_tarpitted,
        "is_replay": False,
    }
    
    try:
        # Get geo data
        gdata = geoip_func(ip) if geoip_func else {}
        
        # Initial connection log
        if log_attack:
            log_attack(ip, 22, "SSH_CONNECT", json.dumps({
                "event": "connection",
                "country": gdata.get("country", "Unknown"),
                "city": gdata.get("city", ""),
                "is_tarpitted": is_tarpitted,
            }))
        
        # Alert on new IP
        if new_ip_alert and gdata:
            new_ip_alert(ip, gdata.get("country", ""), gdata.get("city", ""), "ssh")
        
        # Tarpit delay
        if is_tarpitted:
            time.sleep(TARPIT_DELAY_PER_PACKET * 2)
        else:
            time.sleep(random.uniform(0.08, 0.22))
        
        # Send SSH banner
        banner = random.choice(_SSH_BANNERS)
        conn.sendall(banner)
        
        # Tarpit delay
        if is_tarpitted:
            time.sleep(TARPIT_DELAY_PER_PACKET)
        
        # Receive client version
        conn.settimeout(10 if not is_tarpitted else 30)
        try:
            client_banner = conn.recv(512)
            if client_banner:
                session["client_version"] = client_banner.decode(errors="ignore").strip()
                
                # Detect scanner
                scanner = _detect_scanner(session["client_version"])
                
                # Log with SSH host key fingerprint
                if log_attack:
                    log_attack(ip, 22, "SSH_BANNER_EXCHANGE", json.dumps({
                        "client_version": session["client_version"][:200],
                        "server_version": banner.decode().strip(),
                        "host_key_fingerprint": _get_ssh_host_key_fingerprint(),
                        "scanner_tool": scanner,
                    }))
        except socket.timeout:
            return
        
        # Send Key Exchange Init
        conn.sendall(_ssh_kex_init())
        
        # Tarpit delay
        if is_tarpitted:
            time.sleep(TARPIT_DELAY_PER_PACKET)
        
        # ─── Session Replay (5% chance) ───────────────────────────────────
        replay_session = None
        if _should_replay_session():
            replay_session = _get_replay_session()
            if replay_session:
                session["is_replay"] = True
                if log_attack:
                    log_attack(ip, 22, "SSH_SESSION_REPLAY", json.dumps({
                        "original_username": replay_session["username"],
                        "original_commands": replay_session["commands"],
                    }))
        
        # Process authentication and commands
        for _ in range(50):
            try:
                conn.settimeout(30 if not is_tarpitted else 60)
                data = conn.recv(8192)
                if not data:
                    break
                
                # Tarpit delay
                if is_tarpitted:
                    time.sleep(TARPIT_DELAY_PER_PACKET)
                
                msg_type, msg_data = _parse_ssh_packet(data)
                
                if msg_type is None:
                    continue
                
                # SSH_MSG_KEXINIT (20)
                if msg_type == 20:
                    pass
                
                # SSH_MSG_SERVICE_REQUEST (5)
                elif msg_type == 5:
                    service_name, _ = _extract_string(msg_data)
                    if service_name:
                        conn.sendall(_ssh_service_accept(service_name))
                        if is_tarpitted:
                            time.sleep(TARPIT_DELAY_PER_PACKET)
                
                # SSH_MSG_USERAUTH_REQUEST (50)
                elif msg_type == 50:
                    username, offset = _extract_string(msg_data)
                    service_name, offset = _extract_string(msg_data, offset)
                    method_name, offset = _extract_string(msg_data, offset)
                    
                    if username:
                        username = username.decode(errors="ignore")
                    if method_name:
                        method_name = method_name.decode(errors="ignore")
                    
                    session["username"] = username
                    session["auth_attempts"] += 1
                    
                    # Password authentication
                    if method_name == "password":
                        password, _ = _extract_string(msg_data, offset + 1)
                        if password:
                            password = password.decode(errors="ignore")
                            session["password"] = password
                        
                        is_valid = _validate_credentials(username, password)
                        
                        # Log authentication attempt
                        if log_attack:
                            log_attack(ip, 22, "SSH_AUTH_ATTEMPT", json.dumps({
                                "username": username,
                                "password": password,
                                "method": method_name,
                                "attempt": session["auth_attempts"],
                                "success": False,
                                "is_tarpitted": is_tarpitted,
                            }))
                        
                        # Accept after 2nd attempt or if using replay credentials
                        accept_auth = False
                        if session["auth_attempts"] >= 2 and is_valid:
                            accept_auth = True
                        elif is_valid and random.random() < 0.1:  # 10% chance immediate success
                            accept_auth = True
                        elif replay_session and username == replay_session["username"]:
                            accept_auth = True
                        
                        if accept_auth:
                            session["authenticated"] = True
                            conn.sendall(_ssh_userauth_success())
                            
                            if log_attack:
                                log_attack(ip, 22, "SSH_AUTH_SUCCESS", json.dumps({
                                    "username": username,
                                    "password": password,
                                    "attempts": session["auth_attempts"],
                                    "is_replay": session["is_replay"],
                                }))
                            
                            if is_tarpitted:
                                time.sleep(TARPIT_DELAY_PER_PACKET)
                        else:
                            # Track failed auth for tarpit
                            _failed_auth_tracker[ip] += 1
                            
                            conn.sendall(_ssh_userauth_failure())
                            if is_tarpitted:
                                time.sleep(TARPIT_DELAY_PER_PACKET * 3)
                    
                    # Public key
                    elif method_name == "publickey":
                        if log_attack:
                            log_attack(ip, 22, "SSH_PUBKEY_ATTEMPT", json.dumps({
                                "username": username,
                            }))
                        conn.sendall(_ssh_userauth_failure(b"password"))
                
                # SSH_MSG_CHANNEL_OPEN (90)
                elif msg_type == 90 and session["authenticated"]:
                    channel_type, offset = _extract_string(msg_data)
                    if len(msg_data) >= offset + 12:
                        sender_channel = int.from_bytes(msg_data[offset:offset+4], 'big')
                        session["recipient_channel"] = sender_channel
                        session["channel_open"] = True
                        
                        conn.sendall(_ssh_channel_open_confirmation(sender_channel, 0))
                        if is_tarpitted:
                            time.sleep(TARPIT_DELAY_PER_PACKET)
                
                # SSH_MSG_CHANNEL_REQUEST (98)
                elif msg_type == 98 and session["channel_open"]:
                    recipient_channel = int.from_bytes(msg_data[0:4], 'big')
                    request_type, offset = _extract_string(msg_data, 4)
                    
                    if request_type:
                        request_type = request_type.decode(errors="ignore")
                    
                    if request_type in ["pty-req", "shell"]:
                        conn.sendall(_ssh_channel_success(recipient_channel))
                        
                        if request_type == "shell":
                            prompt = random.choice(_PROMPTS)
                            conn.sendall(_ssh_channel_data(recipient_channel, prompt))
                        
                        if is_tarpitted:
                            time.sleep(TARPIT_DELAY_PER_PACKET)
                    
                    # exec request
                    elif request_type == "exec":
                        command, _ = _extract_string(msg_data, offset + 1)
                        if command:
                            command = command.decode(errors="ignore")
                            session["commands"].append(command)
                            
                            # ─── Session Replay: Use replay commands ──────
                            if replay_session and len(session["commands"]) <= len(replay_session["commands"]):
                                output = _execute_command(command)
                            else:
                                output = _execute_command(command)
                            
                            # Detect malware
                            mal_url = _detect_malware_url(command)
                            if mal_url and log_attack:
                                arch = _detect_arch(command)
                                family = _detect_botnet_family(" ".join(session["commands"]))
                                log_attack(ip, 22, "SSH_MALWARE", json.dumps({
                                    "url": mal_url,
                                    "command": command,
                                    "arch": arch,
                                    "family": family,
                                }))
                            
                            # Log command
                            if log_attack:
                                log_attack(ip, 22, "SSH_COMMAND", json.dumps({
                                    "command": command,
                                    "username": session["username"],
                                }))
                            
                            # Check for honeytokens
                            for honeytoken_file in _IOT_FILES:
                                if honeytoken_file in command:
                                    if log_attack:
                                        log_attack(ip, 22, "SSH_HONEYTOKEN", json.dumps({
                                            "file": honeytoken_file,
                                            "command": command,
                                        }))
                            
                            if output:
                                conn.sendall(_ssh_channel_data(recipient_channel, output))
                            
                            conn.sendall(_ssh_channel_success(recipient_channel))
                            
                            if is_tarpitted:
                                time.sleep(TARPIT_DELAY_PER_PACKET)
                
                # SSH_MSG_CHANNEL_DATA (94)
                elif msg_type == 94 and session["channel_open"]:
                    recipient_channel = int.from_bytes(msg_data[0:4], 'big')
                    data_str, _ = _extract_string(msg_data, 4)
                    
                    if data_str:
                        command = data_str.decode(errors="ignore").strip()
                        
                        if command in ["exit", "quit", "logout"]:
                            break
                        
                        if command:
                            session["commands"].append(command)
                            output = _execute_command(command)
                            
                            # Detect malware
                            mal_url = _detect_malware_url(command)
                            if mal_url and log_attack:
                                arch = _detect_arch(command)
                                family = _detect_botnet_family(" ".join(session["commands"]))
                                log_attack(ip, 22, "SSH_MALWARE", json.dumps({
                                    "url": mal_url,
                                    "command": command,
                                    "arch": arch,
                                    "family": family,
                                }))
                            
                            # Log command
                            if log_attack:
                                log_attack(ip, 22, "SSH_COMMAND", json.dumps({
                                    "command": command,
                                    "username": session["username"],
                                }))
                            
                            # Honeytoken check
                            for honeytoken_file in _IOT_FILES:
                                if honeytoken_file in command:
                                    if log_attack:
                                        log_attack(ip, 22, "SSH_HONEYTOKEN", json.dumps({
                                            "file": honeytoken_file,
                                            "command": command,
                                        }))
                            
                            if output:
                                conn.sendall(_ssh_channel_data(recipient_channel, output))
                            
                            prompt = random.choice(_PROMPTS)
                            conn.sendall(_ssh_channel_data(recipient_channel, prompt))
                            
                            if is_tarpitted:
                                time.sleep(TARPIT_DELAY_PER_PACKET)
                
                # SSH_MSG_DISCONNECT (1)
                elif msg_type == 1:
                    break
            
            except socket.timeout:
                break
            except Exception:
                break
    
    except Exception as e:
        if log_attack:
            log_attack(ip, 22, "SSH_ERROR", json.dumps({"error": str(e)}))
    
    finally:
        # Save session for replay
        if session["commands"] and not session["is_replay"]:
            _save_session_for_replay(session)
        
        # Session complete logging
        if log_attack and (session["commands"] or session["auth_attempts"] > 0):
            session_duration = time.time() - session["start_time"]
            log_attack(ip, 22, "SSH_SESSION_END", json.dumps({
                "duration": round(session_duration, 2),
                "authenticated": session["authenticated"],
                "username": session.get("username", ""),
                "password": session.get("password", ""),
                "auth_attempts": session["auth_attempts"],
                "commands": session["commands"],
                "command_count": len(session["commands"]),
                "is_tarpitted": is_tarpitted,
                "is_replay": session["is_replay"],
            }))
        
        try:
            conn.close()
        except Exception:
            pass