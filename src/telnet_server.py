import socket, threading, time, logging, re, json, os, sys
from pathlib import Path

# Ensure project root is on sys.path
sys.path.append(str(Path(__file__).resolve().parents[1]))
from db import log_attack

try:
    import geoip2.database
    GEOIP_DB = os.environ.get("GEOIP_DB")
    geo_reader = geoip2.database.Reader(GEOIP_DB) if GEOIP_DB else None
except ImportError:
    geo_reader = None

def get_geo(ip):
    if not geo_reader:
        return {"country": "Unknown", "city": "", "latitude": 0.0, "longitude": 0.0}
    try:
        rec = geo_reader.city(ip)
        return {
            "country": rec.country.name or "Unknown",
            "city": rec.city.name or "",
            "latitude": rec.location.latitude or 0.0,
            "longitude": rec.location.longitude or 0.0,
        }
    except Exception:
        return {"country": "Unknown", "city": "", "latitude": 0.0, "longitude": 0.0}

def clean_input(data):
    # Strip Telnet negotiation commands (IAC) and return decoded string
    cleaned = re.sub(b'\xff[\xfb-\xfe].', b'', data).replace(b'\r', b'').replace(b'\n', b'')
    # Remove control characters like Backspace (\x08) or NULL (\x00) for clean DB logging
    return cleaned.decode('utf-8', errors='ignore').replace('\x08', '').replace('\x00', '').strip()

def handle_telnet_client(client, addr):
    ip, port = addr
    logging.info(f"Telnet connection from {ip}:{port}")
    
    geo = get_geo(ip)
    session_data = {
        "source_ip": ip, "source_port": port, "dest_port": 23,
        "service": "telnet", "protocol": "TCP", "method": "EXEC",
        "path": "", "user_agent": "telnet-client",
        "country": geo["country"], "city": geo["city"],
        "latitude": geo["latitude"], "longitude": geo["longitude"],
        "threat_level": "high"
    }

    username = ""
    commands_run = []

    try:
        client.settimeout(60.0) # Give them more time to interact
        
        # 1. Realistic HiLinux Banner
        client.sendall(b"\r\nWelcome to HiLinux.\r\n\r\n")
        
        login_attempts = 0
        while login_attempts < 3:
            client.sendall(b"(none) login: ")
            username = clean_input(client.recv(1024))
            
            client.sendall(b"Password: ")
            password = clean_input(client.recv(1024))
            
            session_data["username"] = username
            session_data["password"] = password
            
            # Artificial delay to simulate real PAM/shadow password checking
            time.sleep(1.5)
            
            # Mark as critical if they used common botnet creds
            if username in ["root", "admin", "guest", "support", "default"]:
                session_data["threat_level"] = "critical"
                session_data["attack_type"] = "brute-force"
                client.sendall(b"\r\nLogin successful\r\n")
                break
            elif login_attempts >= 1:
                # Always let them in on the 2nd try so we can capture their malware payload!
                client.sendall(b"\r\nLogin successful\r\n")
                break
            else:
                # Fake a failure on the first unknown try to grab more dictionary passwords
                client.sendall(b"Login incorrect\r\n\r\n")
                login_attempts += 1
        
        # 2. Fake Shell Simulation
        cwd = "/"
        session_files = [] # Keep track of dynamically created malicious files
        
        while True:
            # Dynamic prompt based on directory
            prompt = f"{cwd} # ".replace("/root", "~").encode()
            client.sendall(prompt)
            
            cmd_data = client.recv(1024)
            if not cmd_data:
                break
                
            # Handle Ctrl+C (0x03) gracefully like a real terminal
            if b'\x03' in cmd_data:
                client.sendall(b"^C\r\n")
                continue
                
            cmd_line = clean_input(cmd_data)
            if not cmd_line:
                continue
                
            commands_run.append(cmd_line)
            
            # --- AMAZING FEATURE: Command Chaining ---
            # Parse commands like: "cd /tmp; wget http://... && chmod +x ... ; ./..."
            sub_commands = [c.strip() for c in re.split(r';|&&|\|\|', cmd_line) if c.strip()]
            
            # Execute them sequentially
            for cmd_step in sub_commands:
                # Strip out output redirections like "> /dev/null 2>&1" so they don't mess up our parsing
                clean_step = re.sub(r'>\s*/dev/null(?:\s*2>&1)?', '', cmd_step).strip()
                parts = clean_step.split()
                if not parts:
                    continue
                    
                base_cmd = parts[0]
                
                # --- REALISTIC COMMAND RESPONSES ---
                if base_cmd == "ls":
                    out_str = ""
                    if len(parts) > 1 and ("-l" in parts[1] or "-a" in parts[1]):
                        if cwd == "/":
                            out_str = ("total 68\r\n"
                                       "drwx------  1 root  root      6971  Feb 18 09:12  .\r\n"
                                       "drwx------  1 root  root      4143  Feb 18 09:12  ..\r\n"
                                       "drwxr-xr-x  1 root  root      5976  Feb 18 09:12  bin\r\n"
                                       "-rw-r--r--  1 root  root      6313  Feb 18 09:12  dev\r\n"
                                       "drwxr-xr-x  1 root  root      6004  Feb 18 09:12  etc\r\n"
                                       "drwxr-xr-x  1 root  root      7735  Feb 18 09:12  home\r\n"
                                       "-rw-r--r--  1 root  root      4304  Feb 18 09:12  lib\r\n"
                                       "drwxr-xr-x  1 root  root      5948  Feb 18 09:12  mnt\r\n"
                                       "drwxr-xr-x  1 root  root      1527  Feb 18 09:12  proc\r\n"
                                       "drwxr-xr-x  1 root  root      2237  Feb 18 09:12  root\r\n"
                                       "-rw-r--r--  1 root  root      7775  Feb 18 09:12  sbin\r\n"
                                       "-rw-r--r--  1 root  root      3171  Feb 18 09:12  sys\r\n"
                                       "drwxr-xr-x  1 root  root      6682  Feb 18 09:12  tmp\r\n"
                                       "-rw-r--r--  1 root  root      8155  Feb 18 09:12  usr\r\n"
                                       "drwxr-xr-x  1 root  root      6577  Feb 18 09:12  var\r\n"
                                       "drwxr-xr-x  1 root  root      4554  Feb 18 09:12  backup\r\n"
                                       "drwxr-xr-x  1 root  root      1693  Feb 18 09:12  data\r\n")
                        else:
                            out_str = ("total 8\r\n"
                                       "drwx------  1 root  root      2593  Feb 18 09:12  .\r\n"
                                       "drwx------  1 root  root      2610  Feb 18 09:12  ..\r\n")
                            
                        for f in session_files:
                            out_str += f"-rwxr-xr-x  1 root  root     1247  Feb 18 12:34  {f}\r\n"
                        client.sendall(out_str.encode())
                        
                    elif cwd == "/":
                        extra_files = "  ".join(session_files) + "  " if session_files else ""
                        client.sendall(f"bin  dev  etc  home  lib  mnt  proc  root  sbin  sys  tmp  usr  var  backup  data  {extra_files}\r\n".encode())
                    elif cwd in ["/root", "~"]:
                        extra_files = "  ".join(session_files) + "  " if session_files else ""
                        client.sendall(f".bash_history  .bashrc  .profile  .ssh  passwords.txt  .env  {extra_files}\r\n".encode())
                    elif cwd in ["/tmp", "/var", "/dev"] or "tmp" in cwd:
                        extra_files = "  ".join(session_files) + "  " if session_files else ""
                        client.sendall(f"config.json  system.log  resolv.conf  {extra_files}\r\n".encode())
                    else:
                        extra_files = "  ".join(session_files) + "  " if session_files else ""
                        client.sendall(f"{extra_files}\r\n".encode() if extra_files else b"\r\n")
                        
                elif base_cmd == "cd":
                    if len(parts) > 1:
                        target = parts[1]
                        if target == "/": cwd = "/"
                        elif target == "~": cwd = "/root"
                        elif target.startswith("/"): cwd = target
                        elif ".." in target:
                            cwd = "/" if cwd.count('/') <= 1 else cwd.rsplit('/', 1)[0]
                            if cwd == "": cwd = "/"
                        else:
                            cwd = f"/{target}" if cwd == "/" else f"{cwd}/{target}"
                    else:
                        cwd = "/root"
                        
                elif base_cmd == "pwd":
                    client.sendall(f"{cwd}\r\n".encode())
                    
                elif base_cmd in ["wget", "curl", "tftp", "ftpget"]:
                    session_data["attack_type"] = "malware_download"
                    session_data["threat_level"] = "critical"
                    
                    filename = "payload"
                    url = "http://unknown"
                    for i, p in enumerate(parts):
                        if "http://" in p or "ftp://" in p:
                            url = p
                            filename = p.split('/')[-1]
                            
                    if "-O" in parts:
                        try: filename = parts[parts.index("-O") + 1]
                        except: pass
                        
                    client.sendall(f"--2026-02-18 12:34:56--  {url}\r\n".encode())
                    time.sleep(0.5)
                    host = url.split("://")[-1].split("/")[0] if "://" in url else url
                    client.sendall(f"Resolving {host}... 198.51.100.7\r\nConnecting to {host}:80... connected.\r\nHTTP request sent, awaiting response... 200 OK\r\n".encode())
                    client.sendall(f"Length: 1247 (1.2K) [application/octet-stream]\r\nSaving to: '{filename}'\r\n\r\n".encode())
                    time.sleep(0.5)
                    client.sendall(f"{filename}              100%[===================>]   1.22K  --.-KB/s    in 0s\r\n\r\n".encode())
                    client.sendall(f"2026-02-18 12:34:56 (45.2 MB/s) - '{filename}' saved [1247/1247]\r\n".encode())
                    
                    if filename and filename not in session_files:
                        session_files.append(filename)
                        
                elif base_cmd == "ping":
                    target_ip = "8.8.8.8"
                    count = 3
                    # Properly parse -c flag
                    for i, p in enumerate(parts):
                        if p == "-c" and i + 1 < len(parts):
                            try: count = int(parts[i+1])
                            except: pass
                        elif not p.startswith("-") and p != "ping" and getattr(parts, i-1, "") != "-c":
                            target_ip = p
                            
                    client.sendall(f"PING {target_ip} ({target_ip}): 56 data bytes\r\n".encode())
                    for seq in range(count):
                        time.sleep(1.0)
                        client.sendall(f"64 bytes from {target_ip}: seq={seq} ttl=64 time=0.412 ms\r\n".encode())
                    
                    time.sleep(0.2)
                    client.sendall(f"\r\n--- {target_ip} ping statistics ---\r\n".encode())
                    client.sendall(f"{count} packets transmitted, {count} received, 0% packet loss\r\n".encode())

                elif base_cmd.startswith("./"):
                    # AMAZING FEATURE 3: Validate if file exists. 
                    # If it exists, throw arch error. If not, throw realistic "not found"
                    target_file = base_cmd[2:]
                    if target_file in session_files:
                        session_data["attack_type"] = "malware_execution"
                        session_data["threat_level"] = "critical"
                        client.sendall(f"{base_cmd}: line 1: syntax error: unexpected word (expecting \")\")\r\n".encode())
                    else:
                        client.sendall(f"{base_cmd}: command not found\r\n".encode())
                        
                elif base_cmd == "cat":
                    if len(parts) > 1:
                        target = parts[1]
                        if target in session_files:
                            client.sendall(b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\r\n") # Fake ELF header
                        elif target in ["/etc/passwd", "etc/passwd"]:
                            client.sendall(b"root:x:0:0:root:/root:/bin/ash\r\n"
                                           b"bin:x:1:1:bin:/bin:/bin/false\r\n"
                                           b"daemon:x:2:2:daemon:/usr/sbin:/bin/false\r\n"
                                           b"admin:x:500:500:Administrator:/home/admin:/bin/ash\r\n"
                                           b"nobody:x:65534:65534:nobody:/nonexistent:/bin/false\r\n")
                        elif target in ["/etc/shadow", "etc/shadow"]:
                            client.sendall(b"root:$6$salt$Wh5p4Q0/Kv.RN2sHrk7Cx5fX5QY3hjNJ0GZrp3nNpV1XkBb/3yInV3eTzTLi5g.:18950:0:99999:7:::\r\n"
                                           b"admin:$6$salt$AbCdEfGhIj/KlMnOpQrStUvWxYz0123456789abc.:18950:0:99999:7:::\r\n")
                        # AMAZING FEATURE: Hardware & Mount profiling for Botnets
                        elif target in ["/proc/cpuinfo", "proc/cpuinfo"]:
                            # Updated to precisely match your HI3518E_DEMO chip
                            client.sendall(b"Processor\t: ARM926EJ-S rev 5 (v5l)\r\n"
                                           b"BogoMIPS\t: 218.72\r\n"
                                           b"Features\t: swp half thumb fastmult edsp java\r\n"
                                           b"CPU implementer\t: 0x41\r\n"
                                           b"CPU architecture: 5TEJ\r\n"
                                           b"CPU variant\t: 0x0\r\n"
                                           b"CPU part\t: 0x926\r\n"
                                           b"CPU revision\t: 5\r\n"
                                           b"Hardware\t: HI3518E_DEMO\r\n"
                                           b"Revision\t: 0000\r\n")
                        elif target in ["/proc/mounts", "proc/mounts"]:
                            client.sendall(b"rootfs / rootfs rw 0 0\r\n"
                                           b"/dev/root / ext4 rw,relatime,data=ordered 0 0\r\n"
                                           b"devtmpfs /dev devtmpfs rw,relatime,size=115200k,nr_inodes=28800,mode=755 0 0\r\n"
                                           b"proc /proc proc rw,relatime 0 0\r\n"
                                           b"tmpfs /tmp tmpfs rw 0 0\r\n")
                        elif target in ["data", "bin", "etc", "var", "tmp", "usr", "sys", "proc", "sbin", "home", "lib", "mnt", "root", "backup"]:
                            client.sendall(f"cat: {target}: Is a directory\r\n".encode())
                        else:
                            client.sendall(f"cat: {target}: No such file or directory\r\n".encode())
                    else:
                        client.sendall(b"\r\n")
                        
                elif base_cmd == "ps":
                    client.sendall(b"  PID USER       VSZ STAT COMMAND\r\n    1 root      1432 S    init\r\n    2 root         0 S    [kthreadd]\r\n  431 root      1484 S    /sbin/syslogd -n\r\n  450 root      1640 S    /usr/sbin/telnetd\r\n 1102 root      2012 S    -sh\r\n")
                    
                elif base_cmd == "uname":
                    if "-a" in cmd:
                        client.sendall(b"Linux (none) 3.10.73 #1 SMP Fri Jul 14 10:29:16 CST 2017 armv7l GNU/Linux\r\n")
                    else:
                        client.sendall(b"Linux\r\n")
                        
                elif base_cmd == "id":
                    client.sendall(b"uid=0(root) gid=0(root)\r\n")
                    
                elif base_cmd == "whoami":
                    client.sendall(b"root\r\n")
                    
                # You mentioned mount was throwing 'command not found' in testing, so let's match the real device
                elif base_cmd == "mount":
                    client.sendall(b"mount: command not found\r\n")
                    
                elif base_cmd == "ifconfig":
                    client.sendall(b"eth0      Link encap:Ethernet  HWaddr 44:19:B6:7A:2C:D9\r\n"
                                   b"          inet addr:192.168.1.108  Bcast:192.168.1.255  Mask:255.255.255.0\r\n"
                                   b"          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\r\n"
                                   b"          RX packets:38291 errors:0 dropped:0 overruns:0 frame:0\r\n"
                                   b"          TX packets:22145 errors:0 dropped:0 overruns:0 carrier:0\r\n"
                                   b"          inet6 addr: fe80::4619:b6ff:fe7a:2cd9/64 Scope:Link\r\n\r\n"
                                   b"lo        Link encap:Local Loopback\r\n"
                                   b"          inet addr:127.0.0.1  Mask:255.0.0.0\r\n"
                                   b"          UP LOOPBACK RUNNING  MTU:65536  Metric:1\r\n")
                    
                elif base_cmd == "echo":
                    text = " ".join(parts[1:]).strip('"').strip("'")
                    client.sendall(f"{text}\r\n".encode())
                    
                elif base_cmd in ["sh", "bash", "ash", "system", "enable"]:
                    pass # Silently accept shells
                    
                elif base_cmd in ["export", "HISTFILE=/dev/null", "HISTSIZE=0", "ulimit"]:
                    pass # Silently accept anti-forensics / history wiping attempts
                    
                elif base_cmd == "rm":
                    # Stateful Deletion: Actually remove the files they delete!
                    for p in parts[1:]:
                        clean_p = p.replace("-rf", "").replace("-f", "").replace("-r", "").strip()
                        if clean_p in session_files:
                            session_files.remove(clean_p)
                            
                elif base_cmd in ["chmod", "chown", "mkdir", "touch", "cp", "mv", "kill", "chattr"]:
                    pass # Silently succeed commands (makes them think it worked)
                    
                elif base_cmd in ["exit", "quit", "logout"]:
                    break
                    
                elif base_cmd == "busybox":
                    client.sendall(b"BusyBox v1.22.1 (2014-06-11)\r\n")
                    
                # Removed the 'help' command so it correctly falls through to "command not found" 
                # like the real Hikvision device does!
                
                else:
                    # Exact match to your testing output for locate, help, etc.
                    client.sendall(f"{base_cmd}: command not found\r\n".encode())
            
    except socket.timeout:
        pass
    except Exception as e:
        pass
    finally:
        # Save session to DB when they disconnect
        try:
            # FIX: Save the commands into the `path` and `payload` fields so the Dashboard can actually see them!
            cmd_string = " ; ".join(commands_run)
            session_data["path"] = cmd_string[:255] if cmd_string else ""
            session_data["payload"] = "\n".join(commands_run)
            session_data["commands"] = json.dumps(commands_run)
            
            if username or commands_run:
                log_attack(session_data)
        except Exception:
            pass
        client.close()

def start_telnet_server(port=23): # Set directly to standard Telnet port 23
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(100)
        logging.info(f"Realistic Telnet Honeypot running on port {port}")
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_telnet_client, args=(client, addr), daemon=True).start()
    except Exception as e:
        logging.error(f"Telnet failed to start on port {port}: {e}")

if __name__ == "__main__":
    start_telnet_server()
if __name__ == "__main__":
    start_telnet_server()
