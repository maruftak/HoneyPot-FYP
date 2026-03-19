import random
import time
import socket
import json
import os
from collections import defaultdict

# ═══════════════════════════════════════════════════════════════════════════
# ULTIMATE FTP HONEYPOT - Advanced IoT Camera Simulation
# ═══════════════════════════════════════════════════════════════════════════

# ─── Rate Limiting & Tarpit ───────────────────────────────────────────────
_ftp_connection_tracker = defaultdict(list)
_ftp_failed_auth_tracker = defaultdict(int)
_ftp_tarpit_ips = {}

FTP_RATE_LIMIT_WINDOW = 60
FTP_MAX_CONNECTIONS_PER_MINUTE = 8
FTP_MAX_FAILED_AUTH_BEFORE_TARPIT = 3
FTP_TARPIT_DURATION = 300
FTP_TARPIT_DELAY = 1.5

def _should_tarpit_ftp(ip):
    """Check if IP should be tarpitted"""
    now = time.time()
    
    if ip in _ftp_tarpit_ips:
        if now < _ftp_tarpit_ips[ip]:
            return True
        else:
            del _ftp_tarpit_ips[ip]
            _ftp_failed_auth_tracker[ip] = 0
    
    if _ftp_failed_auth_tracker[ip] >= FTP_MAX_FAILED_AUTH_BEFORE_TARPIT:
        _ftp_tarpit_ips[ip] = now + FTP_TARPIT_DURATION
        return True
    
    _ftp_connection_tracker[ip] = [t for t in _ftp_connection_tracker[ip] if now - t < FTP_RATE_LIMIT_WINDOW]
    if len(_ftp_connection_tracker[ip]) >= FTP_MAX_CONNECTIONS_PER_MINUTE:
        _ftp_tarpit_ips[ip] = now + FTP_TARPIT_DURATION
        return True
    
    _ftp_connection_tracker[ip].append(now)
    return False

# ─── FTP Banners (IoT/Embedded Style) ─────────────────────────────────────
_FTP_BANNERS = [
    "220 Hikvision DVR FTP Server V1.0\r\n",
    "220 (vsFTPd 3.0.5)\r\n",
    "220 FTP Server ready.\r\n",
    "220 DVR FTP Server Ready.\r\n",
    "220 Hikvision DS-2CD2043G2-I FTP Service\r\n",
    "220 Welcome to Camera FTP Service\r\n",
]

# ─── Weak Credentials (Expanded) ──────────────────────────────────────────
WEAK_CREDENTIALS = {
    "admin": ["admin", "12345", "password", "admin123", "123456", ""],
    "root": ["root", "12345", "password", "toor", ""],
    "user": ["user", "12345", "password", ""],
    "ftp": ["ftp", "12345", "password", "anonymous", ""],
    "anonymous": ["", "anonymous", "ftp", "guest"],
    "camera": ["camera", "12345", "password", ""],
    "hikvision": ["hikvision", "12345", ""],
}

# ─── IoT File System (Camera FTP Structure) ───────────────────────────────
_IOT_FILE_SYSTEM = {
    "/": {
        "type": "directory",
        "files": ["recordings", "snapshots", "config", "firmware", "logs"],
    },
    
    "/recordings": {
        "type": "directory",
        "files": [
            "record_20260319_100000.mp4",
            "record_20260319_090000.mp4",
            "record_20260319_080000.mp4",
            "record_20260319_070000.mp4",
            "record_20260319_060000.mp4",
        ],
    },
    
    "/snapshots": {
        "type": "directory",
        "files": [
            "snapshot_20260319_100000.jpg",
            "snapshot_20260319_095000.jpg",
            "snapshot_20260319_094000.jpg",
        ],
    },
    
    "/config": {
        "type": "directory",
        "files": [
            "device.conf",
            "network.conf",
            "credentials.txt",  # Honeytoken
            "backup.zip",
        ],
    },
    
    "/firmware": {
        "type": "directory",
        "files": [
            "firmware_v5.7.15.bin",
            "update.sh",
        ],
    },
    
    "/logs": {
        "type": "directory",
        "files": [
            "system.log",
            "access.log",
            "error.log",
        ],
    },
}

# ─── File Metadata (Size, Date) ──────────────────────────────────────────
def _get_file_listing(path="/"):
    """Generate realistic file listing"""
    if path not in _IOT_FILE_SYSTEM:
        return []
    
    entries = []
    fs_entry = _IOT_FILE_SYSTEM[path]
    
    if fs_entry["type"] == "directory":
        for filename in fs_entry.get("files", []):
            # Determine file type and size
            if filename.endswith(".mp4"):
                size = random.randint(1800000000, 2200000000)  # 1.8-2.2 GB
                perms = "-rw-r--r--"
            elif filename.endswith(".jpg"):
                size = random.randint(500000, 2000000)  # 500KB-2MB
                perms = "-rw-r--r--"
            elif filename.endswith(".conf") or filename.endswith(".txt"):
                size = random.randint(512, 4096)
                perms = "-rw-r--r--"
            elif filename.endswith(".zip") or filename.endswith(".tar.gz"):
                size = random.randint(10000000, 50000000)  # 10-50 MB
                perms = "-rw-r--r--"
            elif filename.endswith(".bin"):
                size = random.randint(20000000, 100000000)  # 20-100 MB
                perms = "-rw-r--r--"
            elif filename.endswith(".sh"):
                size = random.randint(256, 2048)
                perms = "-rwxr-xr-x"
            elif filename.endswith(".log"):
                size = random.randint(10000, 100000)
                perms = "-rw-r--r--"
            else:
                size = random.randint(1024, 10240)
                perms = "drwxr-xr-x" if "." not in filename else "-rw-r--r--"
            
            # Generate timestamp (last 24 hours)
            timestamp = time.strftime("%b %d %H:%M", time.localtime(time.time() - random.randint(0, 86400)))
            
            # Format: perms links owner group size date filename
            if "." not in filename:  # Directory
                entry = f"drwxr-xr-x  2 root root     4096 {timestamp} {filename}\r\n"
            else:
                entry = f"{perms}  1 root root {size:>8} {timestamp} {filename}\r\n"
            
            entries.append(entry)
    
    return entries

# ─── Honeytoken Files ─────────────────────────────────────────────────────
_HONEYTOKEN_FILES = {
    "/config/credentials.txt": """# Hikvision Camera Credentials
# DO NOT SHARE - CONFIDENTIAL

Admin Username: admin
Admin Password: Admin@2024!
FTP Username: ftpuser
FTP Password: FtpPass123!
RTSP Password: RtspStream456!

Network Key: WPA2-PSK-AES-TKIP-1234567890
""",
    
    "/config/device.conf": """[Device]
Model=DS-2CD2043G2-I
SerialNumber=DS-2CD2043G2-I20230313BBRR012345
MAC=44:19:B6:7A:2C:D9
FirmwareVersion=V5.7.15 build 230313

[Credentials]
AdminUser=admin
AdminPassword=Admin@2024!
EnableTelnet=true
EnableSSH=true
EnableFTP=true
""",
    
    "/config/backup.zip": "[Binary content - ZIP archive with config files]",
    "/logs/access.log": """2026-03-19 09:00:15 [INFO] FTP login: admin from 192.168.1.100
2026-03-19 09:15:32 [INFO] HTTP access: /ISAPI/System/deviceInfo from 192.168.1.100
2026-03-19 09:30:45 [INFO] RTSP stream started: admin from 192.168.1.100
""",
}

# ─── Session Replay Database ──────────────────────────────────────────────
_ftp_session_replay_db = []
MAX_FTP_REPLAY_SESSIONS = 30

def _save_ftp_session_for_replay(session_data):
    """Save interesting FTP sessions for replay"""
    if len(session_data.get("commands", [])) >= 3:
        _ftp_session_replay_db.append({
            "username": session_data.get("username"),
            "password": session_data.get("password"),
            "commands": session_data.get("commands", []),
            "files_accessed": session_data.get("files_accessed", []),
            "timestamp": time.time(),
        })
        
        if len(_ftp_session_replay_db) > MAX_FTP_REPLAY_SESSIONS:
            _ftp_session_replay_db.pop(0)

def _should_replay_ftp_session():
    """5% chance to replay"""
    return _ftp_session_replay_db and random.random() < 0.05

def _get_ftp_replay_session():
    """Get random replay session"""
    if _ftp_session_replay_db:
        return random.choice(_ftp_session_replay_db)
    return None

# ─── Credential Validation ────────────────────────────────────────────────
def _validate_credentials(username, password):
    """Check if credentials are in weak credentials list"""
    if username in WEAK_CREDENTIALS:
        if password in WEAK_CREDENTIALS[username]:
            return True
    return False

# ═══════════════════════════════════════════════════════════════════════════
# Main FTP Handler (ULTIMATE VERSION)
# ═══════════════════════════════════════════════════════════════════════════

def handle_ftp(conn, addr, log_attack=None, geoip_func=None, intel_fields_func=None, 
               new_ip_alert=None, check_honeytoken_file=None, check_botnet=None, 
               check_honeytoken_cred=None):
    """
    ULTIMATE FTP honeypot handler for IoT cameras
    Simulates Hikvision camera FTP service
    """
    ip, port = addr
    
    # Tarpit check
    is_tarpitted = _should_tarpit_ftp(ip)
    
    # Session tracking
    session = {
        "authenticated": False,
        "username": "",
        "password": "",
        "auth_attempts": 0,
        "commands": [],
        "files_accessed": [],
        "start_time": time.time(),
        "current_dir": "/",
        "transfer_type": "binary",
        "is_tarpitted": is_tarpitted,
        "is_replay": False,
    }
    
    try:
        # GeoIP
        gdata = geoip_func(ip) if geoip_func else {}
        
        # Connection log
        if log_attack:
            log_attack(ip, 21, "FTP_CONNECT", json.dumps({
                "event": "connection",
                "country": gdata.get("country", "Unknown"),
                "city": gdata.get("city", ""),
                "is_tarpitted": is_tarpitted,
            }))
        
        # Alert on new IP
        if new_ip_alert and gdata:
            new_ip_alert(ip, gdata.get("country", ""), gdata.get("city", ""), "ftp")
        
        # Tarpit delay
        if is_tarpitted:
            time.sleep(FTP_TARPIT_DELAY * 2)
        else:
            time.sleep(random.uniform(0.1, 0.3))
        
        # Send banner
        banner = random.choice(_FTP_BANNERS)
        conn.sendall(banner.encode())
        
        # Session replay check
        replay_session = None
        if _should_replay_ftp_session():
            replay_session = _get_ftp_replay_session()
            if replay_session:
                session["is_replay"] = True
                if log_attack:
                    log_attack(ip, 21, "FTP_SESSION_REPLAY", json.dumps({
                        "original_username": replay_session["username"],
                        "original_commands": replay_session["commands"],
                    }))
        
        # Process FTP commands
        for _ in range(50):
            conn.settimeout(30 if not is_tarpitted else 60)
            try:
                line = conn.recv(1024).decode(errors="ignore").strip()
            except socket.timeout:
                break
            
            if not line:
                break
            
            # Tarpit delay
            if is_tarpitted:
                time.sleep(FTP_TARPIT_DELAY)
            
            parts = line.split(" ", 1)
            cmd   = parts[0].upper()
            arg   = parts[1] if len(parts) > 1 else ""
            
            session["commands"].append(f"{cmd} {arg}".strip())
            
            # ═══════════════════════════════════════════════════════════════
            # FTP COMMAND HANDLERS
            # ═══════════════════════════════════════════════════════════════
            
            # ─── USER (Username) ──────────────────────────────────────────
            if cmd == "USER":
                session["username"] = arg
                conn.sendall(b"331 Password required for " + arg.encode() + b".\r\n")
                
                if is_tarpitted:
                    time.sleep(FTP_TARPIT_DELAY)
            
            # ─── PASS (Password) ──────────────────────────────────────────
            elif cmd == "PASS":
                session["password"] = arg
                session["auth_attempts"] += 1
                
                username = session["username"]
                password = arg
                
                # Validate credentials
                is_valid = _validate_credentials(username, password)
                is_bot = check_botnet(username, password) if check_botnet else False
                is_ht_c, ht_cv = check_honeytoken_cred(username, password) if check_honeytoken_cred else (False, None)
                
                # Check replay session
                if replay_session and username == replay_session["username"]:
                    is_valid = True
                
                # Log auth attempt
                if log_attack:
                    log_attack(ip, 21, "FTP_AUTH_ATTEMPT", json.dumps({
                        "username": username,
                        "password": password,
                        "attempt": session["auth_attempts"],
                        "is_botnet": is_bot,
                        "is_honeytoken": is_ht_c,
                        "success": is_valid,
                        "threat_level": "critical" if is_ht_c else ("high" if is_bot else "medium"),
                    }))
                
                # Accept after 2nd attempt or if valid
                if (session["auth_attempts"] >= 2 and is_valid) or is_bot or is_ht_c:
                    session["authenticated"] = True
                    conn.sendall(b"230 Login successful.\r\n")
                    
                    if log_attack:
                        log_attack(ip, 21, "FTP_AUTH_SUCCESS", json.dumps({
                            "username": username,
                            "password": password,
                            "attempts": session["auth_attempts"],
                            "is_botnet": is_bot,
                            "is_honeytoken": is_ht_c,
                            "is_replay": session["is_replay"],
                        }))
                else:
                    # Failed auth
                    _ftp_failed_auth_tracker[ip] += 1
                    conn.sendall(b"530 Login incorrect.\r\n")
                    
                    if is_tarpitted:
                        time.sleep(FTP_TARPIT_DELAY * 2)
            
            # ─── SYST (System Type) ───────────────────────────────────────
            elif cmd == "SYST":
                conn.sendall(b"215 UNIX Type: L8\r\n")
            
            # ─── FEAT (Features) ──────────────────────────────────────────
            elif cmd == "FEAT":
                conn.sendall(b"211-Features:\r\n PASV\r\n EPSV\r\n SIZE\r\n MDTM\r\n REST STREAM\r\n UTF8\r\n MLST\r\n211 End\r\n")
            
            # ─── PWD (Print Working Directory) ────────────────────────────
            elif cmd == "PWD":
                conn.sendall(f'257 "{session["current_dir"]}" is current directory.\r\n'.encode())
            
            # ─── CWD (Change Working Directory) ───────────────────────────
            elif cmd == "CWD" and session["authenticated"]:
                new_dir = arg
                
                # Normalize path
                if new_dir.startswith("/"):
                    target_dir = new_dir
                elif new_dir == "..":
                    # Go up one level
                    if session["current_dir"] != "/":
                        target_dir = "/".join(session["current_dir"].rstrip("/").split("/")[:-1]) or "/"
                    else:
                        target_dir = "/"
                else:
                    target_dir = f"{session['current_dir'].rstrip('/')}/{new_dir}"
                
                # Check if directory exists
                if target_dir in _IOT_FILE_SYSTEM:
                    session["current_dir"] = target_dir
                    conn.sendall(f'250 Directory changed to "{target_dir}".\r\n'.encode())
                else:
                    conn.sendall(b"550 Failed to change directory.\r\n")
            
            # ─── CDUP (Change to Parent Directory) ───────────────────────
            elif cmd == "CDUP" and session["authenticated"]:
                if session["current_dir"] != "/":
                    session["current_dir"] = "/".join(session["current_dir"].rstrip("/").split("/")[:-1]) or "/"
                conn.sendall(b"250 Directory successfully changed.\r\n")
            
            # ─── TYPE (Transfer Type) ─────────────────────────────────────
            elif cmd == "TYPE":
                transfer_type = arg.upper()
                if transfer_type in ("A", "I"):
                    session["transfer_type"] = "ascii" if transfer_type == "A" else "binary"
                    conn.sendall(f"200 Switching to {session['transfer_type'].upper()} mode.\r\n".encode())
                else:
                    conn.sendall(b"504 Command not implemented for that parameter.\r\n")
            
            # ─── PASV (Passive Mode) ──────────────────────────────────────
            elif cmd == "PASV" and session["authenticated"]:
                # Generate random passive port
                p1 = random.randint(128, 255)
                p2 = random.randint(0, 255)
                conn.sendall(f"227 Entering Passive Mode (192,168,1,108,{p1},{p2}).\r\n".encode())
            
            # ─── EPSV (Extended Passive Mode) ────────────────────────────
            elif cmd == "EPSV" and session["authenticated"]:
                passive_port = random.randint(40000, 50000)
                conn.sendall(f"229 Entering Extended Passive Mode (|||{passive_port}|).\r\n".encode())
            
            # ─── PORT (Active Mode) ───────────────────────────────────────
            elif cmd == "PORT" and session["authenticated"]:
                conn.sendall(b"200 PORT command successful.\r\n")
            
            # ─── LIST (Directory Listing) ─────────────────────────────────
            elif cmd == "LIST" and session["authenticated"]:
                path = arg if arg else session["current_dir"]
                
                conn.sendall(b"150 Here comes the directory listing.\r\n")
                
                # Get file listing
                listing = _get_file_listing(path)
                for entry in listing:
                    conn.sendall(entry.encode())
                    if is_tarpitted:
                        time.sleep(0.1)
                
                conn.sendall(b"226 Directory send OK.\r\n")
                
                # Log listing
                if log_attack:
                    log_attack(ip, 21, "FTP_LIST", json.dumps({
                        "username": session["username"],
                        "directory": path,
                        "file_count": len(listing),
                    }))
            
            # ─── NLST (Name List) ─────────────────────────────────────────
            elif cmd == "NLST" and session["authenticated"]:
                path = arg if arg else session["current_dir"]
                
                conn.sendall(b"150 Here comes the directory listing.\r\n")
                
                if path in _IOT_FILE_SYSTEM:
                    for filename in _IOT_FILE_SYSTEM[path].get("files", []):
                        conn.sendall(f"{filename}\r\n".encode())
                
                conn.sendall(b"226 Transfer complete.\r\n")
            
            # ─── SIZE (File Size) ─────────────────────────────────────────
            elif cmd == "SIZE" and session["authenticated"]:
                filename = arg
                
                # Generate realistic file size
                if filename.endswith(".mp4"):
                    size = random.randint(1800000000, 2200000000)
                elif filename.endswith(".jpg"):
                    size = random.randint(500000, 2000000)
                else:
                    size = random.randint(1024, 10240)
                
                conn.sendall(f"213 {size}\r\n".encode())
            
            # ─── MDTM (Modification Time) ─────────────────────────────────
            elif cmd == "MDTM" and session["authenticated"]:
                # Return current time in FTP format: YYYYMMDDhhmmss
                timestamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
                conn.sendall(f"213 {timestamp}\r\n".encode())
            
            # ─── RETR (Download File) ─────────────────────────────────────
            elif cmd == "RETR" and session["authenticated"]:
                filename = arg
                full_path = f"{session['current_dir'].rstrip('/')}/{filename}"
                
                session["files_accessed"].append(filename)
                
                # Check for honeytoken
                if full_path in _HONEYTOKEN_FILES:
                    if log_attack:
                        log_attack(ip, 21, "FTP_HONEYTOKEN", json.dumps({
                            "file": full_path,
                            "username": session["username"],
                            "threat_level": "critical",
                        }))
                
                # Check via callback
                ht_f, ht_fv = check_honeytoken_file(filename) if check_honeytoken_file else (False, None)
                if ht_f and log_attack:
                    log_attack(ip, 21, "FTP_HONEYTOKEN_CALLBACK", json.dumps({
                        "file": filename,
                        "username": session["username"],
                    }))
                
                # Log file access
                if log_attack:
                    log_attack(ip, 21, "FTP_DOWNLOAD", json.dumps({
                        "file": filename,
                        "full_path": full_path,
                        "username": session["username"],
                    }))
                
                # Simulate file transfer (but don't actually send data)
                conn.sendall(b"150 Opening BINARY mode data connection.\r\n")
                time.sleep(random.uniform(0.5, 2.0))  # Simulate transfer
                conn.sendall(b"550 Failed to open file.\r\n")  # Honeypot behavior
            
            # ─── STOR (Upload File) ───────────────────────────────────────
            elif cmd == "STOR" and session["authenticated"]:
                filename = arg
                
                session["files_accessed"].append(f"UPLOAD:{filename}")
                
                # Log upload attempt
                if log_attack:
                    log_attack(ip, 21, "FTP_UPLOAD_ATTEMPT", json.dumps({
                        "file": filename,
                        "username": session["username"],
                        "threat_level": "high",
                    }))
                
                # Accept but don't actually store
                conn.sendall(b"150 Ok to send data.\r\n")
                time.sleep(random.uniform(0.5, 1.5))
                conn.sendall(b"226 Transfer complete.\r\n")
            
            # ─── DELE (Delete File) ───────────────────────────────────────
            elif cmd == "DELE" and session["authenticated"]:
                filename = arg
                
                # Log deletion attempt
                if log_attack:
                    log_attack(ip, 21, "FTP_DELETE_ATTEMPT", json.dumps({
                        "file": filename,
                        "username": session["username"],
                        "threat_level": "critical",
                    }))
                
                conn.sendall(b"250 Delete operation successful.\r\n")
            
            # ─── MKD (Make Directory) ─────────────────────────────────────
            elif cmd == "MKD" and session["authenticated"]:
                dirname = arg
                
                # Log directory creation
                if log_attack:
                    log_attack(ip, 21, "FTP_MKDIR", json.dumps({
                        "directory": dirname,
                        "username": session["username"],
                    }))
                
                conn.sendall(f'257 "{dirname}" created.\r\n'.encode())
            
            # ─── RMD (Remove Directory) ───────────────────────────────────
            elif cmd == "RMD" and session["authenticated"]:
                dirname = arg
                
                # Log directory removal
                if log_attack:
                    log_attack(ip, 21, "FTP_RMDIR", json.dumps({
                        "directory": dirname,
                        "username": session["username"],
                        "threat_level": "high",
                    }))
                
                conn.sendall(b"250 Remove directory operation successful.\r\n")
            
            # ─── NOOP (No Operation) ──────────────────────────────────────
            elif cmd == "NOOP":
                conn.sendall(b"200 NOOP ok.\r\n")
            
            # ─── QUIT (Disconnect) ────────────────────────────────────────
            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye.\r\n")
                break
            
            # ─── HELP ─────────────────────────────────────────────────────
            elif cmd == "HELP":
                conn.sendall(b"214-The following commands are recognized:\r\n USER PASS SYST FEAT PWD CWD CDUP TYPE PASV PORT LIST RETR STOR DELE MKD RMD NOOP QUIT HELP\r\n214 Help OK.\r\n")
            
            # ─── Unknown Command ──────────────────────────────────────────
            else:
                conn.sendall(b"500 Unknown command.\r\n")
                
                # Log unknown command
                if log_attack:
                    log_attack(ip, 21, "FTP_UNKNOWN_COMMAND", json.dumps({
                        "command": f"{cmd} {arg}".strip(),
                        "username": session["username"],
                    }))
    
    except Exception as e:
        if log_attack:
            log_attack(ip, 21, "FTP_ERROR", json.dumps({"error": str(e)}))
    
    finally:
        # Save session for replay
        if session["commands"] and not session["is_replay"]:
            _save_ftp_session_for_replay(session)
        
        # Session complete logging
        if log_attack:
            session_duration = time.time() - session["start_time"]
            log_attack(ip, 21, "FTP_SESSION_END", json.dumps({
                "duration": round(session_duration, 2),
                "authenticated": session["authenticated"],
                "username": session.get("username", ""),
                "password": session.get("password", ""),
                "auth_attempts": session["auth_attempts"],
                "commands": session["commands"],
                "command_count": len(session["commands"]),
                "files_accessed": session["files_accessed"],
                "is_tarpitted": is_tarpitted,
                "is_replay": session["is_replay"],
            }))
        
        try:
            conn.close()
        except Exception:
            pass