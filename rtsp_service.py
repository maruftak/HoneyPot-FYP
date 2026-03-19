import os
import re
import time
import base64
import threading
import hashlib
import random
import json

# Common weak credentials that real IoT cameras use (honeypot will accept these)
WEAK_CREDENTIALS = {
    "admin": ["12345", "admin", "password", "123456", "admin123", ""],
    "root": ["root", "12345", "password", "123456", "admin", ""],
    "user": ["user", "12345", "password", ""],
    "service": ["service", "12345", ""],
    "default": ["default", "12345", ""],
}

# Multiple SDP responses for different channels (more realistic)
SDP_TEMPLATES = {
    "101": """v=0
o=- 0 0 IN IP4 127.0.0.1
s=Hikvision DS-2CD2043G2-I Main Stream
c=IN IP4 0.0.0.0
t=0 0
a=tool:libavformat 58.29.100
m=video 0 RTP/AVP 96
b=AS:4096
a=rtpmap:96 H264/90000
a=fmtp:96 packetization-mode=1;profile-level-id=640028;sprop-parameter-sets=Z2QAKKzZQHgCJ+WEAAADAAQAAAMAyDxYtlg=,aO48gA==
a=control:trackID=1
m=audio 0 RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=control:trackID=2
""",
    "102": """v=0
o=- 0 0 IN IP4 127.0.0.1
s=Hikvision DS-2CD2043G2-I Sub Stream
c=IN IP4 0.0.0.0
t=0 0
a=tool:libavformat 58.29.100
m=video 0 RTP/AVP 96
b=AS:512
a=rtpmap:96 H264/90000
a=fmtp:96 packetization-mode=1;profile-level-id=42001f;sprop-parameter-sets=Z0IAH5WoFAFuQA==,aM48gA==
a=control:trackID=1
""",
    "201": """v=0
o=- 0 0 IN IP4 127.0.0.1
s=Hikvision DS-2CD2043G2-I Third Stream
c=IN IP4 0.0.0.0
t=0 0
m=video 0 RTP/AVP 96
b=AS:256
a=rtpmap:96 H264/90000
a=control:trackID=1
""",
}

def parse_headers(lines):
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers

def parse_digest_auth(header):
    """Parse Digest Authorization header into a dict"""
    auth = {}
    if not header.startswith("Digest "):
        return auth
    for item in header[7:].split(","):
        if "=" in item:
            k, v = item.strip().split("=", 1)
            auth[k.strip()] = v.strip().strip('"')
    return auth

def validate_digest_response(auth, nonce, method, uri, password):
    """
    Validate Digest authentication response (simplified for honeypot)
    Real validation would compute HA1, HA2, and compare response
    For honeypot: we just check if username/password combo is in weak credentials
    """
    username = auth.get("username", "")
    
    # Check against weak credentials
    if username in WEAK_CREDENTIALS:
        if password in WEAK_CREDENTIALS[username]:
            return True
    
    # Also accept any response that looks valid (honeypot behavior)
    # This lets attackers succeed even with slight implementation errors
    if auth.get("response") and len(auth.get("response", "")) == 32:
        return True
    
    return False

def extract_channel_from_url(url):
    """Extract channel number from RTSP URL"""
    # /Streaming/Channels/101 -> 101
    match = re.search(r'/Channels/(\d+)', url)
    if match:
        return match.group(1)
    return "101"  # default

def handle_rtsp(conn, addr, log_attack=None, geoip_func=None, intel_fields_func=None, new_ip_alert=None):
    """
    Realistic RTSP honeypot handler for IoT cameras
    Simulates Hikvision IP camera behavior
    """
    client_ip = addr[0]
    
    # Per-connection session state
    session = {
        "nonce": "%016x" % random.getrandbits(64),
        "session_id": "%08x" % random.getrandbits(32),
        "authenticated": False,
        "username": "",
        "auth_attempts": 0,
        "methods_called": [],
        "start_time": time.time(),
        "last_activity": time.time(),
    }
    
    # Device-specific quirks for realism
    device_quirks = {
        "firmware_version": random.choice(["V5.5.8", "V5.6.2", "V5.7.0", "V5.5.0"]),
        "model": random.choice(["DS-2CD2043G2-I", "DS-2CD2143G0-I", "DS-2CD2043G0-I"]),
        "delay_ms": random.uniform(0.05, 0.15),  # Network latency simulation
    }
    
    try:
        conn.settimeout(15)
        request_count = 0
        
        # Handle multiple RTSP requests in sequence
        for _ in range(10):  # Allow more requests for realistic sessions
            data = b""
            try:
                data = conn.recv(4096)
            except Exception as e:
                break
            
            if not data:
                break
            
            request_count += 1
            session["last_activity"] = time.time()
            
            req = data.decode(errors="ignore")
            lines = req.replace('\r\n', '\n').split('\n')
            
            if not lines or not lines[0].strip():
                continue
            
            req_ln = lines[0].strip()
            parts = req_ln.split()
            
            method = parts[0] if len(parts) > 0 else "OPTIONS"
            url = parts[1] if len(parts) > 1 else "/Streaming/Channels/101"
            version = parts[2] if len(parts) > 2 else "RTSP/1.0"
            
            headers = parse_headers(lines)
            cseq = headers.get("cseq", "1")
            auth_header = headers.get("authorization", "")
            user_agent = headers.get("user-agent", "Unknown")
            
            session["methods_called"].append(method)
            
            # Log the attack attempt
            if log_attack:
                log_data = {
                    "service": "RTSP",
                    "method": method,
                    "url": url,
                    "user_agent": user_agent,
                    "authenticated": session["authenticated"],
                    "username": session.get("username", ""),
                    "auth_attempts": session["auth_attempts"],
                    "cseq": cseq,
                    "request_count": request_count,
                    "session_id": session["session_id"],
                }
                
                # Add geo/intel data if available
                if geoip_func:
                    log_data.update(geoip_func(client_ip))
                if intel_fields_func:
                    log_data.update(intel_fields_func(client_ip))
                
                log_attack(client_ip, 554, "RTSP", json.dumps(log_data))
            
            # Simulate network delay (realistic IoT camera behavior)
            time.sleep(device_quirks["delay_ms"])
            
            # === AUTHENTICATION HANDLING ===
            # DESCRIBE, SETUP, PLAY require authentication
            if method in ("DESCRIBE", "SETUP", "PLAY", "RECORD"):
                if not session["authenticated"]:
                    if auth_header:
                        auth = parse_digest_auth(auth_header)
                        username = auth.get("username", "")
                        
                        session["auth_attempts"] += 1
                        
                        # Check if credentials are valid (weak honeypot credentials)
                        # Try all weak passwords for this username
                        auth_success = False
                        if username in WEAK_CREDENTIALS:
                            for pwd in WEAK_CREDENTIALS[username]:
                                if validate_digest_response(auth, session["nonce"], method, url, pwd):
                                    auth_success = True
                                    session["authenticated"] = True
                                    session["username"] = username
                                    
                                    # Log successful authentication
                                    if log_attack:
                                        log_attack(client_ip, 554, "RTSP_AUTH_SUCCESS", 
                                                 json.dumps({
                                                     "username": username,
                                                     "attempts": session["auth_attempts"],
                                                     "method": method,
                                                     "session_id": session["session_id"]
                                                 }))
                                    break
                        
                        # If auth failed, send 401 again
                        if not auth_success:
                            # Log failed authentication
                            if log_attack:
                                log_attack(client_ip, 554, "RTSP_AUTH_FAILED", 
                                         json.dumps({
                                             "username": username,
                                             "attempts": session["auth_attempts"],
                                             "response": auth.get("response", "")[:16] + "..."
                                         }))
                            
                            # Send 401 Unauthorized (allow a few attempts)
                            if session["auth_attempts"] <= 5:
                                resp = (
                                    f'RTSP/1.0 401 Unauthorized\r\n'
                                    f'CSeq: {cseq}\r\n'
                                    f'WWW-Authenticate: Digest realm="HikVision IP Camera", '
                                    f'nonce="{session["nonce"]}", algorithm="MD5", qop="auth"\r\n'
                                    f'Server: Hikvision RTSP Server {device_quirks["firmware_version"]}\r\n'
                                    f'Date: {time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())}\r\n\r\n'
                                )
                            else:
                                # After 5 failed attempts, close connection (realistic)
                                resp = (
                                    f'RTSP/1.0 403 Forbidden\r\n'
                                    f'CSeq: {cseq}\r\n'
                                    f'Server: Hikvision RTSP Server {device_quirks["firmware_version"]}\r\n\r\n'
                                )
                            
                            conn.sendall(resp.encode())
                            continue
                    else:
                        # No auth header, request authentication
                        resp = (
                            f'RTSP/1.0 401 Unauthorized\r\n'
                            f'CSeq: {cseq}\r\n'
                            f'WWW-Authenticate: Digest realm="HikVision IP Camera", '
                            f'nonce="{session["nonce"]}", algorithm="MD5", qop="auth"\r\n'
                            f'Server: Hikvision RTSP Server {device_quirks["firmware_version"]}\r\n'
                            f'Date: {time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())}\r\n\r\n'
                        )
                        conn.sendall(resp.encode())
                        continue
            
            # === RTSP METHOD HANDLERS ===
            
            if method == "OPTIONS":
                # OPTIONS always succeeds (reconnaissance)
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER, SET_PARAMETER\r\n"
                    f"Server: Hikvision RTSP Server {device_quirks['firmware_version']}\r\n"
                    f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n\r\n"
                )
                conn.sendall(resp.encode())
            
            elif method == "DESCRIBE":
                # Return SDP for the requested channel
                channel = extract_channel_from_url(url)
                sdp = SDP_TEMPLATES.get(channel, SDP_TEMPLATES["101"])
                
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Content-Base: rtsp://{headers.get('host', client_ip)}{url}/\r\n"
                    f"Content-Type: application/sdp\r\n"
                    f"Content-Length: {len(sdp)}\r\n"
                    f"Server: Hikvision RTSP Server {device_quirks['firmware_version']}\r\n"
                    f"Session: {session['session_id']};timeout=60\r\n"
                    f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n\r\n"
                    f"{sdp}"
                )
                conn.sendall(resp.encode())
            
            elif method == "SETUP":
                # Parse Transport header from client
                transport = headers.get("transport", "RTP/AVP;unicast;client_port=8000-8001")
                client_port_match = re.search(r'client_port=(\d+)-(\d+)', transport)
                
                if client_port_match:
                    client_rtp = client_port_match.group(1)
                    client_rtcp = client_port_match.group(2)
                else:
                    client_rtp = "8000"
                    client_rtcp = "8001"
                
                server_rtp = random.randint(40000, 50000)
                server_rtcp = server_rtp + 1
                
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Session: {session['session_id']};timeout=60\r\n"
                    f"Transport: RTP/AVP;unicast;client_port={client_rtp}-{client_rtcp};"
                    f"server_port={server_rtp}-{server_rtcp};ssrc={random.randint(10000000, 99999999):08X}\r\n"
                    f"Server: Hikvision RTSP Server {device_quirks['firmware_version']}\r\n"
                    f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n\r\n"
                )
                conn.sendall(resp.encode())
            
            elif method == "PLAY":
                # PLAY - Start streaming (we won't actually stream, just respond)
                rtp_seq = random.randint(10000, 65535)
                rtp_time = random.randint(100000, 9999999)
                
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Session: {session['session_id']};timeout=60\r\n"
                    f"Range: npt=0.000-\r\n"
                    f"RTP-Info: url={url}/trackID=1;seq={rtp_seq};rtptime={rtp_time},"
                    f"url={url}/trackID=2;seq={rtp_seq+1};rtptime={rtp_time}\r\n"
                    f"Server: Hikvision RTSP Server {device_quirks['firmware_version']}\r\n"
                    f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n\r\n"
                )
                conn.sendall(resp.encode())
                
                # Keep connection alive for a bit (simulate streaming)
                # Real cameras would send RTP packets here
                time.sleep(random.uniform(1.0, 3.0))
            
            elif method == "PAUSE":
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Session: {session['session_id']}\r\n"
                    f"Server: Hikvision RTSP Server {device_quirks['firmware_version']}\r\n\r\n"
                )
                conn.sendall(resp.encode())
            
            elif method == "TEARDOWN":
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Session: {session['session_id']}\r\n"
                    f"Server: Hikvision RTSP Server {device_quirks['firmware_version']}\r\n\r\n"
                )
                conn.sendall(resp.encode())
                break  # Close connection after teardown
            
            elif method == "GET_PARAMETER":
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Session: {session['session_id']}\r\n"
                    f"Server: Hikvision RTSP Server {device_quirks['firmware_version']}\r\n\r\n"
                )
                conn.sendall(resp.encode())
            
            elif method == "SET_PARAMETER":
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Session: {session['session_id']}\r\n"
                    f"Server: Hikvision RTSP Server {device_quirks['firmware_version']}\r\n\r\n"
                )
                conn.sendall(resp.encode())
            
            else:
                # Unknown method
                resp = (
                    f"RTSP/1.0 405 Method Not Allowed\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Allow: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER, SET_PARAMETER\r\n"
                    f"Server: Hikvision RTSP Server {device_quirks['firmware_version']}\r\n\r\n"
                )
                conn.sendall(resp.encode())
    
    except Exception as e:
        # Log any errors for debugging
        if log_attack:
            log_attack(client_ip, 554, "RTSP_ERROR", json.dumps({"error": str(e)}))
    
    finally:
        # Log session summary
        if log_attack and request_count > 0:
            session_duration = time.time() - session["start_time"]
            log_attack(client_ip, 554, "RTSP_SESSION_END", json.dumps({
                "session_id": session["session_id"],
                "duration": round(session_duration, 2),
                "requests": request_count,
                "authenticated": session["authenticated"],
                "username": session.get("username", ""),
                "auth_attempts": session["auth_attempts"],
                "methods": ",".join(session["methods_called"]),
            }))
        
        try:
            conn.close()
        except Exception:
            pass