import os
import re
import time
import base64
import threading
import hashlib
import random

class RTSPSession:
    def __init__(self, ip):
        self.ip = ip
        self.session_id = os.urandom(4).hex()
        self.authenticated = False
        self.cseq = 1
        self.stream_url = ""
        self.last_method = ""
        self.username = ""
        self.password = ""
        self.headers = {}
        self.nonce = self._gen_nonce()
        self.state = "INIT"  # INIT, SETUP, PLAY

    def next_cseq(self):
        self.cseq += 1
        return self.cseq
    
    def _gen_nonce(self):
        return os.urandom(8).hex()
    
    def is_expired(self):
        return (time.time() - self.last_activity) > 60

SDP_RESPONSE = """v=0
o=- 0 0 IN IP4 127.0.0.1
s=Hikvision DS-2CD2043G2-I
c=IN IP4 0.0.0.0
t=0 0
a=tool:libavformat 58.29.100
m=video 0 RTP/AVP 96
a=rtpmap:96 H264/90000
a=control:trackID=1
m=audio 0 RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=control:trackID=2
"""

def parse_headers(lines):
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers

def handle_rtsp(conn, addr, log_attack=None, geoip_func=None, intel_fields_func=None, new_ip_alert=None):
    try:
        conn.settimeout(10)
        for _ in range(5):
            data = b""
            try:
                data = conn.recv(4096)
            except Exception:
                break
            if not data:
                break
            req = data.decode(errors="ignore")
            lines = req.replace('\r\n', '\n').split('\n')
            req_ln = lines[0].strip()
            parts = req_ln.split()
            method = parts[0] if len(parts) > 0 else "OPTIONS"
            url = parts[1] if len(parts) > 1 else "/Streaming/Channels/101"
            headers = parse_headers(lines)
            cseq = headers.get("cseq", "1")

            # Respond to RTSP methods
            if method == "OPTIONS":
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Public: DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, OPTIONS, ANNOUNCE, RECORD, GET_PARAMETER, SET_PARAMETER\r\n"
                    f"Server: Hikvision RTSP Server\r\n\r\n"
                )
                conn.sendall(resp.encode())
            elif method == "DESCRIBE":
                # Always require authentication for realism
                if "authorization" not in headers:
                    resp = (
                        f'RTSP/1.0 401 Unauthorized\r\n'
                        f'CSeq: {cseq}\r\n'
                        f'WWW-Authenticate: Digest realm="Streaming Server", nonce="{random.randint(100000,999999)}", algorithm="MD5"\r\n'
                        f'Server: Hikvision RTSP Server\r\n\r\n'
                    )
                    conn.sendall(resp.encode())
                else:
                    sdp = SDP_RESPONSE
                    resp = (
                        f"RTSP/1.0 200 OK\r\n"
                        f"CSeq: {cseq}\r\n"
                        f"Content-Type: application/sdp\r\n"
                        f"Content-Length: {len(sdp)}\r\n"
                        f"Server: Hikvision RTSP Server\r\n"
                        f"Session: {random.randint(10000000,99999999)}\r\n\r\n"
                        f"{sdp}"
                    )
                    conn.sendall(resp.encode())
            elif method == "SETUP":
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Session: {random.randint(10000000,99999999)}\r\n"
                    f"Transport: RTP/AVP;unicast;client_port=8000-8001;server_port=9000-9001\r\n"
                    f"Server: Hikvision RTSP Server\r\n\r\n"
                )
                conn.sendall(resp.encode())
            elif method == "PLAY":
                resp = (
                    f"RTSP/1.0 200 OK\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Session: {random.randint(10000000,99999999)}\r\n"
                    f"RTP-Info: url={url};seq={random.randint(10000,99999)};rtptime={random.randint(100000, 999999)}\r\n"
                    f"Server: Hikvision RTSP Server\r\n\r\n"
                )
                conn.sendall(resp.encode())
            else:
                resp = (
                    f"RTSP/1.0 405 Method Not Allowed\r\n"
                    f"CSeq: {cseq}\r\n"
                    f"Server: Hikvision RTSP Server\r\n\r\n"
                )
                conn.sendall(resp.encode())
            time.sleep(0.1)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass