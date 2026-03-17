import os, time, socket

def parse_rtsp_request(data):
    """Parse RTSP request and extract method, path, headers."""
    lines = data.split('\n')
    req_line = lines[0].strip()
    method, path, *_ = req_line.split()
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    return method, path, headers

def build_rtsp_response(code=200, cseq='1', session=None, body=None, headers=None):
    status_map = {200: "OK", 401: "Unauthorized", 404: "Not Found", 400: "Bad Request"}
    resp = f"RTSP/1.0 {code} {status_map.get(code, 'OK')}\r\nCSeq: {cseq}\r\n"
    if session:
        resp += f"Session: {session}\r\n"
    if headers:
        for k, v in headers.items():
            resp += f"{k}: {v}\r\n"
    resp += "\r\n"
    if body:
        resp += body
    return resp.encode()

SDP_BODY = """v=0
o=- 0 0 IN IP4 127.0.0.1
s=Hikvision Camera Stream
c=IN IP4 0.0.0.0
t=0 0
m=video 0 RTP/AVP 96
a=rtpmap:96 H264/90000
a=control:trackID=1
"""

def handle_rtsp(conn, addr, log_attack=None, geoip_func=None, intel_fields_func=None, new_ip_alert=None):
    ip, port = addr
    session_id = os.urandom(4).hex()
    try:
        conn.settimeout(12)
        for _ in range(20):
            try:
                raw = conn.recv(4096)
            except socket.timeout:
                break
            if not raw:
                break
            data = raw.decode(errors="ignore")
            method, path, headers = parse_rtsp_request(data)
            cseq = headers.get('cseq', '1')
            user_agent = headers.get('user-agent', '')
            # Optionally extract auth, username, etc.
            username = ""
            password = ""
            if "authorization" in headers:
                # Basic auth parsing
                import base64
                auth = headers["authorization"]
                if "Basic" in auth:
                    b64 = auth.split()[-1]
                    try:
                        up = base64.b64decode(b64).decode()
                        username, password = up.split(":", 1)
                    except Exception:
                        pass

            # Log attack if callback provided
            if log_attack:
                gdata = geoip_func(ip) if geoip_func else {}
                log_attack({
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "source_ip": ip, "source_port": port,
                    "dest_port": 554, "service": "rtsp", "protocol": "TCP",
                    "method": method, "path": path,
                    "username": username, "password": password,
                    "user_agent": user_agent,
                    "attack_type": "camera_streaming" if username else "camera_probe",
                    "threat_level": "high" if username else "medium",
                    **(intel_fields_func(gdata) if intel_fields_func else {}),
                    "country": gdata.get("country", "Unknown"),
                    "city": gdata.get("city", ""),
                    "latitude": gdata.get("latitude"),
                    "longitude": gdata.get("longitude"),
                })
                if new_ip_alert:
                    new_ip_alert(ip, gdata.get("country", "Unknown"), gdata.get("city", ""), "rtsp")

            # Respond to RTSP methods
            if method == "OPTIONS":
                resp = build_rtsp_response(200, cseq, session=session_id, headers={
                    "Public": "OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN"
                })
            elif method == "DESCRIBE":
                resp = build_rtsp_response(200, cseq, session=session_id, headers={
                    "Content-Type": "application/sdp"
                }, body=SDP_BODY)
            elif method == "SETUP":
                resp = build_rtsp_response(200, cseq, session=session_id, headers={
                    "Transport": "RTP/AVP;unicast;client_port=8000-8001"
                })
            elif method == "PLAY":
                resp = build_rtsp_response(200, cseq, session=session_id)
            elif method == "TEARDOWN":
                resp = build_rtsp_response(200, cseq, session=session_id)
            else:
                resp = build_rtsp_response(400, cseq, session=session_id)
            conn.sendall(resp)
    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass
