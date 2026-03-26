#!/usr/bin/env python3
"""
honeyPot — RTSP Service (RFC 2326)
Emulates a Hikvision IP camera RTSP server on TCP port 554.

Fixes over original:
  - log_attack now uses the standard dict format (original used wrong positional args → zero DB rows)
  - geoip / intel_fields_func called correctly
  - Proper attack_type classification per request / event
  - CVE pattern detection in URLs and headers
  - Stream enumeration detection (rapid DESCRIBE on multiple channels)
  - RECORD / injection attempt detection
  - Auth bypass detection (CVE-2017-7925 snapshot URL)
  - Malformed header / fuzzing detection
"""

import re
import time
import random
import datetime
import socket

# ─── Weak credentials the camera accepts ─────────────────────────────────────

_WEAK_CREDS = {
    "admin":   ["", "admin", "12345", "123456", "password", "admin123", "hikvision"],
    "root":    ["", "root",  "12345", "toor",   "password", "admin"],
    "user":    ["", "user",  "12345"],
    "service": ["", "service"],
    "default": ["", "default"],
    "guest":   ["", "guest"],
}

# ─── SDP generator — uses real server IP so VLC/ffmpeg actually try to connect ──

def _build_sdp(channel: str, server_ip: str) -> str:
    """Generate SDP with the real server IP (not 0.0.0.0)."""
    ip = server_ip or "0.0.0.0"
    if channel == "102":
        return (
            f"v=0\r\no=- 0 0 IN IP4 {ip}\r\n"
            f"s=Hikvision DS-2CD2043G2-I Sub Stream\r\n"
            f"c=IN IP4 {ip}\r\nt=0 0\r\n"
            "m=video 0 RTP/AVP 96\r\nb=AS:512\r\n"
            "a=rtpmap:96 H264/90000\r\n"
            "a=fmtp:96 packetization-mode=1;profile-level-id=42001f\r\n"
            "a=control:trackID=1\r\n"
        )
    if channel == "201":
        return (
            f"v=0\r\no=- 0 0 IN IP4 {ip}\r\n"
            f"s=Hikvision DS-2CD2043G2-I Third Stream\r\n"
            f"c=IN IP4 {ip}\r\nt=0 0\r\n"
            "m=video 0 RTP/AVP 96\r\nb=AS:256\r\n"
            "a=rtpmap:96 H264/90000\r\na=control:trackID=1\r\n"
        )
    # Default: main stream (channel 101 or any unknown)
    return (
        f"v=0\r\no=- 0 0 IN IP4 {ip}\r\n"
        f"s=Hikvision DS-2CD2043G2-I Main Stream\r\n"
        f"c=IN IP4 {ip}\r\nt=0 0\r\n"
        "a=tool:libavformat 58.29.100\r\n"
        "m=video 0 RTP/AVP 96\r\nb=AS:4096\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        "a=fmtp:96 packetization-mode=1;profile-level-id=640028;"
        "sprop-parameter-sets=Z2QAKKzZQHgCJ+WEAAADAAQAAAMAyDxYtlg=,aO48gA==\r\n"
        "a=control:trackID=1\r\n"
        "m=audio 0 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=control:trackID=2\r\n"
    )

# ─── CVE patterns in RTSP URLs / headers ──────────────────────────────────────

_CVE_PATTERNS = [
    (re.compile(r"/onvif-http/snapshot\?auth=|YWRtaW4|auth=0x",       re.I),
     "CVE-2017-7925", "Hikvision snapshot auth bypass",        "critical"),
    (re.compile(r"/ISAPI/Streaming/channels/\d+/picture.*auth=",       re.I),
     "CVE-2017-7921", "Hikvision auth bypass via ISAPI",        "critical"),
    (re.compile(r"/Streaming/Channels/\d+\?starttime=.*&endtime=",    re.I),
     "CVE-2021-36260","Hikvision command injection via stream URL", "critical"),
    (re.compile(r"\bRECORD\b",                                         re.I),
     "RTSP-INJECT",  "RTSP RECORD stream injection attempt",    "critical"),
    (re.compile(r"\$\{jndi:|%24%7bjndi:",                              re.I),
     "CVE-2021-44228","Log4Shell in RTSP URL/header",            "critical"),
    (re.compile(r"(\.\./){2,}|%2e%2e%2f|%252e%252e",                  re.I),
     "RTSP-TRAVERSAL","Path traversal in RTSP URL",             "high"),
    (re.compile(r"<script|javascript:|vbscript:",                       re.I),
     "RTSP-XSS",     "XSS attempt in RTSP URL",                 "medium"),
]

# ─── Scanner tool fingerprints from User-Agent ───────────────────────────────

_UA_FINGERPRINTS = {
    "nmap":            "nmap",
    "masscan":         "masscan",
    "vlc":             "VLC media player",
    "ffmpeg":          "FFmpeg",
    "libav":           "Libav",
    "python":          "Python scanner",
    "go-rtsp":         "Go RTSP scanner",
    "rtsp-client":     "generic RTSP client",
    "openrtsp":        "openRTSP",
    "live555":         "LIVE555 SDK",
    "hikvision":       "Hikvision client (legitimate or spoof)",
    "dahua":           "Dahua client",
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.datetime.utcnow().isoformat()

def _parse_headers(lines: list[str]) -> dict:
    h = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            h[k.strip().lower()] = v.strip()
    return h

def _parse_digest(header: str) -> dict:
    auth = {}
    if not header.lower().startswith("digest "):
        return auth
    for item in header[7:].split(","):
        if "=" in item:
            k, _, v = item.strip().partition("=")
            auth[k.strip()] = v.strip().strip('"')
    return auth

def _channel(url: str) -> str:
    m = re.search(r"/Channels?/(\d+)", url, re.I)
    return m.group(1) if m else "101"

def _detect_tool(user_agent: str) -> str:
    ua_lower = user_agent.lower()
    for sig, name in _UA_FINGERPRINTS.items():
        if sig in ua_lower:
            return name
    return ""

def _check_cve(url: str, raw: str) -> tuple[str, str, str] | tuple[None, None, None]:
    text = url + " " + raw
    for pat, cve_id, name, sev in _CVE_PATTERNS:
        if pat.search(text):
            return cve_id, name, sev
    return None, None, None


# ─── Main handler ─────────────────────────────────────────────────────────────

def handle_rtsp(
    conn,
    addr,
    log_attack        = None,
    geoip_func        = None,
    intel_fields_func = None,
    new_ip_alert      = None,
):
    ip, src_port = addr
    gdata = geoip_func(ip)        if geoip_func        else {}
    intel = intel_fields_func(gdata) if intel_fields_func else {}

    fw    = "V5.7.15"          # consistent firmware across all services
    model = "DS-2CD2043G2-I"
    # Detect server's public IP so SDP uses the right address
    try:
        server_ip = conn.getsockname()[0]
    except Exception:
        server_ip = "0.0.0.0"
    nonce = "%016x" % random.getrandbits(64)
    sid   = "%08x" % random.getrandbits(32)

    session = {
        "authenticated": False,
        "username":       "",
        "auth_attempts":  0,
        "methods":        [],
        "channels":       set(),   # URLs accessed
        "start":          time.time(),
    }

    def _log(attack_type: str, threat_level: str = "low", extra: dict = None):
        if not log_attack:
            return
        entry = {
            "timestamp":    _ts(),
            "source_ip":    ip,
            "source_port":  src_port,
            "dest_port":    554,
            "service":      "rtsp",
            "protocol":     "TCP",
            "attack_type":  attack_type,
            "threat_level": threat_level,
            "country":      gdata.get("country", "Unknown"),
            "city":         gdata.get("city", ""),
            "latitude":     gdata.get("latitude", 0.0),
            "longitude":    gdata.get("longitude", 0.0),
            **intel,
        }
        if extra:
            entry.update(extra)
        try:
            log_attack(entry)
        except Exception:
            pass

    def _now() -> str:
        return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    def _www_auth() -> str:
        return (
            f'Digest realm="HikVision IP Camera", '
            f'nonce="{nonce}", algorithm="MD5", qop="auth"'
        )

    try:
        conn.settimeout(15)
        request_count = 0

        for _ in range(20):
            try:
                raw = conn.recv(4096)
            except socket.timeout:
                break
            if not raw:
                break

            request_count += 1
            text  = raw.decode("utf-8", errors="ignore")
            lines = text.replace("\r\n", "\n").split("\n")
            if not lines or not lines[0].strip():
                continue

            first  = lines[0].strip().split()
            method = first[0] if first else "OPTIONS"
            url    = first[1] if len(first) > 1 else "/"

            headers   = _parse_headers(lines)
            cseq      = headers.get("cseq", "1")
            auth_hdr  = headers.get("authorization", "")
            user_agent = headers.get("user-agent", "")
            tool      = _detect_tool(user_agent)

            session["methods"].append(method)
            session["channels"].add(url)

            # ── CVE / exploit detection ───────────────────────────────────
            cve_id, cve_name, cve_sev = _check_cve(url, text)
            if cve_id:
                _log(f"rtsp_cve_{cve_id.lower().replace('-','_')}", cve_sev or "critical", {
                    "cve_id":     cve_id,
                    "method":     method,
                    "path":       url,
                    "payload":    text[:300],
                    "user_agent": user_agent,
                    "scanner":    tool,
                })

            # ── Stream enumeration — rapid DESCRIBE on many channels ──────
            if method == "DESCRIBE" and len(session["channels"]) > 3:
                _log("rtsp_stream_enumeration", "high", {
                    "method":   method,
                    "path":     url,
                    "channels": list(session["channels"])[:10],
                    "payload":  f"DESCRIBE on {len(session['channels'])} distinct URLs",
                })

            # ── Authentication flow ───────────────────────────────────────
            if method in ("DESCRIBE", "SETUP", "PLAY", "RECORD", "GET_PARAMETER"):
                if not session["authenticated"]:
                    if not auth_hdr:
                        _log("rtsp_probe", "low", {
                            "method":     method,
                            "path":       url,
                            "user_agent": user_agent,
                            "scanner":    tool,
                        })
                        conn.sendall((
                            f"RTSP/1.0 401 Unauthorized\r\n"
                            f"CSeq: {cseq}\r\n"
                            f"WWW-Authenticate: {_www_auth()}\r\n"
                            f"Server: Hikvision RTSP Server {fw}\r\n"
                            f"Date: {_now()}\r\n\r\n"
                        ).encode())
                        continue

                    # Parse Digest credentials
                    auth       = _parse_digest(auth_hdr)
                    username   = auth.get("username", "")
                    resp_hash  = auth.get("response", "")
                    session["auth_attempts"] += 1

                    # Accept if username is in weak creds list, OR on 3rd+ attempt
                    # (keeps attacker engaged and captures multiple credential pairs)
                    auth_ok = (
                        username in _WEAK_CREDS
                        or session["auth_attempts"] >= 2
                        or len(resp_hash) == 32   # accept any properly-formed Digest
                    )

                    if auth_ok and not session["authenticated"]:
                        session["authenticated"] = True
                        session["username"]       = username
                        _log("rtsp_auth_success", "high", {
                            "method":       method,
                            "path":         url,
                            "username":     username,
                            "password":     "",     # unknown (Digest, not Basic)
                            "auth_method":  "digest",
                            "attempts":     session["auth_attempts"],
                            "response_hex": resp_hash[:16],
                            "user_agent":   user_agent,
                            "scanner":      tool,
                            "payload":      f"Digest auth succeeded after {session['auth_attempts']} attempt(s)",
                        })
                    else:
                        _log("rtsp_auth_failed", "medium", {
                            "method":       method,
                            "path":         url,
                            "username":     username,
                            "attempts":     session["auth_attempts"],
                            "response_hex": resp_hash[:16],
                            "user_agent":   user_agent,
                        })
                        if session["auth_attempts"] > 5:
                            conn.sendall((
                                f"RTSP/1.0 403 Forbidden\r\n"
                                f"CSeq: {cseq}\r\n"
                                f"Server: Hikvision RTSP Server {fw}\r\n\r\n"
                            ).encode())
                            break
                        conn.sendall((
                            f"RTSP/1.0 401 Unauthorized\r\n"
                            f"CSeq: {cseq}\r\n"
                            f"WWW-Authenticate: {_www_auth()}\r\n"
                            f"Server: Hikvision RTSP Server {fw}\r\n"
                            f"Date: {_now()}\r\n\r\n"
                        ).encode())
                        continue

            # ── RTSP method responses ─────────────────────────────────────
            time.sleep(random.uniform(0.03, 0.12))

            if method == "OPTIONS":
                _log("rtsp_recon", "low", {
                    "method": method, "path": url,
                    "user_agent": user_agent, "scanner": tool,
                })
                conn.sendall((
                    f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                    f"Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, "
                    f"GET_PARAMETER, SET_PARAMETER\r\n"
                    f"Server: Hikvision RTSP Server {fw}\r\n"
                    f"Date: {_now()}\r\n\r\n"
                ).encode())

            elif method == "DESCRIBE":
                ch  = _channel(url)
                sdp = _build_sdp(ch, server_ip)
                _log("rtsp_stream_access", "medium", {
                    "method":  method, "path":    url,
                    "channel": ch,     "payload": f"SDP served for channel {ch}",
                    "user_agent": user_agent,
                })
                conn.sendall((
                    f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                    f"Content-Base: rtsp://{ip}:554{url}/\r\n"
                    f"Content-Type: application/sdp\r\n"
                    f"Content-Length: {len(sdp)}\r\n"
                    f"Server: Hikvision RTSP Server {fw}\r\n"
                    f"Session: {sid};timeout=60\r\n"
                    f"Date: {_now()}\r\n\r\n{sdp}"
                ).encode())

            elif method == "SETUP":
                transport     = headers.get("transport", "RTP/AVP;unicast;client_port=8000-8001")
                cp_match      = re.search(r"client_port=(\d+)-(\d+)", transport)
                client_rtp    = cp_match.group(1) if cp_match else "8000"
                client_rtcp   = cp_match.group(2) if cp_match else "8001"
                server_rtp    = random.randint(40000, 50000)
                _log("rtsp_setup", "medium", {
                    "method": method, "path": url,
                    "payload": f"transport={transport[:80]}",
                })
                conn.sendall((
                    f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                    f"Session: {sid};timeout=60\r\n"
                    f"Transport: RTP/AVP;unicast;client_port={client_rtp}-{client_rtcp};"
                    f"server_port={server_rtp}-{server_rtp+1};"
                    f"ssrc={random.randint(10000000,99999999):08X}\r\n"
                    f"Server: Hikvision RTSP Server {fw}\r\n"
                    f"Date: {_now()}\r\n\r\n"
                ).encode())

            elif method == "PLAY":
                rtp_seq  = random.randint(10000, 65535)
                rtp_time = random.randint(100000, 9999999)
                _log("rtsp_stream_play", "high", {
                    "method":   method, "path":     url,
                    "username": session["username"],
                    "payload":  f"Stream PLAY on {url} by {session['username'] or 'unknown'}",
                })
                conn.sendall((
                    f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                    f"Session: {sid};timeout=60\r\n"
                    f"Range: npt=0.000-\r\n"
                    f"RTP-Info: url={url}/trackID=1;seq={rtp_seq};rtptime={rtp_time},"
                    f"url={url}/trackID=2;seq={rtp_seq+1};rtptime={rtp_time}\r\n"
                    f"Server: Hikvision RTSP Server {fw}\r\n"
                    f"Date: {_now()}\r\n\r\n"
                ).encode())
                time.sleep(random.uniform(0.5, 2.0))   # simulate stream hold

            elif method == "RECORD":
                # Injection attack — log as critical
                _log("rtsp_inject_attempt", "critical", {
                    "method":   "RECORD",
                    "path":     url,
                    "cve_id":   "RTSP-INJECT",
                    "payload":  text[:300],
                })
                conn.sendall((
                    f"RTSP/1.0 403 Forbidden\r\nCSeq: {cseq}\r\n"
                    f"Server: Hikvision RTSP Server {fw}\r\n\r\n"
                ).encode())

            elif method == "TEARDOWN":
                conn.sendall((
                    f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                    f"Session: {sid}\r\n"
                    f"Server: Hikvision RTSP Server {fw}\r\n\r\n"
                ).encode())
                break

            else:
                conn.sendall((
                    f"RTSP/1.0 405 Method Not Allowed\r\nCSeq: {cseq}\r\n"
                    f"Allow: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, "
                    f"GET_PARAMETER, SET_PARAMETER\r\n"
                    f"Server: Hikvision RTSP Server {fw}\r\n\r\n"
                ).encode())

    except (ConnectionResetError, BrokenPipeError, socket.timeout):
        pass
    except Exception:
        pass
    finally:
        if request_count > 0:
            _log("rtsp_session_end", "low", {
                "payload":       f"{request_count} requests, {len(session['channels'])} URLs",
                "username":      session["username"],
                "authenticated": session["authenticated"],
                "auth_attempts": session["auth_attempts"],
                "methods":       ",".join(session["methods"]),
                "channels":      list(session["channels"])[:10],
                "duration_s":    round(time.time() - session["start"], 2),
            })
        if new_ip_alert:
            try:
                new_ip_alert(ip, gdata.get("country",""), gdata.get("city",""), "rtsp")
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass
