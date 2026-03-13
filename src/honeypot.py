import os, time, json, threading, random, secrets, sys, logging, socket
from pathlib import Path
# Ensure project root is on sys.path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from collections import deque, defaultdict
from flask import Flask, request, make_response, redirect
from db import init as init_db, log_attack, log_honeytoken, log_attack_chain, log_device_fingerprint

try:
    import geoip2.database
except ImportError:
    geoip2 = None

app = Flask(__name__)
init_db()

# Logging to logs/honeypot.err
LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "honeypot.err"
try:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=str(LOG_FILE), level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
except PermissionError:
    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

GEOIP_DB = os.environ.get("GEOIP_DB")  # point to GeoLite2-City.mmdb if available
geo_reader = geoip2.database.Reader(GEOIP_DB) if GEOIP_DB and geoip2 else None

RATE_LIMIT = defaultdict(lambda: deque())
RATE_LIMIT_LOCK = threading.Lock()
MAX_REQ_PER_MIN = 40

SESSION_STAGES = defaultdict(lambda: deque(maxlen=8))
SESSION_NONCES = {}

SERVICE_MAP = {
    "ISAPI": "isapi",
    "Streaming": "rtsp",
    "doc/page/login": "http",
}

STAGE_LABELS = {
    "/doc/page/login":    "Login Page",
    "/Security/sessionLogin": "Auth Attempt",
    "/ISAPI/System":      "Device Enum",
    "/ISAPI/":            "ISAPI Probe",
    "/Streaming":         "Stream Access",
    "/onvif/":            "ONVIF Probe",
    "/PSIA/":             "Streaming Info",
    "/cgi-bin/":          "CGI Recon",
}

LOGIN_ERROR_PAGE = """
<html><body style='background:#1a1a1a;color:#f55;padding:20px'>
  <p>Invalid username or password. Please try again.</p>
  <a href='javascript:history.back()' style='color:#0af'>Back</a>
</body></html>
"""

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

def rate_limit(ip):
    with RATE_LIMIT_LOCK:
        queue = RATE_LIMIT[ip]
        now = time.time()
        while queue and now - queue[0] > 60:
            queue.popleft()
        queue.append(now)
        return len(queue) > MAX_REQ_PER_MIN

def detect_service(path):
    for key, svc in SERVICE_MAP.items():
        if key.lower() in path.lower():
            return svc
    if path.startswith("/onvif"):
        return "onvif"
    if path.startswith("/cgi-bin"):
        return "http"
    return "http"

def slow_down(min_ms=80, max_ms=220):
    time.sleep(random.uniform(min_ms, max_ms) / 1000)

def ensure_session_token(ip):
    token = SESSION_NONCES.get(ip)
    if not token:
        token = secrets.token_urlsafe(12)
        SESSION_NONCES[ip] = token
    return token

def validate_session_token(ip, token):
    return token and SESSION_NONCES.get(ip) == token

def tarpit_connection(client_socket, client_address):
    try:
        ip = client_address[0]
        port = client_address[1]
        logging.info(f"Tarpit connection from {ip}:{port}")
        
        # Log the connection to the database so the dashboard sees it
        try:
            geo = get_geo(ip)
            log_attack({
                "source_ip": ip,
                "source_port": port,
                "dest_port": 2223,
                "service": "tarpit",
                "protocol": "TCP",
                "method": "CONNECT",
                "path": "",
                "user_agent": "tarpit-scanner",
                "payload": "",
                "country": geo.get("country", "Unknown"),
                "city": geo.get("city", ""),
                "latitude": geo.get("latitude", 0.0),
                "longitude": geo.get("longitude", 0.0),
                "threat_level": "medium",
                "attack_type": "tarpit_connection"
            })
        except Exception as e:
            pass

        # Send a fake banner slowly
        banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
        for byte in banner:
            client_socket.send(bytes([byte]))
            time.sleep(10)  # Hold connection open, 10 seconds per byte
        
        # Keep sending junk data indefinitely
        while True:
            client_socket.send(b"\x00")
            time.sleep(15)
    except Exception:
        pass
    finally:
        client_socket.close()

def start_tarpit(port=2223):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(100)
        logging.info(f"Tarpit running on port {port}")
        while True:
            client, addr = server.accept()
            threading.Thread(target=tarpit_connection, args=(client, addr), daemon=True).start()
    except Exception as e:
        logging.error(f"Tarpit failed to start on port {port}: {e}")

def describe_stage(path):
    if not path:
        return "Recon"
    pl = path.lower()
    for marker, label in STAGE_LABELS.items():
        if marker.lower() in pl:
            return label
    return "Recon"

def track_stage(ip, path):
    stage = describe_stage(path)
    SESSION_STAGES[ip].append(stage)
    if len(SESSION_STAGES[ip]) >= 3:
        log_attack_chain(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            source_ip=ip,
            chain_id=f"{ip}-{len(SESSION_STAGES[ip])}",
            stages=list(SESSION_STAGES[ip]),
        )

def base_log(payload):
    if not isinstance(payload, dict):
        payload = {}
    ip = request.remote_addr or "0.0.0.0"
    geo = get_geo(ip)
    data = {
        "source_ip": ip,
        "source_port": request.environ.get("REMOTE_PORT", 0),
        "dest_port": request.environ.get("SERVER_PORT", 0),
        "service": detect_service(request.path),
        "protocol": "TCP",
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "payload": request.get_data(as_text=True)[:1024],
        "username": request.form.get("username", ""),
        "password": request.form.get("password", ""),
        "country": geo["country"],
        "city": geo["city"],
        "latitude": geo["latitude"],
        "longitude": geo["longitude"],
        "threat_level": payload.get("threat_level", "high" if "login" in request.path.lower() else "low"),
        "query_string": request.query_string.decode(errors="ignore")[:512],
        "referer": request.headers.get("Referer", "")[:512],
        "host_header": request.headers.get("Host", "")[:512],
        "origin": request.headers.get("Origin", "")[:512],
        "attack_patterns": json.dumps(request.values.to_dict(flat=True))[:512],
        "scanner_tool": request.headers.get("User-Agent", "")[:100],
    }
    data["attack_type"] = payload.get("attack_type", "")
    try:
        log_attack(data)
    except Exception as e:
        logging.exception("log_attack failed: %s", e)
    track_stage(ip, request.path)

@app.before_request
def throttle():
    ip = request.remote_addr or "0.0.0.0"
    if rate_limit(ip):
        return make_response("429 Too Many Requests", 429)

@app.after_request
def add_realistic_headers(response):
    # Mask Flask/Werkzeug by mimicking the typical Hikvision web server
    response.headers["Server"] = "App-webs/"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response

def rtsp_response(status=401):
    resp = make_response("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm=\"hikvision\"\r\n\r\n", status)
    resp.headers["Server"] = "App-webs/"
    resp.headers["Content-Type"] = "application/sdp"
    return resp

@app.route("/doc/page/login.asp", methods=["GET", "POST"])
def login_page():
    ip = request.remote_addr or "0.0.0.0"
    token = ensure_session_token(ip)
    if request.method == "POST":
        cookie = request.cookies.get("HikvisionSession")
        payload = {"username": request.form.get("username"), "password": request.form.get("password")}
        base_log(payload)
        log_honeytoken(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            source_ip=ip,
            token_type="login-form",
            token_value=f"{payload['username']}:{payload['password']}",
            service="http",
            country=get_geo(ip)["country"],
            commands=[],
        )
        resp = make_response(LOGIN_ERROR_PAGE, 200)
        resp.set_cookie("HikvisionSession", token, httponly=True, samesite="Lax")
        slow_down(120, 240)
        return resp
    base_log({})
    html = """
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Hikvision Network Video Recorder</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: linear-gradient(135deg, #1a1a1a 0%, #16213e 100%); font-family: Arial, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .container { background: #fff; border-radius: 8px; box-shadow: 0 8px 16px rgba(0,0,0,0.3); padding: 40px; width: 100%; max-width: 380px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { color: #333; font-size: 24px; margin-bottom: 5px; }
        .logo p { color: #999; font-size: 12px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: #333; font-size: 13px; font-weight: bold; margin-bottom: 8px; }
        input { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; transition: border-color 0.3s; }
        input:focus { outline: none; border-color: #0066cc; }
        button { width: 100%; padding: 10px; background: #0066cc; color: #fff; border: none; border-radius: 4px; font-size: 14px; font-weight: bold; cursor: pointer; transition: background 0.3s; }
        button:hover { background: #0052a3; }
        .footer { text-align: center; margin-top: 20px; color: #999; font-size: 11px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">
          <h1>🎥 Hikvision</h1>
          <p>Network Video Recorder</p>
        </div>
        <form method="POST">
          <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" value="admin" required autofocus>
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Enter password" required>
          </div>
          <button type="submit">Login</button>
        </form>
        <div class="footer">
          <p>DS-2CD2043G2-I v5.7.15</p>
          <p>© 2023 Hikvision Digital Technology</p>
        </div>
      </div>
    </body>
    </html>
    """
    resp = make_response(html, 200)
    resp.set_cookie("HikvisionSession", token, httponly=True, samesite="Lax")
    slow_down(100, 180)
    return resp

@app.route("/ISAPI/<path:rest>", methods=["GET", "POST", "PUT"])
def isapi(rest):
    payload_data = request.get_data(as_text=True)
    
    # Detect CVE-2021-36260 (Hikvision Command Injection)
    if request.method == "PUT" and ("<language>" in payload_data or "system(" in payload_data or "/bin/sh" in payload_data):
        base_log({
            "attack_type": "cve-2021-36260-exploit",
            "threat_level": "critical",
            "notes": "Command injection detected"
        })
        slow_down(200, 500)
        # Device typically returns a 500 error or a specific XML error when crashing/exploited
        return make_response("<?xml version=\"1.0\" ?><Response><status>500</status><statusString>Error</statusString></Response>", 500)
    
    base_log({"attack_type": "isapi-probe"})
    slow_down()
    return make_response("<?xml version=\"1.0\" ?><Response><status>0</status></Response>", 200)

@app.route("/PSIA/Streaming/channels", methods=["GET"])
def psia_stream():
    base_log({"attack_type": "stream-query"})
    xml = """<?xml version="1.0"?><StreamingChannelList><Channel><id>1</id><Name>MainStream</Name><status>active</status></Channel></StreamingChannelList>"""
    slow_down()
    return make_response(xml, 200, {"Content-Type": "application/xml"})

@app.route("/PSIA/MediaInput/channels/1", methods=["GET"])
def psia_media():
    base_log({"attack_type": "media-input"})
    xml = """<?xml version="1.0"?><MediaInputInfo><id>1</id><name>Video1</name><status>online</status><resolution>2048x1536</resolution></MediaInputInfo>"""
    slow_down()
    return make_response(xml, 200, {"Content-Type": "application/xml"})

@app.route("/Streaming/channels", methods=["GET"])
def streaming_channels():
    base_log({"attack_type": "stream-root"})
    slow_down()
    return rtsp_response()

@app.route("/Streaming/channels/101")
def streaming_channel_101():
    base_log({"attack_type": "stream-access"})
    resp = make_response("RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\nWWW-Authenticate: Basic realm=\"hikvision\"\r\nTransport: RTP/AVP;unicast;client_port=8000-8001\r\n\r\n", 401)
    resp.headers["Server"] = "App-webs/"
    resp.headers["Content-Type"] = "application/sdp"
    slow_down()
    return resp

@app.route("/Streaming/<path:rest>")
def streaming(rest):
    base_log({"attack_type": "stream-probe"})
    slow_down()
    return rtsp_response()

@app.route("/ISAPI/System/status", methods=["GET"])
def status():
    base_log({"attack_type": "system-status"})
    xml = """<?xml version="1.0"?><Status><Device>Online</Device><CPU>15%</CPU><Memory>62%</Memory><Temperature>42°C</Temperature></Status>"""
    log_device_fingerprint(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), request.remote_addr or "0.0.0.0", "DS-2CD2043G2-I", "Hikvision", "DS-2CD2043G2-I", "V5.7.15")
    slow_down()
    return make_response(xml, 200, {"Content-Type": "application/xml"})

@app.route("/ISAPI/ContentMgmt/record/control", methods=["POST"])
def record_control():
    base_log({"attack_type": "record-control"})
    slow_down()
    return make_response("<?xml version=\"1.0\"?><Response><status>0</status><message>ok</message></Response>", 200, {"Content-Type": "application/xml"})

@app.route("/Security/userCheck", methods=["POST"])
def user_check():
    payload = {"attack_type": "user-check", "threat_level": "high"}
    base_log(payload)
    slow_down()
    return make_response("<?xml version=\"1.0\"?><Response><status>401</status><message>Unauthorized</message></Response>", 401)

@app.route("/Security/sessionLogin", methods=["GET", "POST"])
def session_login():
    ip = request.remote_addr or "0.0.0.0"
    if request.method == "POST":
        if not validate_session_token(ip, request.cookies.get("HikvisionSession")):
            payload = {"attack_type": "session-login", "threat_level": "critical"}
        else:
            payload = {"attack_type": "session-login", "threat_level": "high"}
        base_log(payload)
        xml = "<?xml version=\"1.0\"?><Response><status>401</status><message>Unauthorized</message></Response>"
        slow_down()
        return make_response(xml, 401, {"Content-Type": "application/xml"})
    base_log({"attack_type": "session-login"})
    xml = "<?xml version=\"1.0\"?><Response><status>200</status><message>OK</message></Response>"
    slow_down()
    return make_response(xml, 200, {"Content-Type": "application/xml"})

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    base_log({})
    # Real cameras redirect root requests to the login page
    if not path or path == "/":
        return redirect("/doc/page/login.asp", code=302)
    
    # Unmatched paths typically return a 404 on real devices
    html = "<html><body><p>404 Not Found</p></body></html>"
    return make_response(html, 404)

if __name__ == "__main__":
    # Start the tarpit in the background on an alternate port (e.g. 2223)
    tarpit_port = int(os.environ.get("TARPIT_PORT", 2223))
    if tarpit_port > 0:
        tarpit_thread = threading.Thread(target=start_tarpit, args=(tarpit_port,), daemon=True)
        tarpit_thread.start()

    app.run(host="0.0.0.0", port=int(os.environ.get("HONEYPOT_PORT", 8080)), debug=False)
