#!/usr/bin/env python3
"""
honeyPot — ONVIF Service (WS-Discovery / SOAP over HTTP, port 8000)
Emulates a Hikvision DS-2CD2043G2-I IP camera ONVIF interface.

Improvements over original:
  - Multi-request loop (persistent connection; attackers send many SOAP calls)
  - CVE detection: CVE-2017-7923 (auth bypass), CVE-2021-36260 (cmd injection),
    XXE injection, SOAP/XML injection, firmware-upload attempts
  - Single structured log entry per SOAP action (no duplicate rows)
  - Brute-force detection (auth_attempts threshold)
  - Threat-level classification per action
  - All log_attack calls use dict format passed to the wrapper
"""

import re
import time
import json
import random
import hashlib
import datetime

# ─── Device Info ─────────────────────────────────────────────────────────────

def _get_device_info():
    return {
        "Manufacturer":    "Hikvision",
        "Model":           random.choice(["DS-2CD2043G2-I", "DS-2CD2143G0-I", "DS-2CD2083G2-IU"]),
        "FirmwareVersion": random.choice(["V5.5.8 build 181121", "V5.6.2 build 190401",
                                          "V5.7.0 build 210703", "V5.7.15 build 230313"]),
        "SerialNumber":    "DS-2CD2043G2-I%d0BBRR%06d" % (random.randint(2020, 2024),
                                                            random.randint(100000, 999999)),
        "HardwareId":      "88%08d" % random.randint(10000000, 99999999),
    }

# ─── Weak credentials ────────────────────────────────────────────────────────

_WEAK_CREDS = {
    "admin":   ["", "admin", "12345", "123456", "password", "admin123", "hikvision"],
    "root":    ["", "root",  "12345", "toor",   "password", "admin"],
    "user":    ["", "user",  "12345"],
    "service": ["", "service"],
    "guest":   ["", "guest"],
    "operator":["", "operator"],
}

# ─── SOAP action threat classification ───────────────────────────────────────

_ACTION_THREAT = {
    # Reconnaissance — low
    "GetSystemDateAndTime":           ("onvif_probe",        "low"),
    "GetCapabilities":                ("onvif_recon",        "low"),
    "GetServices":                    ("onvif_recon",        "low"),
    "GetDeviceInformation":           ("onvif_recon",        "low"),
    "GetHostname":                    ("onvif_recon",        "low"),
    "GetScopes":                      ("onvif_recon",        "low"),
    "GetNetworkInterfaces":           ("onvif_recon",        "medium"),
    "GetNetworkDefaultGateway":       ("onvif_recon",        "medium"),
    "GetDNS":                         ("onvif_recon",        "medium"),
    # Video access — medium/high
    "GetProfiles":                    ("onvif_stream_enum",  "medium"),
    "GetVideoSources":                ("onvif_stream_enum",  "medium"),
    "GetVideoEncoderConfigurations":  ("onvif_stream_enum",  "medium"),
    "GetStreamUri":                   ("onvif_stream_access","high"),
    "GetSnapshotUri":                 ("onvif_snapshot_req", "high"),
    # User management — critical
    "GetUsers":                       ("onvif_user_enum",    "high"),
    "CreateUsers":                    ("onvif_user_create",  "critical"),
    "DeleteUsers":                    ("onvif_user_delete",  "critical"),
    "SetUser":                        ("onvif_user_modify",  "critical"),
    # System ops — critical
    "SystemReboot":                   ("onvif_system_reboot","critical"),
    "SetSystemFactoryDefault":        ("onvif_factory_reset","critical"),
    "StartFirmwareUpgrade":           ("onvif_fw_upgrade",   "critical"),
    "UpgradeFirmware":                ("onvif_fw_upgrade",   "critical"),
    "SetNetworkInterfaces":           ("onvif_net_change",   "critical"),
    "SetDNS":                         ("onvif_net_change",   "critical"),
    "SetHostname":                    ("onvif_net_change",   "critical"),
    "AddScopes":                      ("onvif_scope_change", "high"),
    "RemoveScopes":                   ("onvif_scope_change", "high"),
    "SetRemoteUser":                  ("onvif_user_modify",  "critical"),
}

_NOAUTH_ACTIONS = {"GetSystemDateAndTime", "GetWsdlUrl", "GetCapabilities", "GetServices"}

# ─── CVE patterns ─────────────────────────────────────────────────────────────

_CVE_PATTERNS = [
    # CVE-2017-7923: Hikvision ISAPI auth bypass — camera exposes user list unauthenticated
    (re.compile(r"/ISAPI/Security/users", re.I),
     "CVE-2017-7923", "Hikvision ISAPI user enumeration without auth", "critical"),
    # CVE-2021-36260: Command injection via ONVIF PutDeviceIO or systemReboot body
    (re.compile(r"<[^>]*>\s*[;|&`$\(\{].*?(reboot|wget|curl|sh|bash|python|nc\b)", re.I | re.DOTALL),
     "CVE-2021-36260", "ONVIF command injection in SOAP body", "critical"),
    # XXE — XML external entity injection
    (re.compile(r"<!DOCTYPE\s+\w+\s+\[|<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)", re.I),
     "XXE-INJECTION", "XML External Entity injection in SOAP request", "critical"),
    # SOAP injection (nested opening envelope, script in SOAP body)
    (re.compile(r"<script[\s>]|javascript:|vbscript:|<SOAP-ENV:Envelope[^<]{0,200}<SOAP-ENV:Envelope", re.I | re.DOTALL),
     "SOAP-INJECT", "SOAP envelope injection / XSS attempt", "high"),
    # Log4Shell
    (re.compile(r"\$\{jndi:|%24%7bjndi:", re.I),
     "CVE-2021-44228", "Log4Shell in ONVIF SOAP request", "critical"),
    # Path traversal in ONVIF URI
    (re.compile(r"(\.\./){2,}|%2e%2e%2f|%252e%252e", re.I),
     "ONVIF-TRAVERSAL", "Path traversal in ONVIF request", "high"),
    # Credential stuffing markers (very long username/password)
    (re.compile(r"<wsse:Password[^>]*>[^<]{64,}</wsse:Password>", re.I),
     "ONVIF-BRUTE", "Unusually long ONVIF password (stuffing/fuzzing)", "medium"),
]

# ─── SOAP response templates ──────────────────────────────────────────────────

def _ts():
    return datetime.datetime.utcnow().isoformat()

def _soap_fault(code, reason, detail=""):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:ter="http://www.onvif.org/ver10/error">'
        "<SOAP-ENV:Body><SOAP-ENV:Fault>"
        f"<SOAP-ENV:Code><SOAP-ENV:Value>SOAP-ENV:{code}</SOAP-ENV:Value></SOAP-ENV:Code>"
        f"<SOAP-ENV:Reason><SOAP-ENV:Text xml:lang=\"en\">{reason}</SOAP-ENV:Text></SOAP-ENV:Reason>"
        + (f"<SOAP-ENV:Detail>{detail}</SOAP-ENV:Detail>" if detail else "") +
        "</SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )

def _soap_env(body):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
        ' xmlns:tt="http://www.onvif.org/ver10/schema"'
        ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
        f"<SOAP-ENV:Body>{body}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )

def _http_resp(body, status=200):
    st = {200: "OK", 401: "Unauthorized", 400: "Bad Request",
          500: "Internal Server Error"}.get(status, "OK")
    b = body.encode("utf-8", errors="replace")
    return (
        f"HTTP/1.1 {status} {st}\r\n"
        f"Content-Type: application/soap+xml; charset=utf-8\r\n"
        f"Content-Length: {len(b)}\r\n"
        f"Server: Hikvision ONVIF/2.0\r\n"
        f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + b

# ─── Auth parsing ─────────────────────────────────────────────────────────────

def _parse_auth(soap):
    username = password = nonce_b64 = created = None
    um = re.search(r"<[^:>]*:?Username>([^<]+)<", soap, re.I)
    pm = re.search(r"<[^:>]*:?Password[^>]*>([^<]+)<", soap, re.I)
    nm = re.search(r"<[^:>]*:?Nonce[^>]*>([^<]+)<", soap, re.I)
    cm = re.search(r"<[^:>]*:?Created>([^<]+)<", soap, re.I)
    if um: username  = um.group(1).strip()
    if pm: password  = pm.group(1).strip()
    if nm: nonce_b64 = nm.group(1).strip()
    if cm: created   = cm.group(1).strip()
    return username, password, nonce_b64, created

def _validate_creds(username, password):
    if not username:
        return False
    # Any 32+ char hash-looking password → accepted (digest auth engagement)
    if password and len(password) >= 28 and re.match(r"^[A-Za-z0-9+/=]+$", password):
        return True
    return username in _WEAK_CREDS and (password or "") in _WEAK_CREDS.get(username, [])

# ─── Individual SOAP response bodies ─────────────────────────────────────────

def _resp_capabilities(dev, host):
    return _soap_env(f"""<tds:GetCapabilitiesResponse><tds:Capabilities>
<tt:Device><tt:XAddr>http://{host}:8000/onvif/device_service</tt:XAddr>
<tt:System><tt:DiscoveryResolve>true</tt:DiscoveryResolve><tt:RemoteDiscovery>true</tt:RemoteDiscovery>
<tt:SystemBackup>true</tt:SystemBackup><tt:FirmwareUpgrade>true</tt:FirmwareUpgrade></tt:System>
<tt:Security><tt:TLS1.2>true</tt:TLS1.2><tt:AccessPolicyConfig>true</tt:AccessPolicyConfig></tt:Security>
</tt:Device>
<tt:Events><tt:XAddr>http://{host}:8000/onvif/event</tt:XAddr>
<tt:WSSubscriptionPolicySupport>true</tt:WSSubscriptionPolicySupport></tt:Events>
<tt:Media><tt:XAddr>http://{host}:8000/onvif/media</tt:XAddr>
<tt:StreamingCapabilities><tt:RTP_TCP>true</tt:RTP_TCP><tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>
</tt:StreamingCapabilities></tt:Media>
</tds:Capabilities></tds:GetCapabilitiesResponse>""")

def _resp_device_info(dev):
    return _soap_env(f"""<tds:GetDeviceInformationResponse>
<tds:Manufacturer>{dev["Manufacturer"]}</tds:Manufacturer>
<tds:Model>{dev["Model"]}</tds:Model>
<tds:FirmwareVersion>{dev["FirmwareVersion"]}</tds:FirmwareVersion>
<tds:SerialNumber>{dev["SerialNumber"]}</tds:SerialNumber>
<tds:HardwareId>{dev["HardwareId"]}</tds:HardwareId>
</tds:GetDeviceInformationResponse>""")

def _resp_services(host):
    return _soap_env(f"""<tds:GetServicesResponse>
<tds:Service><tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace>
<tds:XAddr>http://{host}:8000/onvif/device_service</tds:XAddr>
<tds:Version><tt:Major>2</tt:Major><tt:Minor>6</tt:Minor></tds:Version></tds:Service>
<tds:Service><tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>
<tds:XAddr>http://{host}:8000/onvif/media</tds:XAddr>
<tds:Version><tt:Major>2</tt:Major><tt:Minor>6</tt:Minor></tds:Version></tds:Service>
</tds:GetServicesResponse>""")

def _resp_datetime():
    n = time.gmtime()
    return _soap_env(f"""<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime>
<tt:DateTimeType>NTP</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings>
<tt:TimeZone><tt:TZ>GMT+0</tt:TZ></tt:TimeZone>
<tt:UTCDateTime><tt:Time><tt:Hour>{n.tm_hour}</tt:Hour><tt:Minute>{n.tm_min}</tt:Minute>
<tt:Second>{n.tm_sec}</tt:Second></tt:Time>
<tt:Date><tt:Year>{n.tm_year}</tt:Year><tt:Month>{n.tm_mon}</tt:Month>
<tt:Day>{n.tm_mday}</tt:Day></tt:Date></tt:UTCDateTime>
</tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>""")

def _resp_users():
    return _soap_env("""<tds:GetUsersResponse>
<tds:User><tt:Username>admin</tt:Username><tt:UserLevel>Administrator</tt:UserLevel></tds:User>
<tds:User><tt:Username>operator</tt:Username><tt:UserLevel>Operator</tt:UserLevel></tds:User>
<tds:User><tt:Username>user</tt:Username><tt:UserLevel>User</tt:UserLevel></tds:User>
</tds:GetUsersResponse>""")

def _resp_network(host):
    mac = "44:%02X:%02X:%02X:%02X:%02X" % tuple(random.randint(0, 255) for _ in range(5))
    return _soap_env(f"""<tds:GetNetworkInterfacesResponse>
<tds:NetworkInterfaces token="eth0">
<tt:Enabled>true</tt:Enabled>
<tt:Info><tt:Name>eth0</tt:Name><tt:HwAddress>{mac}</tt:HwAddress><tt:MTU>1500</tt:MTU></tt:Info>
<tt:IPv4><tt:Enabled>true</tt:Enabled><tt:Config>
<tt:Manual><tt:Address>{host}</tt:Address><tt:PrefixLength>24</tt:PrefixLength></tt:Manual>
<tt:DHCP>false</tt:DHCP></tt:Config></tt:IPv4>
</tds:NetworkInterfaces></tds:GetNetworkInterfacesResponse>""")

def _resp_profiles():
    return _soap_env("""<trt:GetProfilesResponse>
<trt:Profiles token="Profile_1" fixed="true"><tt:Name>MainStream</tt:Name>
<tt:VideoSourceConfiguration token="VideoSource_1">
<tt:Name>VideoSource_1</tt:Name><tt:SourceToken>VideoSource_1</tt:SourceToken>
<tt:Bounds x="0" y="0" width="2688" height="1520"/>
</tt:VideoSourceConfiguration>
<tt:VideoEncoderConfiguration token="VideoEncoder_1">
<tt:Name>VideoEncoder_1</tt:Name><tt:Encoding>H264</tt:Encoding>
<tt:Resolution><tt:Width>2688</tt:Width><tt:Height>1520</tt:Height></tt:Resolution>
<tt:RateControl><tt:FrameRateLimit>25</tt:FrameRateLimit><tt:BitrateLimit>4096</tt:BitrateLimit></tt:RateControl>
<tt:H264><tt:GovLength>50</tt:GovLength><tt:H264Profile>High</tt:H264Profile></tt:H264>
</tt:VideoEncoderConfiguration></trt:Profiles>
<trt:Profiles token="Profile_2" fixed="true"><tt:Name>SubStream</tt:Name>
<tt:VideoEncoderConfiguration token="VideoEncoder_2">
<tt:Name>VideoEncoder_2</tt:Name><tt:Encoding>H264</tt:Encoding>
<tt:Resolution><tt:Width>704</tt:Width><tt:Height>576</tt:Height></tt:Resolution>
<tt:RateControl><tt:FrameRateLimit>25</tt:FrameRateLimit><tt:BitrateLimit>512</tt:BitrateLimit></tt:RateControl>
</tt:VideoEncoderConfiguration></trt:Profiles>
</trt:GetProfilesResponse>""")

def _resp_stream_uri(host):
    return _soap_env(f"""<trt:GetStreamUriResponse><trt:MediaUri>
<tt:Uri>rtsp://{host}:554/Streaming/Channels/101</tt:Uri>
<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
<tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
<tt:Timeout>PT60S</tt:Timeout></trt:MediaUri></trt:GetStreamUriResponse>""")

def _resp_snapshot_uri(host):
    return _soap_env(f"""<trt:GetSnapshotUriResponse><trt:MediaUri>
<tt:Uri>http://{host}:80/ISAPI/Streaming/channels/101/picture</tt:Uri>
<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
<tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
<tt:Timeout>PT5S</tt:Timeout></trt:MediaUri></trt:GetSnapshotUriResponse>""")

def _resp_hostname(host):
    return _soap_env(f"""<tds:GetHostnameResponse><tds:HostnameInformation>
<tt:FromDHCP>false</tt:FromDHCP>
<tt:Name>DS-2CD2043G2-I</tt:Name>
</tds:HostnameInformation></tds:GetHostnameResponse>""")

def _resp_scopes():
    return _soap_env("""<tds:GetScopesResponse>
<tds:Scopes><tt:ScopeDefinition>Fixed</tt:ScopeDefinition>
<tt:ScopeItem>onvif://www.onvif.org/type/video_encoder</tt:ScopeItem></tds:Scopes>
<tds:Scopes><tt:ScopeDefinition>Fixed</tt:ScopeDefinition>
<tt:ScopeItem>onvif://www.onvif.org/hardware/DS-2CD2043G2-I</tt:ScopeItem></tds:Scopes>
<tds:Scopes><tt:ScopeDefinition>Fixed</tt:ScopeDefinition>
<tt:ScopeItem>onvif://www.onvif.org/name/Hikvision</tt:ScopeItem></tds:Scopes>
</tds:GetScopesResponse>""")

# ─── Action detector ──────────────────────────────────────────────────────────

_ALL_ACTIONS = sorted(_ACTION_THREAT.keys(), key=len, reverse=True)  # longest first

def _detect_action(text):
    for action in _ALL_ACTIONS:
        if action in text:
            return action
    return ""

# ─── Main handler ─────────────────────────────────────────────────────────────

def handle_onvif(
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

    device = _get_device_info()

    session = {
        "auth_attempts":  0,
        "authenticated":  False,
        "username":       "",
        "actions":        [],
        "cves":           [],
        "start":          time.time(),
    }

    def _log(attack_type, threat_level="low", extra=None):
        if not log_attack:
            return
        entry = {
            "timestamp":    _ts(),
            "source_ip":    ip,
            "source_port":  src_port,
            "dest_port":    8000,
            "service":      "onvif",
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

    try:
        conn.settimeout(15)

        for _ in range(12):  # handle up to 12 SOAP requests per connection
            try:
                chunks = []
                conn.settimeout(8)
                while True:
                    part = conn.recv(4096)
                    if not part:
                        break
                    chunks.append(part)
                    # Stop when we have a full HTTP+SOAP body
                    combined = b"".join(chunks)
                    if (b"</SOAP-ENV:Envelope>" in combined or b"</soap:Envelope>" in combined
                            or b"</s:Envelope>" in combined or b"</env:Envelope>" in combined):
                        break
                    if len(combined) > 65536:
                        break
                data = b"".join(chunks)
            except Exception:
                break

            if not data:
                break

            req = data.decode("utf-8", errors="ignore")

            # Parse HTTP line and headers
            lines = req.replace("\r\n", "\n").split("\n")
            req_line = lines[0].strip()
            parts = req_line.split()
            method = parts[0] if parts else "POST"
            path   = parts[1] if len(parts) > 1 else "/"

            headers = {}
            for line in lines[1:]:
                if ":" in line and not line.startswith("<"):
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            user_agent = headers.get("user-agent", "")
            host_hdr   = headers.get("host", ip)
            host_ip    = host_hdr.split(":")[0]

            # ── CVE / injection detection ──────────────────────────────────
            for pat, cve_id, cve_name, sev in _CVE_PATTERNS:
                if pat.search(req):
                    if cve_id not in session["cves"]:
                        session["cves"].append(cve_id)
                    _log(f"onvif_cve_{cve_id.lower().replace('-','_')}", sev, {
                        "cve_id":       cve_id,
                        "cve_name":     cve_name,
                        "path":         path,
                        "user_agent":   user_agent,
                    })

            # ── Detect SOAP action ─────────────────────────────────────────
            action = _detect_action(req)
            session["actions"].append(action or "Unknown")

            attack_type, threat_level = _ACTION_THREAT.get(
                action, ("onvif_request", "low")
            )

            # ── Authentication ─────────────────────────────────────────────
            requires_auth = action not in _NOAUTH_ACTIONS

            username, password, nonce, created = _parse_auth(req)

            auth_ok = False
            if requires_auth:
                if username:
                    session["auth_attempts"] += 1
                    session["username"] = username

                    # Brute-force detection
                    if session["auth_attempts"] >= 5:
                        _log("onvif_brute_force", "critical", {
                            "auth_attempts": session["auth_attempts"],
                            "username":      username,
                        })

                    if _validate_creds(username, password):
                        auth_ok = True
                        session["authenticated"] = True
                        # New IP alert on first successful auth
                        if new_ip_alert and ip not in getattr(handle_onvif, "_seen", set()):
                            try:
                                if not hasattr(handle_onvif, "_seen"):
                                    handle_onvif._seen = set()
                                handle_onvif._seen.add(ip)
                                new_ip_alert(ip, "onvif")
                            except Exception:
                                pass
                    else:
                        # Log auth failure but don't return — keep connection open
                        # so attacker keeps trying (more data for us)
                        _log("onvif_auth_failed", "medium", {
                            "username":      username,
                            "action":        action,
                            "auth_attempts": session["auth_attempts"],
                            "user_agent":    user_agent,
                        })
                        fault = _soap_fault("Sender", "Authentication failure",
                                            "<ter:AuthFailed>Username or password incorrect</ter:AuthFailed>")
                        conn.sendall(_http_resp(fault, status=401))
                        continue
                else:
                    # No credentials at all
                    _log("onvif_no_auth", "low", {"action": action, "path": path})
                    fault = _soap_fault("Sender", "Authentication required")
                    conn.sendall(_http_resp(fault, status=401))
                    continue
            else:
                auth_ok = True

            # ── Generate response ──────────────────────────────────────────
            resp_body = None
            if action == "GetCapabilities":
                resp_body = _resp_capabilities(device, host_ip)
            elif action == "GetDeviceInformation":
                resp_body = _resp_device_info(device)
            elif action == "GetServices":
                resp_body = _resp_services(host_ip)
            elif action == "GetSystemDateAndTime":
                resp_body = _resp_datetime()
            elif action == "GetUsers":
                resp_body = _resp_users()
            elif action == "GetNetworkInterfaces":
                resp_body = _resp_network(host_ip)
            elif action == "GetHostname":
                resp_body = _resp_hostname(host_ip)
            elif action == "GetScopes":
                resp_body = _resp_scopes()
            elif action == "GetProfiles":
                resp_body = _resp_profiles()
            elif action == "GetStreamUri":
                resp_body = _resp_stream_uri(host_ip)
            elif action == "GetSnapshotUri":
                resp_body = _resp_snapshot_uri(host_ip)
            elif action in {"CreateUsers", "DeleteUsers", "SetUser", "SetRemoteUser"}:
                # Accept the change — let attacker think it worked
                resp_body = _soap_env(f"<tds:{action}Response/>")
            elif action in {"SystemReboot", "SetSystemFactoryDefault"}:
                resp_body = _soap_env(
                    f"<tds:{action}Response>"
                    f"<tds:Message>Rebooting...</tds:Message>"
                    f"</tds:{action}Response>"
                )
            elif action in {"StartFirmwareUpgrade", "UpgradeFirmware"}:
                # Pretend to start upgrade
                resp_body = _soap_env(
                    f"<tds:{action}Response>"
                    f"<tds:UploadUri>http://{host_ip}:8000/onvif/upgrade</tds:UploadUri>"
                    f"</tds:{action}Response>"
                )
            elif action in {"SetNetworkInterfaces", "SetDNS", "SetHostname"}:
                resp_body = _soap_env(f"<tds:{action}Response><tds:RebootNeeded>true</tds:RebootNeeded></tds:{action}Response>")
            else:
                # Fallback — return generic capabilities
                resp_body = _resp_capabilities(device, host_ip)

            if resp_body:
                conn.sendall(_http_resp(resp_body))

            # ── Log the action ─────────────────────────────────────────────
            _log(attack_type, threat_level, {
                "soap_action":   action or "Unknown",
                "path":          path,
                "method":        method,
                "user_agent":    user_agent,
                "authenticated": session["authenticated"],
                "username":      session["username"],
                "auth_attempts": session["auth_attempts"],
            })

            # Auth success log (only once per session)
            if auth_ok and username and not getattr(handle_onvif, f"_authlogged_{ip}", False):
                try:
                    setattr(handle_onvif, f"_authlogged_{ip}", True)
                except Exception:
                    pass
                _log("onvif_auth_success", "high", {
                    "username":    username,
                    "auth_nonce":  nonce or "",
                    "user_agent":  user_agent,
                })

            time.sleep(random.uniform(0.02, 0.08))

    except Exception as e:
        _log("onvif_error", "low", {"error": str(e)[:200]})
    finally:
        dur = round(time.time() - session["start"], 2)
        if session["actions"]:
            _log("onvif_session_end", "low", {
                "duration":      dur,
                "authenticated": session["authenticated"],
                "username":      session["username"],
                "auth_attempts": session["auth_attempts"],
                "actions":       ",".join(session["actions"]),
                "cves_seen":     ",".join(session["cves"]),
            })
        try:
            conn.close()
        except Exception:
            pass
