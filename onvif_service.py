import time
import random
import json
import re
import base64
import hashlib

# ═══════════════════════════════════════════════════════════════════════════
# ONVIF Honeypot - Realistic Hikvision IP Camera Simulation
# ═══════════════════════════════════════════════════════════════════════════

# Device info randomization (per session)
def _get_device_info():
    return {
        "Manufacturer": "Hikvision",
        "Model": random.choice(["DS-2CD2043G2-I", "DS-2CD2143G0-I", "DS-2CD2043G0-I"]),
        "FirmwareVersion": random.choice(["V5.5.8", "V5.6.2", "V5.7.0", "V5.7.15 build 230313"]),
        "SerialNumber": f"DS-2CD2043G2-I{random.randint(20200101, 20240313)}BBRR{random.randint(100000, 999999)}",
        "HardwareId": f"88{random.randint(10000000, 99999999)}",
    }

# Weak credentials (honeypot accepts these)
WEAK_CREDENTIALS = {
    "admin": ["12345", "admin", "password", "123456", "admin123", ""],
    "root": ["root", "12345", "password", ""],
    "user": ["user", "12345", ""],
    "service": ["service", "12345", ""],
}

# ═══════════════════════════════════════════════════════════════════════════
# SOAP Response Templates
# ═══════════════════════════════════════════════════════════════════════════

def _soap_fault(code, reason, detail=""):
    """SOAP Fault for authentication failures"""
    fault = f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
  xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding"
  xmlns:ter="http://www.onvif.org/ver10/error">
<SOAP-ENV:Body>
<SOAP-ENV:Fault>
<SOAP-ENV:Code>
<SOAP-ENV:Value>SOAP-ENV:{code}</SOAP-ENV:Value>
</SOAP-ENV:Code>
<SOAP-ENV:Reason>
<SOAP-ENV:Text xml:lang="en">{reason}</SOAP-ENV:Text>
</SOAP-ENV:Reason>
{"<SOAP-ENV:Detail>" + detail + "</SOAP-ENV:Detail>" if detail else ""}
</SOAP-ENV:Fault>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""
    return fault

def _soap_envelope(body):
    """Wrap SOAP body in envelope"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
  xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
  xmlns:tt="http://www.onvif.org/ver10/schema"
  xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
<SOAP-ENV:Body>
{body}
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""

def _http_response(body, status_code=200, content_type="application/soap+xml"):
    """Build HTTP response"""
    status_text = {200: "OK", 401: "Unauthorized", 500: "Internal Server Error"}.get(status_code, "OK")
    return (
        f"HTTP/1.1 {status_code} {status_text}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body.encode())}\r\n"
        f"Server: Hikvision ONVIF/2.0\r\n"
        f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n"
        f"Connection: close\r\n\r\n"
        f"{body}"
    ).encode()

# ═══════════════════════════════════════════════════════════════════════════
# Authentication Parsing (WS-Security UsernameToken)
# ═══════════════════════════════════════════════════════════════════════════

def _parse_auth(soap_request):
    """Extract username/password from SOAP WS-Security header"""
    username = None
    password = None
    
    # Extract Username
    username_match = re.search(r'<wsse:Username>([^<]+)</wsse:Username>', soap_request, re.I)
    if username_match:
        username = username_match.group(1)
    
    # Extract Password (plaintext or digest)
    password_match = re.search(r'<wsse:Password[^>]*>([^<]+)</wsse:Password>', soap_request, re.I)
    if password_match:
        password = password_match.group(1)
    
    return username, password

def _validate_credentials(username, password):
    """Check if credentials are in weak credentials list"""
    if not username or not password:
        return False
    
    # Check against weak credentials
    if username in WEAK_CREDENTIALS:
        if password in WEAK_CREDENTIALS[username]:
            return True
    
    # Honeypot behavior: accept any password that looks like a hash (32+ chars)
    # This catches attackers using digest auth
    if len(password) >= 32:
        return True
    
    return False

# ═══════════════════════════════════════════════════════════════════════════
# SOAP Action Handlers
# ═══════════════════════════════════════════════════════════════════════════

def _handle_get_capabilities(device_info, host_ip):
    """GetCapabilities - Returns camera capabilities"""
    body = f"""<tds:GetCapabilitiesResponse>
<tds:Capabilities>
<tt:Analytics>
<tt:XAddr>http://{host_ip}:8000/onvif/analytics</tt:XAddr>
<tt:RuleSupport>true</tt:RuleSupport>
<tt:AnalyticsModuleSupport>true</tt:AnalyticsModuleSupport>
</tt:Analytics>
<tt:Device>
<tt:XAddr>http://{host_ip}:8000/onvif/device_service</tt:XAddr>
<tt:Network>
<tt:IPFilter>false</tt:IPFilter>
<tt:ZeroConfiguration>true</tt:ZeroConfiguration>
<tt:IPVersion6>true</tt:IPVersion6>
<tt:DynDNS>true</tt:DynDNS>
</tt:Network>
<tt:System>
<tt:DiscoveryResolve>true</tt:DiscoveryResolve>
<tt:DiscoveryBye>true</tt:DiscoveryBye>
<tt:RemoteDiscovery>true</tt:RemoteDiscovery>
<tt:SystemBackup>true</tt:SystemBackup>
<tt:SystemLogging>true</tt:SystemLogging>
<tt:FirmwareUpgrade>true</tt:FirmwareUpgrade>
</tt:System>
<tt:Security>
<tt:TLS1.1>false</tt:TLS1.1>
<tt:TLS1.2>true</tt:TLS1.2>
<tt:OnboardKeyGeneration>true</tt:OnboardKeyGeneration>
<tt:AccessPolicyConfig>true</tt:AccessPolicyConfig>
</tt:Security>
</tt:Device>
<tt:Events>
<tt:XAddr>http://{host_ip}:8000/onvif/event</tt:XAddr>
<tt:WSSubscriptionPolicySupport>true</tt:WSSubscriptionPolicySupport>
<tt:WSPullPointSupport>true</tt:WSPullPointSupport>
</tt:Events>
<tt:Imaging>
<tt:XAddr>http://{host_ip}:8000/onvif/imaging</tt:XAddr>
</tt:Imaging>
<tt:Media>
<tt:XAddr>http://{host_ip}:8000/onvif/media</tt:XAddr>
<tt:StreamingCapabilities>
<tt:RTPMulticast>false</tt:RTPMulticast>
<tt:RTP_TCP>true</tt:RTP_TCP>
<tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>
</tt:StreamingCapabilities>
</tt:Media>
</tds:Capabilities>
</tds:GetCapabilitiesResponse>"""
    return _soap_envelope(body)

def _handle_get_device_information(device_info):
    """GetDeviceInformation - Returns device details"""
    body = f"""<tds:GetDeviceInformationResponse>
<tds:Manufacturer>{device_info['Manufacturer']}</tds:Manufacturer>
<tds:Model>{device_info['Model']}</tds:Model>
<tds:FirmwareVersion>{device_info['FirmwareVersion']}</tds:FirmwareVersion>
<tds:SerialNumber>{device_info['SerialNumber']}</tds:SerialNumber>
<tds:HardwareId>{device_info['HardwareId']}</tds:HardwareId>
</tds:GetDeviceInformationResponse>"""
    return _soap_envelope(body)

def _handle_get_services():
    """GetServices - Returns available ONVIF services"""
    body = """<tds:GetServicesResponse>
<tds:Service>
<tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace>
<tds:XAddr>http://192.168.1.108:8000/onvif/device_service</tds:XAddr>
<tds:Version>
<tt:Major>2</tt:Major>
<tt:Minor>5</tt:Minor>
</tds:Version>
</tds:Service>
<tds:Service>
<tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>
<tds:XAddr>http://192.168.1.108:8000/onvif/media</tds:XAddr>
<tds:Version>
<tt:Major>2</tt:Major>
<tt:Minor>6</tt:Minor>
</tds:Version>
</tds:Service>
<tds:Service>
<tds:Namespace>http://www.onvif.org/ver20/imaging/wsdl</tds:Namespace>
<tds:XAddr>http://192.168.1.108:8000/onvif/imaging</tds:XAddr>
<tds:Version>
<tt:Major>2</tt:Major>
<tt:Minor>0</tt:Minor>
</tds:Version>
</tds:Service>
</tds:GetServicesResponse>"""
    return _soap_envelope(body)

def _handle_get_system_date_time():
    """GetSystemDateAndTime - Returns camera time (no auth required)"""
    now = time.gmtime()
    body = f"""<tds:GetSystemDateAndTimeResponse>
<tds:SystemDateAndTime>
<tt:DateTimeType>NTP</tt:DateTimeType>
<tt:DaylightSavings>false</tt:DaylightSavings>
<tt:TimeZone>
<tt:TZ>GMT+0</tt:TZ>
</tt:TimeZone>
<tt:UTCDateTime>
<tt:Time>
<tt:Hour>{now.tm_hour}</tt:Hour>
<tt:Minute>{now.tm_min}</tt:Minute>
<tt:Second>{now.tm_sec}</tt:Second>
</tt:Time>
<tt:Date>
<tt:Year>{now.tm_year}</tt:Year>
<tt:Month>{now.tm_mon}</tt:Month>
<tt:Day>{now.tm_mday}</tt:Day>
</tt:Date>
</tt:UTCDateTime>
</tds:SystemDateAndTime>
</tds:GetSystemDateAndTimeResponse>"""
    return _soap_envelope(body)

def _handle_get_users():
    """GetUsers - Returns configured users"""
    body = """<tds:GetUsersResponse>
<tds:User>
<tt:Username>admin</tt:Username>
<tt:UserLevel>Administrator</tt:UserLevel>
</tds:User>
<tds:User>
<tt:Username>user</tt:Username>
<tt:UserLevel>Operator</tt:UserLevel>
</tds:User>
</tds:GetUsersResponse>"""
    return _soap_envelope(body)

def _handle_get_network_interfaces():
    """GetNetworkInterfaces - Returns network config"""
    body = f"""<tds:GetNetworkInterfacesResponse>
<tds:NetworkInterfaces token="eth0">
<tt:Enabled>true</tt:Enabled>
<tt:Info>
<tt:Name>eth0</tt:Name>
<tt:HwAddress>44:19:B6:7A:2C:D9</tt:HwAddress>
<tt:MTU>1500</tt:MTU>
</tt:Info>
<tt:IPv4>
<tt:Enabled>true</tt:Enabled>
<tt:Config>
<tt:Manual>
<tt:Address>192.168.1.108</tt:Address>
<tt:PrefixLength>24</tt:PrefixLength>
</tt:Manual>
<tt:DHCP>false</tt:DHCP>
</tt:Config>
</tt:IPv4>
</tds:NetworkInterfaces>
</tds:GetNetworkInterfacesResponse>"""
    return _soap_envelope(body)

def _handle_get_profiles():
    """GetProfiles - Returns media profiles (stream configurations)"""
    body = """<trt:GetProfilesResponse>
<trt:Profiles token="Profile_1" fixed="true">
<tt:Name>MainStream</tt:Name>
<tt:VideoSourceConfiguration token="VideoSource_1">
<tt:Name>VideoSource_1</tt:Name>
<tt:SourceToken>VideoSource_1</tt:SourceToken>
<tt:Bounds x="0" y="0" width="2688" height="1520"/>
</tt:VideoSourceConfiguration>
<tt:VideoEncoderConfiguration token="VideoEncoder_1">
<tt:Name>VideoEncoder_1</tt:Name>
<tt:Encoding>H264</tt:Encoding>
<tt:Resolution>
<tt:Width>2688</tt:Width>
<tt:Height>1520</tt:Height>
</tt:Resolution>
<tt:Quality>4</tt:Quality>
<tt:RateControl>
<tt:FrameRateLimit>25</tt:FrameRateLimit>
<tt:EncodingInterval>1</tt:EncodingInterval>
<tt:BitrateLimit>4096</tt:BitrateLimit>
</tt:RateControl>
<tt:H264>
<tt:GovLength>50</tt:GovLength>
<tt:H264Profile>High</tt:H264Profile>
</tt:H264>
</tt:VideoEncoderConfiguration>
</trt:Profiles>
<trt:Profiles token="Profile_2" fixed="true">
<tt:Name>SubStream</tt:Name>
<tt:VideoEncoderConfiguration token="VideoEncoder_2">
<tt:Name>VideoEncoder_2</tt:Name>
<tt:Encoding>H264</tt:Encoding>
<tt:Resolution>
<tt:Width>704</tt:Width>
<tt:Height>576</tt:Height>
</tt:Resolution>
<tt:Quality>3</tt:Quality>
<tt:RateControl>
<tt:FrameRateLimit>25</tt:FrameRateLimit>
<tt:BitrateLimit>512</tt:BitrateLimit>
</tt:RateControl>
</tt:VideoEncoderConfiguration>
</trt:Profiles>
</trt:GetProfilesResponse>"""
    return _soap_envelope(body)

def _handle_get_stream_uri():
    """GetStreamUri - Returns RTSP stream URL (what attackers want!)"""
    body = f"""<trt:GetStreamUriResponse>
<trt:MediaUri>
<tt:Uri>rtsp://192.168.1.108:554/Streaming/Channels/101</tt:Uri>
<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
<tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
<tt:Timeout>PT60S</tt:Timeout>
</trt:MediaUri>
</trt:GetStreamUriResponse>"""
    return _soap_envelope(body)

def _handle_get_snapshot_uri():
    """GetSnapshotUri - Returns snapshot image URL"""
    body = """<trt:GetSnapshotUriResponse>
<trt:MediaUri>
<tt:Uri>http://192.168.1.108:80/ISAPI/Streaming/channels/101/picture</tt:Uri>
<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
<tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
<tt:Timeout>PT5S</tt:Timeout>
</trt:MediaUri>
</trt:GetSnapshotUriResponse>"""
    return _soap_envelope(body)

# ═══════════════════════════════════════════════════════════════════════════
# Main ONVIF Handler
# ═══════════════════════════════════════════════════════════════════════════

def handle_onvif(conn, addr, log_attack=None, geoip_func=None, intel_fields_func=None, new_ip_alert=None):
    """
    Realistic ONVIF honeypot handler
    Simulates Hikvision IP camera ONVIF interface
    """
    ip, port = addr
    device_info = _get_device_info()
    
    # Session tracking
    session = {
        "authenticated": False,
        "username": "",
        "auth_attempts": 0,
        "actions_called": [],
        "start_time": time.time(),
    }
    
    try:
        conn.settimeout(15)
        data = conn.recv(16384)
        if not data:
            return
        
        req = data.decode(errors="ignore")
        
        # Extract HTTP headers
        lines = req.split("\n")
        req_line = lines[0].strip() if lines else ""
        method = req_line.split()[0] if req_line.split() else "POST"
        path = req_line.split()[1] if len(req_line.split()) > 1 else "/"
        
        # Extract User-Agent
        user_agent = ""
        for line in lines:
            if line.lower().startswith("user-agent:"):
                user_agent = line.split(":", 1)[1].strip()
                break
        
        # Determine host IP for responses
        host_ip = "192.168.1.108"  # Default
        for line in lines:
            if line.lower().startswith("host:"):
                host_header = line.split(":", 1)[1].strip()
                host_ip = host_header.split(":")[0] if ":" in host_header else host_header
                break
        
        # Parse SOAP action
        soap_action = ""
        action_patterns = [
            "GetCapabilities", "GetDeviceInformation", "GetServices",
            "GetSystemDateAndTime", "GetUsers", "CreateUsers", "DeleteUsers",
            "SetUser", "GetNetworkInterfaces", "GetHostname", "GetScopes",
            "GetProfiles", "GetStreamUri", "GetSnapshotUri", "GetVideoSources",
            "GetVideoEncoderConfigurations", "GetVideoSourceConfigurations",
            "GetMetadataConfigurations", "GetAudioEncoderConfigurations",
            "SystemReboot", "SetSystemFactoryDefault",
        ]
        for action in action_patterns:
            if action in req:
                soap_action = action
                break
        
        session["actions_called"].append(soap_action or "Unknown")
        
        # ═══════════════════════════════════════════════════════════════════
        # AUTHENTICATION CHECK
        # ═══════════════════════════════════════════════════════════════════
        
        # GetSystemDateAndTime doesn't require auth (per ONVIF spec)
        requires_auth = soap_action not in ["GetSystemDateAndTime", ""]
        
        username, password = _parse_auth(req)
        
        if requires_auth:
            if username and password:
                session["auth_attempts"] += 1
                session["username"] = username
                
                if _validate_credentials(username, password):
                    session["authenticated"] = True
                    
                    # Log successful authentication
                    if log_attack:
                        log_attack(ip, 8000, "ONVIF_AUTH_SUCCESS", json.dumps({
                            "username": username,
                            "action": soap_action,
                            "attempts": session["auth_attempts"],
                        }))
                else:
                    # Authentication failed
                    if log_attack:
                        log_attack(ip, 8000, "ONVIF_AUTH_FAILED", json.dumps({
                            "username": username,
                            "action": soap_action,
                            "attempts": session["auth_attempts"],
                        }))
                    
                    # Return SOAP Fault
                    fault = _soap_fault("Sender", "Authentication failure", 
                                       "<ter:AuthFailed>Username or password incorrect</ter:AuthFailed>")
                    conn.sendall(_http_response(fault, status_code=401))
                    return
            else:
                # No credentials provided
                if log_attack:
                    log_attack(ip, 8000, "ONVIF_NO_AUTH", json.dumps({
                        "action": soap_action,
                    }))
                
                fault = _soap_fault("Sender", "Authentication required")
                conn.sendall(_http_response(fault, status_code=401))
                return
        
        # ═══════════════════════════════════════════════════════════════════
        # HANDLE SOAP ACTION
        # ═══════════════════════════════════════════════════════════════════
        
        response_body = None
        
        if soap_action == "GetCapabilities":
            response_body = _handle_get_capabilities(device_info, host_ip)
        
        elif soap_action == "GetDeviceInformation":
            response_body = _handle_get_device_information(device_info)
        
        elif soap_action == "GetServices":
            response_body = _handle_get_services()
        
        elif soap_action == "GetSystemDateAndTime":
            response_body = _handle_get_system_date_time()
        
        elif soap_action == "GetUsers":
            response_body = _handle_get_users()
        
        elif soap_action == "GetNetworkInterfaces":
            response_body = _handle_get_network_interfaces()
        
        elif soap_action == "GetProfiles":
            response_body = _handle_get_profiles()
        
        elif soap_action == "GetStreamUri":
            # This is what attackers want — RTSP stream URL!
            response_body = _handle_get_stream_uri()
            if log_attack:
                log_attack(ip, 8000, "ONVIF_STREAM_REQUEST", json.dumps({
                    "action": "GetStreamUri",
                    "username": session.get("username", ""),
                    "threat_level": "high",
                }))
        
        elif soap_action == "GetSnapshotUri":
            response_body = _handle_get_snapshot_uri()
        
        elif soap_action in ["CreateUsers", "DeleteUsers", "SetUser"]:
            # User management — potential exploitation
            if log_attack:
                log_attack(ip, 8000, "ONVIF_USER_MGMT", json.dumps({
                    "action": soap_action,
                    "username": session.get("username", ""),
                    "threat_level": "critical",
                }))
            response_body = _soap_envelope(f"<tds:{soap_action}Response/>")
        
        elif soap_action in ["SystemReboot", "SetSystemFactoryDefault"]:
            # System manipulation
            if log_attack:
                log_attack(ip, 8000, "ONVIF_SYSTEM_CHANGE", json.dumps({
                    "action": soap_action,
                    "threat_level": "critical",
                }))
            response_body = _soap_envelope(f"<tds:{soap_action}Response><tds:Message>OK</tds:Message></tds:{soap_action}Response>")
        
        else:
            # Unknown action — respond with GetCapabilities as fallback
            response_body = _handle_get_capabilities(device_info, host_ip)
        
        # Send response
        if response_body:
            conn.sendall(_http_response(response_body))
        
        # General logging
        if log_attack:
            log_attack(ip, 8000, f"ONVIF_{soap_action or 'Unknown'}", json.dumps({
                "action": soap_action or "Unknown",
                "path": path,
                "user_agent": user_agent,
                "authenticated": session["authenticated"],
                "username": session.get("username", ""),
                "method": method,
            }))
        
        # Simulate device processing delay
        time.sleep(random.uniform(0.05, 0.15))
        
    except Exception as e:
        # Log errors
        if log_attack:
            log_attack(ip, 8000, "ONVIF_ERROR", json.dumps({"error": str(e)}))
    
    finally:
        # Session complete logging
        if log_attack and session["actions_called"]:
            session_duration = time.time() - session["start_time"]
            log_attack(ip, 8000, "ONVIF_SESSION_END", json.dumps({
                "duration": round(session_duration, 2),
                "authenticated": session["authenticated"],
                "username": session.get("username", ""),
                "auth_attempts": session["auth_attempts"],
                "actions": ",".join(session["actions_called"]),
            }))
        
        try:
            conn.close()
        except Exception:
            pass