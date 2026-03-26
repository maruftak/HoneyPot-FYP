#!/usr/bin/env python3
"""
tr069_service.py — TR-069 / CWMP ISP router management honeypot (port 7547)

TR-069 (CWMP) is the protocol ISPs use to manage CPE (routers, modems, set-top boxes).
Port 7547 on the CPE listens for the ACS (ISP's server) to connect and push config.

Targeted by:
  - Mirai 'Aidra' variant — NewNTPServer SOAP injection → RCE
    Took down ~900,000 Deutsche Telekom routers in Nov 2016
  - Mirai 'Wifatch' variant
  - CVE-2014-8244 (Linksys TR-064 RCE)
  - Generic CWMP scanners probing for open management ports
  - Masscan/Shodan crawlers that re-distribute the IP as a vulnerable CPE target

Attack pattern: attacker sends SOAP SetParameterValues with:
  NewNTPServer = "$(shell command)"  ← classic Mirai injection
  or uploads a fake firmware via TransferComplete / Download

This honeypot accepts SOAP requests, logs payloads, and returns
realistic CWMP responses to keep the scanner engaged.
"""

import socket
import re
import random
import datetime

_DEVICE_OUI        = "00259E"
_DEVICE_SERIAL     = "CP0611JTLNW0123"
_DEVICE_MODEL      = "DSL-2750B"
_DEVICE_VENDOR     = "D-Link"
_FIRMWARE_VERSION  = "1.06"
_SPEC_VERSION      = "1.0"
_CWMP_VERSION      = "1-0"

_SOAP_NS = (
    'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:cwmp="urn:dslforum-org:cwmp-1-0" '
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
)


def _ts():
    return datetime.datetime.utcnow().isoformat()


def _cwmp_date():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _inform_response():
    """CWMP InformResponse — sent after device reports in."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        f'<soap:Envelope {_SOAP_NS}>\r\n'
        '<soap:Header>\r\n'
        '  <cwmp:ID soap:mustUnderstand="1">1</cwmp:ID>\r\n'
        '</soap:Header>\r\n'
        '<soap:Body>\r\n'
        '  <cwmp:InformResponse>\r\n'
        '    <MaxEnvelopes>1</MaxEnvelopes>\r\n'
        '  </cwmp:InformResponse>\r\n'
        '</soap:Body>\r\n'
        '</soap:Envelope>\r\n'
    )


def _get_param_values_response(params: dict):
    """Response to GetParameterValues."""
    values_xml = ""
    for name, val in params.items():
        values_xml += (
            f'    <ParameterValueStruct>\r\n'
            f'      <Name>{name}</Name>\r\n'
            f'      <Value xsi:type="xsd:string">{val}</Value>\r\n'
            f'    </ParameterValueStruct>\r\n'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        f'<soap:Envelope {_SOAP_NS}>\r\n'
        '<soap:Header><cwmp:ID soap:mustUnderstand="1">2</cwmp:ID></soap:Header>\r\n'
        '<soap:Body>\r\n'
        '  <cwmp:GetParameterValuesResponse>\r\n'
        '    <ParameterList soap:arrayType="cwmp:ParameterValueStruct[{count}]">\r\n'
        f'{values_xml}'
        '    </ParameterList>\r\n'
        '  </cwmp:GetParameterValuesResponse>\r\n'
        '</soap:Body>\r\n'
        '</soap:Envelope>\r\n'
    ).replace("{count}", str(len(params)))


def _set_param_response():
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        f'<soap:Envelope {_SOAP_NS}>\r\n'
        '<soap:Header><cwmp:ID soap:mustUnderstand="1">3</cwmp:ID></soap:Header>\r\n'
        '<soap:Body>\r\n'
        '  <cwmp:SetParameterValuesResponse>\r\n'
        '    <Status>0</Status>\r\n'
        '  </cwmp:SetParameterValuesResponse>\r\n'
        '</soap:Body>\r\n'
        '</soap:Envelope>\r\n'
    )


def _download_response():
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        f'<soap:Envelope {_SOAP_NS}>\r\n'
        '<soap:Header><cwmp:ID soap:mustUnderstand="1">4</cwmp:ID></soap:Header>\r\n'
        '<soap:Body>\r\n'
        '  <cwmp:DownloadResponse>\r\n'
        '    <Status>1</Status>\r\n'
        f'    <StartTime>{_cwmp_date()}</StartTime>\r\n'
        f'    <CompleteTime>{_cwmp_date()}</CompleteTime>\r\n'
        '  </cwmp:DownloadResponse>\r\n'
        '</soap:Body>\r\n'
        '</soap:Envelope>\r\n'
    )


def _fault_response(code="9007", detail="Upload failed"):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        f'<soap:Envelope {_SOAP_NS}>\r\n'
        '<soap:Header><cwmp:ID soap:mustUnderstand="1">0</cwmp:ID></soap:Header>\r\n'
        '<soap:Body>\r\n'
        '  <soap:Fault>\r\n'
        '    <faultcode>Client</faultcode>\r\n'
        '    <faultstring>CWMP fault</faultstring>\r\n'
        '    <detail>\r\n'
        '      <cwmp:Fault>\r\n'
        f'        <FaultCode>{code}</FaultCode>\r\n'
        f'        <FaultString>{detail}</FaultString>\r\n'
        '      </cwmp:Fault>\r\n'
        '    </detail>\r\n'
        '  </soap:Fault>\r\n'
        '</soap:Body>\r\n'
        '</soap:Envelope>\r\n'
    )


def _http_response(status_line, body, extra_headers=""):
    body_bytes = body.encode() if isinstance(body, str) else body
    headers = (
        f"HTTP/1.1 {status_line}\r\n"
        f"Content-Type: text/xml; charset=\"utf-8\"\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: keep-alive\r\n"
        f"Server: mini_httpd/1.19 19dec2003\r\n"
        + extra_headers +
        "\r\n"
    )
    return headers.encode() + body_bytes


# Realistic router parameter values exposed via CWMP
_DEVICE_PARAMS = {
    "InternetGatewayDevice.DeviceInfo.Manufacturer":        _DEVICE_VENDOR,
    "InternetGatewayDevice.DeviceInfo.ModelName":           _DEVICE_MODEL,
    "InternetGatewayDevice.DeviceInfo.SerialNumber":        _DEVICE_SERIAL,
    "InternetGatewayDevice.DeviceInfo.SoftwareVersion":     _FIRMWARE_VERSION,
    "InternetGatewayDevice.DeviceInfo.HardwareVersion":     "T1_1.0",
    "InternetGatewayDevice.DeviceInfo.UpTime":              str(random.randint(86400, 864000)),
    "InternetGatewayDevice.ManagementServer.URL":           "http://acs.isp.example.com:7547/acs",
    "InternetGatewayDevice.ManagementServer.Username":      "admin",
    "InternetGatewayDevice.ManagementServer.Password":      "admin",
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress":
        f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.DefaultGateway":
        "10.0.0.1",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID":
        f"D-Link_{random.randint(1000,9999)}",
    "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase":
        "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=10)),
    "InternetGatewayDevice.Time.NTPServer1":                "time.nist.gov",
    "InternetGatewayDevice.Time.NTPServer2":                "pool.ntp.org",
}


def handle_tr069(conn, addr, log_attack=None, geoip_func=None,
                 intel_fields_func=None, new_ip_alert=None, inc_counter=None):
    ip, src_port = addr
    gdata   = geoip_func(ip) if geoip_func else {}
    country = gdata.get("country", "Unknown")
    city    = gdata.get("city", "")

    def _log(attack_type, threat="medium", extra=None):
        if not log_attack:
            return
        entry = {
            "timestamp":    _ts(),
            "source_ip":    ip,
            "source_port":  src_port,
            "dest_port":    7547,
            "service":      "tr069",
            "protocol":     "TCP",
            "attack_type":  attack_type,
            "threat_level": threat,
            "country":      country,
            "city":         city,
            "latitude":     gdata.get("latitude", 0.0),
            "longitude":    gdata.get("longitude", 0.0),
        }
        if intel_fields_func:
            entry.update(intel_fields_func(gdata))
        if extra:
            entry.update(extra)
        try:
            log_attack(entry)
        except Exception:
            pass

    if new_ip_alert:
        try:
            new_ip_alert(ip, country, city, "tr069")
        except Exception:
            pass
    if inc_counter:
        try:
            inc_counter("sessions")
        except Exception:
            pass

    _log("tr069_connect", "low")

    try:
        conn.settimeout(20)

        while True:
            try:
                raw = conn.recv(16384)
            except socket.timeout:
                break
            if not raw:
                break

            text = raw.decode(errors="ignore")

            # Parse HTTP request line
            lines  = text.split("\n")
            req_ln = lines[0].strip().split()
            method = req_ln[0] if req_ln else "POST"
            path   = req_ln[1] if len(req_ln) > 1 else "/"

            # Empty POST — ACS acknowledging end of session
            if method == "POST" and len(raw) < 150:
                conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                break

            # ── Detect attack type from SOAP payload ─────────────────────

            # Mirai NewNTPServer / SetNTPServer injection
            ntp_match = re.search(
                r"NTPServer[12]?[^>]*>\s*([^\s<]{5,200})", text, re.IGNORECASE
            )
            if ntp_match and (";" in ntp_match.group(1) or "$(" in ntp_match.group(1)
                               or "`" in ntp_match.group(1) or "wget" in ntp_match.group(1).lower()
                               or "curl" in ntp_match.group(1).lower()):
                _log("tr069_mirai_ntp_injection", "critical", {
                    "notes": "CVE NewNTPServer command injection — Mirai Aidra variant",
                    "payload": ntp_match.group(1)[:200],
                })
            elif ntp_match:
                _log("tr069_ntp_set", "medium", {"ntp_value": ntp_match.group(1)[:80]})

            # Download / firmware push
            if re.search(r"<cwmp:Download|<Download>", text, re.IGNORECASE):
                url_m = re.search(r"<URL>(.*?)</URL>", text, re.IGNORECASE | re.DOTALL)
                url   = url_m.group(1).strip() if url_m else ""
                _log("tr069_firmware_download", "critical", {
                    "notes": "Firmware download — possible malicious firmware push",
                    "url":   url[:200],
                })
                conn.sendall(_http_response("200 OK", _download_response()))
                continue

            # GetParameterValues
            if re.search(r"<cwmp:GetParameterValues|GetParameterValues>", text, re.IGNORECASE):
                # Find which params requested
                names = re.findall(r"<Name>(.*?)</Name>", text, re.IGNORECASE | re.DOTALL)
                names = [n.strip() for n in names]
                params = {}
                for n in names:
                    if n in _DEVICE_PARAMS:
                        params[n] = _DEVICE_PARAMS[n]
                    else:
                        # Return a plausible empty value
                        params[n] = ""
                if not params:
                    params = _DEVICE_PARAMS
                conn.sendall(_http_response("200 OK", _get_param_values_response(params)))
                _log("tr069_get_params", "medium", {
                    "params": ",".join(names[:10]),
                })
                continue

            # SetParameterValues
            if re.search(r"<cwmp:SetParameterValues|SetParameterValues>", text, re.IGNORECASE):
                # Extract all set values
                pairs = re.findall(
                    r"<Name>(.*?)</Name>\s*<Value[^>]*>(.*?)</Value>",
                    text, re.IGNORECASE | re.DOTALL
                )
                payload_summary = "; ".join(f"{n}={v[:40]}" for n, v in pairs[:10])
                threat = "critical" if any(
                    kw in text.lower() for kw in ["wget", "curl", "$(", "`;", "shell", "passwd", "shadow"]
                ) else "high"
                conn.sendall(_http_response("200 OK", _set_param_response()))
                _log("tr069_set_params", threat, {
                    "notes": "SetParameterValues — possible config manipulation or command injection",
                    "payload": payload_summary[:300],
                })
                continue

            # Inform (device check-in) — attacker spoofing a CPE
            if re.search(r"<cwmp:Inform|<Inform>", text, re.IGNORECASE):
                conn.sendall(_http_response("200 OK", _inform_response()))
                _log("tr069_inform", "low")
                continue

            # Generic POST — return InformResponse to keep scanner engaged
            if method in ("GET", "POST"):
                conn.sendall(_http_response("200 OK", _inform_response()))
                _log("tr069_generic_probe", "low", {"path": path})
                continue

            break

    except (ConnectionResetError, BrokenPipeError, socket.timeout):
        pass
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
