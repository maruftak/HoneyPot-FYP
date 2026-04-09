#!/usr/bin/env python3
"""
honeyPot — HTTP/HTTPS Service Module
Realistic Hikvision DS-2CD2043G2-I web interface emulation.
Handles ports 80, 443, 8080.

Import and call handle_http() from honeypot.py.
"""

import json
import re
import random
import socket
import config

# ─── Hikvision firmware colour palette ────────────────────────────────────────
HIK_CSS = """
  :root {
    --hik-blue:      #1b5ca8;
    --hik-blue-dark: #134a8a;
    --hik-blue-lt:   #2471c8;
    --hik-red:       #d9251d;
    --hik-grey-bg:   #e8eaec;
    --hik-grey-mid:  #c5c8cc;
    --hik-grey-bdr:  #a8aaad;
    --hik-white:     #ffffff;
    --hik-text:      #333333;
    --hik-text-mid:  #666666;
    --hik-text-lt:   #999999;
    --hik-panel:     #f4f5f6;
    --hik-shadow:    rgba(0,0,0,0.18);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Arial', 'Helvetica Neue', sans-serif;
    font-size: 13px;
    color: var(--hik-text);
    background: var(--hik-grey-bg);
    min-height: 100vh;
  }
"""

# ─── Server header pool (randomised per request) ──────────────────────────────
_SERVER_HEADERS = [
    "App-webs/",
    "GoAhead-Webs",
    "Boa/0.94.14rc21",
    "Boa/0.93.15",
    "GoAhead-Webs/2.5.0",
]

# ─── Decoy download files ─────────────────────────────────────────────────────
# Served as realistic fake content; every download is logged as a honeytoken hit.
# Format: path → (content_type, download_filename, body_bytes)

# Fake MIPS 32-bit big-endian ELF (Hikvision camera firmware style)
_FAKE_FIRMWARE_BIN = (
    b'\x7fELF'              # ELF magic
    + b'\x01'               # 32-bit
    + b'\x02'               # big-endian
    + b'\x01'               # version 1
    + b'\x00' * 9           # padding / OS ABI
    + b'\x00\x02'           # ET_EXEC
    + b'\x00\x08'           # EM_MIPS
    + b'\x00\x00\x00\x01'   # ELF version
    + b'\x80\x00\x10\x00'   # entry point
    + b'\x00\x00\x00\x34'   # phoff
    + b'\x00\x1f\x80\x00'   # shoff (placeholder)
    + b'\x30\x00\x10\x00'   # flags (MIPS)
    + b'\x00\x34'           # ehsize
    + b'\x00\x20'           # phentsize
    + b'\x00\x03'           # phnum
    + b'\x00\x28'           # shentsize
    + b'\x00\x0e'           # shnum
    + b'\x00\x0d'           # shstrndx
    + b'\x00\x01\x00\x01' * 512
    + b'DS-2CD2043G2-I\x00'
    + b'V5.7.15 build 230313\x00'
    + b'Hikvision\x00'
    + b'\x00' * 2048
)

# Minimal gzip stream containing a fake config XML (FNAME field gives filename hint)
_FAKE_CONFIG_GZ = (
    b'\x1f\x8b'             # gzip magic
    + b'\x08'               # deflate
    + b'\x08'               # FNAME flag
    + b'\x00' * 4           # mtime
    + b'\x00'               # XFL
    + b'\x03'               # OS = Unix
    + b'config.xml\x00'     # original filename
    + b'\x01'               # deflate stored block, BFINAL=1
    + b'\x00' * 4           # LEN/NLEN placeholder
    + b'<?xml version="1.0"?><Config><version>5.7.15</version></Config>'
    + b'\x00' * 4           # CRC32 + ISIZE placeholder
)

_FAKE_PASSWD = (
    b"root:x:0:0:root:/root:/bin/sh\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    b"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    b"admin:x:1000:1000:Administrator:/home/admin:/bin/sh\n"
    b"user:x:1001:1001:User:/home/user:/bin/sh\n"
    b"guest:x:1002:1002:Guest:/home/guest:/bin/sh\n"
    b"ftp:x:33:33:FTP daemon:/var/ftp:/usr/sbin/nologin\n"
    b"sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin\n"
    b"hikvision:x:500:500:Hikvision:/home/hikvision:/bin/sh\n"
)

_FAKE_SYSTEM_CFG = (
    b"# DS-2CD2043G2-I System Configuration\n"
    b"# Generated: 2024-11-01 08:32:15\n"
    b"[system]\n"
    b"hostname=IPCamera\n"
    b"model=DS-2CD2043G2-I\n"
    b"firmware=V5.7.15\n"
    b"serial=DS-2CD2043G2-I20230313CCCH012345678\n"
    b"[network]\n"
    b"ip=192.168.1.108\n"
    b"mask=255.255.255.0\n"
    b"gateway=192.168.1.1\n"
    b"dns=8.8.8.8\n"
    b"[auth]\n"
    b"admin_user=admin\n"
    b"admin_pass=Admin@2024!\n"
    b"[rtsp]\n"
    b"port=554\n"
    b"path=/Streaming/Channels/101\n"
)

_FAKE_NVRAM_CFG = (
    b"wan_ipaddr=98.90.248.178\n"
    b"wan_gateway=98.90.248.1\n"
    b"wan_netmask=255.255.255.0\n"
    b"lan_ipaddr=192.168.1.1\n"
    b"lan_netmask=255.255.255.0\n"
    b"http_passwd=Admin@2024!\n"
    b"http_username=admin\n"
    b"model=DS-2CD2043G2-I\n"
    b"firmware_version=V5.7.15\n"
    b"uptime=1382945\n"
)

_FAKE_PROC_VERSION = (
    b"Linux version 3.10.0-862 (gcc version 4.9.3) "
    b"#1 SMP Thu Nov  1 08:32:15 UTC 2023\n"
)

_FAKE_ISAPI_CONFIG = b"""<?xml version="1.0" encoding="UTF-8"?>
<Configuration version="2.0">
  <System>
    <deviceName>IPCamera</deviceName>
    <model>DS-2CD2043G2-I</model>
    <firmwareVersion>V5.7.15 build 230313</firmwareVersion>
    <serialNumber>DS-2CD2043G2-I20230313CCCH012345678</serialNumber>
  </System>
  <Network>
    <ipAddress>192.168.1.108</ipAddress>
    <subnetMask>255.255.255.0</subnetMask>
    <defaultGateway>192.168.1.1</defaultGateway>
    <primaryDNS>8.8.8.8</primaryDNS>
    <httpPort>80</httpPort>
    <httpsPort>443</httpsPort>
    <rtspPort>554</rtspPort>
  </Network>
  <Security>
    <UserList>
      <User id="1">
        <userName>admin</userName>
        <password>Admin@2024!</password>
        <userLevel>Administrator</userLevel>
      </User>
      <User id="2">
        <userName>operator</userName>
        <password>Camera123</password>
        <userLevel>Operator</userLevel>
      </User>
    </UserList>
  </Security>
  <RTSP>
    <streamURL>rtsp://192.168.1.108:554/Streaming/Channels/101</streamURL>
    <authMode>digest</authMode>
  </RTSP>
</Configuration>"""

# Minimal JPEG — 1×1 pixel grey JFIF image (valid, opens in any viewer)
_FAKE_SNAPSHOT_JPG = (
    b'\xff\xd8\xff\xe0'         # SOI + APP0 marker
    + b'\x00\x10'               # APP0 length
    + b'JFIF\x00'               # identifier
    + b'\x01\x01'               # version 1.1
    + b'\x00'                   # aspect ratio units (0=no units)
    + b'\x00\x01\x00\x01'       # X/Y density = 1
    + b'\x00\x00'               # thumbnail size = 0
    + b'\xff\xdb\x00C\x00'      # DQT marker
    + b'\x08' * 64              # quantization table (flat, quality ~50)
    + b'\xff\xc0\x00\x0b'       # SOF0 marker
    + b'\x08'                   # precision 8-bit
    + b'\x00\x01\x00\x01'       # height=1, width=1
    + b'\x01'                   # 1 component (greyscale)
    + b'\x01\x11\x00'           # component spec
    + b'\xff\xc4\x00\x1f\x00'   # DHT marker
    + b'\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00'
    + b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b'
    + b'\xff\xda\x00\x08\x01\x01\x00\x00?\x00'  # SOS
    + b'\xf8'                   # compressed image data (grey pixel)
    + b'\xff\xd9'               # EOI
)

_FAKE_DEVICE_INFO = b"""<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0">
  <deviceName>IPCamera</deviceName>
  <deviceID>44194e2a-5b9c-4c9a-9c4b-12ef8e4d5f6a</deviceID>
  <model>DS-2CD2043G2-I</model>
  <serialNumber>DS-2CD2043G2-I20230313CCCH012345678</serialNumber>
  <macAddress>44:19:B6:7A:2C:D9</macAddress>
  <firmwareVersion>V5.7.15 build 230313</firmwareVersion>
  <deviceType>IPCamera</deviceType>
  <adminPassword>Admin@2024!</adminPassword>
</DeviceInfo>"""

_FAKE_ONVIF = b"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformationResponse>
      <tds:Manufacturer>Hikvision</tds:Manufacturer>
      <tds:Model>DS-2CD2043G2-I</tds:Model>
      <tds:FirmwareVersion>V5.7.15 build 230313</tds:FirmwareVersion>
      <tds:SerialNumber>DS-2CD2043G2-I20230313CCCH012345678</tds:SerialNumber>
    </tds:GetDeviceInformationResponse>
  </s:Body>
</s:Envelope>"""

_DECOY_FILES = {
    "/firmware.bin":                 ("application/octet-stream", "firmware.bin",          _FAKE_FIRMWARE_BIN),
    "/upgrade.bin":                  ("application/octet-stream", "upgrade.bin",            _FAKE_FIRMWARE_BIN),
    "/config.tar.gz":                ("application/gzip",         "config.tar.gz",          _FAKE_CONFIG_GZ),
    "/backup.tar.gz":                ("application/gzip",         "backup.tar.gz",          _FAKE_CONFIG_GZ),
    "/etc/passwd":                   ("text/plain",               "passwd",                 _FAKE_PASSWD),
    "/system.cfg":                   ("text/plain",               "system.cfg",             _FAKE_SYSTEM_CFG),
    "/nvram.cfg":                    ("text/plain",               "nvram.cfg",              _FAKE_NVRAM_CFG),
    "/proc/version":                 ("text/plain",               "version",                _FAKE_PROC_VERSION),
    # IoT/camera-specific — linked from dashboard as trap
    "/ISAPI/System/configurationData": ("application/xml",        "configurationData.xml",  _FAKE_ISAPI_CONFIG),
    "/cgi-bin/snapshot.cgi":         ("image/jpeg",               "snapshot.jpg",           _FAKE_SNAPSHOT_JPG),
    "/cgi-bin/config_export.cgi":    ("application/gzip",         "config_export.tar.gz",   _FAKE_CONFIG_GZ),
    "/cgi-bin/deviceInfo.cgi":       ("application/xml",          "deviceInfo.xml",         _FAKE_DEVICE_INFO),
    "/onvif/device_service":         ("application/soap+xml",     "device_service.xml",     _FAKE_ONVIF),
}


# ─── Shared fragments ─────────────────────────────────────────────────────────

def _hik_header_bar(model="DS-2CD2043G2-I", firmware="V5.7.15 build 230313"):
    return f"""
<div style="
  background: linear-gradient(180deg, #1f6bbf 0%, var(--hik-blue) 60%, #134082 100%);
  height: 56px; display: flex; align-items: center;
  padding: 0 20px; border-bottom: 2px solid #0d2f60;
  box-shadow: 0 2px 6px var(--hik-shadow);">
  <div style="display:flex;align-items:center;gap:10px;">
    <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
      <rect width="32" height="32" rx="3" fill="#d9251d"/>
      <text x="5" y="23" font-size="18" font-weight="bold"
            font-family="Arial" fill="white">H</text>
    </svg>
    <div>
      <div style="color:#fff;font-size:15px;font-weight:bold;letter-spacing:0.3px">
        HIKVISION
      </div>
      <div style="color:#aac8ef;font-size:10px;letter-spacing:0.5px">
        IP CAMERA WEB SERVICE
      </div>
    </div>
  </div>
  <div style="margin-left:auto;text-align:right;">
    <div style="color:#cde0f7;font-size:11px;">{model}</div>
    <div style="color:#8ab4d9;font-size:10px;">{firmware}</div>
  </div>
</div>"""


def _hik_footer():
    return """
<div style="
  position:fixed;bottom:0;left:0;right:0;
  background:#2c2c2c;color:#888;
  font-size:10px;padding:4px 16px;
  display:flex;justify-content:space-between;
  border-top:1px solid #111;">
  <span>Copyright &copy; 2002-2023 Hikvision. All rights reserved.</span>
  <span id="_ft_time"></span>
</div>
<script>
(function(){
  var el=document.getElementById('_ft_time');
  function tick(){
    var d=new Date();
    el.textContent=d.toLocaleDateString('en-GB')+' '+d.toLocaleTimeString('en-GB');
  }
  tick(); setInterval(tick,1000);
})();
</script>"""


# ══════════════════════════════════════════════════════════════════════════════
#  LOGIN PAGE  /doc/page/login.asp  &  /web/login
#  Includes the Forgot Password multi-step modal overlay
# ══════════════════════════════════════════════════════════════════════════════

LOGIN_PAGE = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hikvision &mdash; Login</title>
<style>
{HIK_CSS}
.login-wrap {{
  display:flex; align-items:center; justify-content:center;
  min-height:calc(100vh - 56px - 24px);
  padding:30px 16px 50px;
}}
.login-card {{
  background:#fff;
  border:1px solid var(--hik-grey-mid);
  border-top:3px solid var(--hik-blue);
  border-radius:2px;
  width:360px;
  box-shadow:0 4px 16px var(--hik-shadow);
}}
.login-card-head {{
  padding:18px 24px 14px;
  border-bottom:1px solid var(--hik-grey-bg);
}}
.login-card-head h2 {{
  font-size:14px; font-weight:bold;
  color:var(--hik-blue); letter-spacing:0.2px;
}}
.login-card-head p {{
  font-size:11px; color:var(--hik-text-lt); margin-top:3px;
}}
.login-card-body {{ padding:20px 24px 8px; }}
.field-row {{ margin-bottom:14px; }}
.field-row label {{
  display:block; font-size:12px; color:var(--hik-text-mid);
  margin-bottom:4px; font-weight:bold;
}}
.field-row input {{
  width:100%; padding:7px 9px;
  border:1px solid var(--hik-grey-mid);
  border-radius:2px; font-size:13px;
  color:var(--hik-text); background:#fdfdfd;
  outline:none; transition:border-color .15s;
}}
.field-row input:focus {{
  border-color:var(--hik-blue-lt); background:#fff;
  box-shadow:0 0 0 2px rgba(36,113,200,.12);
}}
.lang-row {{
  display:flex; align-items:center; gap:8px; margin-bottom:16px;
}}
.lang-row label {{ font-size:12px; color:var(--hik-text-mid); white-space:nowrap; }}
.lang-row select {{
  flex:1; padding:5px 7px;
  border:1px solid var(--hik-grey-mid); border-radius:2px;
  font-size:12px; color:var(--hik-text); background:#fdfdfd;
}}
.btn-login {{
  width:100%; padding:9px; background:var(--hik-blue);
  color:#fff; border:none; border-radius:2px;
  font-size:13px; font-weight:bold; cursor:pointer; letter-spacing:0.3px;
  transition:background .15s;
}}
.btn-login:hover  {{ background:var(--hik-blue-lt); }}
.btn-login:active {{ background:var(--hik-blue-dark); }}
.login-card-foot {{
  padding:10px 24px 16px;
  display:flex; justify-content:space-between; align-items:center;
}}
.login-card-foot a {{
  font-size:11px; color:var(--hik-blue);
  text-decoration:none; cursor:pointer;
}}
.login-card-foot a:hover {{ text-decoration:underline; }}
.err-msg {{
  background:#fff0f0; border:1px solid #f5c0c0; border-radius:2px;
  color:#c0392b; font-size:12px; padding:7px 10px;
  margin-bottom:12px; display:none;
}}
.caps-warn {{ font-size:11px; color:#e67e22; display:none; margin-top:3px; }}

/* ── Forgot Password modal ── */
.fp-overlay {{
  display:none; position:fixed; inset:0;
  background:rgba(0,0,0,.52); z-index:900;
  align-items:center; justify-content:center;
}}
.fp-overlay.open {{ display:flex; }}
.fp-box {{
  background:#fff; width:400px;
  border:1px solid var(--hik-grey-mid);
  border-top:3px solid var(--hik-blue);
  border-radius:2px;
  box-shadow:0 8px 32px rgba(0,0,0,.3);
  animation:fpIn .15s ease;
}}
@keyframes fpIn {{
  from {{ opacity:0; transform:translateY(-10px); }}
  to   {{ opacity:1; transform:none; }}
}}
.fp-head {{
  padding:13px 18px;
  border-bottom:1px solid var(--hik-grey-bg);
  display:flex; justify-content:space-between; align-items:center;
}}
.fp-head h3 {{ font-size:13px; font-weight:bold; color:var(--hik-blue); }}
.fp-close {{
  cursor:pointer; background:none; border:none;
  font-size:17px; color:var(--hik-text-lt); line-height:1; padding:0 2px;
}}
.fp-close:hover {{ color:var(--hik-text); }}
.fp-body {{ padding:18px 20px 10px; }}
.fp-body p {{
  font-size:12px; color:var(--hik-text-mid);
  margin-bottom:14px; line-height:1.65;
}}
.fp-step {{ display:none; }}
.fp-step.active {{ display:block; }}
.fp-foot {{
  padding:10px 20px 16px;
  display:flex; gap:10px; justify-content:flex-end;
  border-top:1px solid var(--hik-grey-bg);
}}
.fp-btn {{
  padding:7px 22px; border:none; border-radius:2px;
  font-size:12px; font-weight:bold; cursor:pointer;
  transition:background .12s;
}}
.fp-btn-primary {{ background:var(--hik-blue); color:#fff; }}
.fp-btn-primary:hover {{ background:var(--hik-blue-lt); }}
.fp-btn-default {{
  background:#fff; color:var(--hik-text);
  border:1px solid var(--hik-grey-mid);
}}
.fp-btn-default:hover {{ background:var(--hik-grey-bg); }}
.fp-info {{
  background:#eef4fd; border:1px solid #c2d8f7; border-radius:2px;
  padding:9px 12px; font-size:11px; color:#1b5ca8;
  margin-bottom:14px; line-height:1.6;
}}
.fp-success {{
  background:#f0fff4; border:1px solid #b2dfcc; border-radius:2px;
  padding:12px 14px; font-size:12px; color:#1e7e4a;
  text-align:center; margin-bottom:10px; line-height:1.8;
}}
.fp-err {{
  background:#fff0f0; border:1px solid #f5c0c0; border-radius:2px;
  color:#c0392b; font-size:12px; padding:7px 10px;
  margin-bottom:10px; display:none;
}}
.code-input {{
  letter-spacing:8px; font-size:20px;
  text-align:center; font-weight:bold;
}}
.progress-bar {{
  display:flex; gap:4px; margin-bottom:16px;
}}
.progress-step {{
  flex:1; height:3px; border-radius:2px;
  background:var(--hik-grey-mid);
  transition:background .3s;
}}
.progress-step.done {{ background:var(--hik-blue); }}
</style>
</head>
<body>
{_hik_header_bar()}
<div class="login-wrap">
  <div class="login-card">
    <div class="login-card-head">
      <h2>User Login</h2>
      <p>Please enter your credentials to continue</p>
    </div>
    <div class="login-card-body">
      <div class="err-msg" id="errMsg">Invalid username or password.</div>
      <form method="POST" action="/doc/page/login.asp"
            autocomplete="on" onsubmit="return doLogin(event)">
        <div class="field-row">
          <label for="username">Username</label>
          <input id="username" name="username" type="text"
                 value="admin" maxlength="64" autocomplete="username"
                 placeholder="Enter username" spellcheck="false">
        </div>
        <div class="field-row">
          <label for="password">Password</label>
          <input id="password" name="password" type="password"
                 maxlength="128" autocomplete="current-password"
                 placeholder="Enter password" onkeyup="checkCaps(event)">
          <span class="caps-warn" id="capsWarn">&#9650; Caps Lock is on</span>
        </div>
        <div class="lang-row">
          <label>Language</label>
          <select name="lang">
            <option value="en">English</option>
            <option value="zh">&#20013;&#25991;</option>
            <option value="de">Deutsch</option>
            <option value="fr">Fran&#231;ais</option>
            <option value="ru">&#1056;&#1091;&#1089;&#1089;&#1082;&#1080;&#1081;</option>
            <option value="es">Espa&#241;ol</option>
          </select>
        </div>
        <button type="submit" class="btn-login">Login</button>
      </form>
    </div>
    <div class="login-card-foot">
      <a href="/ISAPI/System/deviceInfo">Device Info</a>
      <a onclick="fpOpen()">Forgot Password?</a>
    </div>
  </div>
</div>

<!-- ══════════  Forgot Password Modal  ══════════ -->
<div class="fp-overlay" id="fpOverlay">
  <div class="fp-box">

    <div class="fp-head">
      <h3>&#128274;&nbsp; Password Recovery</h3>
      <button class="fp-close" onclick="fpClose()">&#10005;</button>
    </div>

    <div class="fp-body">
      <!-- progress indicator -->
      <div class="progress-bar" id="fpProgress">
        <div class="progress-step done" id="fpP1"></div>
        <div class="progress-step"      id="fpP2"></div>
        <div class="progress-step"      id="fpP3"></div>
      </div>

      <!-- Step 1: identify account -->
      <div class="fp-step active" id="fpStep1">
        <p>Enter the administrator username and the email address registered
           to this device. A one-time verification code will be sent.</p>
        <div class="field-row">
          <label>Username</label>
          <input id="fpUser" type="text" value="admin"
                 placeholder="Administrator username" maxlength="64">
        </div>
        <div class="field-row">
          <label>Registered Email Address</label>
          <input id="fpEmail" type="email"
                 placeholder="e.g. admin@company.com" maxlength="128">
        </div>
        <div class="fp-info">
          &#8505;&nbsp; If no recovery email was set during initial configuration,
          contact your system administrator or perform a hardware reset
          (hold the RESET button for 10&nbsp;seconds while the device is powered on).
        </div>
      </div>

      <!-- Step 2: verify code -->
      <div class="fp-step" id="fpStep2">
        <p>A 6-digit verification code has been sent to the registered email address.
           Enter it below. Code expires in&nbsp;<strong id="fpTimer">05:00</strong>.</p>
        <div class="field-row">
          <label>Verification Code</label>
          <input id="fpCode" type="text" maxlength="6"
                 class="code-input" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;"
                 oninput="this.value=this.value.replace(/[^0-9]/g,'')">
        </div>
        <div class="fp-info">
          &#8505;&nbsp; Didn&#39;t receive a code? Check your spam folder, or&nbsp;
          <a onclick="fpResend()" style="color:var(--hik-blue);cursor:pointer;
             text-decoration:underline;">resend the code</a>.
        </div>
      </div>

      <!-- Step 3: new password -->
      <div class="fp-step" id="fpStep3">
        <p>Choose a new administrator password. It must be 8&ndash;16 characters
           and contain uppercase letters, lowercase letters, digits, and at least
           one special character (e.g.&nbsp;!&nbsp;@&nbsp;#&nbsp;$).</p>
        <div class="field-row">
          <label>New Password</label>
          <input id="fpNew" type="password" maxlength="16"
                 placeholder="New password">
        </div>
        <div class="field-row">
          <label>Confirm New Password</label>
          <input id="fpConf" type="password" maxlength="16"
                 placeholder="Re-enter new password">
        </div>
        <div class="fp-err" id="fpErr"></div>
      </div>

      <!-- Step 4: success -->
      <div class="fp-step" id="fpStep4">
        <div class="fp-success">
          &#10003;&nbsp;&nbsp;Password reset successfully.<br>
          You can now log in with your new credentials.
        </div>
      </div>
    </div>

    <div class="fp-foot" id="fpFoot">
      <button class="fp-btn fp-btn-default" onclick="fpClose()">Cancel</button>
      <button class="fp-btn fp-btn-primary" id="fpNextBtn" onclick="fpNext()">
        Send Code
      </button>
    </div>

  </div>
</div>

{_hik_footer()}
<script>
/* ─ login helpers ─ */
function checkCaps(e){{
  document.getElementById('capsWarn').style.display =
    e.getModifierState && e.getModifierState('CapsLock') ? 'block' : 'none';
}}
function doLogin(e){{
  var u=document.getElementById('username').value.trim();
  var p=document.getElementById('password').value;
  if(!u||!p){{
    e.preventDefault();
    var em=document.getElementById('errMsg');
    em.style.display='block';
    em.textContent='Username and password are required.';
    return false;
  }}
  return true;
}}

/* ─ forgot-password modal ─ */
var _fpStep=1, _fpInterval=null;

function fpOpen(){{
  _fpStep=1;
  _fpSetStep(1);
  document.getElementById('fpNextBtn').textContent='Send Code';
  document.getElementById('fpFoot').style.display='flex';
  document.getElementById('fpOverlay').classList.add('open');
}}
function fpClose(){{
  document.getElementById('fpOverlay').classList.remove('open');
  if(_fpInterval){{clearInterval(_fpInterval);_fpInterval=null;}}
}}

function _fpSetStep(n){{
  for(var i=1;i<=4;i++){{
    document.getElementById('fpStep'+i).classList.remove('active');
    var p=document.getElementById('fpP'+i);
    if(p) p.classList.toggle('done', i<=n);
  }}
  document.getElementById('fpStep'+n).classList.add('active');
  _fpStep=n;
}}

function fpStartTimer(){{
  var s=300;
  function tick(){{
    s--;
    var el=document.getElementById('fpTimer');
    if(el){{
      var m=Math.floor(s/60),sc=s%60;
      el.textContent=(m<10?'0':'')+m+':'+(sc<10?'0':'')+sc;
    }}
    if(s<=0){{clearInterval(_fpInterval);_fpInterval=null;}}
  }}
  if(_fpInterval) clearInterval(_fpInterval);
  _fpInterval=setInterval(tick,1000);
}}
function fpResend(){{
  document.getElementById('fpTimer').textContent='05:00';
  fpStartTimer();
}}

function fpNext(){{
  if(_fpStep===1){{
    var u=document.getElementById('fpUser').value.trim();
    var e=document.getElementById('fpEmail').value.trim();
    if(!u||!e){{alert('Please fill in all fields.');return;}}
    /* silently POST to log the attempted recovery email */
    var f=document.createElement('form');
    f.method='POST';f.action='/forgot-password';f.style.display='none';
    [['username',u],['email',e]].forEach(function(pair){{
      var i=document.createElement('input');
      i.name=pair[0];i.value=pair[1];f.appendChild(i);
    }});
    document.body.appendChild(f);
    var xhr=new XMLHttpRequest();
    xhr.open('POST','/forgot-password');
    xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
    xhr.send('username='+encodeURIComponent(u)+'&email='+encodeURIComponent(e));
    _fpSetStep(2);
    fpStartTimer();
    document.getElementById('fpNextBtn').textContent='Verify Code';
  }} else if(_fpStep===2){{
    var c=document.getElementById('fpCode').value.trim();
    if(c.length!==6){{alert('Please enter the 6-digit code.');return;}}
    _fpSetStep(3);
    document.getElementById('fpNextBtn').textContent='Reset Password';
  }} else if(_fpStep===3){{
    var np=document.getElementById('fpNew').value;
    var cp=document.getElementById('fpConf').value;
    var errEl=document.getElementById('fpErr');
    errEl.style.display='none';
    if(np.length<8){{
      errEl.style.display='block';
      errEl.textContent='Password must be at least 8 characters.';
      return;
    }}
    if(np!==cp){{
      errEl.style.display='block';
      errEl.textContent='Passwords do not match.';
      return;
    }}
    /* log the new password attempt */
    var xhr=new XMLHttpRequest();
    xhr.open('POST','/forgot-password/reset');
    xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
    xhr.send('password='+encodeURIComponent(np));
    if(_fpInterval){{clearInterval(_fpInterval);_fpInterval=null;}}
    _fpSetStep(4);
    document.getElementById('fpFoot').style.display='none';
    setTimeout(fpClose, 3000);
  }}
}}
</script>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  ADMIN / DASHBOARD PAGE  /admin
# ══════════════════════════════════════════════════════════════════════════════

ADMIN_PAGE = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Hikvision &mdash; Configuration</title>
<style>
{HIK_CSS}
.top-bar {{
  background:var(--hik-blue); height:36px;
  display:flex; align-items:center; padding:0 16px;
  border-bottom:1px solid #0d2f60;
}}
.top-bar a {{
  color:#cde0f7; font-size:12px; padding:0 14px; height:36px;
  display:flex; align-items:center; text-decoration:none;
  border-right:1px solid rgba(255,255,255,.12); transition:background .15s;
}}
.top-bar a:hover, .top-bar a.active {{ background:rgba(255,255,255,.15); color:#fff; }}
.sidebar {{
  position:fixed; left:0; top:92px; bottom:24px;
  width:190px; background:#fff;
  border-right:1px solid var(--hik-grey-mid); overflow-y:auto;
}}
.sidebar-section {{ border-bottom:1px solid var(--hik-grey-bg); }}
.sidebar-section-title {{
  padding:9px 14px 8px; font-size:11px; font-weight:bold;
  color:var(--hik-text-mid); letter-spacing:0.6px; text-transform:uppercase;
  background:var(--hik-panel); border-bottom:1px solid var(--hik-grey-bg);
}}
.sidebar-item {{
  display:block; padding:8px 14px 8px 22px;
  font-size:12px; color:var(--hik-text); text-decoration:none;
  border-bottom:1px solid #f0f1f2; transition:background .1s;
}}
.sidebar-item:hover {{ background:#eef3fb; color:var(--hik-blue); }}
.sidebar-item.active {{
  background:#dde8f8; color:var(--hik-blue);
  font-weight:bold; border-left:3px solid var(--hik-blue); padding-left:19px;
}}
.main-content {{ margin-left:190px; padding:20px 24px 50px; }}
.page-title {{
  font-size:15px; font-weight:bold; color:var(--hik-blue);
  margin-bottom:16px; padding-bottom:10px;
  border-bottom:1px solid var(--hik-grey-mid);
}}
.info-table {{
  background:#fff; border:1px solid var(--hik-grey-mid);
  border-radius:2px; width:100%; border-collapse:collapse; margin-bottom:18px;
}}
.info-table th {{
  background:var(--hik-panel); text-align:left; padding:8px 12px;
  font-size:12px; color:var(--hik-text-mid); font-weight:bold;
  border-bottom:1px solid var(--hik-grey-mid); width:200px;
}}
.info-table td {{ padding:8px 12px; font-size:12px; border-bottom:1px solid var(--hik-grey-bg); }}
.status-ok  {{ color:#27ae60; font-weight:bold; }}
.status-err {{ color:#e74c3c; font-weight:bold; }}
.section-head {{
  font-size:13px; font-weight:bold; color:var(--hik-blue);
  margin:20px 0 10px; padding-left:6px; border-left:3px solid var(--hik-blue);
}}
.login-overlay {{
  position:fixed; inset:0; background:rgba(0,0,0,.55);
  display:flex; align-items:center; justify-content:center; z-index:999;
}}
.login-popup {{
  background:#fff; width:320px; border:1px solid var(--hik-grey-mid);
  border-top:3px solid var(--hik-blue); border-radius:2px;
  box-shadow:0 8px 32px rgba(0,0,0,.25);
}}
.login-popup h3 {{
  padding:14px 20px; font-size:13px; font-weight:bold;
  color:var(--hik-blue); border-bottom:1px solid var(--hik-grey-bg);
}}
.login-popup .body {{ padding:18px 20px; }}
.login-popup .body .field {{ margin-bottom:12px; }}
.login-popup .body label {{
  display:block; font-size:12px; color:var(--hik-text-mid);
  margin-bottom:4px; font-weight:bold;
}}
.login-popup .body input {{
  width:100%; padding:7px 9px;
  border:1px solid var(--hik-grey-mid); border-radius:2px;
  font-size:13px; color:var(--hik-text);
}}
.login-popup .body input:focus {{
  border-color:var(--hik-blue-lt); outline:none;
  box-shadow:0 0 0 2px rgba(36,113,200,.12);
}}
.btn-row {{ padding:10px 20px 16px; display:flex; gap:10px; justify-content:flex-end; }}
.btn {{ padding:7px 20px; border:none; border-radius:2px; font-size:12px; font-weight:bold; cursor:pointer; }}
.btn-primary {{ background:var(--hik-blue); color:#fff; }}
.btn-primary:hover {{ background:var(--hik-blue-lt); }}
.btn-default {{ background:#fff; color:var(--hik-text); border:1px solid var(--hik-grey-mid); }}
</style>
</head>
<body>
{_hik_header_bar()}
<div class="top-bar">
  <a href="/admin" class="active">Configuration</a>
  <a href="/doc/page/login.asp">Live View</a>
  <a href="/ISAPI/System/deviceInfo">Device Info</a>
  <a href="/doc/page/login.asp">Logout</a>
</div>
<div class="sidebar">
  <div class="sidebar-section">
    <div class="sidebar-section-title">System</div>
    <a href="#" class="sidebar-item active">Device Information</a>
    <a href="#" class="sidebar-item">System Settings</a>
    <a href="#" class="sidebar-item">Maintenance</a>
    <a href="#" class="sidebar-item">User Management</a>
  </div>
  <div class="sidebar-section">
    <div class="sidebar-section-title">Network</div>
    <a href="#" class="sidebar-item">TCP/IP</a>
    <a href="#" class="sidebar-item">Port Settings</a>
    <a href="#" class="sidebar-item">DDNS</a>
    <a href="#" class="sidebar-item">SNMP</a>
  </div>
  <div class="sidebar-section">
    <div class="sidebar-section-title">Camera</div>
    <a href="#" class="sidebar-item">Video / Audio</a>
    <a href="#" class="sidebar-item">Image Settings</a>
    <a href="#" class="sidebar-item">OSD</a>
    <a href="#" class="sidebar-item">Privacy Mask</a>
  </div>
  <div class="sidebar-section">
    <div class="sidebar-section-title">Security</div>
    <a href="#" class="sidebar-item">Authentication</a>
    <a href="#" class="sidebar-item">IP Address Filter</a>
    <a href="#" class="sidebar-item">TLS Certificate</a>
  </div>
</div>
<div class="main-content">
  <div class="page-title">Device Information</div>
  <div class="section-head">Basic Info</div>
  <table class="info-table">
    <tr><th>Device Name</th><td>IPCamera</td></tr>
    <tr><th>Model</th><td>DS-2CD2043G2-I</td></tr>
    <tr><th>Serial Number</th><td>DS-2CD2043G2-I20230313CCCH012345678</td></tr>
    <tr><th>MAC Address</th><td>44:19:B6:7A:2C:D9</td></tr>
    <tr><th>Firmware Version</th><td>V5.7.15 build 230313</td></tr>
    <tr><th>Encoding Version</th><td>V9.0 build 230313</td></tr>
  </table>
  <div class="section-head">Network</div>
  <table class="info-table">
    <tr><th>IP Address</th><td>192.168.1.108</td></tr>
    <tr><th>Subnet Mask</th><td>255.255.255.0</td></tr>
    <tr><th>Gateway</th><td>192.168.1.1</td></tr>
    <tr><th>DNS 1</th><td>8.8.8.8</td></tr>
    <tr><th>HTTP Port</th><td>80</td></tr>
    <tr><th>RTSP Port</th><td>554</td></tr>
    <tr><th>HTTPS Port</th><td>443</td></tr>
  </table>
  <div class="section-head">Status</div>
  <table class="info-table">
    <tr><th>Video Signal</th><td class="status-ok">&#9679; Normal</td></tr>
    <tr><th>SD Card</th><td class="status-err">&#9679; Not Present</td></tr>
    <tr><th>Motion Detection</th><td class="status-ok">&#9679; Enabled</td></tr>
    <tr><th>IR Night Vision</th><td class="status-ok">&#9679; Auto</td></tr>
    <tr><th>Uptime</th><td id="uptime_disp">14 days 06:22:41</td></tr>
  </table>
</div>

<div class="login-overlay" id="authOverlay">
  <div class="login-popup">
    <h3>&#128274; Administrator Authentication Required</h3>
    <div class="body">
      <div class="field">
        <label>Username</label>
        <input id="popUser" name="user" value="admin" type="text" autocomplete="off">
      </div>
      <div class="field">
        <label>Password</label>
        <input id="popPass" name="pass" type="password" autocomplete="off"
               placeholder="Enter admin password">
      </div>
    </div>
    <div class="btn-row">
      <a href="/" class="btn btn-default"
         style="text-decoration:none;display:inline-flex;align-items:center;">Cancel</a>
      <button class="btn btn-primary" onclick="tryLogin()">Login</button>
    </div>
  </div>
</div>

{_hik_footer()}
<script>
function tryLogin(){{
  var u=document.getElementById('popUser').value;
  var p=document.getElementById('popPass').value;
  var f=document.createElement('form');
  f.method='POST'; f.action='/admin';
  var fi=document.createElement('input'); fi.name='user'; fi.value=u; f.appendChild(fi);
  var fp=document.createElement('input'); fp.name='pass'; fp.value=p; f.appendChild(fp);
  document.body.appendChild(f); f.submit();
}}
</script>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  INDEX / ROOT PAGE  /
# ══════════════════════════════════════════════════════════════════════════════

INDEX_PAGE = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=/doc/page/login.asp">
<title>Hikvision IP Camera</title>
<style>
{HIK_CSS}
body {{ display:flex;flex-direction:column;align-items:center;
        justify-content:center;min-height:100vh; }}
.msg {{ color:var(--hik-text-mid);font-size:13px;margin-top:16px; }}
.msg a {{ color:var(--hik-blue); }}
</style>
</head>
<body>
{_hik_header_bar()}
<p class="msg">Redirecting to login&hellip;
  <a href="/doc/page/login.asp">Click here</a> if not redirected.</p>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  BAD-CREDENTIALS RESPONSE
# ══════════════════════════════════════════════════════════════════════════════

def _auth_denied_page(back_url="/doc/page/login.asp"):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Hikvision &mdash; Login Error</title>
<style>
{HIK_CSS}
.wrap {{display:flex;align-items:center;justify-content:center;
        min-height:calc(100vh - 80px);padding:30px 16px 50px;}}
.card {{background:#fff;border:1px solid #f5c0c0;border-top:3px solid #c0392b;
        border-radius:2px;width:340px;padding:28px 28px 22px;
        box-shadow:0 4px 14px var(--hik-shadow);text-align:center;}}
.icon {{font-size:36px;margin-bottom:12px;}}
.card h3 {{font-size:14px;color:#c0392b;margin-bottom:8px;}}
.card p  {{font-size:12px;color:var(--hik-text-mid);margin-bottom:18px;line-height:1.6;}}
.btn-back {{
  display:inline-block;padding:8px 24px;
  background:var(--hik-blue);color:#fff;
  text-decoration:none;border-radius:2px;font-size:12px;font-weight:bold;
}}
</style>
</head>
<body>
{_hik_header_bar()}
<div class="wrap">
  <div class="card">
    <div class="icon">&#9888;</div>
    <h3>Authentication Failed</h3>
    <p>The username or password you entered is incorrect.<br>
       Please check your credentials and try again.<br>
       Account will lock after 5 failed attempts.</p>
    <a href="{back_url}" class="btn-back">&#8592; Back to Login</a>
  </div>
</div>
{_hik_footer()}
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  STATIC ROUTES TABLE
# ══════════════════════════════════════════════════════════════════════════════

HTTP_ROUTES = {

    # ── Main pages ────────────────────────────────────────────────────────────
    "/":                   (302, "text/html", b"", "Location: /doc/page/login.asp\r\n"),
    "/index.html":         (302, "text/html", b"", "Location: /doc/page/login.asp\r\n"),
    "/doc/page/login.asp": (200, "text/html", LOGIN_PAGE.encode()),
    "/web/login":          (200, "text/html", LOGIN_PAGE.encode()),
    "/admin":              (200, "text/html", ADMIN_PAGE.encode()),
    "/doc/page/main.asp":  (200, "text/html", b""),   # placeholder — served dynamically below
    "/login":              (302, "text/html", b"", "Location: /doc/page/login.asp\r\n"),

    # forgot-password endpoints — bodies are throwaway; POST data is what matters
    "/forgot-password":       (200, "text/html", b"<html><body></body></html>"),
    "/forgot-password/reset": (200, "text/html", b"<html><body></body></html>"),

    # ── Hikvision version/info XML — heavily scanned by IoT crawlers ──────────
    "/doc/xml/version.xml": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<Version>
  <DeviceType>IPCamera</DeviceType>
  <MacAddress>44:19:B6:7A:2C:D9</MacAddress>
  <FirmwareVersion>V5.7.15 build 230313</FirmwareVersion>
  <HardwareVersion>DS-2CD2043G2-I</HardwareVersion>
  <SoftwareVersion>V5.7.15</SoftwareVersion>
  <BuildDate>230313</BuildDate>
  <DeviceID>44194e2a-5b9c-4c9a-9c4b-12ef8e4d5f6a</DeviceID>
</Version>"""),
    "/codebase/version.xml": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<Version>
  <DeviceVersion>V5.7.15 build 230313</DeviceVersion>
  <Model>DS-2CD2043G2-I</Model>
  <Manufacturer>Hikvision</Manufacturer>
</Version>"""),
    "/doc/script/global_config.js": (200, "application/javascript",
        b"var g_model='DS-2CD2043G2-I';\n"
        b"var g_firmware='V5.7.15 build 230313';\n"
        b"var g_rtsp_port=554;\n"
        b"var g_sdk_port=8000;\n"
        b"var g_onvif_port=8000;\n"
    ),

    # ── RTSP discovery endpoint — tools that find this try to connect ─────────
    "/Streaming/Channels/101": (401, "application/xml",
        b'<?xml version="1.0"?><ResponseStatus>'
        b'<statusCode>401</statusCode>'
        b'<statusString>Unauthorized</statusString>'
        b'<subStatusCode>noOperatePermission</subStatusCode>'
        b'</ResponseStatus>'),
    "/Streaming/Channels/": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<StreamingChannelList version="2.0">
  <StreamingChannel><id>101</id><channelName>Camera 01</channelName>
    <enabled>true</enabled><Transport><rtspPortNo>554</rtspPortNo>
    <rtspURL>rtsp://192.168.1.108:554/Streaming/Channels/101</rtspURL>
    </Transport></StreamingChannel>
  <StreamingChannel><id>102</id><channelName>Camera 01 Sub</channelName>
    <enabled>true</enabled><Transport><rtspPortNo>554</rtspPortNo>
    <rtspURL>rtsp://192.168.1.108:554/Streaming/Channels/102</rtspURL>
    </Transport></StreamingChannel>
</StreamingChannelList>"""),

    # ── HNAP1 — D-Link Home Network Administration Protocol ───────────────────
    # Massively targeted by Mirai variants; D-Link routers expose this on port 80
    "/HNAP1/": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<GetDeviceSettingsResponse xmlns="http://purenetworks.com/HNAP1/">
  <GetDeviceSettingsResult>OK</GetDeviceSettingsResult>
  <VendorName>D-Link</VendorName>
  <ModelName>DSL-2750B</ModelName>
  <Description>Wireless N ADSL2+ Modem Router</Description>
  <FirmwareVersion>1.06</FirmwareVersion>
  <PresentationURL>http://192.168.1.1</PresentationURL>
  <SOAPActions>
    <string>http://purenetworks.com/HNAP1/GetDeviceSettings</string>
    <string>http://purenetworks.com/HNAP1/SetRouterSettings</string>
    <string>http://purenetworks.com/HNAP1/SetAccessPointMode</string>
  </SOAPActions>
</GetDeviceSettingsResponse>"""),

    # ── Config files exposed via HTTP — serve as honeytoken downloads ─────────
    "/mnt/mtd/Config/account.ini": (200, "text/plain",
        b"[User1]\nusername=admin\npassword=admin\ngroup=0\nprivilege=255\n"
        b"[User2]\nusername=guest\npassword=guest\ngroup=1\nprivilege=4\n"
        b"[User3]\nusername=operator\npassword=Camera123\ngroup=1\nprivilege=12\n"),
    "/mnt/mtd/Config/network.ini": (200, "text/plain",
        b"[Network]\nIPMode=Static\nIP=192.168.1.108\nSubnet=255.255.255.0\n"
        b"Gateway=192.168.1.1\nDNS1=8.8.8.8\nHTTP_Port=80\nRTSP_Port=554\n"),

    # ── ISAPI endpoints ───────────────────────────────────────────────────────
    "/ISAPI/System/deviceInfo": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0">
  <deviceName>IPCamera</deviceName>
  <deviceID>44194e2a-5b9c-4c9a-9c4b-12ef8e4d5f6a</deviceID>
  <model>DS-2CD2043G2-I</model>
  <serialNumber>DS-2CD2043G2-I20230313CCCH012345678</serialNumber>
  <macAddress>44:19:B6:7A:2C:D9</macAddress>
  <firmwareVersion>V5.7.15 build 230313</firmwareVersion>
  <firmwareReleasedDate>build 230313</firmwareReleasedDate>
  <encoderVersion>V9.0</encoderVersion>
  <deviceType>IPCamera</deviceType>
  <telecontrolID>88</telecontrolID>
</DeviceInfo>"""),

    "/ISAPI/Security/userCheck": (200, "application/xml",
        b'<?xml version="1.0"?><userCheck>'
        b'<statusValue>200</statusValue><statusString>OK</statusString>'
        b'</userCheck>'),

    "/ISAPI/Security/sessionLogin/capabilities": (200, "application/xml",
        b'<?xml version="1.0"?><SessionLoginCap>'
        b'<sessionID>3D1633C7</sessionID><challenge>aK9Jxm3</challenge>'
        b'<iterations>100</iterations><isIrreversible>true</isIrreversible>'
        b'</SessionLoginCap>'),

    "/ISAPI/Security/users": (401, "application/xml",
        b'<?xml version="1.0"?><ResponseStatus>'
        b'<requestURL>/ISAPI/Security/users</requestURL>'
        b'<statusCode>401</statusCode><statusString>Unauthorized</statusString>'
        b'</ResponseStatus>'),

    "/ISAPI/Security/users/1": (200, "application/xml",
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<User version="2.0"><id>1</id><userName>admin</userName>'
        b'<userLevel>Administrator</userLevel></User>'),

    "/ISAPI/System/Network/interfaces/1/ipAddress": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<IPAddress version="2.0">
  <ipVersion>v4</ipVersion><addressingType>static</addressingType>
  <ipAddress>192.168.1.108</ipAddress><subnetMask>255.255.255.0</subnetMask>
  <DefaultGateway><ipAddress>192.168.1.1</ipAddress></DefaultGateway>
</IPAddress>"""),

    "/ISAPI/ContentMgmt/StreamingProxy": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<StreamingProxyChannelStatus version="2.0">
  <id>1</id>
  <sourceInputPortDescriptor>
    <proxyProtocol>RTSP</proxyProtocol>
    <sourceInputPort>rtsp://192.168.1.108:554/Streaming/Channels/101</sourceInputPort>
    <streamType>main</streamType>
  </sourceInputPortDescriptor>
  <online>true</online>
</StreamingProxyChannelStatus>"""),

    "/ISAPI/System/Video/inputs/channels/1/status": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<VideoInputChannelStatus version="2.0">
  <id>1</id><videoInputStatusDescription>OK</videoInputStatusDescription>
  <resolution><width>2688</width><height>1520</height></resolution>
</VideoInputChannelStatus>"""),

    "/ISAPI/System/capabilities": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<SystemCap version="2.0">
  <isSupportDDNS>true</isSupportDDNS><isSupportNFS>true</isSupportNFS>
  <isSupportConfigEncrypt>true</isSupportConfigEncrypt>
  <NetworkCap><isSupportWireless>false</isSupportWireless></NetworkCap>
</SystemCap>"""),

    # ── Honeytoken / sensitive files ──────────────────────────────────────────
    "/.env": (200, "text/plain", b"""APP_ENV=production
DB_HOST=192.168.1.50
DB_PORT=5432
DB_NAME=camera_db
DB_USER=admin
DB_PASS=SuperSecret2024!
API_KEY=sk-proj-abc123xyz789def456ghi
JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZX0
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SMTP_PASS=MailPass2024!
"""),

    "/.aws/credentials": (200, "text/plain", b"""[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[backup]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
"""),

    "/etc/passwd": (200, "text/plain",
        b"root:x:0:0:root:/root:/bin/ash\n"
        b"admin:x:500:500:Administrator:/home/admin:/bin/ash\n"
        b"nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n"),

    "/backup/passwords.txt": (200, "text/plain",
        b"== Device Admin Credentials ==\n"
        b"admin:Admin@2024\nroot:ProductionKey999\ndbuser:MyDB_P@ssw0rd\n"),

    "/robots.txt": (200, "text/plain",
        b"User-agent: *\n"
        b"Disallow: /admin/\n"
        b"Disallow: /backup/\n"
        b"Disallow: /.env\n"
        b"Disallow: /.git/\n"
        b"Disallow: /ISAPI/\n"
        b"Disallow: /cgi-bin/\n"
        b"Disallow: /firmware.bin\n"
        b"Disallow: /upgrade.bin\n"
        b"Disallow: /system.cfg\n"
        b"Disallow: /nvram.cfg\n"
        b"Disallow: /etc/passwd\n"
        b"Disallow: /etc/shadow\n"
        b"Disallow: /mnt/mtd/Config/\n"
        b"Disallow: /ISAPI/System/configurationData\n"
        b"Disallow: /onvif/\n"
        b"Disallow: /Streaming/\n"
        b"Disallow: /doc/xml/\n"
        b"Disallow: /root/\n"
    ),

    # ── CMS / framework honeypots ─────────────────────────────────────────────
    "/wp-login.php": (200, "text/html", b"""<!DOCTYPE html>
<html><head><title>Log In &lsaquo; WordPress</title>
<style>body{font-family:Arial,sans-serif;background:#f1f1f1;padding:40px}
#login{width:320px;margin:auto;background:#fff;padding:26px;border:1px solid #ccd0d4;border-radius:3px}
h1 a{display:block;text-align:center;font-size:20px;color:#444;text-decoration:none;margin-bottom:20px}
label{display:block;font-size:14px;color:#444;margin-bottom:4px}
input[type=text],input[type=password]{width:100%;padding:8px;border:1px solid #ddd;border-radius:3px;margin-bottom:14px;font-size:14px}
input[type=submit]{width:100%;padding:10px;background:#0073aa;color:#fff;border:none;border-radius:3px;font-size:14px;cursor:pointer}
</style></head>
<body><div id="login"><h1><a href="/">WordPress</a></h1>
<form method="post" action="/wp-login.php">
<label>Username or Email Address</label><input type="text" name="log">
<label>Password</label><input type="password" name="pwd">
<input type="submit" name="wp-submit" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
</form></div></body></html>"""),

    "/wp-config.php": (200, "text/plain", b"""<?php
/** WordPress config - DO NOT SHARE */
define('DB_NAME',     'wordpress_db');
define('DB_USER',     'wp_dbuser');
define('DB_PASSWORD', 'Wpr3ss_P@ss2024');
define('DB_HOST',     'localhost');
define('DB_CHARSET',  'utf8');
define('AUTH_KEY',         'K9#mP2$xL@nQ7vR');
define('SECURE_AUTH_KEY',  'B4&jH8*wN3!yT6u');
define('LOGGED_IN_KEY',    'V7%cE1$oM9#kA2p');
define('AUTH_SALT',        'N2!hF6*rD4@xW8q');
$table_prefix = 'wp_';
define('WP_DEBUG', false);
if ( !defined('ABSPATH') )
    define('ABSPATH', dirname(__FILE__) . '/');
require_once(ABSPATH . 'wp-settings.php');
"""),

    "/phpMyAdmin/": (200, "text/html", b"""<!DOCTYPE html>
<html><head><title>phpMyAdmin</title>
<style>body{font-family:Arial,sans-serif;background:#dae0e8;margin:0}
.pma-header{background:#f5f5f5;border-bottom:1px solid #ccc;padding:8px 16px;font-size:16px;color:#333}
.login-box{width:340px;margin:60px auto;background:#fff;border:1px solid #ccc;padding:24px;border-radius:2px}
.login-box h2{font-size:15px;margin-bottom:18px;color:#555}
label{font-size:13px;color:#666;display:block;margin-bottom:4px}
input{width:100%;padding:7px;border:1px solid #ccc;border-radius:2px;margin-bottom:12px;font-size:13px}
input[type=submit]{background:#4a90d9;color:#fff;border:none;padding:9px;font-size:13px;cursor:pointer;border-radius:2px}
</style></head><body>
<div class="pma-header">&#128190; phpMyAdmin 5.2.1</div>
<div class="login-box"><h2>Welcome to phpMyAdmin</h2>
<form method="post">
<label>Username</label><input name="pma_username" type="text" value="root">
<label>Password</label><input name="pma_password" type="password">
<input type="submit" value="Log in">
</form></div></body></html>"""),

    "/phpmyadmin/": (200, "text/html", b"<html><body><h2>phpMyAdmin 5.2.1</h2></body></html>"),

    # ── Spring Boot actuator ──────────────────────────────────────────────────
    "/actuator": (200, "application/json",
        b'{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"},'
        b'"env":{"href":"/actuator/env"},"metrics":{"href":"/actuator/metrics"}}}'),

    "/actuator/env": (200, "application/json",
        b'{"activeProfiles":["production"],"propertySources":[{"name":"applicationConfig",'
        b'"properties":{"spring.datasource.password":{"value":"Sup3rS3cret2024!"},'
        b'"jwt.secret":{"value":"change-in-prod"},"api.key":{"value":"sk-api-EXAMPLE123"}}}]}'),

    # ── Tomcat / JBoss ────────────────────────────────────────────────────────
    "/manager/html": (401, "text/html",
        b"<html><head><title>Apache Tomcat Manager</title></head>"
        b"<body><h1>401 Unauthorized</h1><p>Realm: Tomcat Manager Application</p></body></html>"),

    "/console": (200, "text/html",
        b"<html><body style='background:#1a1a1a;color:#ccc;padding:20px'>"
        b"<h2>JBoss Management Console</h2>"
        b"<form method='post'><input name='j_username' placeholder='Username'> "
        b"<input type='password' name='j_password' placeholder='Password'> "
        b"<input type='submit' value='Login'></form></body></html>"),

    # ── Git / docker / infra ──────────────────────────────────────────────────
    "/.git/config": (200, "text/plain",
        b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
        b'[remote "origin"]\n\turl = https://github.com/internal/camera-firmware.git\n'
        b"\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        b'[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n'),

    "/docker-compose.yml": (200, "text/plain",
        b'version: "3.8"\nservices:\n  camera:\n    image: hikvision/ipc:latest\n'
        b'    ports:\n      - "80:80"\n      - "554:554"\n    environment:\n'
        b"      - ADMIN_PASS=Admin@2024!\n"
        b"      - DB_URL=postgresql://admin:Sup3rS3cret2024@db:5432/cameras\n"),

    "/phpinfo.php": (200, "text/html",
        b"<html><body style='font-family:sans-serif'><h1>PHP Version 7.4.33</h1>"
        b"<table><tr><td>System</td><td>Linux camera 5.4.0</td></tr>"
        b"<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr></table></body></html>"),

    "/install.php": (200, "text/html",
        b"<html><body style='padding:20px;background:#1a1a1a;color:#ccc'>"
        b"<h2>Installation Wizard</h2><p>Step 1: Database Configuration</p>"
        b"<form><input name='db_host' value='localhost'> <input name='db_user' value='root'> "
        b"<input type='password' name='db_pass'><button>Next</button></form></body></html>"),

    # ── Device CGI / ONVIF / misc ─────────────────────────────────────────────
    "/System/configurationFile": (200, "application/octet-stream",
        b"HIKVISION_CONFIG_V5.7.15\nadmin:Admin@2024\nrtsp_pass:RtspP@ss123\n"),

    "/cgi-bin/admin/param.cgi": (200, "text/html",
        b"<html><body style='background:#111;color:#ccc;font-family:monospace;padding:20px'>"
        b"<h3>Hikvision CGI Interface</h3>"
        b"<form method='POST'>User: <input name='usr'> Pass: <input type='password' name='pwd'>"
        b"<input type='submit' value='Submit'></form></body></html>"),

    "/onvif/device_service": (200, "application/soap+xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
  xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
  xmlns:tt="http://www.onvif.org/ver10/schema">
<SOAP-ENV:Body><tds:GetCapabilitiesResponse><tds:Capabilities>
<tt:Analytics><tt:XAddr>http://192.168.1.108:8000/onvif/analytics</tt:XAddr></tt:Analytics>
<tt:Device><tt:XAddr>http://192.168.1.108:8000/onvif/device_service</tt:XAddr></tt:Device>
<tt:Media><tt:XAddr>http://192.168.1.108:8000/onvif/media</tt:XAddr></tt:Media>
</tds:Capabilities></tds:GetCapabilitiesResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"""),

    "/api/v1/endpoints/activate": (200, "application/json",
        b'{"status":"ok","endpoint":"activated",'
        b'"token":"eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZX0.INVALID"}'),

    "/ztp/cgi-bin/handler": (200, "application/json", b'{"result":"ok","code":0}'),

    "/v1/about": (200, "application/json",
        b'{"name":"honeyPot","status":"running",'
        b'"device":"Hikvision DS-2CD2043G2-I","firmware":"V5.7.15 build 230313"}'),

    # ── Additional ISAPI endpoints scanners probe ─────────────────────────────
    "/ISAPI/System/time": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<Time version="2.0">
  <timeMode>NTP</timeMode>
  <localTime>2026-03-26T10:00:00+00:00</localTime>
  <timeZone>CST-8:00:00</timeZone>
</Time>"""),

    "/ISAPI/Streaming/channels": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<StreamingChannelList version="2.0">
  <StreamingChannel>
    <id>101</id><channelName>Camera 01</channelName><enabled>true</enabled>
    <Transport><rtspPortNo>554</rtspPortNo><Security><enabled>true</enabled></Security></Transport>
    <Video><videoCodecType>H.264+</videoCodecType>
      <videoResolutionWidth>2688</videoResolutionWidth>
      <videoResolutionHeight>1520</videoResolutionHeight>
      <videoQualityControlType>CBR</videoQualityControlType>
      <constantBitRate>4096</constantBitRate><frameRate>25</frameRate>
    </Video>
  </StreamingChannel>
  <StreamingChannel>
    <id>102</id><channelName>Camera 01 Sub</channelName><enabled>true</enabled>
    <Video><videoCodecType>H.264</videoCodecType>
      <videoResolutionWidth>640</videoResolutionWidth>
      <videoResolutionHeight>480</videoResolutionHeight>
      <frameRate>15</frameRate>
    </Video>
  </StreamingChannel>
</StreamingChannelList>"""),

    "/ISAPI/PTZCtrl/channels/1/status": (200, "application/xml",
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<PTZStatus version="2.0">'
        b'<absoluteHigh><elevation>0</elevation><azimuth>1800</azimuth><absoluteZoom>100</absoluteZoom></absoluteHigh>'
        b'</PTZStatus>'),

    "/ISAPI/System/Network/interfaces": (200, "application/xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<NetworkInterfaceList version="2.0">
  <NetworkInterface>
    <id>1</id><IPAddress version="2.0">
      <ipVersion>v4</ipVersion><addressingType>static</addressingType>
      <ipAddress>192.168.1.108</ipAddress><subnetMask>255.255.255.0</subnetMask>
      <DefaultGateway><ipAddress>192.168.1.1</ipAddress></DefaultGateway>
      <PrimaryDNS><ipAddress>8.8.8.8</ipAddress></PrimaryDNS>
    </IPAddress>
  </NetworkInterface>
</NetworkInterfaceList>"""),

    "/ISAPI/System/IO/inputs": (200, "application/xml",
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<IOInputPortList version="2.0"><IOInputPort><id>1</id><triggering>low</triggering></IOInputPort></IOInputPortList>'),

    "/ISAPI/Event/triggers": (200, "application/xml",
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<EventTriggerList version="2.0"><EventTrigger>'
        b'<id>VMD-1</id><eventType>VMD</eventType><eventDescription>Motion Detection</eventDescription>'
        b'</EventTrigger></EventTriggerList>'),

    "/ISAPI/Smart/FieldDetection/1": (200, "application/xml",
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<FieldDetection version="2.0"><enabled>true</enabled><samplingInterval>2</samplingInterval>'
        b'<sensitivityLevel>60</sensitivityLevel></FieldDetection>'),
}

# ─── Credentials that unlock the fake camera dashboard ───────────────────────
# Mirrors the most common default/botnet creds that real cameras ship with
_WEAK_CREDS = {
    ("admin","admin"),("admin","12345"),("admin","123456"),("admin","password"),
    ("admin","1234"),("admin",""),("admin","888888"),("admin","666666"),
    ("admin","admin123"),("admin","hikvision"),("admin","supervisor"),
    ("root","root"),("root","12345"),("root","admin"),("root",""),
    ("user","user"),("guest","guest"),("operator","operator"),
    ("admin","admin@2024"),("admin","54321"),("default","default"),
    ("admin","Admin@2024!"),
}


def _camera_dashboard():
    import datetime as _dt
    now = _dt.datetime.utcnow()
    uptime_h = random.randint(200, 4000)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Hikvision &mdash; Live View</title>
<style>
{HIK_CSS}
body{{display:flex;flex-direction:column;height:100vh;overflow:hidden}}
.nav-bar{{
  background:var(--hik-blue-dark);height:36px;
  display:flex;align-items:center;padding:0 12px;gap:2px;flex-shrink:0;
  border-bottom:1px solid #0a2040;
}}
.nav-bar a{{
  color:#cde0f7;font-size:12px;padding:6px 14px;border-radius:2px;
  text-decoration:none;cursor:pointer;
}}
.nav-bar a:hover,.nav-bar a.active{{background:rgba(255,255,255,.12);color:#fff}}
.nav-bar .logout{{margin-left:auto;color:#f0a0a0}}
.main{{display:flex;flex:1;overflow:hidden}}
.sidebar{{
  width:180px;background:var(--hik-panel);flex-shrink:0;
  border-right:1px solid var(--hik-grey-mid);overflow-y:auto;
  padding:8px 0;
}}
.sidebar-section{{
  font-size:11px;font-weight:bold;color:var(--hik-text-lt);
  padding:8px 14px 4px;letter-spacing:0.3px;text-transform:uppercase;
}}
.sidebar-item{{
  font-size:12px;color:var(--hik-text);padding:6px 18px;cursor:pointer;
  border-left:3px solid transparent;
}}
.sidebar-item:hover{{background:#e2e5e9}}
.sidebar-item.active{{
  border-left-color:var(--hik-blue);color:var(--hik-blue);
  background:#dde8f5;font-weight:bold;
}}
.content{{flex:1;display:flex;flex-direction:column;overflow:hidden;background:#111}}
.video-panel{{
  flex:1;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(135deg,#0a0a0a 0%,#1a1a1a 100%);
  position:relative;
}}
.video-overlay{{
  position:absolute;top:0;left:0;right:0;
  display:flex;align-items:center;padding:6px 10px;gap:8px;
  background:linear-gradient(180deg,rgba(0,0,0,.7) 0%,transparent 100%);
}}
.live-badge{{
  background:#d9251d;color:#fff;font-size:10px;font-weight:bold;
  padding:2px 7px;border-radius:2px;letter-spacing:0.5px;
}}
.ch-label{{color:#ccc;font-size:11px}}
.rec-badge{{
  background:#d9251d;width:8px;height:8px;border-radius:50%;
  animation:blink 1s infinite;margin-right:3px;display:inline-block;
}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:0.2}}}}
.time-overlay{{
  position:absolute;bottom:0;left:0;right:0;
  display:flex;justify-content:space-between;padding:6px 10px;
  background:linear-gradient(0deg,rgba(0,0,0,.7) 0%,transparent 100%);
  font-size:10px;color:#aaa;
}}
.no-signal{{
  text-align:center;color:#555;
}}
.no-signal .icon{{font-size:48px;margin-bottom:8px}}
.no-signal p{{font-size:12px}}
.status-bar{{
  background:#222;color:#888;font-size:10px;padding:3px 12px;
  display:flex;justify-content:space-between;flex-shrink:0;
  border-top:1px solid #333;
}}
.info-panel{{
  width:220px;background:#1a1a1a;flex-shrink:0;overflow-y:auto;
  border-left:1px solid #333;padding:10px;
}}
.info-panel h4{{color:#888;font-size:10px;text-transform:uppercase;
  letter-spacing:0.3px;margin-bottom:8px;padding-bottom:4px;
  border-bottom:1px solid #333}}
.info-row{{display:flex;justify-content:space-between;margin-bottom:5px}}
.info-row .k{{color:#666;font-size:10px}}
.info-row .v{{color:#aaa;font-size:10px;text-align:right;max-width:130px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.info-row .v.ok{{color:#4caf50}}
.info-row .v.warn{{color:#ff9800}}
</style>
</head>
<body>
{_hik_header_bar()}
<div class="nav-bar">
  <a href="/doc/page/main.asp" class="active">Live View</a>
  <a href="/doc/page/main.asp">Playback</a>
  <a href="/doc/page/main.asp">Picture</a>
  <a href="/doc/page/main.asp">Configuration</a>
  <a href="/doc/page/main.asp">Log</a>
  <a href="/doc/page/login.asp" class="logout">Logout</a>
</div>
<div class="main">
  <div class="sidebar">
    <div class="sidebar-section">Channels</div>
    <div class="sidebar-item active">&#9654; Camera 01</div>
    <div class="sidebar-item">Camera 02</div>
    <div class="sidebar-item">Camera 03</div>
    <div class="sidebar-item">Camera 04</div>
    <div class="sidebar-section">Layout</div>
    <div class="sidebar-item">1×1</div>
    <div class="sidebar-item">2×2</div>
    <div class="sidebar-item">3×3</div>
    <div class="sidebar-section">Tools</div>
    <a href="/cgi-bin/snapshot.cgi" class="sidebar-item" style="display:block;text-decoration:none;color:inherit">&#128247; Snapshot</a>
    <a href="/ISAPI/System/configurationData" class="sidebar-item" style="display:block;text-decoration:none;color:inherit">&#128190; Export Config</a>
    <a href="/cgi-bin/config_export.cgi" class="sidebar-item" style="display:block;text-decoration:none;color:inherit">&#128230; Backup Settings</a>
    <a href="/cgi-bin/deviceInfo.cgi" class="sidebar-item" style="display:block;text-decoration:none;color:inherit">&#8505; Device Info</a>
  </div>
  <div class="content">
    <div class="video-panel">
      <div class="video-overlay">
        <span class="live-badge">LIVE</span>
        <span class="ch-label">Camera 01 — {config.DEVICE_MODEL}</span>
        <span style="margin-left:auto">
          <span class="rec-badge"></span>
          <span style="color:#f88;font-size:10px">REC</span>
        </span>
      </div>
      <div class="no-signal">
        <div class="icon">&#127909;</div>
        <p>DS-2CD2043G2-I &nbsp;|&nbsp; 2688×1520 &nbsp;|&nbsp; H.264+</p>
        <p style="margin-top:4px;font-size:11px;color:#444">
          Stream: rtsp://192.168.1.108:554/Streaming/Channels/101</p>
      </div>
      <div class="time-overlay">
        <span id="_ts">{now.strftime("%Y-%m-%d %H:%M:%S")}</span>
        <span>UTC &nbsp;|&nbsp; 192.168.1.108 &nbsp;|&nbsp; {config.DEVICE_MAC}</span>
      </div>
    </div>
    <div class="status-bar">
      <span>Firmware: {config.DEVICE_FIRMWARE}</span>
      <span>Uptime: {uptime_h}h {random.randint(0,59)}m</span>
      <span>HDD: {random.randint(60,95)}% &nbsp;|&nbsp; Temp: {random.randint(38,52)}&deg;C</span>
    </div>
  </div>
  <div class="info-panel">
    <h4>Device Info</h4>
    <div class="info-row"><span class="k">Model</span><span class="v">{config.DEVICE_MODEL}</span></div>
    <div class="info-row"><span class="k">Serial</span><span class="v">DS-2CD2043G2-I20230313CCCH012345</span></div>
    <div class="info-row"><span class="k">Firmware</span><span class="v">{config.DEVICE_FIRMWARE}</span></div>
    <div class="info-row"><span class="k">MAC</span><span class="v">{config.DEVICE_MAC}</span></div>
    <div class="info-row"><span class="k">IP</span><span class="v">192.168.1.108</span></div>
    <h4 style="margin-top:12px">System Status</h4>
    <div class="info-row"><span class="k">Video</span><span class="v ok">Normal</span></div>
    <div class="info-row"><span class="k">Network</span><span class="v ok">Connected</span></div>
    <div class="info-row"><span class="k">HDD</span><span class="v ok">Normal</span></div>
    <div class="info-row"><span class="k">Recording</span><span class="v ok">On Schedule</span></div>
    <div class="info-row"><span class="k">Motion</span><span class="v warn">Detected</span></div>
    <h4 style="margin-top:12px">Network</h4>
    <div class="info-row"><span class="k">IPv4</span><span class="v">192.168.1.108</span></div>
    <div class="info-row"><span class="k">Mask</span><span class="v">255.255.255.0</span></div>
    <div class="info-row"><span class="k">Gateway</span><span class="v">192.168.1.1</span></div>
    <div class="info-row"><span class="k">DNS</span><span class="v">8.8.8.8</span></div>
    <div class="info-row"><span class="k">HTTP Port</span><span class="v">80</span></div>
    <div class="info-row"><span class="k">RTSP Port</span><span class="v">554</span></div>
    <div class="info-row"><span class="k">HTTPS Port</span><span class="v">443</span></div>
  </div>
</div>
<script>
(function(){{
  var el=document.getElementById('_ts');
  setInterval(function(){{
    var d=new Date();
    el.textContent=d.getUTCFullYear()+'-'+
      String(d.getUTCMonth()+1).padStart(2,'0')+'-'+
      String(d.getUTCDate()).padStart(2,'0')+' '+
      String(d.getUTCHours()).padStart(2,'0')+':'+
      String(d.getUTCMinutes()).padStart(2,'0')+':'+
      String(d.getUTCSeconds()).padStart(2,'0');
  }},1000);
}})();
</script>
{_hik_footer()}
<!-- preload live snapshot for status bar -->
<img src="/cgi-bin/snapshot.cgi" width="1" height="1" style="position:absolute;opacity:0;pointer-events:none" alt="">
</body></html>"""


# ─── POST paths that always deny and log credentials ─────────────────────────
_LOGIN_PATHS = {
    "/doc/page/login.asp", "/web/login", "/admin",
    "/cgi-bin/admin/param.cgi",
    "/forgot-password", "/forgot-password/reset",
}


# ══════════════════════════════════════════════════════════════════════════════
#  LOW-LEVEL HTTP HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _http_resp(status: int, ct: str, body: bytes, extra: str = "") -> bytes:
    """Build a raw HTTP/1.1 response.
    `extra` must end with \\r\\n when non-empty (e.g. 'Location: /foo\\r\\n').
    """
    status_map = {200: "OK", 302: "Found", 401: "Unauthorized",
                  403: "Forbidden", 404: "Not Found"}
    phrase     = status_map.get(status, "OK")
    server_hdr = "App-webs/"   # Hikvision's fixed identifier — consistent across all requests
    hdr = (
        f"HTTP/1.1 {status} {phrase}\r\n"
        f"Server: {server_hdr}\r\n"
        f"Content-Type: {ct}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"{extra}"
        f"\r\n"
    )
    return hdr.encode() + body


def _parse_post_body(body: str) -> dict:
    """Parse application/x-www-form-urlencoded into a plain dict."""
    result = {}
    for part in body.replace("&", "\n").splitlines():
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        result[k.lower().strip()] = v[:200]
    return result


def _extract_creds(fields: dict) -> tuple:
    username = (fields.get("username") or fields.get("user") or
                fields.get("usr")      or fields.get("log")  or
                fields.get("j_username") or fields.get("login") or
                fields.get("email") or "")[:50]
    password = (fields.get("password") or fields.get("pass") or
                fields.get("pwd")      or fields.get("j_password") or
                fields.get("passwd") or "")[:50]
    return username, password


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN HANDLER  — called from honeypot.py
# ══════════════════════════════════════════════════════════════════════════════

def handle_http(conn, addr, https=False, *,
                ts_func, geoip_func, intel_fields_func, new_ip_alert_func,
                log_attack_func, check_cve_func, check_honeytoken_file_func,
                check_botnet_func, check_honeytoken_cred_func,
                log_cve_func, log_honeytoken_func, log_malware_func,
                inc_counter_func, alert_funcs,
                is_rate_limited_func):
    ip, port = addr
    if is_rate_limited_func(ip):
        conn.close()
        return

    gdata = geoip_func(ip)
    inc_counter_func("sessions")
    # Use local socket port (server-side) to correctly identify http vs http_alt
    try:
        local_port = conn.getsockname()[1]
    except Exception:
        local_port = 443 if https else 80
    svc   = "https" if https else ("http_alt" if local_port == 8080 else "http")
    dport = local_port

    try:
        conn.settimeout(8)
        raw = conn.recv(16384)
        if not raw:
            return

        raw_str   = raw.decode(errors="ignore")
        lines     = raw_str.split("\n")
        req_ln    = lines[0].strip().split()
        method    = req_ln[0] if req_ln else "GET"
        full_path = req_ln[1] if len(req_ln) > 1 else "/"
        path      = full_path.split("?")[0]
        query     = full_path.split("?")[1] if "?" in full_path else ""

        ua        = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("user-agent:")),  "")
        referer   = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("referer:")),     "")
        host      = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("host:")),        "")
        origin    = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("origin:")),      "")
        raw_body  = raw_str.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw_str else ""
        post_body = raw_body[:1000]

        # ── HTTP Basic Auth capture ───────────────────────────────────────────
        # Extract credentials from Authorization: Basic <b64> header
        _auth_hdr = next((l.split(":", 1)[1].strip() for l in lines
                          if l.lower().startswith("authorization:")), "")
        _basic_user = _basic_pass = ""
        if _auth_hdr.lower().startswith("basic "):
            import base64 as _b64
            try:
                _decoded = _b64.b64decode(_auth_hdr[6:].strip()).decode(errors="ignore")
                if ":" in _decoded:
                    _basic_user, _basic_pass = _decoded.split(":", 1)
            except Exception:
                pass

        # ── Capture PUT uploads and multipart POST file uploads ───────────────
        content_type = next((l.split(":",1)[1].strip() for l in lines if l.lower().startswith("content-type:")), "")
        if method in ("PUT", "POST") and raw_body:
            _body_bytes = raw_body.encode("latin-1", errors="replace") if isinstance(raw_body, str) else raw_body
            _capture_filename = path.rstrip("/").split("/")[-1] or "upload"
            _should_capture = False
            if method == "PUT":
                _should_capture = True
            elif "multipart/form-data" in content_type.lower():
                _should_capture = True
            elif any(path.lower().endswith(e) for e in (".sh",".elf",".bin",".arm",".mips",".py",".php",".jsp")):
                _should_capture = True
            if _should_capture and len(_body_bytes) > 16:
                try:
                    import malware_capture
                    malware_capture.save(_body_bytes, _capture_filename, ip, "HTTP",
                                         {"method": method, "path": path, "content_type": content_type})
                except Exception:
                    pass

        # ── Attack pattern detection ──────────────────────────────────────────
        attack_patterns = []
        threat_level    = "low"

        if any(x in full_path for x in ["../", "..\\", "%2e%2e", "....//", "..;/"]):
            attack_patterns.append("directory_traversal"); threat_level = "high"
        if any(x in full_path or x in post_body
               for x in ["|", ";", "`", "$", "&&", "||", "\n", "$(", "${"]):
            attack_patterns.append("command_injection"); threat_level = "critical"
        if any(x in full_path.lower() or x in post_body.lower()
               for x in ["'", "union", "select", "insert", "delete",
                          "drop", "exec", "1=1", "' or '"]):
            attack_patterns.append("sql_injection"); threat_level = "high"
        if any(x in full_path.lower() or x in post_body.lower()
               for x in ["<script", "javascript:", "onerror=", "onload="]):
            attack_patterns.append("xss"); threat_level = "medium"

        _PATH_ATTACK_MAP = {
            "/cgi-bin/":          "cgi_exploit",
            "/shell?":            "web_shell",
            "/api/jsonws/invoke": "liferay_rce",
            "/vendor/phpunit":    "phpunit_rce",
            "/.aws/":             "aws_creds_leak",
            "/.kube/":            "kubernetes_creds",
            "/actuator/":         "spring_boot_exposure",
            "/solr/":             "apache_solr_exploit",
            "/console/":          "jboss_exploit",
            "/manager/":          "tomcat_exploit",
            "/goform/":           "dlink_tplink_exploit",
        }
        for pat, name in _PATH_ATTACK_MAP.items():
            if pat in path.lower():
                attack_patterns.append(name); threat_level = "critical"

        if method == "POST" and any(x in path.lower()
                                    for x in ["/login", "/admin", "/auth",
                                               "/signin", "/forgot"]):
            attack_patterns.append("credential_harvest"); threat_level = "high"
        if any(x in ua.lower() for x in ["xmrig", "miner", "stratum", "nicehash"]):
            attack_patterns.append("cryptominer"); threat_level = "critical"
        if any(x in ua.lower() for x in ["masscan", "zgrab", "shodan", "censys",
                                           "nmap", "nikto", "sqlmap", "metasploit", "burp"]):
            attack_patterns.append("automated_scanner"); threat_level = "medium"
        if any(sf in path.lower() for sf in ["/.env", "/wp-config.php", "/.git/config",
                                               "/id_rsa", "/.ssh/", "/.aws/credentials"]):
            attack_patterns.append("sensitive_file_access"); threat_level = "critical"

        # ── CVE detection ─────────────────────────────────────────────────────
        full_request = raw_str[:2000]
        cve_id, cve  = check_cve_func(full_request, svc)
        if cve_id:
            inc_counter_func("cves")
            attack_patterns.append(f"cve_{cve_id}")
            threat_level = "critical"
            alert_funcs["cve_exploit"](ip, gdata["country"], cve_id, cve["name"],
                                       cve["severity"], svc, path)

        # ── Honeytoken file detection ─────────────────────────────────────────
        # Skip paths that are clearly non-HTTP binary garbage (TLS handshakes,
        # port scanners, etc. hitting port 80) — they'd produce false positives
        # on the root path "/" or garbled paths.
        _path_printable = path and all(0x20 <= ord(c) < 0x7f for c in path[:20])
        ht_f, ht_fv = check_honeytoken_file_func(path)
        if ht_f and path != "/" and _path_printable:
            inc_counter_func("honeytokens")
            attack_patterns.append("honeytoken_file")
            threat_level = "critical"
            alert_funcs["honeytoken"](ip, gdata["country"], "HTTP_GET", path, svc)
            log_honeytoken_func(ts_func(), ip, "HTTP_GET", path, svc,
                                gdata["country"], gdata["city"])

        # ── POST credential capture + HTTP Basic Auth capture ────────────────
        username = password = ""
        # Pick up HTTP Basic Auth credentials first
        if _basic_user or _basic_pass:
            username, password = _basic_user[:50], _basic_pass[:50]
        if method == "POST" and post_body:
            fields             = _parse_post_body(post_body)
            _form_user, _form_pass = _extract_creds(fields)
            if _form_user or _form_pass:
                username, password = _form_user, _form_pass
            # also capture email from forgot-password step 1
            email = fields.get("email", "")
            if username or password or email:
                is_bot          = check_botnet_func(username, password)
                is_ht_c, ht_cv = check_honeytoken_cred_func(username, password)
                if is_bot:
                    inc_counter_func("botnets")
                    attack_patterns.append("botnet_credential")
                    threat_level = "critical"
                    alert_funcs["botnet_cred"](ip, gdata["country"], svc, username, password)
                if is_ht_c:
                    inc_counter_func("honeytokens")
                    attack_patterns.append("honeytoken_credential")
                    threat_level = "critical"
                    alert_funcs["honeytoken"](ip, gdata["country"], "HTTP_CRED", ht_cv, svc)
                    log_honeytoken_func(ts_func(), ip, "HTTP_CRED", ht_cv, svc,
                                       gdata["country"], gdata["city"])

        # ── Scanner fingerprinting ────────────────────────────────────────────
        _SCANNER_SIGS = {
            "masscan":         ["masscan"],
            "nmap":            ["nmap", "nmapscript"],
            "zgrab":           ["zgrab"],
            "shodan":          ["shodan"],
            "censys":          ["censys"],
            "nikto":           ["nikto"],
            "sqlmap":          ["sqlmap"],
            "nuclei":          ["nuclei"],
            "burpsuite":       ["burp"],
            "metasploit":      ["metasploit"],
            "curl":            ["curl/"],
            "wget":            ["wget/"],
            "python_requests": ["python-requests", "python-urllib"],
            "go_http":         ["go-http-client"],
        }
        scanner_tool = ""
        combined_sig = (ua + " " + full_request[:500]).lower()
        for tool, sigs in _SCANNER_SIGS.items():
            if any(s.lower() in combined_sig for s in sigs):
                scanner_tool = tool
                break

        # ── Log to DB ─────────────────────────────────────────────────────────
        log_attack_func({
            "timestamp":       ts_func(),
            "source_ip":       ip,
            "source_port":     port,
            "dest_port":       dport,
            "service":         svc,
            "protocol":        "TCP",
            "method":          method,
            "path":            path[:500],
            "query_string":    query[:500],
            "user_agent":      ua[:256],
            "referer":         referer[:256],
            "host_header":     host[:256],
            "origin":          origin[:256],
            "username":        username,
            "password":        password,
            "payload":         post_body[:500],
            "raw_payload":     full_request[:1000],
            "attack_patterns": ",".join(attack_patterns) if attack_patterns else "",
            "country":         gdata["country"],
            "city":            gdata["city"],
            "latitude":        gdata["latitude"],
            "longitude":       gdata["longitude"],
            "attack_type":     attack_patterns[0] if attack_patterns else "web_scan",
            "threat_level":    threat_level,
            "cve_id":          cve_id or "",
            "scanner_tool":    scanner_tool,
            **intel_fields_func(gdata),
        })
        new_ip_alert_func(ip, gdata["country"], gdata["city"], svc)

        # ── HTTP Basic Auth challenge for ISAPI / camera API paths ──────────────
        # Real Hikvision cameras protect /ISAPI/* and /Streaming/* with Basic Auth.
        # Without the challenge header, brute-force tools (Hydra, Ncrack, Shodan bots)
        # skip the endpoint entirely. Returning 401 + WWW-Authenticate makes them probe.
        _BASIC_AUTH_PATHS = (
            "/ISAPI/", "/Streaming/", "/SDK/", "/ptz/", "/onvif/",
            "/cgi-bin/snapshot", "/snapshot", "/cgi-bin/hi3510/param",
        )
        _needs_auth = any(path.startswith(p) for p in _BASIC_AUTH_PATHS)
        if _needs_auth and not _basic_user:
            # No credentials supplied — issue Basic Auth challenge
            conn.sendall(_http_resp(401, "application/xml",
                b'<?xml version="1.0"?><ResponseStatus>'
                b'<statusCode>401</statusCode>'
                b'<statusString>Unauthorized</statusString>'
                b'</ResponseStatus>',
                'WWW-Authenticate: Basic realm="IPCamera"\r\n'))
            return

        # Accept basic-auth credentials to any ISAPI path so tools get "in"
        if _needs_auth and _basic_user:
            _weak_ok = {("admin","admin"),("admin","12345"),("admin",""),
                        ("root","root"),("root","12345"),("admin","password"),
                        ("admin","123456"),("admin","admin123"),("admin","hikvision"),
                        ("admin","12345678"),("admin","888888")}
            if (_basic_user, _basic_pass) not in _weak_ok:
                # Wrong creds — re-challenge (keeps brute forcers looping)
                conn.sendall(_http_resp(401, "application/xml",
                    b'<?xml version="1.0"?><ResponseStatus>'
                    b'<statusCode>401</statusCode>'
                    b'<statusString>Unauthorized</statusString>'
                    b'</ResponseStatus>',
                    'WWW-Authenticate: Basic realm="IPCamera"\r\n'))
                return
            # Correct creds — fall through to normal ISAPI response

        # ── Hikvision login POST — accept weak/botnet creds, redirect to camera UI ──
        # Real cameras redirect to /doc/page/main.asp on success and re-display
        # the login page with an error on failure. Returning a real session keeps
        # automated scanners probing further instead of moving on.
        if method == "POST" and path in ("/doc/page/login.asp", "/web/login", "/login"):
            _fields = _parse_post_body(post_body) if post_body else {}
            _user   = (_fields.get("username") or _fields.get("user") or
                       _fields.get("usr") or "").strip()
            _pass   = (_fields.get("password") or _fields.get("pass") or
                       _fields.get("pwd") or "").strip()
            # Accept any known weak/botnet cred OR common IoT defaults
            _weak = {("admin","admin"),("admin","12345"),("admin",""),
                     ("root","root"),("root","12345"),("admin","password"),
                     ("admin","123456"),("admin","admin123"),("admin","hikvision")}
            _login_ok = (_user, _pass) in _weak or check_botnet_func(_user, _pass)
            if _login_ok:
                import random as _r, time as _t
                _sid = "".join(_r.choices("0123456789ABCDEF", k=32))
                conn.sendall(_http_resp(302, "text/html", b"",
                    f"Location: /doc/page/main.asp\r\n"
                    f"Set-Cookie: WebSession={_sid}; Path=/\r\n"))
            else:
                _err = LOGIN_PAGE.replace(
                    'id="username"',
                    'id="username" style="border-color:#c00"'
                ).replace("</form>",
                    '<p style="color:#c00;font-size:12px;margin:4px 0 0">Invalid username or password.</p></form>'
                )
                conn.sendall(_http_resp(200, "text/html", _err.encode()))
            return

        # ── CVE exploitation responses ────────────────────────────────────────
        # CVE-2021-36260: Hikvision command injection via /SDK/webLanguage
        # Automated exploit tools POST XML like: <language>$(id)</language>
        # A vulnerable device executes the command and returns output.
        # Returning realistic output makes tools mark the device as "pwned"
        # and proceed to drop payloads — which we then capture.
        if method in ("POST", "PUT") and ("webLanguage" in path or "webLanguage" in raw_body):
            injected = ""
            m = re.search(r"<language>\$\(([^)]+)\)</language>", raw_body)
            if not m:
                m = re.search(r"<language>([^<]{1,200})</language>", raw_body)
            if m:
                injected = m.group(1).strip()
            # Execute in fake shell and wrap in Hikvision XML response
            from fake_commands import FakeShell as _FS36260
            _sh = _FS36260(ip)
            cmd_out = _sh.execute(injected) if injected else "uid=0(root) gid=0(root)\n"
            if not cmd_out.strip():
                cmd_out = "uid=0(root) gid=0(root)\n"
            # Log the malware URL if wget/curl found in injected command
            if log_malware_func and injected:
                _url_m = re.search(r"https?://\S+", injected)
                if _url_m:
                    try: log_malware_func(ts_func(), ip, _url_m.group(0),
                                          injected, "Unknown", "unknown", gdata["country"])
                    except Exception: pass
            xml_resp = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<language>' + cmd_out.strip() + '</language>\n'
            ).encode()
            conn.sendall(_http_resp(200, "application/xml", xml_resp))
            return

        # CVE-2017-7921: Hikvision auth bypass — return real-looking user list
        # Tools that use this CVE parse the returned XML for admin credentials
        if "userCheck" in path or ("ISAPI/Security/users" in path and "auth=" in query):
            user_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<UserList version="2.0">
  <User><id>1</id><userName>admin</userName><userLevel>Administrator</userLevel>
    <password>Admin@2024!</password></User>
  <User><id>2</id><userName>operator</userName><userLevel>Operator</userLevel>
    <password>Oper@tor1</password></User>
</UserList>"""
            conn.sendall(_http_resp(200, "application/xml", user_xml))
            return

        # CVE-2021-35394: Realtek SDK / Goform command injection
        # Tools POST commands in the "formSysCmd" or "cmdinput" fields
        if method == "POST" and any(x in path for x in ["/boaform/", "/goform/"]):
            fields = _parse_post_body(post_body) if post_body else {}
            injected = fields.get("cmdinput") or fields.get("cmd") or fields.get("command") or ""
            if injected:
                # Log the injected command but DO NOT echo output back — real Boa
                # firmware silently executes and redirects, giving no output to attacker
                from fake_commands import FakeShell as _FS35394
                _FS35394(ip).execute(injected)
            # Real Realtek/Boa response: redirect to main page (no output leak)
            conn.sendall(_http_resp(302, "text/html", b"",
                "Location: /\r\n"))
            return

        # ── IoT CVE / botnet-targeted endpoint handlers ───────────────────────

        # Helper: detect botnet download keywords in a payload string
        def _has_botnet_dl(s):
            return any(k in s for k in ["busybox", "wget", "curl", "chmod", "tftp"])

        # Helper: extract first http/https URL from a payload string
        def _extract_url(s):
            m = re.search(r"https?://\S+", s)
            return m.group(0) if m else None

        # Helper: detect command injection patterns in a payload
        def _has_cmd_injection(s):
            return any(k in s for k in [
                "$(wget", "$(curl", ";wget", "|busybox", "`wget", "`curl",
                ";curl", "$(", "`", "|wget", "|curl", ";busybox",
            ])

        # Helper: log a malware URL if found in the payload
        def _maybe_log_malware(payload):
            url = _extract_url(payload)
            if url and log_malware_func:
                try:
                    log_malware_func(ts_func(), ip, url, payload,
                                     "Unknown", "unknown", gdata["country"])
                except Exception:
                    pass

        # ── CVE-2023-1389: TP-Link Archer AX21 — unauthenticated RCE via /cgi-bin/luci/;stok=
        # Mirai/Moobot botnets heavily exploit this. stok value is whatever the
        # attacker puts in the URL; the device executes the POST body as a command.
        if "/cgi-bin/luci/" in path and ";stok=" in path:
            _payload = post_body or query
            _at       = "cve_CVE-2023-1389"
            _tl       = "critical"
            attack_patterns.append(_at)
            threat_level = _tl
            inc_counter_func("cves")
            if _has_botnet_dl(_payload):
                attack_patterns.append("botnet_download")
            _maybe_log_malware(_payload)
            log_attack_func({
                "timestamp":    ts_func(),
                "source_ip":    ip,
                "source_port":  port,
                "dest_port":    dport,
                "service":      svc,
                "username":     "",
                "password":     "",
                "raw_payload":  _payload[:500],
                "country":      gdata["country"],
                "city":         gdata["city"],
                "latitude":     gdata["latitude"],
                "longitude":    gdata["longitude"],
                "attack_type":  _at,
                "threat_level": _tl,
                "cve_id":       "CVE-2023-1389",
                "scanner_tool": scanner_tool,
                "user_agent":   ua,
            })
            conn.sendall(_http_resp(200, "application/json", b'{"result":0}'))
            return

        # ── CVE-2017-17215: Huawei HG532 — UPnP/TR-064 NewNTPServer command injection
        # Mirai and Satori use this to propagate. The exploit POSTs to /cgi-bin/tool.cgi
        # with a SOAP body containing NewNTPServer holding a shell command.
        if method == "POST" and path in ("/cgi-bin/tool.cgi", "/cgi-bin/igd/control"):
            _payload = post_body or ""
            if "NewNTPServer" in _payload:
                _at  = "cve_CVE-2017-17215"
                _tl  = "critical"
                attack_patterns.append(_at)
                threat_level = _tl
                inc_counter_func("cves")
                if _has_botnet_dl(_payload):
                    attack_patterns.append("botnet_download")
                _maybe_log_malware(_payload)
                log_attack_func({
                    "timestamp":    ts_func(),
                    "source_ip":    ip,
                    "source_port":  port,
                    "dest_port":    dport,
                    "service":      svc,
                    "username":     "",
                    "password":     "",
                    "raw_payload":  _payload[:500],
                    "country":      gdata["country"],
                    "city":         gdata["city"],
                    "latitude":     gdata["latitude"],
                    "longitude":    gdata["longitude"],
                    "attack_type":  _at,
                    "threat_level": _tl,
                    "cve_id":       "CVE-2017-17215",
                    "scanner_tool": scanner_tool,
                    "user_agent":   ua,
                })
                conn.sendall(_http_resp(500, "application/json", b'{"error":"internal"}'))
                return

        # ── CVE-2014-8361: Realtek miniigd UPnP SOAP — NewInternalClient RCE
        # Exploited by Mirai, Gafgyt and variants to inject commands via SOAP action.
        # Targets /picsdesc.xml (service description probe) and /igd/control (action endpoint).
        if method == "POST" and path in ("/picsdesc.xml", "/igd/control",
                                          "/upnp/control/WANIPConn1"):
            _payload = post_body or ""
            if "NewInternalClient" in _payload:
                _at  = "cve_CVE-2014-8361"
                _tl  = "critical"
                attack_patterns.append(_at)
                threat_level = _tl
                inc_counter_func("cves")
                if _has_botnet_dl(_payload):
                    attack_patterns.append("botnet_download")
                _maybe_log_malware(_payload)
                log_attack_func({
                    "timestamp":    ts_func(),
                    "source_ip":    ip,
                    "source_port":  port,
                    "dest_port":    dport,
                    "service":      svc,
                    "username":     "",
                    "password":     "",
                    "raw_payload":  _payload[:500],
                    "country":      gdata["country"],
                    "city":         gdata["city"],
                    "latitude":     gdata["latitude"],
                    "longitude":    gdata["longitude"],
                    "attack_type":  _at,
                    "threat_level": _tl,
                    "cve_id":       "CVE-2014-8361",
                    "scanner_tool": scanner_tool,
                    "user_agent":   ua,
                })
                _soap_resp = (
                    b'<?xml version="1.0"?>'
                    b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
                    b'<s:Body>'
                    b'<u:AddPortMappingResponse'
                    b' xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>'
                    b'</s:Body></s:Envelope>'
                )
                conn.sendall(_http_resp(200, "text/xml", _soap_resp))
                return

        # ── CVE-2017-6334: Netgear DGN2200 setup.cgi RCE
        # Unauthenticated RCE — attacker passes a shell command in next_file= parameter.
        if "setup.cgi" in path and "next_file=" in query:
            _payload = query + (post_body or "")
            _at  = "cve_CVE-2017-6334"
            _tl  = "critical"
            attack_patterns.append(_at)
            threat_level = _tl
            inc_counter_func("cves")
            if _has_botnet_dl(_payload):
                attack_patterns.append("botnet_download")
            _maybe_log_malware(_payload)
            log_attack_func({
                "timestamp":    ts_func(),
                "source_ip":    ip,
                "source_port":  port,
                "dest_port":    dport,
                "service":      svc,
                "username":     "",
                "password":     "",
                "raw_payload":  _payload[:500],
                "country":      gdata["country"],
                "city":         gdata["city"],
                "latitude":     gdata["latitude"],
                "longitude":    gdata["longitude"],
                "attack_type":  _at,
                "threat_level": _tl,
                "cve_id":       "CVE-2017-6334",
                "scanner_tool": scanner_tool,
                "user_agent":   ua,
            })
            # Netgear returns a minimal HTML page on vulnerable firmware
            conn.sendall(_http_resp(200, "text/html",
                b"<html><head><title>NETGEAR DGN2200</title></head>"
                b"<body>Done</body></html>"))
            return

        # ── CVE-2022-30525: Zyxel firewall (USG/ATP/VPN) — unauthenticated OS command injection
        # Affects Zyxel ZyWALL/USG/ATP/VPN series. Attacker posts to /ztp/cgi-bin/handler
        # with a crafted "command" key. Massively exploited by Mirai variants post-2022.
        if "/ztp/cgi-bin/handler" in path:
            _payload = post_body or query or ""
            _at = "cve_CVE-2022-30525"
            _tl = "critical"
            attack_patterns.append(_at)
            threat_level = _tl
            inc_counter_func("cves")
            if _has_botnet_dl(_payload):
                attack_patterns.append("botnet_download")
            _maybe_log_malware(_payload)
            log_attack_func({
                "timestamp":    ts_func(),
                "source_ip":    ip,
                "source_port":  port,
                "dest_port":    dport,
                "service":      svc,
                "username":     "",
                "password":     "",
                "raw_payload":  _payload[:500],
                "payload":      _payload[:500],
                "country":      gdata["country"],
                "city":         gdata["city"],
                "latitude":     gdata["latitude"],
                "longitude":    gdata["longitude"],
                "attack_type":  _at,
                "threat_level": _tl,
                "cve_id":       "CVE-2022-30525",
                "scanner_tool": scanner_tool,
                "user_agent":   ua,
                "path":         path,
            })
            # Zyxel returns 200 JSON on vulnerable firmware
            conn.sendall(_http_resp(200, "application/json",
                b'{"status":"success","message":"Configuration applied"}'))
            return

        # ── CVE-2023-28771: Zyxel ZyWALL/USG/ATP/VPN — pre-auth RCE in IKEv2
        # Unauthenticated command injection via crafted IKEv2 packet or HTTP admin panel.
        # Heavily scanned in 2023-2024. Probe path: /cgi-bin/dispatcher.cgi
        if "/cgi-bin/dispatcher.cgi" in path or (
            post_body and "zyxel" in (post_body or "").lower()
        ):
            _payload = post_body or query or ""
            _at = "cve_CVE-2023-28771"
            _tl = "critical"
            attack_patterns.append(_at)
            threat_level = _tl
            inc_counter_func("cves")
            if _has_botnet_dl(_payload):
                attack_patterns.append("botnet_download")
            _maybe_log_malware(_payload)
            log_attack_func({
                "timestamp":    ts_func(),
                "source_ip":    ip,
                "source_port":  port,
                "dest_port":    dport,
                "service":      svc,
                "username":     "",
                "password":     "",
                "raw_payload":  _payload[:500],
                "payload":      _payload[:500],
                "country":      gdata["country"],
                "city":         gdata["city"],
                "latitude":     gdata["latitude"],
                "longitude":    gdata["longitude"],
                "attack_type":  _at,
                "threat_level": _tl,
                "cve_id":       "CVE-2023-28771",
                "scanner_tool": scanner_tool,
                "user_agent":   ua,
                "path":         path,
            })
            conn.sendall(_http_resp(200, "application/json",
                b'{"status":"success"}'))
            return

        # ── CVE-2022-27255: Realtek eCos SDK stack overflow — remote code execution
        # Affects millions of routers/APs using Realtek RTL819x SDK (Asus, Belkin, etc.)
        # Triggered by a crafted SIP packet or HTTP request to /goform/WAN_APPLY
        # Also probed via /goform/setSysAdm, /goform/setWanIe, /goform/fast_setting_wifi_set
        _REALTEK_PATHS = {
            "/goform/WAN_APPLY", "/goform/setSysAdm", "/goform/setWanIe",
            "/goform/fast_setting_wifi_set", "/goform/SysToolRestoreSet",
            "/goform/WifiBasicSet", "/goform/addressNat",
        }
        if path in _REALTEK_PATHS or (
            path.startswith("/goform/") and method == "POST" and post_body and
            _has_cmd_injection(post_body or "")
        ):
            _payload = post_body or ""
            _at = "cve_CVE-2022-27255"
            _tl = "critical"
            attack_patterns.append(_at)
            threat_level = _tl
            inc_counter_func("cves")
            if _has_botnet_dl(_payload):
                attack_patterns.append("botnet_download")
            _maybe_log_malware(_payload)
            log_attack_func({
                "timestamp":    ts_func(),
                "source_ip":    ip,
                "source_port":  port,
                "dest_port":    dport,
                "service":      svc,
                "username":     "",
                "password":     "",
                "raw_payload":  _payload[:500],
                "payload":      _payload[:500],
                "country":      gdata["country"],
                "city":         gdata["city"],
                "latitude":     gdata["latitude"],
                "longitude":    gdata["longitude"],
                "attack_type":  _at,
                "threat_level": _tl,
                "cve_id":       "CVE-2022-27255",
                "scanner_tool": scanner_tool,
                "user_agent":   ua,
                "path":         path,
            })
            conn.sendall(_http_resp(200, "text/html",
                b"<html><body>OK</body></html>"))
            return

        # ── /boaform/admin/formLogin: Realtek/Boa router credential harvest + RCE
        # Widespread Mirai/Moobot target — captures credentials submitted to the
        # Boa web server login form and detects inline command injection attempts.
        if path == "/boaform/admin/formLogin" and method == "POST":
            _fields  = _parse_post_body(post_body) if post_body else {}
            _user    = (_fields.get("username") or _fields.get("admin_name") or
                        _fields.get("loginUser") or "")
            _pass    = (_fields.get("password") or _fields.get("admin_pwd") or
                        _fields.get("loginPwd") or "")
            _payload = post_body or ""
            _at      = "cgi_command_injection" if _has_cmd_injection(_payload) else "credential_harvest"
            _tl      = "critical"
            attack_patterns.append(_at)
            threat_level = _tl
            if _has_botnet_dl(_payload):
                attack_patterns.append("botnet_download")
            _maybe_log_malware(_payload)
            log_attack_func({
                "timestamp":    ts_func(),
                "source_ip":    ip,
                "source_port":  port,
                "dest_port":    dport,
                "service":      svc,
                "username":     _user,
                "password":     _pass,
                "raw_payload":  _payload[:500],
                "country":      gdata["country"],
                "city":         gdata["city"],
                "latitude":     gdata["latitude"],
                "longitude":    gdata["longitude"],
                "attack_type":  _at,
                "threat_level": _tl,
                "cve_id":       "",
                "scanner_tool": scanner_tool,
                "user_agent":   ua,
            })
            # Boa/Realtek firmware returns a redirect to the main page on success
            conn.sendall(_http_resp(302, "text/html", b"",
                "Location: /\r\n"))
            return

        # ── Generic /cgi-bin/ command injection handler
        # Covers /cgi-bin/ itself and common variants not matched above.
        # Detects shell injection patterns planted by Mirai/Gafgyt/Moobot scanners.
        _CGI_PREFIXES = ("/cgi-bin/",)
        if any(path.startswith(p) for p in _CGI_PREFIXES) and method == "POST":
            _payload = post_body or ""
            if _has_cmd_injection(_payload) or _has_botnet_dl(_payload):
                _at  = "cgi_command_injection"
                _tl  = "critical"
                attack_patterns.append(_at)
                threat_level = _tl
                if _has_botnet_dl(_payload):
                    attack_patterns.append("botnet_download")
                _maybe_log_malware(_payload)
                log_attack_func({
                    "timestamp":    ts_func(),
                    "source_ip":    ip,
                    "source_port":  port,
                    "dest_port":    dport,
                    "service":      svc,
                    "username":     "",
                    "password":     "",
                    "raw_payload":  _payload[:500],
                    "country":      gdata["country"],
                    "city":         gdata["city"],
                    "latitude":     gdata["latitude"],
                    "longitude":    gdata["longitude"],
                    "attack_type":  _at,
                    "threat_level": _tl,
                    "cve_id":       "",
                    "scanner_tool": scanner_tool,
                    "user_agent":   ua,
                })
                conn.sendall(_http_resp(500, "application/json", b'{"error":"internal"}'))
                return

        # ── Decoy file downloads ──────────────────────────────────────────────
        # Serve realistic fake content for bait paths (firmware, passwd, configs).
        # Honeytoken alert + DB log already fired above at the honeytoken check.
        if method == "GET" and path in _DECOY_FILES:
            ct, fname, body = _DECOY_FILES[path]
            extra = f'Content-Disposition: attachment; filename="{fname}"\r\n'
            conn.sendall(_http_resp(200, ct, body, extra))
            return

        # ── Route → response ──────────────────────────────────────────────────
        # Camera dashboard — rendered fresh each request so the timestamp is live
        if path == "/doc/page/main.asp" and method == "GET":
            conn.sendall(_http_resp(200, "text/html", _camera_dashboard().encode()))
            return

        if path in HTTP_ROUTES:
            route     = HTTP_ROUTES[path]
            status    = route[0]
            ct        = route[1]
            resp_body = route[2]
            extra_hdr = route[3] if len(route) > 3 else ""

            # POST to credential-capture paths: accept weak creds, deny others
            if method == "POST" and path in _LOGIN_PATHS:
                fields = _parse_post_body(post_body) if post_body else {}
                u, p   = _extract_creds(fields)
                if (u.lower(), p) in _WEAK_CREDS or (u.lower(), p.lower()) in _WEAK_CREDS:
                    # Accepted — redirect to fake camera dashboard with session cookie
                    session_id = "".join(random.choices("ABCDEF0123456789", k=16))
                    dash = _camera_dashboard().encode()
                    conn.sendall(_http_resp(200, "text/html", dash,
                        f"Set-Cookie: WebSession={session_id}; Path=/; HttpOnly\r\n"))
                else:
                    denied = _auth_denied_page(back_url="/doc/page/login.asp").encode()
                    conn.sendall(_http_resp(401, "text/html", denied))
                return

            conn.sendall(_http_resp(status, ct, resp_body, extra_hdr))

        elif any(x in path for x in ["wp-", "wordpress"]):
            conn.sendall(_http_resp(200, "text/html", HTTP_ROUTES["/wp-login.php"][2]))

        elif any(x in path.lower() for x in ["phpmyadmin", "pma"]):
            conn.sendall(_http_resp(200, "text/html", HTTP_ROUTES["/phpMyAdmin/"][2]))

        elif "backup" in path.lower() or path.endswith((".sql", ".zip", ".tar.gz")):
            conn.sendall(_http_resp(403, "text/html", b"<h1>403 Forbidden</h1>"))

        elif path.startswith("/api"):
            intel    = intel_fields_func(gdata)
            api_body = json.dumps({
                "status":    "ok",
                "version":   "1.0.0",
                "ip":        ip,
                "country":   gdata["country"],
                "city":      gdata["city"],
                "latitude":  gdata["latitude"],
                "longitude": gdata["longitude"],
                **intel,
            }).encode()
            conn.sendall(_http_resp(200, "application/json", api_body))

        elif path.startswith("/ISAPI"):
            conn.sendall(_http_resp(401, "application/xml",
                b'<?xml version="1.0"?><ResponseStatus>'
                b'<statusCode>401</statusCode>'
                b'<statusString>Unauthorized</statusString>'
                b'</ResponseStatus>'))

        else:
            conn.sendall(_http_resp(404, "text/html",
                b"<html><body><h1>404 Not Found</h1></body></html>"))

    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass