#!/usr/bin/env python3
"""
device_identity.py — Single source of truth for honeypot device identity.

ALL services must import from here so the device looks identical across
every protocol. A scanner that hits HTTP, RTSP, ONVIF, SSH, and FTP on the
same IP should see the exact same serial, MAC, firmware, and device name.
"""

# ─── Primary device (Hikvision IP Camera — used by HTTP, RTSP, ONVIF, SSH, FTP, Telnet, HIK_SDK) ─
HIK = {
    "model":        "DS-2CD2043G2-I",
    "full_name":    "HIKVISION DS-2CD2043G2-I",
    "vendor":       "Hikvision Digital Technology Co., Ltd.",
    "serial":       "DS-2CD2043G2-I20230313CCCH012345678",
    "mac":          "44:19:b6:7a:2c:d9",      # lowercase consistent
    "mac_upper":    "44:19:B6:7A:2C:D9",
    "firmware":     "V5.7.15 build 230313",
    "firmware_ver": "V5.7.15",
    "build_date":   "230313",
    "hardware":     "DS-2CD2043G2-I",
    "sdk_version":  "V6.1.9.48",
    "uuid":         "44194e2a-5b9c-4c9a-9c4b-12ef8e4d5f6a",
    # Network — the private LAN IP the device thinks it has
    "lan_ip":       "192.168.1.108",
    "gateway":      "192.168.1.1",
    "subnet":       "255.255.255.0",
    "dns1":         "8.8.8.8",
    "dns2":         "8.8.4.4",
    # Ports
    "http_port":    80,
    "rtsp_port":    554,
    "onvif_port":   8000,
    "sdk_port":     8200,
    # Capabilities
    "channels":     1,
    "resolution":   "2688x1520",
    "codec":        "H.264",
    # Kernel / OS (HiSilicon Hi3516EV300)
    "kernel":       "Linux version 3.10.14 (builder@hikvision) (gcc version 4.8.3) #1 SMP PREEMPT Mon Sep 18 16:26:25 CST 2017",
    "cpu":          "Hi3516EV300",
    "arch":         "armv7l",
}

# ─── Dahua DVR (port 37777) ────────────────────────────────────────────────────
DAHUA = {
    "model":        "DHI-NVR4104HS-P-4KS2/L",
    "vendor":       "Dahua Technology",
    "serial":       "2L0610DAZ00002A",
    "mac":          "3c:ef:8c:4a:1b:22",
    "firmware":     "V2.820.0000000.18.R",
    "build_date":   "2021-08-18",
    "device_type":  "NVR",
    "channels":     4,
    "lan_ip":       "192.168.1.108",
}

# ─── HiSilicon/XMEye DVR (port 34567) ─────────────────────────────────────────
XMEYE = {
    "model":        "HI3518E_50H10L_S38",
    "vendor":       "XM Technology",
    "serial":       "66H25856YADFF1234",
    "mac":          "1c:c0:e1:55:30:ab",
    "firmware":     "V4.02.R11.00000117.10010.040.0000000",
    "hardware":     "1.00",
    "device_name":  "IPC",
    "channels":     4,
    "lan_ip":       "192.168.1.108",
}

# ─── TR-069 router/CPE (port 7547) ────────────────────────────────────────────
TR069 = {
    "model":        "DSL-2750B",
    "vendor":       "D-Link",
    "oui":          "00259E",
    "serial":       "CP0611JTLNW0123",
    "firmware":     "1.06",
    "hardware":     "T1_1.0",
    "device_type":  "InternetGatewayDevice",
    "lan_ip":       "192.168.1.1",
    "ssid":         "D-Link_4A2B",
    "wifi_pass":    "94jk2xmvp7",
}

# ─── Android ADB NVR (port 5555) ──────────────────────────────────────────────
ADB_DEV = {
    "model":        "NVR-4CH-4K",
    "serial":       "HK2021040812345",
    "android_ver":  "8.1.0",
    "sdk_ver":      "27",
    "build_id":     "OPM1.171019.011.B1",
    "manufacturer": "HiChip",
    "product":      "nvr_4ch",
    "device":       "hi3798mv200",
    "cpu_abi":      "armeabi-v7a",
}

# ─── Shared default credentials ───────────────────────────────────────────────
# These are the weak creds accepted across all services.
# Consistency matters — if admin/12345 works on HTTP it should work on RTSP.
WEAK_CREDS = {
    ("admin",    ""),
    ("admin",    "admin"),
    ("admin",    "12345"),
    ("admin",    "123456"),
    ("admin",    "888888"),
    ("admin",    "Admin@2024"),
    ("admin",    "admin123"),
    ("root",     ""),
    ("root",     "root"),
    ("root",     "12345"),
    ("root",     "xc3511"),
    ("root",     "vizxv"),
    ("guest",    ""),
    ("guest",    "guest"),
    ("operator", "operator"),
    ("888888",   "888888"),
    ("666666",   "666666"),
    ("default",  ""),
    ("default",  "tluafed"),
    ("service",  ""),
    ("ubnt",     "ubnt"),
    ("user",     "user"),
}


def is_weak_cred(username: str, password: str) -> bool:
    return (username.lower(), password) in WEAK_CREDS or \
           (username.lower(), "") in WEAK_CREDS
