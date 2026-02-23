#!/usr/bin/env python3
"""
IoT Device Profile Engine
Emulates multiple real IoT devices with device-specific vulnerabilities.
Provides realistic banners, firmware versions, and services.
"""

import random
from dataclasses import dataclass

@dataclass
class IoTProfile:
    vendor: str
    model: str
    firmware: str
    mac_prefix: str
    services: list  # [port, protocol, banner_name]
    vulnerabilities: list  # [CVE_ID, severity, service]
    
class HikvisionCamera:
    """Hikvision IP Camera DS-2CD2043G2-I"""
    def __init__(self):
        self.vendor = "Hikvision"
        self.model = "DS-2CD2043G2-I"
        self.firmware = "V5.7.15 build 230313"
        self.mac_prefix = "44:19:B6"
        self.vulnerabilities = [
            ("CVE-2017-7921", "critical", "http"),
            ("CVE-2021-36260", "critical", "http"),
            ("CVE-2017-7923", "critical", "http"),
        ]
    
    def get_banner(self, service):
        banners = {
            "telnet": "\r\n\r\nHikvision DS-2CD2043G2-I\r\nFirmware: V5.7.15 build 230313\r\n\r\nlogin: ",
            "http": "Server: App-webs/\r\nX-Frame-Options: SAMEORIGIN\r\n",
            "rtsp": "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hikvision RTSP Server\r\n\r\n",
            "ssh": b"SSH-2.0-dropbear_2017.75\r\n",
            "ftp": "220 Hikvision FTP Server\r\n",
        }
        return banners.get(service, "")


class DahuaCamera:
    """Dahua IP Camera IPC-HFW4431R-Z"""
    def __init__(self):
        self.vendor = "Dahua"
        self.model = "IPC-HFW4431R-Z"
        self.firmware = "V2.800.0000000.24.R"
        self.mac_prefix = "00:0C:29"
        self.vulnerabilities = [
            ("CVE-2021-33044", "critical", "http"),
            ("CVE-2021-33045", "critical", "http"),
        ]
    
    def get_banner(self, service):
        banners = {
            "telnet": "\r\n\r\nDahua IPC login: ",
            "http": "Server: Dahua-HTTP/2.0\r\nConnection: Keep-Alive\r\n",
            "rtsp": "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Dahua RTSP\r\n\r\n",
            "ssh": b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
            "ftp": "220 Dahua DVR FTP\r\n",
        }
        return banners.get(service, "")


class TPLinkRouter:
    """TP-Link Archer C7 WiFi Router"""
    def __init__(self):
        self.vendor = "TP-Link"
        self.model = "Archer C7"
        self.firmware = "3.15.3 Build 180305"
        self.mac_prefix = "64:16:F0"
        self.vulnerabilities = [
            ("CVE-2020-12812", "high", "http"),
            ("CVE-2020-14307", "high", "http"),
        ]
    
    def get_banner(self, service):
        banners = {
            "telnet": "\r\n\r\nTP-LINK Archer C7\r\nFirmware: 3.15.3\r\n\r\nLogin: ",
            "http": "Server: Linux/2.6 UPnP/1.0 miniupnpd/1.9\r\n",
        }
        return banners.get(service, "")


class MikroTikRouter:
    """MikroTik RouterOS hAP ac"""
    def __init__(self):
        self.vendor = "MikroTik"
        self.model = "hAP ac"
        self.firmware = "6.48.6"
        self.mac_prefix = "00:0C:42"
        self.vulnerabilities = [
            ("CVE-2018-14847", "critical", "http"),
        ]
    
    def get_banner(self, service):
        banners = {
            "ssh": b"SSH-2.0-ROSSSH\r\n",
            "telnet": "\r\n\r\nMikroTik RouterOS 6.48.6\r\nlogin: ",
        }
        return banners.get(service, "")


class NodeMCU:
    """NodeMCU ESP8266 IoT Board"""
    def __init__(self):
        self.vendor = "Espressif"
        self.model = "NodeMCU v3"
        self.firmware = "3.0.5"
        self.mac_prefix = "5C:CF:7F"
        self.vulnerabilities = [
            ("CVE-2020-12451", "medium", "http"),
        ]
    
    def get_banner(self, service):
        banners = {
            "telnet": "\r\n\r\nESP8266 Terminal\r\n\r\nlogin: ",
            "http": "Server: Arduino\r\n",
        }
        return banners.get(service, "")


class PiHole:
    """Raspberry Pi running Pi-hole DNS Sinkhole"""
    def __init__(self):
        self.vendor = "Raspberry Pi"
        self.model = "Pi-hole v5.x"
        self.firmware = "5.18"
        self.mac_prefix = "B8:27:EB"
        self.vulnerabilities = [
            ("CVE-2021-32256", "high", "http"),
        ]
    
    def get_banner(self, service):
        banners = {
            "http": "Server: lighttpd/1.4.59\r\n",
            "dns": "Pi-hole DNS Server v5.18\r\n",
        }
        return banners.get(service, "")


class RaspberryPi:
    """Generic Raspberry Pi Device"""
    def __init__(self):
        self.vendor = "Raspberry Pi"
        self.model = "Raspberry Pi 4"
        self.firmware = "Bullseye 5.15.76"
        self.mac_prefix = "B8:27:EB"
        self.vulnerabilities = []
    
    def get_banner(self, service):
        banners = {
            "ssh": b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n",
            "telnet": "\r\n\r\nRaspbian GNU/Linux 11\r\n\r\nlogin: ",
        }
        return banners.get(service, "")


# Device selection
DEVICES = {
    "hikvision": HikvisionCamera,
    "dahua": DahuaCamera,
    "tplink": TPLinkRouter,
    "mikrotik": MikroTikRouter,
    "nodemcu": NodeMCU,
    "pihole": PiHole,
    "raspberry": RaspberryPi,
}


def get_random_device():
    """Return a random IoT device profile"""
    device_class = random.choice(list(DEVICES.values()))
    return device_class()


def get_device(name):
    """Get specific device by name"""
    if name in DEVICES:
        return DEVICES[name]()
    return HikvisionCamera()  # Default


def generate_mac():
    """Generate random MAC address"""
    return "{}:{}:{}:{}:{}:{}".format(
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )
