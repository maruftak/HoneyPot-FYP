#!/usr/bin/env python3
"""
IoT Device Profile Engine — SENTINEL Honeypot
Emulates Hikvision, Dahua, TP-Link, MikroTik etc.
"""

import random

class HikvisionCamera:
    def __init__(self):
        self.vendor = "Hikvision"
        self.model = "DS-2CD2042WD-I"
        self.firmware = "V5.5.82 build 180927"
        self.mac = "44:19:B6:" + ":".join(f"{random.randint(0,255):02X}" for _ in range(3))

    def get_banner(self, service):
        banners = {
            "telnet": f"\r\n\r\nHikvision {self.model}\r\nFirmware: {self.firmware}\r\n\r\nlogin: ",
            "http": f"Server: App-webs/\r\nX-Frame-Options: SAMEORIGIN\r\n",
            "rtsp": "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hikvision RTSP Server\r\n\r\n",
            "ssh": b"SSH-2.0-dropbear_2017.75\r\n",
            "ftp": "220 Hikvision FTP Server\r\n",
        }
        return banners.get(service, "")

class DahuaCamera:
    def __init__(self):
        self.vendor = "Dahua"
        self.model = "IPC-HFW4431R-Z"
        self.firmware = "V2.800.0000000.24.R"

    def get_banner(self, service):
        banners = {
            "telnet": f"\r\n\r\nDahua {self.model} login: ",
            "http": "Server: Dahua-HTTP/2.0\r\nConnection: Keep-Alive\r\n",
            "rtsp": "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Dahua RTSP\r\n\r\n",
            "ssh": b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
            "ftp": "220 Dahua DVR FTP Server\r\n",
        }
        return banners.get(service, "")

class TPLinkRouter:
    def __init__(self):
        self.vendor = "TP-Link"
        self.model = "Archer C7"
        self.firmware = "3.15.3 Build 180305"

    def get_banner(self, service):
        banners = {
            "telnet": f"\r\n\r\nTP-LINK {self.model}\r\nFirmware Version: {self.firmware}\r\n\r\nLogin: ",
            "http": "Server: GoAhead-Webs\r\nX-UA-Compatible: IE=Edge\r\n",
            "ssh": b"SSH-2.0-OpenSSH_6.7p1 Raspbian-5+deb8u8\r\n",
            "ftp": "220 TP-Link FTP ready\r\n",
        }
        return banners.get(service, "")

class MikroTikRouter:
    def __init__(self):
        self.vendor = "MikroTik"
        self.model = "RouterOS"
        self.firmware = "6.49.7 (stable)"

    def get_banner(self, service):
        banners = {
            "telnet": "\r\n\r\n  MMM      MMM       KKK                          TTTTTTTTTTT      KKK\r\n  MMMM    MMMM       KKK                          TTTTTTTTTTT      KKK\r\n  MMM MMMM MMM  III  KKK  KKK  RRRRRR    OOOOOO       TTT     III  KKK  KKK\r\n  MMM  MM  MMM  III  KKKKK     RRR  RRR OOO  OOO      TTT     III  KKKKK\r\n  MMM      MMM  III  KKK KKK   RRRRRR   OOO  OOO      TTT     III  KKK KKK\r\n  MMM      MMM  III  KKK  KKK  RRR RRR   OOOOOO       TTT     III  KKK  KKK\r\n\r\n  MikroTik RouterOS 6.49.7\r\n\r\nLogin: ",
            "http": "Server: nginx\r\nX-Powered-By: PHP/7.4\r\n",
            "ssh": b"SSH-2.0-ROSSSH\r\n",
            "ftp": "220 MikroTik FTP server ready\r\n",
        }
        return banners.get(service, "")

DEVICE_PROFILES = [HikvisionCamera, DahuaCamera, TPLinkRouter, MikroTikRouter]

class IoTDeviceManager:
    def __init__(self):
        # Pick one device profile for this honeypot instance
        self._profile = random.choice(DEVICE_PROFILES)()

    def get_banner(self, service):
        return self._profile.get_banner(service)

    @property
    def vendor(self):
        return self._profile.vendor

    @property
    def model(self):
        return self._profile.model

    @property
    def firmware(self):
        return self._profile.firmware
