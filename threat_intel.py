#!/usr/bin/env python3
"""
Threat Intelligence Module
IP reputation scoring, ASN lookup, botnet C&C detection, attack correlation.
"""

import socket
import re
import time
from collections import defaultdict

# ─── IP Reputation Scoring ───────────────────────────────────────────────────
class ReputationScorer:
    def __init__(self):
        self.cache = {}  # ip -> (score, timestamp)
        self.cache_ttl = 3600  # 1 hour
    
    def score(self, ip, attack_data):
        """
        Score attacker reputation (0-100, higher = more malicious).
        Factors: botnet creds, CVE exploits, malware, honeytokens, Tor, multiple services
        """
        if ip in self.cache:
            age = time.time() - self.cache[ip][1]
            if age < self.cache_ttl:
                return self.cache[ip][0]
        
        score = 0
        
        # Botnet activity: +25 points
        if attack_data.get("is_botnet"):
            score += 25
        
        # CVE exploit attempt: +20 points
        if attack_data.get("cve_id"):
            score += 20
        
        # Malware download: +30 points
        if attack_data.get("malware_url"):
            score += 30
        
        # Honeytoken trigger: +15 points
        if attack_data.get("is_honeytoken"):
            score += 15
        
        # Tor exit node: +10 points
        if attack_data.get("is_tor"):
            score += 10
        
        # Multi-service attack (lateral movement): +15 points
        if attack_data.get("services_targeted", 0) > 3:
            score += 15
        
        # Persistence attempts (cron, rc.d): +20 points
        if attack_data.get("persistence_attempt"):
            score += 20
        
        # High velocity (>50 attempts/minute): +10 points
        if attack_data.get("velocity", 0) > 50:
            score += 10
        
        score = min(100, score)
        self.cache[ip] = (score, time.time())
        return score


# ─── Botnet C&C Detection ────────────────────────────────────────────────────
KNOWN_BOTNET_C2_IPS = {
    # Mirai C2 nodes (example list - keep updated)
    "162.125.18.0/24": "Mirai",
    "185.220.101.0/24": "Tor Exit",
    "103.145.128.0/17": "Mirai",
}

KNOWN_BOTNET_DOMAINS = [
    "botnet.cc",
    "c2.xyz",
    "cnc.malware.net",
]

def check_known_c2(ip):
    """Check if IP matches known botnet C2"""
    try:
        ip_int = int(ip.replace(".", "").rstrip("0")) // 256
        # Simple check - in production, use proper IPDB
        for cidr, botnet in KNOWN_BOTNET_C2_IPS.items():
            pass  # Would use ipaddress.ip_address() for real check
    except:
        pass
    return None


# ─── ASN & ISP Detection ─────────────────────────────────────────────────────
def get_asn_info(ip):
    """
    Try to get ASN info for IP.
    Returns: {"asn": "AS12345", "org": "CloudFlare", "type": "datacenter|residential|unknown"}
    """
    # In production, integrate with MaxMind GeoIP database or Team Cymru
    
    known_datacenters = [
        "google",
        "amazon",
        "cloudflare",
        "digitalocean",
        "linode",
        "vultr",
        "hetzner",
        "aws",
        "azure",
    ]
    
    return {
        "asn": None,
        "org": None,
        "type": "unknown",
    }


# ─── Attack Pattern Correlation ──────────────────────────────────────────────
class AttackCorrelator:
    def __init__(self):
        self.ip_history = defaultdict(list)  # ip -> [attacks]
        self.campaigns = []  # list of related attack campaigns
    
    def add_attack(self, ip, attack):
        """Log attack and check for patterns"""
        self.ip_history[ip].append({
            "timestamp": attack.get("timestamp"),
            "service": attack.get("service"),
            "attack_type": attack.get("attack_type"),
            "payload": attack.get("payload", "")[:200],
        })
    
    def detect_campaign(self, min_ips=5, min_attacks=10):
        """
        Detect coordinated campaigns:
        - Same payloads from different IPs
        - Same targets but different times
        - Botnet propagation patterns
        """
        campaigns = []
        
        # Group by payload similarity
        payload_groups = defaultdict(list)
        for ip, attacks in self.ip_history.items():
            for attack in attacks:
                payload = attack.get("payload", "")
                if payload:
                    payload_groups[payload[:50]].append(ip)
        
        for payload, ips in payload_groups.items():
            if len(set(ips)) >= min_ips:
                campaigns.append({
                    "type": "coordinated_payload",
                    "ips_count": len(set(ips)),
                    "sample_payload": payload,
                })
        
        return campaigns
    
    def get_ip_profile(self, ip):
        """Get complete attack profile for IP"""
        attacks = self.ip_history.get(ip, [])
        if not attacks:
            return None
        
        services = set(a["service"] for a in attacks)
        attack_types = set(a["attack_type"] for a in attacks)
        
        return {
            "ip": ip,
            "total_attacks": len(attacks),
            "services_targeted": list(services),
            "attack_types": list(attack_types),
            "first_seen": attacks[0]["timestamp"] if attacks else None,
            "last_seen": attacks[-1]["timestamp"] if attacks else None,
            "time_span_seconds": None,  # Calculate if needed
        }


# ─── Malware Family Classification ───────────────────────────────────────────
class MalwareFamilyClassifier:
    """Classify malware by behavioral signatures"""
    
    FAMILIES = {
        "Mirai": {
            "indicators": ["ECCHI", "SKIDDIES", "busybox", "cat /proc/cpuinfo"],
            "targets": ["Hikvision", "DVR", "Camera"],
        },
        "Gafgyt": {
            "indicators": ["HTTPFLOOD", "UDPFLOOD", "JUNK", "HOLD"],
            "targets": ["Router", "Camera"],
        },
        "Mozi": {
            "indicators": ["mozi", "nttpd", "DHT"],
            "targets": ["Router", "Gateway"],
        },
        "Sora": {
            "indicators": ["SORA", "sora"],
            "targets": ["Generic"],
        },
        "Muhstik": {
            "indicators": ["muhstik", "irc."],
            "targets": ["Generic"],
        },
        "Okiru": {
            "indicators": ["Okiru", "bins"],
            "targets": ["ARM devices"],
        },
    }
    
    @staticmethod
    def classify(command_logs):
        """Classify malware family from commands"""
        for family, config in MalwareFamilyClassifier.FAMILIES.items():
            for indicator in config["indicators"]:
                for cmd in command_logs:
                    if indicator.lower() in cmd.lower():
                        return family
        return "Unknown"


# ─── Vulnerability Scoring (CVSS) ──────────────────────────────────────────
CVE_SEVERITY_MAP = {
    "CVE-2017-7921": 9.8,    # Hikvision auth bypass
    "CVE-2021-36260": 9.6,   # Command injection
    "CVE-2021-44228": 10.0,  # Log4Shell
    "CVE-2014-6271": 9.8,    # Shellshock
    "CVE-2024-3400": 9.4,    # PAN-OS RCE
    "CVE-2024-21887": 9.4,   # Ivanti RCE
}

def get_cve_severity(cve_id):
    """Get CVSS score for CVE"""
    return CVE_SEVERITY_MAP.get(cve_id, 5.0)


# ─── Risk Assessment Engine ───────────────────────────────────────────────────
class RiskAssessment:
    """Calculate overall risk from attack"""
    
    @staticmethod
    def calculate(attack_data):
        """
        Calculate risk score (0-100) from attack parameters.
        Returns: {"risk_level": "low|medium|high|critical", "score": float, "factors": []}
        """
        risk = 0
        factors = []
        
        # Threat level from detection
        threat_map = {"low": 10, "medium": 30, "high": 60, "critical": 90}
        threat_score = threat_map.get(attack_data.get("threat_level", "low"), 10)
        risk += threat_score * 0.4
        if threat_score > 30:
            factors.append("Elevated threat level")
        
        # CVE exploitation
        if attack_data.get("cve_id"):
            cve_score = get_cve_severity(attack_data["cve_id"])
            risk += (cve_score / 10) * 40
            factors.append(f"CVE attempt: {attack_data['cve_id']}")
        
        # Botnet activity
        if attack_data.get("is_botnet"):
            risk += 25
            factors.append("Botnet credentials used")
        
        # Malware payload
        if attack_data.get("malware_url"):
            risk += 30
            factors.append("Malware download detected")
        
        # Honeytoken trigger
        if attack_data.get("is_honeytoken"):
            risk += 35
            factors.append("Honeytoken accessed")
        
        risk = min(100, risk)
        
        if risk >= 75:
            level = "critical"
        elif risk >= 50:
            level = "high"
        elif risk >= 25:
            level = "medium"
        else:
            level = "low"
        
        return {
            "risk_level": level,
            "score": round(risk, 1),
            "factors": factors,
        }
