#!/usr/bin/env python3
"""
Protocol Analyzer
Detects and analyzes IoT-specific protocol attacks (MQTT, Modbus, ONVIF, etc).
Identifies payload patterns and malware families.
"""

import re
import json

# ─── MQTT Payload Analysis ────────────────────────────────────────────────────
MQTT_BOTNET_TOPICS = [
    "botnet/cmd",
    "mirai/cmd",
    "dga/update",
    "gafgyt/execute",
    "c2/out",
    "command",
    "control",
]

def analyze_mqtt_payload(payload_bytes):
    """Analyze MQTT CONNECT packet for botnet indicators"""
    try:
        payload = payload_bytes.decode(errors='ignore')
        indicators = {
            "is_botnet": False,
            "family": None,
            "client_id": None,
            "username": None,
        }
        
        # Detect botnet families by client ID pattern
        if "Mirai" in payload or "mirai" in payload:
            indicators["family"] = "Mirai"
            indicators["is_botnet"] = True
        elif "Gafgyt" in payload:
            indicators["family"] = "Gafgyt"
            indicators["is_botnet"] = True
        elif "Mozi" in payload:
            indicators["family"] = "Mozi"
            indicators["is_botnet"] = True
        
        return indicators
    except:
        return None


def check_mqtt_subscribe_topic(topic):
    """Check if MQTT topic matches known botnet C&C"""
    for botnet_topic in MQTT_BOTNET_TOPICS:
        if botnet_topic.lower() in topic.lower():
            return True
    return False


# ─── Modbus/SCADA Attack Detection ────────────────────────────────────────────
MODBUS_DANGEROUS_FUNCTIONS = {
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    16: "write_multiple_registers",
    23: "read_write_registers",
}

def analyze_modbus_packet(data):
    """Detect suspicious Modbus/ICS commands"""
    if len(data) < 12:
        return None
    
    try:
        # Modbus TCP frame: [Transaction ID 2][Protocol ID 2][Length 2][Unit ID 1][Function Code 1]...
        func_code = data[7]
        
        if func_code in MODBUS_DANGEROUS_FUNCTIONS:
            return {
                "function": MODBUS_DANGEROUS_FUNCTIONS[func_code],
                "severity": "high" if func_code in [5, 6, 16] else "medium",
                "is_dangerous": func_code in [5, 6, 16, 23],  # Write operations
            }
    except:
        pass
    return None


# ─── ONVIF WS-Discovery Attack Detection ──────────────────────────────────────
def analyze_onvif_request(payload):
    """Detect ONVIF/WS-Discovery reconnaissance"""
    payload_str = payload.decode(errors='ignore')
    
    indicators = {
        "is_discovery": False,
        "is_bruteforce": False,
        "targets": [],
    }
    
    if "Probe" in payload_str or "ws-discovery" in payload_str.lower():
        indicators["is_discovery"] = True
    
    if "/onvif/device_service" in payload_str or "GetDeviceInformation" in payload_str:
        indicators["is_bruteforce"] = True
    
    return indicators if (indicators["is_discovery"] or indicators["is_bruteforce"]) else None


# ─── Redis RCE Detection ──────────────────────────────────────────────────────
REDIS_DANGEROUS_COMMANDS = [
    b"CONFIG SET",
    b"SCRIPT LOAD",
    b"EVAL",
    b"EVALSHA",
    b"SLAVEOF",
    b"REPLICAOF",
]

def check_redis_rce(cmd):
    """Detect Redis RCE attempts"""
    cmd_upper = cmd.upper() if isinstance(cmd, str) else cmd.decode(errors='ignore').upper()
    
    for dangerous in REDIS_DANGEROUS_COMMANDS:
        if dangerous.decode().upper() in cmd_upper:
            return True
    return False


# ─── Docker API Escape Detection ──────────────────────────────────────────────
DOCKER_DANGEROUS_ENDPOINTS = [
    "/v1.40/containers",
    "/v1.40/images",
    "/v1.40/exec",
    "/volumes",
    "/networks",
    "/services",
]

def check_docker_escape(path):
    """Detect Docker container escape attempts"""
    for endpoint in DOCKER_DANGEROUS_ENDPOINTS:
        if endpoint.lower() in path.lower():
            return True
    return False


# ─── Malware URL Analysis ────────────────────────────────────────────────────
MALWARE_SIGNATURES = {
    "mirai": [".arm", ".mips", ".mipsel", ".sh4", ".x86"],
    "gafgyt": [".arm5", ".arm6", ".arm7", ".x86"],
    "doflo": [".arm7"],
    "sora": [".elf"],
    "okiru": [".bins", ".arm"],
}

def analyze_malware_url(url):
    """Classify malware download URL"""
    url_lower = url.lower()
    
    for family, signatures in MALWARE_SIGNATURES.items():
        for sig in signatures:
            if sig in url_lower:
                return family.upper()
    
    # Generic detection by pattern
    if re.search(r"\.(elf|bin|sh|arm|mips|x86|ppc|m68k)", url_lower):
        return "UNKNOWN_BINARY"
    
    return None


# ─── VNC RFB Protocol Detection ───────────────────────────────────────────────
def check_vnc_bruteforce(payload):
    """Detect VNC RFB protocol version exchanges (bruteforce scanner)"""
    if payload.startswith(b"RFB"):
        return True
    return False


# ─── HTTP IoT Path Detection ─────────────────────────────────────────────────
IOT_DEVICE_PATHS = {
    "/ISAPI/": "Hikvision",
    "/device/": "Dahua",
    "/cgi-bin/": "Generic DVR",
    "/api/v1/": "Generic API",
    "/admin/": "Generic Admin",
    "/.well-known/": "Discovery",
}

def detect_iot_device_type(path):
    """Detect what IoT device attacker thinks we are"""
    for pattern, device_type in IOT_DEVICE_PATHS.items():
        if pattern.lower() in path.lower():
            return device_type
    return "Unknown"


# ─── Attack Chain Detection ───────────────────────────────────────────────────
def correlate_attack_chain(attack_list):
    """
    Correlate multiple attacks from same IP to detect attack chains.
    Returns: {
        "is_chain": bool,
        "stage": str (recon, bruteforce, exploit, payload),
        "progression": [list of stages],
    }
    """
    if not attack_list:
        return None
    
    progression = []
    stages = set()
    
    for attack in attack_list:
        attack_type = attack.get("attack_type", "").lower()
        
        if "scan" in attack_type or "banner" in attack_type:
            if "recon" not in stages:
                progression.append("recon")
                stages.add("recon")
        
        elif "brute" in attack_type or "login" in attack_type:
            if "bruteforce" not in stages:
                progression.append("bruteforce")
                stages.add("bruteforce")
        
        elif "cve" in attack_type or "exploit" in attack_type:
            if "exploit" not in stages:
                progression.append("exploit")
                stages.add("exploit")
        
        elif "malware" in attack_type or "download" in attack_type:
            if "payload" not in stages:
                progression.append("payload")
                stages.add("payload")
    
    return {
        "is_chain": len(progression) > 1,
        "stage": progression[-1] if progression else "unknown",
        "progression": progression,
    }
