#!/usr/bin/env python3
"""
Machine Learning Features Extraction
Generates 30+ features from attacks for clustering, anomaly detection, and classification.
"""

import hashlib
from datetime import datetime


class MLFeaturesExtractor:
    """Extract ML features from attack data"""
    
    @staticmethod
    def extract(attack_data, historical_data=None):
        """
        Extract 30+ features for ML analysis.
        
        Returns: {
            "basic": {...},        # IP, time, service
            "payload": {...},      # Text analysis
            "behavioral": {...},   # Attack patterns
            "temporal": {...},     # Time-based
        }
        """
        features = {}
        
        # ── Basic Features ─────────────────────────────────────────────────
        features["ip"] = attack_data.get("source_ip", "")
        features["service"] = attack_data.get("service", "")
        features["port"] = attack_data.get("dest_port", 0)
        features["protocol"] = attack_data.get("protocol", "TCP")
        features["country"] = attack_data.get("country", "")
        features["is_tor"] = 1 if attack_data.get("is_tor") else 0
        
        # ── Payload Features ───────────────────────────────────────────────
        payload = attack_data.get("payload", "")
        features["payload_length"] = len(payload)
        features["payload_entropy"] = MLFeaturesExtractor._entropy(payload)
        features["payload_hash"] = hashlib.md5(payload.encode()).hexdigest()[:8]
        features["has_shellcode"] = 1 if any(x in payload for x in ["\\x90", "\\xcc", "\\xcd"]) else 0
        
        # Text characteristics
        features["payload_upper_ratio"] = len([c for c in payload if c.isupper()]) / max(len(payload), 1)
        features["payload_digit_ratio"] = len([c for c in payload if c.isdigit()]) / max(len(payload), 1)
        features["payload_special_chars"] = len([c for c in payload if not c.isalnum()]) / max(len(payload), 1)
        
        # ── Attack Type Features ───────────────────────────────────────────
        attack_type = attack_data.get("attack_type", "").lower()
        features["is_bruteforce"] = 1 if "brute" in attack_type else 0
        features["is_scanner"] = 1 if "scan" in attack_type else 0
        features["is_exploit"] = 1 if "exploit" in attack_type else 0
        features["is_botnet"] = 1 if attack_data.get("is_botnet") else 0
        
        # ── Credential Features ────────────────────────────────────────────
        username = attack_data.get("username", "")
        password = attack_data.get("password", "")
        features["has_credentials"] = 1 if (username or password) else 0
        features["username_length"] = len(username)
        features["password_length"] = len(password)
        features["is_default_cred"] = 1 if MLFeaturesExtractor._is_default(username, password) else 0
        
        # ── Command Features ───────────────────────────────────────────────
        commands = attack_data.get("commands", [])
        features["command_count"] = len(commands)
        features["has_wget_curl"] = 1 if any("wget" in c or "curl" in c for c in commands) else 0
        features["has_chmod"] = 1 if any("chmod" in c for c in commands) else 0
        features["has_cron"] = 1 if any("cron" in c for c in commands) else 0
        features["has_persistence_attempt"] = 1 if any(x in " ".join(commands) for x in ["rc.d", "init.d", "crontab"]) else 0
        
        # ── CVE & Threat Features ──────────────────────────────────────────
        features["cve_id"] = attack_data.get("cve_id", "")
        features["threat_level_score"] = MLFeaturesExtractor._threat_to_score(
            attack_data.get("threat_level", "low")
        )
        
        # ── Temporal Features (if historical data available) ───────────────
        if historical_data:
            features["attacks_from_ip_24h"] = historical_data.get("attacks_24h", 0)
            features["unique_services_attacked"] = historical_data.get("unique_services", 0)
            features["time_since_first_attack"] = historical_data.get("hours_active", 0)
        else:
            features["attacks_from_ip_24h"] = 1
            features["unique_services_attacked"] = 1
            features["time_since_first_attack"] = 0
        
        # ── HTTP-Specific Features ─────────────────────────────────────────
        if attack_data.get("service") == "http":
            path = attack_data.get("path", "")
            method = attack_data.get("method", "")
            features["http_method"] = method
            features["http_path_depth"] = path.count("/")
            features["http_path_length"] = len(path)
            features["has_sql_injection"] = 1 if "'" in path or "drop" in path.lower() else 0
            features["has_path_traversal"] = 1 if ".." in path else 0
        
        # ── Geographic Features ────────────────────────────────────────────
        features["latitude"] = attack_data.get("latitude", 0)
        features["longitude"] = attack_data.get("longitude", 0)
        features["distance_from_honeypot"] = MLFeaturesExtractor._calc_distance(
            features["latitude"], features["longitude"]
        )
        
        return features
    
    @staticmethod
    def _entropy(text):
        """Calculate Shannon entropy of text (0-1 scale)"""
        if not text:
            return 0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        import math
        entropy = 0
        for count in freq.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        
        return min(entropy / 8, 1.0)  # Normalize to 0-1
    
    @staticmethod
    def _is_default(username, password):
        """Check if credentials are default/well-known"""
        defaults = [
            ("admin", "admin"),
            ("root", "root"),
            ("root", "12345"),
            ("admin", "12345"),
            ("admin", "password"),
            ("guest", "guest"),
        ]
        return (username, password) in defaults
    
    @staticmethod
    def _threat_to_score(threat_level):
        """Convert threat level to numeric score"""
        levels = {"low": 1, "medium": 5, "high": 7, "critical": 10}
        return levels.get(threat_level, 1)
    
    @staticmethod
    def _calc_distance(lat, lon, honeypot_lat=20, honeypot_lon=10):
        """Calculate distance from honeypot (simplified)"""
        if not lat or not lon:
            return 0
        
        # Simplified Haversine-like calculation
        import math
        dlat = abs(lat - honeypot_lat)
        dlon = abs(lon - honeypot_lon)
        distance = math.sqrt(dlat**2 + dlon**2) * 111  # rough km conversion
        return min(distance, 20000)  # Cap at 20k km


class AnomalyDetector:
    """Detect anomalous attacks"""
    
    def __init__(self):
        self.baseline = {}  # service -> baseline stats
        self.samples = {}   # service -> [features]
    
    def add_sample(self, features):
        """Add feature vector to baseline"""
        service = features.get("service", "unknown")
        if service not in self.samples:
            self.samples[service] = []
        self.samples[service].append(features)
    
    def is_anomaly(self, features, threshold=2.5):
        """
        Detect if attack is anomalous (deviation from baseline).
        threshold: standard deviations from mean
        """
        service = features.get("service", "unknown")
        if service not in self.samples or len(self.samples[service]) < 5:
            return False  # Need baseline
        
        # Simple approach: check payload length deviation
        lengths = [s.get("payload_length", 0) for s in self.samples[service]]
        mean = sum(lengths) / len(lengths)
        
        import math
        variance = sum((x - mean) ** 2 for x in lengths) / len(lengths)
        std_dev = math.sqrt(variance)
        
        if std_dev == 0:
            return False
        
        z_score = abs((features.get("payload_length", 0) - mean) / std_dev)
        return z_score > threshold


class AttackClusterer:
    """Cluster similar attacks together"""
    
    @staticmethod
    def cluster_by_payload(features_list, similarity_threshold=0.8):
        """
        Cluster attacks by payload similarity.
        Groups similar payloads together.
        """
        clusters = []
        assigned = set()
        
        for i, f1 in enumerate(features_list):
            if i in assigned:
                continue
            
            cluster = [i]
            assigned.add(i)
            
            for j, f2 in enumerate(features_list[i+1:], start=i+1):
                if j in assigned:
                    continue
                
                # Simple similarity: hash match or similar length
                if f1.get("payload_hash") == f2.get("payload_hash"):
                    cluster.append(j)
                    assigned.add(j)
                elif abs(f1.get("payload_length", 0) - f2.get("payload_length", 0)) < 50:
                    cluster.append(j)
                    assigned.add(j)
            
            clusters.append(cluster)
        
        return clusters
    
    @staticmethod
    def cluster_by_behavior(features_list):
        """Cluster by attack behavior pattern"""
        clusters = {
            "bruteforce": [],
            "scanning": [],
            "exploits": [],
            "malware": [],
            "other": [],
        }
        
        for i, f in enumerate(features_list):
            if f.get("is_bruteforce"):
                clusters["bruteforce"].append(i)
            elif f.get("is_scanner"):
                clusters["scanning"].append(i)
            elif f.get("is_exploit"):
                clusters["exploits"].append(i)
            elif f.get("has_wget_curl") or f.get("has_persistence_attempt"):
                clusters["malware"].append(i)
            else:
                clusters["other"].append(i)
        
        return {k: v for k, v in clusters.items() if v}
