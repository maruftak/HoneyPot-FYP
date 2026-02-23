#!/usr/bin/env python3
"""
Integration Example — How to use all new IoT honeypot modules
Shows practical examples of leveraging the new capabilities.
"""

# ============================================================================
# EXAMPLE 1: Complete Attack Analysis Pipeline
# ============================================================================

def analyze_complete_attack(raw_connection_data):
    """
    Demonstrates full workflow: receive attack → analyze → enrich → log
    """
    from iot_profiles import get_random_device
    from protocol_analyzer import analyze_mqtt_payload, correlate_attack_chain
    from threat_intel import ReputationScorer, RiskAssessment, AttackCorrelator
    from ml_features import MLFeaturesExtractor
    import db
    
    # Step 1: Parse raw connection
    ip = raw_connection_data["source_ip"]
    service = raw_connection_data["service"]
    payload = raw_connection_data["payload"]
    
    # Step 2: Log basic attack
    attack = {
        "timestamp": raw_connection_data["timestamp"],
        "source_ip": ip,
        "service": service,
        "payload": payload,
        "is_botnet": raw_connection_data.get("is_botnet", False),
        "cve_id": raw_connection_data.get("cve_id"),
        "country": raw_connection_data.get("country"),
        "city": raw_connection_data.get("city"),
    }
    db.log_attack(attack)
    
    # Step 3: Threat Intelligence Analysis
    scorer = ReputationScorer()
    reputation_score = scorer.score(ip, attack)
    
    risk_assessment = RiskAssessment.calculate(attack)
    db.log_threat_score(
        attack["timestamp"],
        ip,
        risk_assessment["score"],
        risk_assessment["risk_level"],
        risk_assessment["factors"]
    )
    
    # Step 4: ML Features Extraction
    ml_extractor = MLFeaturesExtractor()
    features = ml_extractor.extract(attack)
    
    # Features can be saved for ML pipeline:
    # - Anomaly detection
    # - Attack classification
    # - Clustering similar attacks
    
    # Step 5: Attack Chain Detection
    historical = db.query(
        "SELECT * FROM attacks WHERE source_ip=? ORDER BY timestamp DESC LIMIT 20",
        (ip,)
    )
    if historical:
        chain = correlate_attack_chain(historical)
        if chain["is_chain"]:
            db.log_attack_chain(
                attack["timestamp"],
                ip,
                f"chain_{ip}_{int(time.time())}",
                chain["progression"]
            )
    
    # Step 6: Update IP Profile
    db.update_ip_profile(ip, attack)
    
    # Step 7: Alert if critical
    if risk_assessment["risk_level"] == "critical":
        import alerts
        alerts.critical_threat(
            ip,
            attack["country"],
            risk_assessment["score"],
            risk_assessment["factors"]
        )
    
    return {
        "reputation_score": reputation_score,
        "risk_assessment": risk_assessment,
        "features": features,
        "chain": chain if 'chain' in locals() else None,
    }


# ============================================================================
# EXAMPLE 2: Detect Coordinated Botnet Campaign
# ============================================================================

def detect_botnet_campaign():
    """
    Scan for coordinated attacks from multiple IPs.
    Identifies organized botnet campaigns vs random script kiddies.
    """
    from threat_intel import AttackCorrelator, MalwareFamilyClassifier
    import db
    
    correlator = AttackCorrelator()
    classifier = MalwareFamilyClassifier()
    
    # Get all attacks from last 24 hours
    attacks = db.query("""
        SELECT * FROM attacks
        WHERE timestamp > datetime('now', '-24 hours')
        ORDER BY timestamp DESC
    """)
    
    # Analyze each attack
    for attack in attacks:
        correlator.add_attack(attack["source_ip"], attack)
        
        # Classify botnet family if applicable
        if attack["commands"]:
            import json
            try:
                commands = json.loads(attack["commands"])
                family = classifier.classify(commands)
                print(f"[BOTNET] {attack['source_ip']} - Family: {family}")
            except:
                pass
    
    # Detect campaigns
    campaigns = correlator.detect_campaign(min_ips=5, min_attacks=10)
    
    if campaigns:
        print(f"\n[!] ALERT: Coordinated campaign detected!")
        for campaign in campaigns:
            print(f"    Type: {campaign['type']}")
            print(f"    IPs involved: {campaign['ips_count']}")
            print(f"    Sample payload: {campaign['sample_payload'][:100]}")
    
    return campaigns


# ============================================================================
# EXAMPLE 3: ML-Based Anomaly Detection
# ============================================================================

def detect_anomalies_ml():
    """
    Uses machine learning to identify unusual attacks.
    Trains baseline from normal attacks, alerts on deviations.
    """
    from ml_features import MLFeaturesExtractor, AnomalyDetector
    import db
    
    extractor = MLFeaturesExtractor()
    detector = AnomalyDetector()
    
    # Get historical attacks (training data)
    historical = db.query("""
        SELECT * FROM attacks
        WHERE timestamp > datetime('now', '-7 days')
        AND threat_level = 'low'
        LIMIT 1000
    """)
    
    # Build baseline
    print("[ML] Building anomaly detection baseline...")
    for attack in historical:
        features = extractor.extract(attack)
        detector.add_sample(features)
    
    # Get recent attacks
    recent = db.query("""
        SELECT * FROM attacks
        WHERE timestamp > datetime('now', '-1 hour')
    """)
    
    # Check for anomalies
    anomalies = []
    for attack in recent:
        features = extractor.extract(attack)
        if detector.is_anomaly(features, threshold=2.5):
            anomalies.append({
                "ip": attack["source_ip"],
                "service": attack["service"],
                "payload_length": features["payload_length"],
                "attack_type": attack["attack_type"],
            })
    
    if anomalies:
        print(f"\n[!] {len(anomalies)} ANOMALIES DETECTED:")
        for anom in anomalies:
            print(f"    {anom['ip']} - {anom['service']} (payload: {anom['payload_length']} bytes)")
    
    return anomalies


# ============================================================================
# EXAMPLE 4: Export Features for External ML Pipeline
# ============================================================================

def export_features_for_ml(output_file="attack_features.jsonl"):
    """
    Exports all attack features to JSONL format for:
    - scikit-learn clustering
    - TensorFlow classification
    - pandas analysis
    """
    from ml_features import MLFeaturesExtractor
    import db
    import json
    
    extractor = MLFeaturesExtractor()
    
    # Get all attacks
    attacks = db.query("SELECT * FROM attacks LIMIT 10000")
    
    # Get historical data for each IP (for temporal features)
    ip_stats = {}
    for attack in attacks:
        ip = attack["source_ip"]
        if ip not in ip_stats:
            ip_count = db.scalar(
                "SELECT COUNT(*) FROM attacks WHERE source_ip=?",
                (ip,)
            )
            unique_services = db.scalar("""
                SELECT COUNT(DISTINCT service) FROM attacks WHERE source_ip=?
            """, (ip,))
            ip_stats[ip] = {
                "attacks_24h": ip_count,
                "unique_services": unique_services,
                "hours_active": 24,  # Simplified
            }
    
    # Extract and export features
    with open(output_file, 'w') as f:
        for attack in attacks:
            features = extractor.extract(
                attack,
                historical_data=ip_stats.get(attack["source_ip"], {})
            )
            f.write(json.dumps(features) + "\n")
    
    print(f"[ML] Exported {len(attacks)} attack features to {output_file}")
    print(f"    Ready for scikit-learn, TensorFlow, or pandas analysis")
    
    return output_file


# ============================================================================
# EXAMPLE 5: Real-Time Dashboard Updates
# ============================================================================

def get_dashboard_data_enhanced():
    """
    Provides enriched data for dashboard with threat intelligence.
    """
    import db
    
    data = {
        "basic_stats": db.get_stats(24),
        "threat_scores": db.query("""
            SELECT source_ip, risk_score, risk_level, factors
            FROM threat_scores
            WHERE timestamp > datetime('now', '-24 hours')
            ORDER BY risk_score DESC
            LIMIT 10
        """),
        "active_chains": db.query("""
            SELECT source_ip, stages, timestamp
            FROM attack_chains
            WHERE is_active = 1
            ORDER BY timestamp DESC
        """),
        "device_fingerprints": db.query("""
            SELECT device_type, vendor, model, COUNT(*) as frequency
            FROM device_fingerprints
            WHERE timestamp > datetime('now', '-7 days')
            GROUP BY device_type, vendor, model
            ORDER BY frequency DESC
        """),
        "dangerous_ips": db.query("""
            SELECT source_ip, total_attacks, is_botnet, is_tor, reputation_score
            FROM ip_profiles
            ORDER BY reputation_score DESC
            LIMIT 20
        """),
    }
    
    return data


# ============================================================================
# EXAMPLE 6: Integration with Existing Honeypot
# ============================================================================

def integrate_into_honeypot_main():
    """
    Shows how to integrate into honeypot.py's main attack handler.
    Add this to handle_telnet(), handle_http(), etc.
    """
    
    # In your handler function, after detecting attack:
    import time
    from datetime import datetime
    
    attack_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": "203.0.113.45",
        "service": "telnet",
        "protocol": "TCP",
        "dest_port": 23,
        "username": "admin",
        "password": "admin",
        "is_botnet": True,
        "country": "China",
        "city": "Beijing",
        "latitude": 39.90,
        "longitude": 116.40,
        "attack_type": "brute_force",
        "threat_level": "high",
        "commands": ["cat /proc/cpuinfo", "mkdir /tmp/bot"],
    }
    
    # STEP 1: Log basic attack
    import db
    db.log_attack(attack_data)
    
    # STEP 2: Add threat intelligence enrichment
    from threat_intel import RiskAssessment
    risk = RiskAssessment.calculate(attack_data)
    db.log_threat_score(
        attack_data["timestamp"],
        attack_data["source_ip"],
        risk["score"],
        risk["risk_level"],
        risk["factors"]
    )
    
    # STEP 3: Update IP profile
    db.update_ip_profile(attack_data["source_ip"], attack_data)
    
    # STEP 4: Send alert if critical
    if risk["risk_level"] == "critical":
        import alerts
        alerts._send(f"""
        🚨 CRITICAL ATTACK DETECTED
        
        IP: {attack_data['source_ip']}
        Service: {attack_data['service']}
        Risk Score: {risk['score']}/100
        Risk Level: {risk['risk_level']}
        
        Factors:
        {chr(10).join(f'  • {f}' for f in risk['factors'])}
        """)


# ============================================================================
# EXAMPLE 7: Attack Statistics & Analytics
# ============================================================================

def get_threat_analytics():
    """
    Provides threat analytics for reports and dashboards.
    """
    import db
    
    analytics = {
        "top_dangerous_countries": db.query("""
            SELECT attacks.country, 
                   COUNT(*) as attack_count,
                   AVG(threat_scores.risk_score) as avg_risk
            FROM attacks
            LEFT JOIN threat_scores ON attacks.source_ip = threat_scores.source_ip
            WHERE attacks.timestamp > datetime('now', '-24 hours')
            GROUP BY attacks.country
            ORDER BY avg_risk DESC
            LIMIT 10
        """),
        
        "attack_severity_distribution": db.query("""
            SELECT threat_level, COUNT(*) as count
            FROM attacks
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY threat_level
        """),
        
        "botnet_family_distribution": db.query("""
            SELECT attacks.source_ip, COUNT(*) as attacks_count
            FROM attacks
            WHERE is_botnet = 1
            AND timestamp > datetime('now', '-7 days')
            GROUP BY source_ip
            ORDER BY attacks_count DESC
            LIMIT 10
        """),
        
        "attack_chains_detected": db.query("""
            SELECT is_active, COUNT(*) as count
            FROM attack_chains
            WHERE timestamp > datetime('now', '-7 days')
            GROUP BY is_active
        """),
    }
    
    return analytics


# ============================================================================
# USAGE
# ============================================================================

if __name__ == "__main__":
    import time
    
    print("=" * 70)
    print("honeyPot Advanced IoT Features - Integration Examples")
    print("=" * 70)
    
    print("\n[1] Complete Attack Analysis Pipeline")
    print("    analyze_complete_attack(raw_data)")
    
    print("\n[2] Botnet Campaign Detection")
    print("    campaigns = detect_botnet_campaign()")
    
    print("\n[3] ML-Based Anomaly Detection")
    print("    anomalies = detect_anomalies_ml()")
    
    print("\n[4] Export Features for ML")
    print("    export_features_for_ml('attack_features.jsonl')")
    
    print("\n[5] Enhanced Dashboard Data")
    print("    data = get_dashboard_data_enhanced()")
    
    print("\n[6] Threat Analytics & Reports")
    print("    analytics = get_threat_analytics()")
    
    print("\n" + "=" * 70)
    print("See ENHANCEMENTS.md for complete documentation")
    print("=" * 70)
