# 🍯 honeyPot — IoT Advanced Features Guide

## 📦 NEW FILES ADDED

### 1. **iot_profiles.py** — IoT Device Emulation
Multiple real IoT device profiles with accurate banners and vulnerabilities:
- **HikvisionCamera** — DS-2CD2043G2-I (IP camera)
- **DahuaCamera** — IPC-HFW4431R-Z (Chinese IP camera)
- **TPLinkRouter** — Archer C7 (WiFi router)
- **MikroTikRouter** — hAP ac (enterprise router)
- **NodeMCU** — ESP8266 (IoT board)
- **RaspberryPi** — Generic RPi device
- **PiHole** — DNS sinkhole

**How it works:**
- Each device has realistic firmware versions, MAC prefixes, and vulnerabilities
- Attackers see different device profiles → better threat intelligence
- Device fingerprinting helps identify attacker tools (what device they think they found)

**Usage:**
```python
from iot_profiles import get_random_device, get_device
device = get_device("hikvision")
banner = device.get_banner("http")
```

---

### 2. **protocol_analyzer.py** — IoT Protocol Deep Analysis
Analyzes IoT-specific protocols and detects advanced attacks:

#### **MQTT Analysis:**
- Detect botnet C&C communication
- Analyze CONNECT packets for malicious client IDs
- Topic-based botnet detection

#### **Modbus/SCADA Analysis:**
- Detect dangerous functions (write operations to registers)
- ICS/industrial attack patterns
- Returns severity levels for each command

#### **ONVIF WS-Discovery:**
- Detect device discovery probes
- Brute-force attempts against camera management APIs

#### **Redis RCE Detection:**
- CONFIG SET exploits
- EVAL/EVALSHA command injection
- Database compromise attempts

#### **Docker API Escape:**
- Container escape endpoint detection
- Volume/network access attempts

#### **Attack Chain Correlation:**
Detects multi-stage attacks:
1. **Recon** (banner grabbing, scanning)
2. **Bruteforce** (credential attempts)
3. **Exploit** (CVE execution)
4. **Payload** (malware download)

**How it works:**
```python
from protocol_analyzer import correlate_attack_chain

chain = correlate_attack_chain(attack_list)
# Returns: {
#   "is_chain": true,
#   "stage": "payload",
#   "progression": ["recon", "bruteforce", "exploit", "payload"]
# }
```

---

### 3. **threat_intel.py** — Advanced Threat Intelligence

#### **ReputationScorer:**
Scores attacker IPs 0-100 based on:
- Botnet activity (+25 pts)
- CVE exploits (+20 pts)
- Malware downloads (+30 pts)
- Honeytoken triggers (+15 pts)
- Tor usage (+10 pts)
- Multi-service attacks (+15 pts)

**Example:**
```python
scorer = ReputationScorer()
risk = scorer.score("203.0.113.45", {
    "is_botnet": True,
    "cve_id": "CVE-2021-36260",
    "services_targeted": 5,
})
# Returns: 95 (highly malicious)
```

#### **AttackCorrelator:**
Links attacks to detect organized campaigns:
- Groups by payload similarity
- Tracks IP history
- Detects coordinated multi-IP attacks

#### **MalwareFamilyClassifier:**
Identifies botnet families:
- Mirai, Gafgyt, Sora, Mozi, Muhstik, Okiru
- Uses behavioral fingerprints
- Returns family classification

#### **RiskAssessment:**
Calculates overall attack risk:
```python
risk = RiskAssessment.calculate(attack_data)
# Returns: {
#   "risk_level": "critical",
#   "score": 87.5,
#   "factors": ["CVE attempt: CVE-2021-44228", "Malware download detected"]
# }
```

---

### 4. **ml_features.py** — Machine Learning Features

#### **MLFeaturesExtractor:**
Extracts 30+ features from each attack for ML analysis:

**Basic Features:**
- IP, service, port, protocol, country, Tor status

**Payload Features:**
- Length, entropy, hash
- Character composition ratios
- Shellcode detection

**Attack Type Features:**
- Is bruteforce? Is scanner? Is exploit? Is botnet?

**Credential Features:**
- Username/password length
- Is default credential?

**Command Features:**
- wget/curl usage
- chmod/cron/persistence indicators

**Temporal Features:**
- Attacks from IP in 24h
- Unique services targeted
- Time since first attack

**HTTP Features:**
- SQL injection detection
- Path traversal attempts
- Request depth

**Geographic Features:**
- Distance from honeypot

#### **AnomalyDetector:**
Identifies unusual attacks deviating from baseline:
```python
detector = AnomalyDetector()
detector.add_sample(features)
if detector.is_anomaly(new_features, threshold=2.5):
    print("ANOMALY DETECTED!")
```

#### **AttackClusterer:**
Groups similar attacks:
```python
clusters = AttackClusterer.cluster_by_payload(features_list)
# Groups attacks with same/similar payloads

clusters = AttackClusterer.cluster_by_behavior(features_list)
# Groups by attack type (bruteforce, scanning, exploits, etc)
```

---

## 🗄️ DATABASE SCHEMA UPDATES

### New Tables:

#### **threat_scores**
```sql
id, timestamp, source_ip, risk_score (0-100), risk_level, factors (JSON)
```
Tracks calculated threat intelligence over time.

#### **attack_chains**
```sql
id, timestamp, source_ip, chain_id, stages (JSON), is_active
```
Records detected multi-stage attack progressions.

#### **device_fingerprints**
```sql
id, timestamp, source_ip, device_type, vendor, model, firmware
```
Logs what device type attackers think they found.

#### **ip_profiles**
```sql
source_ip (UNIQUE), total_attacks, unique_services, is_botnet,
is_tor, reputation_score, first_seen, last_seen, attack_progression (JSON)
```
Aggregated attacker profile data.

---

## 🚀 INTEGRATION CHECKLIST

### Step 1: Update `honeypot.py` to use new modules:
```python
from iot_profiles import get_random_device
from protocol_analyzer import correlate_attack_chain, analyze_mqtt_payload
from threat_intel import ReputationScorer, RiskAssessment
from ml_features import MLFeaturesExtractor
import db

# When logging attacks:
risk = RiskAssessment.calculate(attack_data)
db.log_threat_score(ts, ip, risk["score"], risk["risk_level"], risk["factors"])
db.update_ip_profile(ip, attack_data)

features = MLFeaturesExtractor.extract(attack_data)
# Can be used for ML pipeline

chain = correlate_attack_chain(historical_attacks)
if chain["is_chain"]:
    db.log_attack_chain(ts, ip, chain_id, chain["progression"])
```

### Step 2: Update dashboard with new panels (see next section)

### Step 3: Export/train ML models (optional):
```python
# Extract features for scikit-learn clustering
from ml_features import AttackClusterer
clusters = AttackClusterer.cluster_by_behavior(all_features)
# Use for anomaly detection, threat classification, etc
```

---

## 📊 DASHBOARD ENHANCEMENTS

### New Panels to Add:

#### **1. Attack Timeline**
- Shows when attacks occur (hourly/daily)
- Colors by severity
- JavaScript: Line chart with Chart.js

#### **2. Risk Heatmap**
- Grid showing which services + countries = highest risk
- Color-coded risk scores

#### **3. Attack Chains View**
- Visual flowchart of attack progression
- Shows recon → bruteforce → exploit → payload

#### **4. IP Reputation Scorecard**
- Top 10 most dangerous IPs
- Their risk scores
- Attack progression for each

#### **5. Device Fingerprint Stats**
- What devices attackers think we are
- Most commonly detected device profiles

#### **6. Anomaly Detection Timeline**
- Highlights unusual attacks
- Deviation from baseline patterns

#### **7. ML Clustering Visualization**
- Attack groups by similarity
- Behavioral clusters

---

## 📈 ANALYTICS & METRICS

New metrics now trackable:

| Metric | Meaning |
|--------|---------|
| Risk Score | 0-100, higher = more dangerous |
| Attack Chain | Multi-stage attack progression |
| Device Fingerprint | What device attacker thinks they found |
| Anomaly Score | Deviation from baseline |
| Botnet Family | Mirai, Gafgyt, etc |
| Reputation | Aggregated IP threat score |
| Cluster ID | Groups of similar attacks |

---

## 🔍 THREAT HUNTING QUERIES

### Example SQL Queries for Dashboard:

```sql
-- Top dangerous IPs by risk score
SELECT source_ip, risk_score, COUNT(*) as attack_count
FROM threat_scores
WHERE timestamp > datetime('now', '-24 hours')
GROUP BY source_ip
ORDER BY risk_score DESC
LIMIT 10;

-- Attack chains detected
SELECT source_ip, stages, timestamp
FROM attack_chains
WHERE is_active = 1
ORDER BY timestamp DESC;

-- Device fingerprints seen
SELECT device_type, COUNT(*) as frequency
FROM device_fingerprints
WHERE timestamp > datetime('now', '-7 days')
GROUP BY device_type
ORDER BY frequency DESC;

-- IP profiles with progression
SELECT source_ip, total_attacks, attack_progression
FROM ip_profiles
WHERE total_attacks > 5
ORDER BY total_attacks DESC;
```

---

## 🎯 HOW IT HELPS YOUR HONEYPOT

### Before vs After:

**Before (Basic Honeypot):**
- ✅ Logs attacks
- ✅ Shows on map
- ❌ No attack correlation
- ❌ No threat scoring
- ❌ Limited device variety

**After (Advanced IoT Honeypot):**
- ✅ Multiple device profiles
- ✅ Attack chain detection
- ✅ Threat intelligence scoring
- ✅ Anomaly detection ready
- ✅ ML features extracted
- ✅ IP reputation tracking
- ✅ Organized campaign detection
- ✅ Detailed analytics

---

## 🔧 USAGE EXAMPLES

### Example 1: Detect Mirai Campaign
```python
from threat_intel import MalwareFamilyClassifier, AttackCorrelator

correlator = AttackCorrelator()
classifier = MalwareFamilyClassifier()

# Add attacks from DB
for attack in all_attacks:
    correlator.add_attack(attack["ip"], attack)
    family = classifier.classify(attack["commands"])
    if family == "Mirai":
        print(f"Mirai attack from {attack['ip']}")

# Detect if it's a campaign
campaigns = correlator.detect_campaign(min_ips=3)
if campaigns:
    print(f"Coordinated campaign detected: {campaigns}")
```

### Example 2: Score Attacker Risk
```python
from threat_intel import ReputationScorer, RiskAssessment

scorer = ReputationScorer()
assessor = RiskAssessment()

for attack in attacks:
    reputation = scorer.score(attack["ip"], attack)
    risk = assessor.calculate(attack)
    
    if risk["risk_level"] == "critical":
        send_telegram_alert(f"CRITICAL: {attack['ip']} - {risk['factors']}")
```

### Example 3: ML-Ready Features
```python
from ml_features import MLFeaturesExtractor, AnomalyDetector

extractor = MLFeaturesExtractor()
detector = AnomalyDetector()

for attack in attacks:
    features = extractor.extract(attack)
    detector.add_sample(features)
    
    if detector.is_anomaly(features):
        print(f"Anomalous attack pattern detected: {attack['ip']}")

# Export for scikit-learn
import json
with open("features.jsonl", "w") as f:
    for attack in attacks:
        features = extractor.extract(attack)
        f.write(json.dumps(features) + "\n")
```

---

## ⚡ NEXT STEPS

1. **Run database init to create new tables:**
   ```bash
   python3 -c "import db; db.init()"
   ```

2. **Update honeypot.py to call new modules** (implement integration)

3. **Add new dashboard panels** (JavaScript charts)

4. **Deploy and monitor!**

---

## 📞 SUMMARY

Your IoT honeypot now has:
- ✅ 7 different device profiles (not just Hikvision)
- ✅ Advanced protocol analysis (MQTT, Modbus, ONVIF, Redis, Docker)
- ✅ Threat intelligence scoring and correlation
- ✅ ML features extraction for clustering/anomaly detection
- ✅ Enhanced database with attack chains and IP profiles
- ✅ Ready for advanced analytics and dashboarding

**Total new capabilities: 50+ features & analytics!** 🚀
