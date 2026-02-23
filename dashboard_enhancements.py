#!/usr/bin/env python3
"""
Dashboard API Enhancements
New API endpoints for the dashboard to display threat intelligence.
Add these to dashboard.py
"""

# Add these functions to dashboard.py and wire them up with @app.route()

def add_to_dashboard():
    """
    Copy-paste these functions into dashboard.py after the existing API routes.
    """
    
    code = '''
# ─── THREAT INTELLIGENCE ENDPOINTS ────────────────────────────────────────

@app.route("/api/threat-scores")
@cached(10)
def api_threat_scores():
    """Get top 20 most dangerous IPs by risk score"""
    hours = request.args.get("hours", 24, type=int)
    rows = db.query("""
        SELECT 
            source_ip,
            risk_score,
            risk_level,
            factors,
            timestamp
        FROM threat_scores
        WHERE timestamp > datetime('now', '-' || ? || ' hours')
        ORDER BY risk_score DESC
        LIMIT 20
    """, (hours,))
    
    return jsonify({
        "scores": rows,
        "count": len(rows),
        "max_risk": max([r["risk_score"] for r in rows] or [0]),
    })


@app.route("/api/attack-chains")
@cached(15)
def api_attack_chains():
    """Get detected attack chains/progressions"""
    rows = db.query("""
        SELECT 
            source_ip,
            chain_id,
            stages,
            timestamp,
            is_active
        FROM attack_chains
        WHERE is_active = 1 OR timestamp > datetime('now', '-7 days')
        ORDER BY timestamp DESC
        LIMIT 50
    """)
    
    import json
    for r in rows:
        try:
            r["stages"] = json.loads(r["stages"] or "[]")
        except:
            r["stages"] = []
    
    return jsonify({
        "chains": rows,
        "active_count": sum(1 for r in rows if r["is_active"]),
    })


@app.route("/api/device-fingerprints")
@cached(20)
def api_device_fingerprints():
    """What IoT devices attackers think we are"""
    rows = db.query("""
        SELECT 
            device_type,
            vendor,
            model,
            firmware,
            COUNT(*) as frequency
        FROM device_fingerprints
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY device_type, vendor, model
        ORDER BY frequency DESC
    """)
    
    return jsonify({
        "fingerprints": rows,
        "unique_devices": len(rows),
        "total_fingerprints": sum(r["frequency"] for r in rows),
    })


@app.route("/api/ip-profiles")
@cached(15)
def api_ip_profiles():
    """Get detailed attacker IP profiles"""
    rows = db.query("""
        SELECT 
            source_ip,
            total_attacks,
            unique_services,
            is_botnet,
            is_tor,
            reputation_score,
            first_seen,
            last_seen
        FROM ip_profiles
        WHERE total_attacks > 2
        ORDER BY reputation_score DESC
        LIMIT 50
    """)
    
    return jsonify({
        "profiles": rows,
        "count": len(rows),
        "botnet_count": sum(1 for r in rows if r["is_botnet"]),
        "tor_count": sum(1 for r in rows if r["is_tor"]),
    })


@app.route("/api/anomalies")
@cached(5)
def api_anomalies():
    """Get anomalous attacks detected by ML"""
    from ml_features import MLFeaturesExtractor, AnomalyDetector
    
    # Get recent attacks
    recent = db.query("""
        SELECT * FROM attacks
        WHERE timestamp > datetime('now', '-1 hour')
        LIMIT 100
    """)
    
    # Build detector from historical baseline
    historical = db.query("""
        SELECT * FROM attacks
        WHERE timestamp > datetime('now', '-7 days')
        AND threat_level = 'low'
        LIMIT 500
    """)
    
    detector = AnomalyDetector()
    extractor = MLFeaturesExtractor()
    
    for attack in historical:
        features = extractor.extract(attack)
        detector.add_sample(features)
    
    # Find anomalies in recent
    anomalies = []
    for attack in recent:
        features = extractor.extract(attack)
        if detector.is_anomaly(features, threshold=2.0):
            anomalies.append({
                "ip": attack["source_ip"],
                "service": attack["service"],
                "timestamp": attack["timestamp"],
                "payload_length": features["payload_length"],
                "entropy": features["payload_entropy"],
            })
    
    return jsonify({
        "anomalies": anomalies,
        "count": len(anomalies),
    })


@app.route("/api/threat-timeline")
@cached(10)
def api_threat_timeline():
    """Timeline of threat level over time"""
    hours = request.args.get("hours", 24, type=int)
    
    rows = db.query("""
        SELECT 
            strftime('%Y-%m-%d %H:00', timestamp) as hour,
            threat_level,
            COUNT(*) as count,
            AVG(CASE 
                WHEN threat_level = 'critical' THEN 4
                WHEN threat_level = 'high' THEN 3
                WHEN threat_level = 'medium' THEN 2
                ELSE 1 END) as avg_severity
        FROM attacks
        WHERE timestamp > datetime('now', '-' || ? || ' hours')
        GROUP BY hour, threat_level
        ORDER BY hour ASC
    """, (hours,))
    
    # Pivot for chart
    timeline = {}
    for r in rows:
        if r["hour"] not in timeline:
            timeline[r["hour"]] = {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "severity": 0
            }
        timeline[r["hour"]][r["threat_level"]] = r["count"]
        timeline[r["hour"]]["severity"] = r["avg_severity"]
    
    return jsonify({"timeline": timeline})


@app.route("/api/campaign-analysis")
@cached(30)
def api_campaign_analysis():
    """Detect and analyze coordinated attack campaigns"""
    from threat_intel import AttackCorrelator
    
    # Get all attacks from last 24 hours
    attacks = db.query("""
        SELECT * FROM attacks
        WHERE timestamp > datetime('now', '-24 hours')
    """)
    
    correlator = AttackCorrelator()
    for attack in attacks:
        correlator.add_attack(attack["source_ip"], attack)
    
    campaigns = correlator.detect_campaign(min_ips=3, min_attacks=5)
    
    return jsonify({
        "campaigns": campaigns,
        "campaign_count": len(campaigns),
        "suspected_botnets": [c for c in campaigns if "mirai" in str(c).lower()],
    })


@app.route("/api/risk-distribution")
@cached(20)
def api_risk_distribution():
    """Distribution of risk levels"""
    rows = db.query("""
        SELECT 
            risk_level,
            COUNT(*) as count,
            MIN(risk_score) as min_score,
            MAX(risk_score) as max_score,
            AVG(risk_score) as avg_score
        FROM threat_scores
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY risk_level
    """)
    
    distribution = {r["risk_level"]: r["count"] for r in rows}
    
    return jsonify({
        "distribution": distribution,
        "details": rows,
        "total_scored": sum(r["count"] for r in rows),
    })


@app.route("/api/malware-families")
@cached(20)
def api_malware_families():
    """Malware family distribution"""
    from threat_intel import MalwareFamilyClassifier
    import json
    
    rows = db.query("""
        SELECT 
            family,
            COUNT(*) as frequency,
            COUNT(DISTINCT source_ip) as unique_ips
        FROM malware_urls
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY family
        ORDER BY frequency DESC
    """)
    
    return jsonify({
        "families": rows,
        "total_downloads": sum(r["frequency"] for r in rows),
        "unique_families": len(rows),
    })


@app.route("/api/service-risk-matrix")
@cached(15)
def api_service_risk_matrix():
    """Risk heatmap: services vs threat levels"""
    rows = db.query("""
        SELECT 
            service,
            threat_level,
            COUNT(*) as count
        FROM attacks
        WHERE timestamp > datetime('now', '-24 hours')
        GROUP BY service, threat_level
    """)
    
    matrix = {}
    for r in rows:
        if r["service"] not in matrix:
            matrix[r["service"]] = {}
        matrix[r["service"]][r["threat_level"]] = r["count"]
    
    return jsonify({
        "matrix": matrix,
        "services": list(matrix.keys()),
        "threat_levels": ["low", "medium", "high", "critical"],
    })


@app.route("/api/export-ml-features")
def api_export_ml_features():
    """Export features for ML analysis"""
    from ml_features import MLFeaturesExtractor
    import json
    
    limit = request.args.get("limit", 1000, type=int)
    attacks = db.query("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?", (limit,))
    
    extractor = MLFeaturesExtractor()
    features_list = []
    
    for attack in attacks:
        features = extractor.extract(attack)
        features_list.append(features)
    
    # Return as JSONL download
    from io import StringIO
    output = StringIO()
    for f in features_list:
        output.write(json.dumps(f) + "\\n")
    
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype="application/x-ndjson",
        headers={"Content-Disposition": "attachment;filename=ml_features.jsonl"}
    )
    '''
    
    return code


# ═════════════════════════════════════════════════════════════════════════
# NEW DASHBOARD PANELS (HTML/JavaScript)
# ═════════════════════════════════════════════════════════════════════════

DASHBOARD_PANELS = """
<!-- ══ PANEL: THREAT INTELLIGENCE ══ -->
<div class="panel" id="panel-threat-intel">
  <div class="card" style="padding:14px">
    <div class="card-title">🎯 Threat Intelligence</div>
    
    <!-- Top Dangerous IPs -->
    <div style="margin-bottom:20px">
      <h4 style="margin-bottom:10px">Top Dangerous IPs (Risk Score)</h4>
      <div id="threat-table" style="max-height:300px;overflow-y:auto">
        <table style="width:100%;font-size:11px">
          <tr style="border-bottom:1px solid var(--border)">
            <th style="text-align:left;padding:8px">IP</th>
            <th style="text-align:center">Risk</th>
            <th style="text-align:center">Level</th>
          </tr>
          <tbody id="threat-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- ══ PANEL: ATTACK CHAINS ══ -->
<div class="panel" id="panel-chains">
  <div class="card" style="padding:14px">
    <div class="card-title">🔗 Attack Chains Detected</div>
    <div id="chains-list" style="max-height:400px;overflow-y:auto"></div>
  </div>
</div>

<!-- ══ PANEL: DEVICE FINGERPRINTS ══ -->
<div class="panel" id="panel-fingerprints">
  <div class="card" style="padding:14px">
    <div class="card-title">🔍 Device Fingerprints</div>
    <p style="color:var(--muted);font-size:11px;margin-bottom:10px">
      What IoT devices attackers think we are
    </p>
    <div id="fingerprint-chart" style="height:250px"></div>
  </div>
</div>

<!-- ══ PANEL: RISK HEATMAP ══ -->
<div class="panel" id="panel-risk-heatmap">
  <div class="card" style="padding:14px">
    <div class="card-title">📊 Service Risk Heatmap</div>
    <div id="risk-matrix" style="overflow-x:auto">
      <table style="font-size:10px;border-collapse:collapse;margin-top:10px">
        <tr id="risk-header"></tr>
        <tbody id="risk-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ══ PANEL: ANOMALIES ══ -->
<div class="panel" id="panel-anomalies">
  <div class="card" style="padding:14px">
    <div class="card-title">⚡ ML-Detected Anomalies</div>
    <div id="anomalies-list" style="max-height:300px;overflow-y:auto"></div>
  </div>
</div>

<!-- JavaScript to load new panels -->
<script>
async function loadThreatIntel() {
  const data = await api('/api/threat-scores?hours=24');
  if (!data) return;
  
  const tbody = document.getElementById('threat-tbody');
  tbody.innerHTML = '';
  
  for (const score of (data.scores || []).slice(0, 10)) {
    const color = score.risk_level === 'critical' ? 'var(--red)' :
                  score.risk_level === 'high' ? 'var(--orange)' :
                  score.risk_level === 'medium' ? 'var(--yellow)' : 'var(--green)';
    
    const row = tbody.insertRow();
    row.innerHTML = `
      <td style="padding:8px;font-family:var(--mono)">${score.source_ip}</td>
      <td style="padding:8px;text-align:center"><b>${score.risk_score.toFixed(1)}</b></td>
      <td style="padding:8px;text-align:center;color:${color}"><b>${score.risk_level.toUpperCase()}</b></td>
    `;
  }
}

async function loadAttackChains() {
  const data = await api('/api/attack-chains');
  if (!data) return;
  
  const list = document.getElementById('chains-list');
  list.innerHTML = '';
  
  for (const chain of (data.chains || []).slice(0, 15)) {
    const stages = chain.stages.join(' → ') || 'unknown';
    const div = document.createElement('div');
    div.style.cssText = 'padding:8px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:10px';
    div.innerHTML = `
      <div style="color:var(--green);font-weight:bold">${chain.source_ip}</div>
      <div style="color:var(--muted)">${stages}</div>
      <div style="color:var(--dim);font-size:9px">${new Date(chain.timestamp).toLocaleString()}</div>
    `;
    list.appendChild(div);
  }
}

async function loadDeviceFingerprints() {
  const data = await api('/api/device-fingerprints');
  if (!data || !data.fingerprints) return;
  
  const devices = data.fingerprints.map(f => ({
    label: `${f.vendor} ${f.model}`,
    value: f.frequency
  }));
  
  // Create pie chart
  const ctx = document.createElement('canvas');
  ctx.id = 'fingerprint-canvas';
  document.getElementById('fingerprint-chart').innerHTML = '';
  document.getElementById('fingerprint-chart').appendChild(ctx);
  
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: devices.map(d => d.label),
      datasets: [{
        data: devices.map(d => d.value),
        backgroundColor: ['#ff3054', '#ff8c00', '#ffd60a', '#00ff88', '#0a84ff', '#bf5af2'],
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: 'var(--text)', font: { size: 10 } } } }
    }
  });
}

async function loadRiskHeatmap() {
  const data = await api('/api/service-risk-matrix');
  if (!data) return;
  
  const header = document.getElementById('risk-header');
  const levels = ['low', 'medium', 'high', 'critical'];
  header.innerHTML = '<th style="padding:6px;border:1px solid var(--border)">Service</th>' +
    levels.map(l => `<th style="padding:6px;border:1px solid var(--border);text-align:center">${l}</th>`).join('');
  
  const tbody = document.getElementById('risk-tbody');
  tbody.innerHTML = '';
  
  for (const service of Object.keys(data.matrix || {})) {
    const row = tbody.insertRow();
    row.innerHTML = `<td style="padding:6px;border:1px solid var(--border);font-weight:bold">${service}</td>` +
      levels.map(level => {
        const count = data.matrix[service][level] || 0;
        const intensity = count > 50 ? 0.9 : count > 10 ? 0.5 : 0.2;
        const color = level === 'critical' ? `rgba(255,48,84,${intensity})` :
                      level === 'high' ? `rgba(255,140,0,${intensity})` :
                      level === 'medium' ? `rgba(255,214,10,${intensity})` : `rgba(0,255,136,${intensity})`;
        return `<td style="padding:6px;border:1px solid var(--border);text-align:center;background:${color}">${count}</td>`;
      }).join('');
  }
}

async function loadAnomalies() {
  const data = await api('/api/anomalies');
  if (!data) return;
  
  const list = document.getElementById('anomalies-list');
  list.innerHTML = '';
  
  if (!data.anomalies || data.anomalies.length === 0) {
    list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--muted)">No anomalies detected</div>';
    return;
  }
  
  for (const anom of data.anomalies) {
    const div = document.createElement('div');
    div.style.cssText = 'padding:8px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:10px';
    div.innerHTML = `
      <div style="color:var(--yellow);font-weight:bold">⚠️ ${anom.ip}</div>
      <div style="color:var(--muted)">Service: ${anom.service} | Payload: ${anom.payload_length} bytes | Entropy: ${anom.entropy.toFixed(2)}</div>
    `;
    list.appendChild(div);
  }
}

// Load all new panels on demand
function loadNewPanels() {
  if (S.panel === 'threat-intel') loadThreatIntel();
  if (S.panel === 'chains') loadAttackChains();
  if (S.panel === 'fingerprints') loadDeviceFingerprints();
  if (S.panel === 'risk-heatmap') loadRiskHeatmap();
  if (S.panel === 'anomalies') loadAnomalies();
}

// Update every 10 seconds
setInterval(loadNewPanels, 10000);
</script>
"""

if __name__ == "__main__":
    print("Dashboard Enhancement Code")
    print("=" * 70)
    print("\n1. Copy the API route functions into dashboard.py")
    print("2. Add the HTML panels to dashboard.html")
    print("3. Add navigation items to sidebar")
    print("\nSee ENHANCEMENTS.md for details")
