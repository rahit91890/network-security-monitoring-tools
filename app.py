#!/usr/bin/env python3
"""
Flask GUI Dashboard for Network Security Monitoring Tools (NIDS)
Provides web-based interface for real-time threat visualization, 
incident response, and configuration management.

Author: rahit91890
License: MIT
"""

from flask import Flask, render_template, jsonify, request
import json
import random
from datetime import datetime, timedelta
import os
import sys

# Add core modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-secret-key-in-production'

# =============== DASHBOARD ROUTES ===============

@app.route('/')
def index():
    """Main dashboard page with real-time threat visualization"""
    return render_template('dashboard.html')

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get current system statistics and threat overview"""
    # TODO: Replace with actual data from NIDS engine
    stats = {
        'total_packets': random.randint(10000, 50000),
        'threats_detected': random.randint(10, 100),
        'anomalies': random.randint(5, 50),
        'blocked_ips': random.randint(20, 200),
        'system_status': 'active',
        'last_update': datetime.now().isoformat()
    }
    return jsonify(stats)

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get recent threat detections with details"""
    limit = request.args.get('limit', 20, type=int)
    
    # TODO: Replace with actual threat data from NIDS
    threat_types = ['SQL Injection', 'XSS', 'Port Scan', 'DDoS', 'Brute Force', 'Malware']
    severities = ['low', 'medium', 'high', 'critical']
    
    threats = []
    for i in range(limit):
        threats.append({
            'id': i + 1,
            'timestamp': (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat(),
            'type': random.choice(threat_types),
            'severity': random.choice(severities),
            'source_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'target_ip': f"192.168.1.{random.randint(1,254)}",
            'status': random.choice(['detected', 'blocked', 'investigating'])
        })
    
    return jsonify(threats)

@app.route('/api/network-traffic', methods=['GET'])
def get_network_traffic():
    """Get network traffic statistics over time"""
    hours = request.args.get('hours', 24, type=int)
    
    # TODO: Replace with actual network traffic data
    traffic_data = []
    for i in range(hours):
        traffic_data.append({
            'timestamp': (datetime.now() - timedelta(hours=hours-i)).isoformat(),
            'packets': random.randint(1000, 10000),
            'bytes': random.randint(1000000, 10000000),
            'threats': random.randint(0, 10)
        })
    
    return jsonify(traffic_data)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get active security alerts requiring attention"""
    # TODO: Replace with actual alerts from NIDS
    alert_types = ['High threat activity', 'Anomaly detected', 'Rule violation', 'Suspicious pattern']
    
    alerts = []
    for i in range(5):
        alerts.append({
            'id': i + 1,
            'message': random.choice(alert_types),
            'severity': random.choice(['medium', 'high', 'critical']),
            'timestamp': (datetime.now() - timedelta(minutes=random.randint(0, 120))).isoformat(),
            'acknowledged': random.choice([True, False])
        })
    
    return jsonify(alerts)

# =============== INCIDENT RESPONSE CONTROLS ===============

@app.route('/api/incident/block-ip', methods=['POST'])
def block_ip():
    """Block a specific IP address"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
    
    # TODO: Implement actual IP blocking via NIDS
    return jsonify({
        'success': True,
        'message': f'IP {ip_address} has been blocked',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/incident/unblock-ip', methods=['POST'])
def unblock_ip():
    """Unblock a previously blocked IP address"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
    
    # TODO: Implement actual IP unblocking
    return jsonify({
        'success': True,
        'message': f'IP {ip_address} has been unblocked',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/incident/acknowledge', methods=['POST'])
def acknowledge_alert():
    """Acknowledge a security alert"""
    data = request.get_json()
    alert_id = data.get('alert_id')
    
    if not alert_id:
        return jsonify({'error': 'Alert ID required'}), 400
    
    # TODO: Update alert status in database
    return jsonify({
        'success': True,
        'message': f'Alert {alert_id} acknowledged',
        'timestamp': datetime.now().isoformat()
    })

# =============== CONFIGURATION MANAGEMENT ===============

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current NIDS configuration"""
    # TODO: Load actual config from config.yaml
    config = {
        'network_interface': 'eth0',
        'ml_model_path': 'models/anomaly_detector.pkl',
        'signature_rules_path': 'rules/signatures.yar',
        'siem_enabled': True,
        'siem_endpoint': 'http://localhost:9200',
        'threat_feeds_enabled': True,
        'detection_threshold': 0.7
    }
    return jsonify(config)

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update NIDS configuration"""
    data = request.get_json()
    
    # TODO: Validate and save config to config.yaml
    # TODO: Reload NIDS with new configuration
    
    return jsonify({
        'success': True,
        'message': 'Configuration updated successfully',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get NIDS engine status"""
    # TODO: Get actual status from NIDS engine
    status = {
        'engine': 'running',
        'capture_active': True,
        'ml_model_loaded': True,
        'signature_db_loaded': True,
        'siem_connected': True,
        'threat_feeds_updated': True,
        'uptime_seconds': random.randint(3600, 86400)
    }
    return jsonify(status)

# =============== ML MODEL MANAGEMENT ===============

@app.route('/api/ml/retrain', methods=['POST'])
def retrain_model():
    """Trigger ML model retraining"""
    # TODO: Implement model retraining with new data
    return jsonify({
        'success': True,
        'message': 'Model retraining initiated',
        'estimated_time': '10 minutes'
    })

@app.route('/api/ml/performance', methods=['GET'])
def get_ml_performance():
    """Get ML model performance metrics"""
    # TODO: Get actual model performance data
    metrics = {
        'accuracy': 0.94,
        'precision': 0.91,
        'recall': 0.89,
        'f1_score': 0.90,
        'false_positives': random.randint(5, 20),
        'false_negatives': random.randint(2, 10),
        'last_trained': (datetime.now() - timedelta(days=7)).isoformat()
    }
    return jsonify(metrics)

# =============== ERROR HANDLERS ===============

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("="*60)
    print("Network Security Monitoring Tools - Web Dashboard")
    print("="*60)
    print(f"Starting Flask server...")
    print(f"Dashboard will be available at: http://localhost:5000")
    print(f"API endpoints available at: http://localhost:5000/api/*")
    print("="*60)
    
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
