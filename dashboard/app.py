# Dashboard Application for Network Security Monitoring

from flask import Flask, render_template, jsonify, request
from datetime import datetime, timedelta
import json
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Mock data for demonstration
threat_data = {
    'critical': 3,
    'high': 12,
    'medium': 45,
    'low': 128
}

recent_alerts = [
    {'time': '2025-10-02 21:30:15', 'severity': 'critical', 'type': 'DDoS Attack', 'source': '192.168.1.100'},
    {'time': '2025-10-02 21:25:42', 'severity': 'high', 'type': 'Port Scan', 'source': '10.0.0.25'},
    {'time': '2025-10-02 21:20:18', 'severity': 'medium', 'type': 'Suspicious Traffic', 'source': '172.16.0.50'},
    {'time': '2025-10-02 21:15:33', 'severity': 'high', 'type': 'SQL Injection Attempt', 'source': '203.0.113.45'},
    {'time': '2025-10-02 21:10:22', 'severity': 'low', 'type': 'Failed Login Attempt', 'source': '198.51.100.10'}
]

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html', 
                         threat_summary=threat_data,
                         recent_alerts=recent_alerts[:5])

@app.route('/api/threats')
def get_threats():
    """API endpoint for threat data"""
    return jsonify(threat_data)

@app.route('/api/alerts')
def get_alerts():
    """API endpoint for recent alerts"""
    limit = request.args.get('limit', 10, type=int)
    return jsonify(recent_alerts[:limit])

@app.route('/api/network-stats')
def get_network_stats():
    """API endpoint for network statistics"""
    stats = {
        'packets_analyzed': 1250000,
        'threats_detected': 188,
        'blocked_connections': 45,
        'active_monitors': 8,
        'uptime_hours': 72.5
    }
    return jsonify(stats)

@app.route('/api/traffic-history')
def get_traffic_history():
    """API endpoint for traffic history (last 24 hours)"""
    history = []
    now = datetime.now()
    for i in range(24):
        time_point = now - timedelta(hours=23-i)
        history.append({
            'timestamp': time_point.strftime('%H:%M'),
            'packets': 50000 + (i * 1000),
            'threats': max(0, 10 - abs(i - 12))
        })
    return jsonify(history)

@app.route('/api/threat-types')
def get_threat_types():
    """API endpoint for threat type distribution"""
    types = {
        'DDoS': 15,
        'Port Scan': 42,
        'SQL Injection': 8,
        'Malware': 5,
        'Brute Force': 23,
        'Suspicious Traffic': 95
    }
    return jsonify(types)

@app.route('/alerts')
def alerts_page():
    """Detailed alerts page"""
    return render_template('alerts.html', alerts=recent_alerts)

@app.route('/analytics')
def analytics_page():
    """Analytics and reporting page"""
    return render_template('analytics.html')

@app.route('/settings')
def settings_page():
    """Settings and configuration page"""
    return render_template('settings.html')

if __name__ == '__main__':
    print("Starting Network Security Monitoring Dashboard...")
    print("Dashboard available at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
