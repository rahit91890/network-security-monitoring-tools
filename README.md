# Network Security Monitoring Tools

🛡️ A comprehensive suite of tools for Network Security Monitoring including ML-based NIDS, Zero Trust Monitor, SIEM Dashboard, and Threat Intelligence Integration.

## 📋 Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Components](#components)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

### 🔍 Network Intrusion Detection System (NIDS)
- **Real-time Traffic Analysis**: Monitor network traffic in real-time
- **ML-based Anomaly Detection**: Uses Isolation Forest for detecting unusual patterns
- **Signature-based Detection**: Random Forest classifier for known attack patterns
- **Behavioral Analysis**: Identify deviations from normal network behavior
- **Threat Visualization**: Interactive dashboard for threat analysis

### 🔐 Zero Trust Network Monitor
- **Continuous Authentication**: Verify users and devices continuously
- **Microsegmentation Monitoring**: Monitor and enforce network segmentation
- **Policy Enforcement**: Implement zero-trust security policies
- **User Behavior Analytics**: Track and analyze user activities
- **Trust Score Calculation**: Dynamic trust scoring for access decisions

### 📊 Security Dashboard
- **Real-time Metrics**: Live monitoring of security events
- **Threat Visualization**: Charts and graphs for threat analysis
- **Alert Management**: Centralized alert handling and prioritization
- **Historical Data**: Track trends and patterns over time
- **RESTful API**: Programmatic access to security data

### 🔗 Integrations
- **SIEM Integration**: Connect with existing SIEM platforms
- **Threat Intelligence**: Integrate external threat feeds
- **Automated Response**: Trigger actions based on detected threats

## 📁 Project Structure

```
network-security-monitoring-tools/
├── nids/                      # Network Intrusion Detection System
│   ├── main.py               # Main NIDS application
│   ├── models.py             # ML models (Isolation Forest, Random Forest)
│   └── utils.py              # Utility functions for packet analysis
├── dashboard/                 # Web Dashboard
│   ├── app.py                # Flask application
│   ├── templates/            # HTML templates
│   │   └── dashboard.html   # Main dashboard template
│   └── static/               # Static assets
│       └── style.css        # Dashboard styles
├── zero_trust/               # Zero Trust Monitor
│   ├── main.py              # Zero trust monitoring
│   └── analytics.py         # User behavior analytics (placeholder)
├── integrations/            # External integrations
│   ├── siem.py             # SIEM platform integration (placeholder)
│   └── threat_intel.py     # Threat intelligence feeds (placeholder)
├── LICENSE                   # MIT License
├── README.md                # This file
└── PROJECT_STRUCTURE.md     # Detailed project structure
```

## 🔧 Prerequisites

- **Python**: 3.8 or higher
- **pip**: Python package manager
- **Virtual Environment**: Recommended for isolation

### System Requirements
- **OS**: Linux, macOS, or Windows
- **RAM**: Minimum 4GB (8GB recommended)
- **Network**: Access to monitored network interfaces
- **Permissions**: Root/Administrator for packet capture

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/rahit91890/network-security-monitoring-tools.git
cd network-security-monitoring-tools
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

**Required packages:**
```
scapy>=2.5.0
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
flask>=2.3.0
joblib>=1.3.0
```

### 4. Create Requirements File (if needed)

```bash
cat > requirements.txt << EOF
scapy==2.5.0
scikit-learn==1.3.2
pandas==2.1.3
numpy==1.26.2
flask==3.0.0
joblib==1.3.2
EOF
```

## ⚙️ Configuration

### 1. Network Interface Configuration

Edit `nids/main.py` to specify your network interface:

```python
interface = "eth0"  # Change to your network interface
```

### 2. Dashboard Configuration

Update `dashboard/app.py` with your preferences:

```python
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this!
app.run(debug=True, host='0.0.0.0', port=5000)     # Configure host/port
```

### 3. Zero Trust Policies

Configure policies in `zero_trust/main.py`:

```python
config = {
    "trust_threshold": 70,
    "auth_interval": 300,  # seconds
    "microsegments": {...}
}
```

## 🚀 Usage

### Running the NIDS

```bash
# Make sure you have necessary permissions
sudo python3 nids/main.py
```

**Output:**
- Real-time packet analysis
- Anomaly detection alerts
- Attack type classification
- Statistics and summaries

### Running the Dashboard

```bash
python3 dashboard/app.py
```

Access the dashboard at: `http://localhost:5000`

**Features:**
- Live threat statistics
- Recent security alerts
- Network traffic graphs
- Threat type distribution

### Running Zero Trust Monitor

```bash
python3 zero_trust/main.py
```

**Capabilities:**
- Continuous authentication verification
- Microsegmentation enforcement
- Policy compliance checking
- Access attempt logging

## 🧩 Components

### NIDS Module (`nids/`)

**Main Components:**
- `PacketCapture`: Capture and analyze network packets
- `AnomalyDetector`: ML-based anomaly detection
- `SignatureDetector`: Known attack pattern recognition
- `ThreatAnalyzer`: Comprehensive threat analysis

**Key Functions:**
```python
from nids.models import AnomalyDetector, SignatureDetector

# Anomaly Detection
detector = AnomalyDetector()
detector.train(training_data)
anomalies = detector.predict(network_data)

# Signature Detection
sig_detector = SignatureDetector()
sig_detector.train(X_train, y_train)
attacks = sig_detector.predict(network_data)
```

### Dashboard Module (`dashboard/`)

**API Endpoints:**
- `GET /`: Main dashboard page
- `GET /api/threats`: Get threat statistics
- `GET /api/alerts`: Get recent alerts
- `GET /api/network-stats`: Get network statistics
- `GET /api/traffic-history`: Get 24h traffic history
- `GET /api/threat-types`: Get threat type distribution

**Example API Usage:**
```bash
curl http://localhost:5000/api/threats
curl http://localhost:5000/api/alerts?limit=10
```

### Zero Trust Module (`zero_trust/`)

**Core Features:**
```python
from zero_trust.main import ZeroTrustMonitor

monitor = ZeroTrustMonitor()

# Verify authentication
monitor.verify_continuous_auth("user123", "session_abc")

# Check policy compliance
result = monitor.check_policy_compliance(request)

# Get trust score
score = monitor.get_trust_score("user123")
```

### Integration Modules (`integrations/`)

**SIEM Integration** (Placeholder):
- Connect to Splunk, ELK, or other SIEM platforms
- Forward security events
- Receive threat intelligence

**Threat Intelligence** (Placeholder):
- Integrate with threat feeds (MISP, OTX, etc.)
- Enrich security events
- Automated threat lookups

## 🔒 Security Considerations

1. **Permissions**: NIDS requires root/admin privileges for packet capture
2. **Secret Keys**: Change default secret keys in production
3. **Network Access**: Secure dashboard access with authentication
4. **Data Privacy**: Handle captured data according to regulations
5. **Updates**: Keep dependencies updated for security patches

## 🛠️ Development

### Adding New Features

1. Create feature branch
2. Implement changes
3. Add tests
4. Submit pull request

### Testing

```bash
# Test NIDS
python3 -m pytest tests/test_nids.py

# Test Dashboard
python3 -m pytest tests/test_dashboard.py
```

## 📈 Future Enhancements

- [ ] Complete integrations/siem.py implementation
- [ ] Complete integrations/threat_intel.py implementation  
- [ ] Complete zero_trust/analytics.py implementation
- [ ] Add more dashboard templates (alerts.html, analytics.html, settings.html)
- [ ] Implement real-time WebSocket updates
- [ ] Add user authentication to dashboard
- [ ] Create configuration file support
- [ ] Add Docker deployment
- [ ] Implement automated testing suite
- [ ] Add database backend for persistent storage

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**rahit91890**
- GitHub: [@rahit91890](https://github.com/rahit91890)
- Repository: [network-security-monitoring-tools](https://github.com/rahit91890/network-security-monitoring-tools)

## 🙏 Acknowledgments

- Scikit-learn for ML algorithms
- Scapy for packet manipulation
- Flask for web framework
- Community contributors

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review closed issues for solutions

---

**Note**: This project is for educational and research purposes. Ensure you have proper authorization before monitoring any network.
