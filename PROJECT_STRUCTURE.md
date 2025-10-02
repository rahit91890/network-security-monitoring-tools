# Project Structure and Implementation Plan

This document outlines the full structure, purposes, and stubs for each component to be created for the Network Security Monitoring Tools project. Use this as a blueprint while files are being added.

## Structure

- nids/
  - main.py: Core NIDS engine (created)
  - utils.py: Packet parsing, features, signatures (created)
  - models.py: ML models and behavior analytics
- dashboard/
  - app.py: Flask app for visualization and IR
  - templates/
    - base.html, index.html, alerts.html
  - static/
    - css/style.css, js/app.js
- zero_trust/
  - main.py: Zero-trust monitoring and enforcement
  - analytics.py: UBA and continuous auth verification
- integrations/
  - siem.py: SIEM integrations
  - threat_intel.py: Threat intelligence feeds
- README.md: Setup and usage guide (to be updated)
- requirements.txt: Dependencies

## nids/models.py (stub)
```python
#!/usr/bin/env python3
from typing import List
import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self, n_estimators: int = 100, contamination: float = 0.01):
        self.model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=42)
        self._initialized = False

    def partial_fit(self, X: List[List[float]]):
        X = np.array(X)
        # IsolationForest has no partial_fit; refit with accumulated data in production
        self.model.fit(X)
        self._initialized = True

    def is_anomaly(self, features: List[float], threshold: float = 0.7) -> bool:
        X = np.array(features).reshape(1, -1)
        if not self._initialized:
            # Bootstrap with a small normal baseline
            self.model.fit(X)
            self._initialized = True
        score = -self.model.score_samples(X)[0]
        return score >= threshold

class BehaviorAnalyzer:
    def __init__(self, window: int = 300):
        self.window = window
        self.state = {}

    def analyze(self, packet_info: dict):
        # Minimal stub: return alert if accessing telnet (23) or unusual TTL
        alerts = []
        if packet_info.get('dst_port') == 23:
            alerts.append({'reason': 'Telnet access', 'severity': 'high', 'packet': packet_info})
        if packet_info.get('ttl', 64) < 10:
            alerts.append({'reason': 'Low TTL suspicious', 'severity': 'medium', 'packet': packet_info})
        return alerts
```

## dashboard/app.py (stub)
```python
from flask import Flask, render_template, jsonify, request
import os

app = Flask(__name__)

ALERTS = []

@app.route('/')
def index():
    return render_template('index.html')

@app.get('/api/alerts')
def get_alerts():
    limit = int(request.args.get('limit', 100))
    return jsonify(ALERTS[-limit:])

@app.post('/api/alerts')
def add_alert():
    data = request.json
    ALERTS.append(data)
    return {'status': 'ok'}, 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
```

## dashboard/templates/base.html (stub)
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>NSM Dashboard</title>
  <link rel="stylesheet" href="/static/css/style.css" />
</head>
<body>
  <header><h1>Network Security Monitoring</h1></header>
  <main>
    {% block content %}{% endblock %}
  </main>
  <script src="/static/js/app.js"></script>
</body>
</html>
```

## dashboard/templates/index.html (stub)
```html
{% extends 'base.html' %}
{% block content %}
<section>
  <h2>Recent Alerts</h2>
  <ul id="alerts"></ul>
</section>
{% endblock %}
```

## dashboard/static/css/style.css (stub)
```css
body { font-family: system-ui, sans-serif; margin: 0; padding: 0; }
header { background: #0d1117; color: #fff; padding: 1rem; }
main { padding: 1rem; }
#alerts li { margin: .5rem 0; border-left: 4px solid #888; padding-left: .5rem; }
```

## dashboard/static/js/app.js (stub)
```javascript
async function loadAlerts() {
  const res = await fetch('/api/alerts?limit=100');
  const data = await res.json();
  const ul = document.getElementById('alerts');
  ul.innerHTML = '';
  data.slice().reverse().forEach(a => {
    const li = document.createElement('li');
    li.textContent = `[${a.timestamp || ''}] ${a.type || 'alert'} - ${a.severity || 'medium'}`;
    ul.appendChild(li);
  });
}
setInterval(loadAlerts, 3000);
loadAlerts();
```

## zero_trust/main.py (stub)
```python
#!/usr/bin/env python3
"""Zero Trust Network Monitoring and Policy Enforcement."""
from typing import Dict, List
from datetime import datetime

class PolicyEngine:
    def __init__(self):
        self.policies: List[Dict] = []

    def load(self, policies: List[Dict]):
        self.policies = policies

    def evaluate(self, context: Dict) -> List[Dict]:
        decisions = []
        for p in self.policies:
            if all(context.get(k) == v for k, v in p.get('match', {}).items()):
                decisions.append({'action': p.get('action', 'deny'), 'policy': p})
        return decisions

class ZeroTrustMonitor:
    def __init__(self):
        self.engine = PolicyEngine()

    def process_event(self, event: Dict) -> List[Dict]:
        ctx = {
            'user': event.get('user'),
            'device': event.get('device'),
            'resource': event.get('resource'),
            'time': datetime.utcnow().isoformat(),
            'risk': event.get('risk', 'low'),
        }
        return self.engine.evaluate(ctx)

if __name__ == '__main__':
    zt = ZeroTrustMonitor()
    zt.engine.load([
        {'match': {'resource': 'prod-db', 'risk': 'high'}, 'action': 'mfa_challenge'},
        {'match': {'user': 'guest'}, 'action': 'deny'},
    ])
    print(zt.process_event({'user': 'guest', 'resource': 'prod-db', 'risk': 'low'}))
```

## zero_trust/analytics.py (stub)
```python
"""User Behavior Analytics and Continuous Authentication."""
from typing import Dict, List

class UBA:
    def __init__(self):
        self.baselines: Dict[str, Dict] = {}

    def score_event(self, event: Dict) -> float:
        # Very simple baseline: penalize new device
        user = event.get('user')
        device = event.get('device')
        base = self.baselines.setdefault(user, {'devices': set()})
        score = 0.0
        if device not in base['devices']:
            score += 0.7
            base['devices'].add(device)
        return min(score, 1.0)
```

## integrations/siem.py (stub)
```python
"""SIEM integration handlers (e.g., Splunk, Elastic, QRadar)."""
from typing import Dict
import json

class SIEMClient:
    def __init__(self, kind: str = 'generic', endpoint: str = ''):
        self.kind = kind
        self.endpoint = endpoint

    def send_event(self, event: Dict):
        # Placeholder: in production send via HTTP/SDK
        print(f"[SIEM:{self.kind}] {json.dumps(event)}")
```

## integrations/threat_intel.py (stub)
```python
"""Threat intelligence feeds integration (MISP, OTX, STIX/TAXII)."""
from typing import List

class ThreatIntel:
    def __init__(self):
        self.iocs: List[str] = []

    def load_feed(self, items: List[str]):
        self.iocs.extend(items)

    def is_malicious(self, value: str) -> bool:
        return value in set(self.iocs)
```

## requirements.txt (suggested)
```
flask
scapy
numpy
scikit-learn
```

## README additions (to include)

- Python 3.10+
- Create and activate venv
- pip install -r requirements.txt
- Run NIDS: python -m nids.main -i eth0
- Run Dashboard: python dashboard/app.py
- Configure signatures.json and policies as needed
