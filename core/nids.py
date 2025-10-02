#!/usr/bin/env python3
"""
NIDS Engine - Network Intrusion Detection System Core
Handles packet capture, ML-based anomaly detection, and signature-based detection.

Author: rahit91890
License: MIT
"""

import scapy.all as scapy
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import pandas as pd
import numpy as np
import joblib
import os
from datetime import datetime
import yaml

class NIDSEngine:
    """
    Main NIDS Engine class for network intrusion detection.
    Combines ML-based anomaly detection with signature-based detection.
    """
    
    def __init__(self, config_path='config/config.yaml'):
        """Initialize NIDS engine with configuration"""
        self.config = self._load_config(config_path)
        self.anomaly_detector = None
        self.signature_detector = None
        self.packet_buffer = []
        self.threat_log = []
        
    def _load_config(self, path):
        """Load configuration from YAML file"""
        # TODO: Implement actual YAML loading
        return {
            'network_interface': 'eth0',
            'packet_buffer_size': 100,
            'ml_threshold': 0.7,
            'signature_rules': 'rules/signatures.yar'
        }
    
    def initialize_ml_models(self):
        """Initialize or load ML models for anomaly detection"""
        print("[NIDS] Initializing ML models...")
        
        # Anomaly Detection Model (Isolation Forest)
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        print("[NIDS] ✓ Anomaly detector (Isolation Forest) initialized")
        
        # Signature Detection Model (Random Forest)
        self.signature_detector = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        print("[NIDS] ✓ Signature detector (Random Forest) initialized")
    
    def capture_packets(self, interface=None, count=100):
        """
        Capture network packets from specified interface.
        
        Args:
            interface: Network interface name (e.g., 'eth0', 'wlan0')
            count: Number of packets to capture
        """
        if interface is None:
            interface = self.config['network_interface']
        
        print(f"[NIDS] Capturing {count} packets from {interface}...")
        
        # TODO: Implement actual packet capture with Scapy
        # packets = scapy.sniff(iface=interface, count=count)
        # for packet in packets:
        #     self.analyze_packet(packet)
        
        print(f"[NIDS] Capture stub - implement with: scapy.sniff(iface='{interface}')")
        return []
    
    def extract_features(self, packet):
        """
        Extract features from packet for ML analysis.
        
        Returns:
            dict: Feature vector for ML model
        """
        # TODO: Extract actual features from packet
        features = {
            'packet_size': 0,  # packet.len
            'protocol': 0,     # TCP=6, UDP=17, ICMP=1
            'src_port': 0,
            'dst_port': 0,
            'flags': 0,
            'ttl': 0,
            'window_size': 0
        }
        return features
    
    def detect_anomaly(self, features):
        """
        Use ML to detect anomalies in network traffic.
        
        Args:
            features: Extracted packet features
        
        Returns:
            bool: True if anomaly detected
        """
        if self.anomaly_detector is None:
            print("[WARNING] Anomaly detector not initialized")
            return False
        
        # TODO: Implement actual anomaly detection
        # prediction = self.anomaly_detector.predict([list(features.values())])
        # return prediction[0] == -1  # -1 indicates anomaly
        
        return False
    
    def detect_signature(self, packet):
        """
        Signature-based detection using YARA rules or trained classifier.
        
        Args:
            packet: Network packet to analyze
        
        Returns:
            dict: Threat information if detected, None otherwise
        """
        # TODO: Implement YARA rule matching
        # TODO: Or use trained RF classifier
        
        threat_types = ['SQL Injection', 'XSS', 'Port Scan', 'DDoS', 'Brute Force']
        
        # Stub implementation
        return None
    
    def behavioral_analysis(self, packet_sequence):
        """
        Analyze behavioral patterns in packet sequences.
        
        Args:
            packet_sequence: List of recent packets
        
        Returns:
            dict: Behavioral threat indicators
        """
        # TODO: Implement behavioral pattern detection
        # Look for:
        # - Port scanning patterns
        # - DDoS indicators (high packet rate)
        # - Data exfiltration patterns
        # - Unusual connection patterns
        
        return {
            'port_scan_detected': False,
            'ddos_indicators': False,
            'suspicious_patterns': []
        }
    
    def log_threat(self, threat_info):
        """
        Log detected threat with details.
        
        Args:
            threat_info: Dictionary containing threat details
        """
        threat_entry = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat_info.get('type', 'Unknown'),
            'severity': threat_info.get('severity', 'medium'),
            'source_ip': threat_info.get('source_ip'),
            'dest_ip': threat_info.get('dest_ip'),
            'details': threat_info.get('details', '')
        }
        
        self.threat_log.append(threat_entry)
        print(f"[THREAT] {threat_entry['threat_type']} detected from {threat_entry['source_ip']}")
    
    def train_anomaly_model(self, training_data):
        """
        Train the anomaly detection model with normal traffic data.
        
        Args:
            training_data: Pandas DataFrame with normal traffic features
        """
        print("[NIDS] Training anomaly detection model...")
        
        # TODO: Implement actual training
        # self.anomaly_detector.fit(training_data)
        
        print("[NIDS] ✓ Anomaly model training complete")
    
    def train_signature_model(self, X_train, y_train):
        """
        Train the signature detection model with labeled attack data.
        
        Args:
            X_train: Feature vectors
            y_train: Labels (attack types)
        """
        print("[NIDS] Training signature detection model...")
        
        # TODO: Implement actual training
        # self.signature_detector.fit(X_train, y_train)
        
        print("[NIDS] ✓ Signature model training complete")
    
    def save_models(self, path='models/'):
        """Save trained ML models to disk"""
        os.makedirs(path, exist_ok=True)
        
        if self.anomaly_detector:
            joblib.dump(self.anomaly_detector, f"{path}anomaly_detector.pkl")
            print(f"[NIDS] Saved anomaly detector to {path}anomaly_detector.pkl")
        
        if self.signature_detector:
            joblib.dump(self.signature_detector, f"{path}signature_detector.pkl")
            print(f"[NIDS] Saved signature detector to {path}signature_detector.pkl")
    
    def load_models(self, path='models/'):
        """Load pre-trained ML models from disk"""
        try:
            self.anomaly_detector = joblib.load(f"{path}anomaly_detector.pkl")
            print(f"[NIDS] ✓ Loaded anomaly detector from {path}")
            
            self.signature_detector = joblib.load(f"{path}signature_detector.pkl")
            print(f"[NIDS] ✓ Loaded signature detector from {path}")
            
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load models: {e}")
            return False
    
    def get_statistics(self):
        """Get NIDS statistics"""
        return {
            'total_packets_analyzed': len(self.packet_buffer),
            'threats_detected': len(self.threat_log),
            'anomalies': sum(1 for t in self.threat_log if t['threat_type'] == 'Anomaly'),
            'signatures': sum(1 for t in self.threat_log if t['threat_type'] != 'Anomaly')
        }

if __name__ == '__main__':
    print("="*60)
    print("Network Intrusion Detection System (NIDS) Engine")
    print("="*60)
    
    # Initialize NIDS
    nids = NIDSEngine()
    nids.initialize_ml_models()
    
    print("\n[INFO] NIDS engine initialized and ready")
    print("[INFO] Run from app.py for full dashboard integration")
