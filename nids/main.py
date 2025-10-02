#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS) - Core Engine

Implements ML-based anomaly detection, signature-based detection,
and behavioral analysis for real-time network traffic monitoring.
"""

import logging
import json
import threading
from typing import Dict, List, Optional
from datetime import datetime
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from collections import defaultdict

from utils import parse_packet, extract_features, load_signatures
from models import AnomalyDetector, BehaviorAnalyzer


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NIDS:
    """
    Core Network Intrusion Detection System implementing multiple detection techniques.
    """
    
    def __init__(self, interface: str = 'eth0', config: Optional[Dict] = None):
        """
        Initialize NIDS with network interface and configuration.
        
        Args:
            interface: Network interface to monitor
            config: Configuration dictionary for detection parameters
        """
        self.interface = interface
        self.config = config or self._default_config()
        
        # Initialize detection components
        self.anomaly_detector = AnomalyDetector()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.signatures = load_signatures(self.config.get('signatures_path', 'signatures.json'))
        
        # Traffic statistics
        self.stats = defaultdict(int)
        self.alerts = []
        self.running = False
        
        logger.info(f"NIDS initialized on interface {interface}")
    
    def _default_config(self) -> Dict:
        """Return default configuration."""
        return {
            'anomaly_threshold': 0.7,
            'behavior_window': 300,  # 5 minutes
            'max_alerts': 1000,
            'enable_ml': True,
            'enable_signatures': True,
            'enable_behavioral': True,
            'capture_filter': 'ip',
        }
    
    def start(self):
        """Start the NIDS monitoring."""
        self.running = True
        logger.info("Starting NIDS monitoring...")
        
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter=self.config['capture_filter'],
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            self.running = False
    
    def stop(self):
        """Stop the NIDS monitoring."""
        logger.info("Stopping NIDS monitoring...")
        self.running = False
    
    def _process_packet(self, packet):
        """Process a single captured packet."""
        try:
            # Parse packet
            packet_info = parse_packet(packet)
            if not packet_info:
                return
            
            self.stats['total_packets'] += 1
            
            # Signature-based detection
            if self.config['enable_signatures']:
                sig_alerts = self._signature_detection(packet_info)
                if sig_alerts:
                    self._generate_alerts(sig_alerts, 'signature')
            
            # ML-based anomaly detection
            if self.config['enable_ml']:
                features = extract_features(packet_info)
                if self.anomaly_detector.is_anomaly(features, self.config['anomaly_threshold']):
                    self._generate_alerts([packet_info], 'anomaly')
            
            # Behavioral analysis
            if self.config['enable_behavioral']:
                behavior_alerts = self.behavior_analyzer.analyze(packet_info)
                if behavior_alerts:
                    self._generate_alerts(behavior_alerts, 'behavioral')
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _signature_detection(self, packet_info: Dict) -> List[Dict]:
        """Perform signature-based detection."""
        alerts = []
        
        for signature in self.signatures:
            if self._match_signature(packet_info, signature):
                alerts.append({
                    'packet': packet_info,
                    'signature': signature,
                    'severity': signature.get('severity', 'medium')
                })
                self.stats['signature_matches'] += 1
        
        return alerts
    
    def _match_signature(self, packet_info: Dict, signature: Dict) -> bool:
        """Check if packet matches a signature."""
        for key, value in signature.get('match', {}).items():
            if packet_info.get(key) != value:
                return False
        return True
    
    def _generate_alerts(self, alerts: List[Dict], alert_type: str):
        """Generate and store alerts."""
        for alert in alerts:
            alert_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'type': alert_type,
                'data': alert,
                'severity': alert.get('severity', 'medium')
            }
            
            self.alerts.append(alert_data)
            self.stats[f'{alert_type}_alerts'] += 1
            
            # Trim alerts if exceeding max
            if len(self.alerts) > self.config['max_alerts']:
                self.alerts = self.alerts[-self.config['max_alerts']:]
            
            logger.warning(f"Alert generated: {alert_type} - {alert_data['severity']}")
    
    def get_stats(self) -> Dict:
        """Get current statistics."""
        return dict(self.stats)
    
    def get_alerts(self, limit: Optional[int] = None) -> List[Dict]:
        """Get recent alerts."""
        if limit:
            return self.alerts[-limit:]
        return self.alerts
    
    def export_alerts(self, filepath: str):
        """Export alerts to JSON file."""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.alerts, f, indent=2)
            logger.info(f"Alerts exported to {filepath}")
        except Exception as e:
            logger.error(f"Error exporting alerts: {e}")


def main():
    """Main entry point for NIDS."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface to monitor')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    args = parser.parse_args()
    
    # Load config if provided
    config = None
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Initialize and start NIDS
    nids = NIDS(interface=args.interface, config=config)
    
    try:
        nids.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        nids.stop()
        stats = nids.get_stats()
        logger.info(f"Final statistics: {stats}")
        nids.export_alerts('alerts.json')


if __name__ == '__main__':
    main()
