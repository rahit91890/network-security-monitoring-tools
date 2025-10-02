#!/usr/bin/env python3
"""
Utility functions for NIDS - Network traffic parsing and feature extraction.
"""

import json
import logging
from typing import Dict, Optional, List
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Raw
import hashlib


logger = logging.getLogger(__name__)


def parse_packet(packet) -> Optional[Dict]:
    """
    Parse a network packet and extract relevant information.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        Dictionary containing packet information or None if parsing fails
    """
    try:
        if not packet.haslayer(IP):
            return None
        
        packet_info = {
            'timestamp': datetime.utcnow().isoformat(),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': packet[IP].proto,
            'ttl': packet[IP].ttl,
            'length': len(packet)
        }
        
        # TCP layer
        if packet.haslayer(TCP):
            packet_info.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'tcp_flags': packet[TCP].flags,
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack,
                'window': packet[TCP].window,
                'protocol_name': 'TCP'
            })
        
        # UDP layer
        elif packet.haslayer(UDP):
            packet_info.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport,
                'protocol_name': 'UDP'
            })
        
        # ICMP layer
        elif packet.haslayer(ICMP):
            packet_info.update({
                'icmp_type': packet[ICMP].type,
                'icmp_code': packet[ICMP].code,
                'protocol_name': 'ICMP'
            })
        
        # Payload
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            packet_info['payload_hash'] = hashlib.md5(payload).hexdigest()
            packet_info['payload_length'] = len(payload)
        
        return packet_info
        
    except Exception as e:
        logger.error(f"Error parsing packet: {e}")
        return None


def extract_features(packet_info: Dict) -> List[float]:
    """
    Extract numerical features from packet information for ML models.
    
    Args:
        packet_info: Dictionary containing packet information
        
    Returns:
        List of numerical features
    """
    features = [
        hash(packet_info.get('src_ip', '')) % 1000000,  # Source IP hash
        hash(packet_info.get('dst_ip', '')) % 1000000,  # Destination IP hash
        packet_info.get('src_port', 0),
        packet_info.get('dst_port', 0),
        packet_info.get('protocol', 0),
        packet_info.get('ttl', 0),
        packet_info.get('length', 0),
        packet_info.get('payload_length', 0),
        int(packet_info.get('tcp_flags', 0)) if 'tcp_flags' in packet_info else 0,
        packet_info.get('window', 0),
    ]
    
    return features


def load_signatures(filepath: str) -> List[Dict]:
    """
    Load attack signatures from JSON file.
    
    Args:
        filepath: Path to signatures JSON file
        
    Returns:
        List of signature dictionaries
    """
    try:
        with open(filepath, 'r') as f:
            signatures = json.load(f)
        logger.info(f"Loaded {len(signatures)} signatures from {filepath}")
        return signatures
    except FileNotFoundError:
        logger.warning(f"Signatures file not found: {filepath}. Using default signatures.")
        return get_default_signatures()
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing signatures file: {e}")
        return get_default_signatures()


def get_default_signatures() -> List[Dict]:
    """
    Return default attack signatures.
    
    Returns:
        List of default signature dictionaries
    """
    return [
        {
            'name': 'Port Scan',
            'description': 'Multiple connection attempts to different ports',
            'match': {
                'protocol_name': 'TCP',
            },
            'severity': 'medium'
        },
        {
            'name': 'SYN Flood',
            'description': 'High volume of SYN packets',
            'match': {
                'protocol_name': 'TCP',
                'tcp_flags': 2  # SYN flag
            },
            'severity': 'high'
        },
        {
            'name': 'ICMP Flood',
            'description': 'High volume of ICMP packets',
            'match': {
                'protocol_name': 'ICMP'
            },
            'severity': 'medium'
        },
        {
            'name': 'Suspicious Port Access',
            'description': 'Access to commonly exploited ports',
            'match': {
                'dst_port': 23  # Telnet
            },
            'severity': 'high'
        }
    ]


def format_alert(alert_data: Dict) -> str:
    """
    Format alert data for display.
    
    Args:
        alert_data: Alert dictionary
        
    Returns:
        Formatted alert string
    """
    return f"[{alert_data['timestamp']}] {alert_data['type'].upper()} - Severity: {alert_data['severity']}"


def calculate_packet_rate(timestamps: List[str], window_seconds: int = 60) -> float:
    """
    Calculate packet rate over a time window.
    
    Args:
        timestamps: List of ISO format timestamps
        window_seconds: Time window in seconds
        
    Returns:
        Packets per second
    """
    if not timestamps:
        return 0.0
    
    try:
        times = [datetime.fromisoformat(ts) for ts in timestamps]
        times.sort()
        
        if len(times) < 2:
            return 0.0
        
        duration = (times[-1] - times[0]).total_seconds()
        if duration == 0:
            return 0.0
        
        return len(times) / duration
        
    except Exception as e:
        logger.error(f"Error calculating packet rate: {e}")
        return 0.0


def is_private_ip(ip_address: str) -> bool:
    """
    Check if an IP address is private.
    
    Args:
        ip_address: IP address string
        
    Returns:
        True if private, False otherwise
    """
    private_ranges = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255')
    ]
    
    try:
        octets = [int(x) for x in ip_address.split('.')]
        ip_int = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        
        for start, end in private_ranges:
            start_octets = [int(x) for x in start.split('.')]
            end_octets = [int(x) for x in end.split('.')]
            start_int = (start_octets[0] << 24) + (start_octets[1] << 16) + (start_octets[2] << 8) + start_octets[3]
            end_int = (end_octets[0] << 24) + (end_octets[1] << 16) + (end_octets[2] << 8) + end_octets[3]
            
            if start_int <= ip_int <= end_int:
                return True
        
        return False
        
    except Exception:
        return False
