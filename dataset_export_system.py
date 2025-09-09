# dataset_export_system.py - Transform scenarios into ML-ready datasets
import json
import csv
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
import random
import hashlib
import pickle
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import warnings

# Suppress pandas warnings for cleaner output
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

@dataclass
class NetworkFlow:
    """Represents a network flow record"""
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration: float
    flags: str
    flow_label: str  # 'normal' or 'attack'
    attack_type: Optional[str] = None  # Specific attack type if applicable

@dataclass
class DeviceBehavior:
    """Represents device behavior record"""
    timestamp: str
    device_id: str
    device_type: str
    action: str
    frequency: float
    data_size: int
    energy_consumption: float
    status: str
    anomaly_score: float
    behavior_label: str  # 'normal' or 'malicious'
    attack_phase: Optional[str] = None  # Attack phase if applicable

@dataclass
class DatasetMetadata:
    """Dataset metadata for tracking and validation"""
    dataset_id: str
    creation_date: str
    scenarios_count: int
    normal_samples: int
    attack_samples: int
    time_range: Dict[str, str]
    device_types: List[str]
    attack_types: List[str]
    quality_score: float
    generation_parameters: Dict[str, Any]
    file_paths: Dict[str, str] = None
    data_statistics: Dict[str, Any] = None

@dataclass
class AttackScenario:
    """Mock AttackScenario class for demonstration"""
    scenario_id: str
    attack_vector: str
    target_devices: List[str]
    timeline: List[Dict[str, Any]]
    quality_score: float
    
    
class NetworkTrafficSynthesizer:
    """Generates realistic network traffic from attack scenarios"""
    
    def __init__(self):
        self.device_ip_ranges = {
            'smart_camera': '192.168.1.100-120',
            'smart_thermostat': '192.168.1.121-130', 
            'smart_doorbell': '192.168.1.131-140',
            'smart_lock': '192.168.1.141-150',
            'smart_hub': '192.168.1.151-160',
            'smart_speaker': '192.168.1.161-170',
            'smart_tv': '192.168.1.171-180',
            'smart_bulb': '192.168.1.181-190'
        }
    
    def get_device_ip(self, device_type: str) -> str:
        """Get realistic IP for device type with proper segmentation"""
        device_ip_ranges = {
            'smart_tv': '192.168.1.20-29',
            'smart_thermostat': '192.168.1.30-39', 
            'smart_camera': '192.168.1.40-49',
            'smart_doorbell': '192.168.1.45-49',
            'smart_lock': '192.168.1.35-39',
            'smart_hub': '192.168.1.1-5',
            'smartphone': '192.168.1.100-120',
            'laptop': '192.168.1.150-170'
        }
        
        ip_range = device_ip_ranges.get(device_type, '192.168.1.200-220')
        start_ip, end_ip = ip_range.split('-')
        base_ip = '.'.join(start_ip.split('.')[:-1])
        start_octet = int(start_ip.split('.')[-1])
        end_octet = int(end_ip)
        
        return f"{base_ip}.{random.randint(start_octet, end_octet)}"
    
    
      
    def _load_normal_patterns(self) -> Dict[str, Dict]:
        """Load normal traffic patterns for each device type"""
        return {
            'smart_camera': {
                'protocols': ['TCP', 'UDP'],
                'ports': [80, 443, 554, 1935, 8080],  # HTTP, HTTPS, RTSP, RTMP, Alt-HTTP
                'packet_sizes': [64, 1500, 1400, 576, 1200],
                'flow_duration': (10, 3600),  # 10 seconds to 1 hour
                'data_rates': (100, 5000),  # KB/s
                'connection_frequency': (30, 300)  # seconds between connections
            },
            'smart_thermostat': {
                'protocols': ['TCP', 'UDP'],
                'ports': [80, 443, 1883, 5683, 8883],  # HTTP, HTTPS, MQTT, CoAP, MQTT-TLS
                'packet_sizes': [64, 128, 256, 512],
                'flow_duration': (5, 60),
                'data_rates': (1, 50),
                'connection_frequency': (60, 900)
            },
            'smart_doorbell': {
                'protocols': ['TCP', 'UDP'],
                'ports': [80, 443, 554, 1883, 5684],
                'packet_sizes': [64, 1500, 1400, 800],
                'flow_duration': (5, 300),
                'data_rates': (50, 2000),
                'connection_frequency': (300, 3600)  # Event-driven
            },
            'smart_lock': {
                'protocols': ['TCP', 'UDP'], 
                'ports': [80, 443, 1883, 5684],
                'packet_sizes': [64, 128, 256],
                'flow_duration': (1, 10),
                'data_rates': (1, 10),
                'connection_frequency': (3600, 86400)  # Low frequency
            },
            'smart_hub': {
                'protocols': ['TCP', 'UDP'],
                'ports': [80, 443, 1883, 5683, 5684, 8080, 9443],
                'packet_sizes': [64, 256, 512, 1500],
                'flow_duration': (1, 7200),
                'data_rates': (10, 1000),
                'connection_frequency': (10, 60)
            },
            'smart_speaker': {
                'protocols': ['TCP', 'UDP'],
                'ports': [80, 443, 4070, 8080, 9443],
                'packet_sizes': [64, 512, 1024, 1500],
                'flow_duration': (30, 1800),
                'data_rates': (50, 500),
                'connection_frequency': (60, 1800)
            },
            'smart_tv': {
                'protocols': ['TCP', 'UDP'],
                'ports': [80, 443, 1935, 8080, 8443],
                'packet_sizes': [1500, 1400, 1200, 1024],
                'flow_duration': (300, 7200),
                'data_rates': (1000, 8000),
                'connection_frequency': (30, 600)
            },
            'smart_bulb': {
                'protocols': ['TCP', 'UDP'],
                'ports': [80, 443, 1883, 5683],
                'packet_sizes': [64, 128, 256],
                'flow_duration': (1, 30),
                'data_rates': (1, 20),
                'connection_frequency': (300, 3600)
            }
        }
    
    def _load_attack_patterns(self) -> Dict[str, Dict]:
        """Load attack traffic patterns"""
        return {
            'reconnaissance': {
                'protocols': ['TCP', 'UDP', 'ICMP'],
                'ports': list(range(1, 1025)) + [1433, 1521, 3306, 5432, 8080],  # Common + DB ports
                'packet_sizes': [64, 128],
                'flow_duration': (0.1, 2),
                'data_rates': (1, 100),
                'connection_frequency': (0.1, 1),
                'characteristics': ['high_connection_rate', 'sequential_ports', 'small_packets']
            },
            'exploitation': {
                'protocols': ['TCP', 'UDP'],
                'ports': [80, 443, 22, 23, 1883, 8080, 8443],
                'packet_sizes': [64, 1500, 2048, 4096, 8192],  # Including oversized packets
                'flow_duration': (1, 30),
                'data_rates': (10, 500),
                'connection_frequency': (1, 10),
                'characteristics': ['oversized_packets', 'malformed_requests', 'rapid_retries']
            },
            'command_control': {
                'protocols': ['TCP', 'UDP'],
                'ports': [443, 8080, 8443, 53, 9001, 4444],  # HTTPS, HTTP-Alt, DNS tunneling, C2
                'packet_sizes': [64, 256, 512, 1024],
                'flow_duration': (60, 7200),
                'data_rates': (1, 100),
                'connection_frequency': (300, 3600),
                'characteristics': ['encrypted_payload', 'periodic_beacons', 'dns_tunneling']
            },
            'data_exfiltration': {
                'protocols': ['TCP', 'UDP'],
                'ports': [80, 443, 21, 22, 25, 993, 995],  # Web, FTP, SSH, Email
                'packet_sizes': [1500, 1400, 1200, 1024],
                'flow_duration': (300, 7200),
                'data_rates': (500, 10000),
                'connection_frequency': (60, 300),
                'characteristics': ['large_uploads', 'sustained_connections', 'unusual_destinations']
            },
            'lateral_movement': {
                'protocols': ['TCP', 'UDP'],
                'ports': [22, 23, 135, 139, 445, 1883, 3389, 5985],  # SSH, Telnet, SMB, RDP, WinRM
                'packet_sizes': [64, 256, 512, 1500],
                'flow_duration': (10, 300),
                'data_rates': (10, 200),
                'connection_frequency': (30, 300),
                'characteristics': ['internal_scanning', 'credential_attempts', 'protocol_abuse']
            },
            'denial_of_service': {
                'protocols': ['TCP', 'UDP', 'ICMP'],
                'ports': [80, 443, 53, 1883],
                'packet_sizes': [64, 1500, 65535],  # Including max size packets
                'flow_duration': (0.1, 5),
                'data_rates': (1000, 50000),  # Very high rates
                'connection_frequency': (0.01, 0.1),  # Very frequent
                'characteristics': ['flood_attack', 'amplification', 'resource_exhaustion']
            }
        }
    
    def _populate_external_ips(self):
        """Pre-populate external IP cache for consistency"""
        external_ranges = [
            "8.8.8", "8.8.4", "1.1.1", "1.0.0",  # DNS servers
            "208.67.222", "208.67.220", "76.76.19", "76.76.76",  # OpenDNS
            "23.123.45", "104.244.42", "172.217.15", "142.250.191",  # CDNs/Cloud
            "54.230.123", "52.84.45", "13.107.42",  # AWS/Azure CDN
            "199.232.123", "151.101.65"  # Fastly, Reddit CDN
        ]
        
        for base in external_ranges:
            for i in range(1, 255, 10):  # Sample IPs from each range
                self.external_ip_cache.append(f"{base}.{i}")
    

    def generate_normal_traffic(self, device_type: str, duration_hours: int, start_time: datetime) -> List[NetworkFlow]:
        """Generate realistic normal traffic with proper time patterns"""
        flows = []
        
        # Realistic hourly patterns (peak evening, low night)
        hourly_multipliers = {
            0: 0.2, 1: 0.15, 2: 0.1, 3: 0.1, 4: 0.1, 5: 0.15,  # Night
            6: 0.4, 7: 0.7, 8: 1.0, 9: 1.2,  # Morning
            10: 1.1, 11: 1.1, 12: 1.0, 13: 0.9, 14: 0.8, 15: 0.9,  # Day
            16: 1.0, 17: 1.1, 18: 1.3, 19: 1.4, 20: 1.5, 21: 1.3, 22: 1.0, 23: 0.6  # Evening
        }
        
        # Generate flows hour by hour
        for hour_offset in range(duration_hours):
            current_time = start_time + timedelta(hours=hour_offset)
            hour_of_day = current_time.hour
            
            # Calculate flows for this hour based on realistic patterns
            base_flows_per_hour = self._get_base_flows_for_device(device_type)
            flows_this_hour = int(base_flows_per_hour * hourly_multipliers[hour_of_day])
            
            # Generate flows for this hour
            for _ in range(flows_this_hour):
                flow_time = current_time + timedelta(minutes=random.uniform(0, 60))
                flow = self._create_realistic_normal_flow(device_type, flow_time)
                flows.append(flow)
        
        return flows

    def _get_base_flows_for_device(self, device_type: str) -> int:
        """Get base flows per hour for device type"""
        flows_per_hour = {
            'smart_camera': 20,      # Continuous streaming
            'smart_thermostat': 1,   # Very light usage
            'smart_doorbell': 2,     # Event-driven
            'smart_lock': 0.5,       # Minimal
            'smart_hub': 10,         # Coordination traffic
            'smart_tv': 30,          # Heavy streaming
            'smartphone': 15,        # Moderate usage
            'laptop': 25             # Work/browsing
        }
        return flows_per_hour.get(device_type, 5)

    def _create_realistic_normal_flow(self, device_type: str, timestamp: datetime) -> NetworkFlow:
        """Create realistic normal flow with proper sizing"""
        
        # Realistic data sizes by device type (in bytes)
        device_data_ranges = {
            'smart_camera': (50000, 500000),    # Video chunks
            'smart_thermostat': (100, 1000),    # Small status updates
            'smart_doorbell': (10000, 100000),  # Image/video
            'smart_lock': (64, 256),            # Minimal data
            'smart_hub': (500, 5000),           # Coordination
            'smart_tv': (100000, 2000000),      # Streaming
            'smartphone': (1000, 50000),        # Web/apps
            'laptop': (5000, 200000)            # Work/browsing
        }
        
        data_range = device_data_ranges.get(device_type, (1000, 10000))
        byte_count = random.randint(*data_range)
        
        # Realistic packet count based on data size
        avg_packet_size = random.randint(800, 1500)  # Typical Ethernet
        packet_count = max(1, byte_count // avg_packet_size)
        
        # Realistic duration
        duration = random.uniform(1, 30)  # 1-30 seconds typical
        
        return NetworkFlow(
            timestamp=timestamp.isoformat(),
            src_ip=self._get_device_ip(device_type),
            dst_ip=self._generate_external_ip(),
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 1883, 53]),
            protocol=random.choice(['TCP', 'UDP']),
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            flags=random.choice(['ACK', 'PSH', 'SYN', 'FIN']),
            flow_label='normal'
        )
        
    
    def generate_attack_traffic(self, scenario: AttackScenario, 
                               start_time: datetime) -> List[NetworkFlow]:
        """Generate attack traffic based on scenario"""
        flows = []
        
        current_time = start_time
        
        for phase in scenario.timeline:
            phase_flows = self._generate_phase_traffic(
                phase, scenario.target_devices, current_time, scenario.attack_vector
            )
            flows.extend(phase_flows)
            
            # Move to next phase
            duration_minutes = phase.get('duration_minutes', 10)
            current_time += timedelta(minutes=duration_minutes)
        
        logger.debug(f"Generated {len(flows)} attack flows for scenario {scenario.scenario_id}")
        return flows
    
    def _create_normal_flow(self, device_ip: str, device_type: str, pattern: Dict, 
                           timestamp: datetime) -> NetworkFlow:
        """Create a single normal network flow"""
        
        # Select random characteristics from pattern
        protocol = random.choice(pattern['protocols'])
        dst_port = random.choice(pattern['ports'])
        packet_size = random.choice(pattern['packet_sizes'])
        
        # Generate flow characteristics
        duration_range = pattern['flow_duration']
        duration = random.uniform(duration_range[0], duration_range[1])
        
        rate_range = pattern['data_rates']
        data_rate = random.uniform(rate_range[0], rate_range[1])  # KB/s
        
        # Calculate packet and byte counts
        total_bytes = int(data_rate * 1024 * duration)  # Convert KB to bytes
        packet_count = max(1, total_bytes // packet_size)
        
        # Generate destination IP (external service)
        dst_ip = self._generate_external_ip()
        
        return NetworkFlow(
            timestamp=timestamp.isoformat(),
            src_ip=device_ip,
            dst_ip=dst_ip,
            src_port=random.randint(1024, 65535),
            dst_port=dst_port,
            protocol=protocol,
            packet_count=packet_count,
            byte_count=total_bytes,
            duration=duration,
            flags=self._generate_tcp_flags(protocol),
            flow_label='normal'
        )
    
    def _generate_phase_traffic(self, phase: Dict, target_devices: List[str], 
                               start_time: datetime, attack_vector: str) -> List[NetworkFlow]:
        """Generate traffic for a specific attack phase"""
        flows = []
        phase_name = phase.get('phase', 'unknown')
        
        # Map phase to attack pattern
        attack_type = self._map_phase_to_attack_type(phase_name)
        
        if attack_type not in self.attack_traffic_patterns:
            return flows
        
        pattern = self.attack_traffic_patterns[attack_type]
        duration_minutes = phase.get('duration_minutes', 10)
        
        # Generate multiple flows for this phase
        num_flows = self._calculate_phase_flows(attack_type, duration_minutes)
        
        for i in range(num_flows):
            # Distribute flows across the phase duration
            flow_time = start_time + timedelta(
                minutes=random.uniform(0, duration_minutes)
            )
            
            # Select target device
            device_type = random.choice(target_devices) if target_devices else 'smart_hub'
            device_ip = self._get_device_ip(device_type)
            
            flow = self._create_attack_flow(device_ip, pattern, flow_time, attack_type, attack_vector)
            flows.append(flow)
        
        return flows
    
    def _map_phase_to_attack_type(self, phase_name: str) -> str:
        """Map attack phase to traffic pattern type"""
        phase_name = phase_name.lower()
        
        if any(keyword in phase_name for keyword in ['recon', 'target', 'discovery', 'scan']):
            return 'reconnaissance'
        elif any(keyword in phase_name for keyword in ['exploit', 'access', 'breach', 'compromise']):
            return 'exploitation'
        elif any(keyword in phase_name for keyword in ['lateral', 'movement', 'propagation', 'spread']):
            return 'lateral_movement'
        elif any(keyword in phase_name for keyword in ['exfiltration', 'collection', 'steal', 'extract']):
            return 'data_exfiltration'
        elif any(keyword in phase_name for keyword in ['dos', 'denial', 'flood', 'amplification']):
            return 'denial_of_service'
        else:
            return 'command_control'
    
    def _create_attack_flow(self, device_ip: str, pattern: Dict, 
                           timestamp: datetime, attack_type: str, attack_vector: str) -> NetworkFlow:
        """Create a single attack network flow"""
        
        protocol = random.choice(pattern['protocols'])
        dst_port = random.choice(pattern['ports'])
        packet_size = random.choice(pattern['packet_sizes'])
        
        # Attack flows often have different characteristics
        duration_range = pattern['flow_duration']
        duration = random.uniform(duration_range[0], duration_range[1])
        
        rate_range = pattern['data_rates']
        data_rate = random.uniform(rate_range[0], rate_range[1])
        
        # Modify characteristics based on attack type
        if attack_type == 'reconnaissance':
            # Scanning typically has many small, short flows
            duration = min(duration, 2)
            packet_count = random.randint(1, 5)
            total_bytes = packet_count * packet_size
        elif attack_type == 'data_exfiltration':
            # Exfiltration has large data transfers
            data_rate *= random.uniform(2, 5)  # Higher data rate
            total_bytes = int(data_rate * 1024 * duration)
            packet_count = max(1, total_bytes // packet_size)
        elif attack_type == 'denial_of_service':
            # DoS attacks have very high packet rates
            packet_count = random.randint(1000, 10000)
            total_bytes = packet_count * packet_size
        else:
            total_bytes = int(data_rate * 1024 * duration)
            packet_count = max(1, total_bytes // packet_size)
        
        # Attack traffic might target internal IPs for lateral movement
        if attack_type == 'lateral_movement':
            dst_ip = self._generate_internal_ip()
        else:
            dst_ip = self._generate_external_ip()
        
        return NetworkFlow(
            timestamp=timestamp.isoformat(),
            src_ip=device_ip,
            dst_ip=dst_ip,
            src_port=random.randint(1024, 65535),
            dst_port=dst_port,
            protocol=protocol,
            packet_count=packet_count,
            byte_count=total_bytes,
            duration=duration,
            flags=self._generate_tcp_flags(protocol, attack_type),
            flow_label='attack',
            attack_type=attack_type
        )
    
    def _get_device_ip(self, device_type: str) -> str:
        """Get IP address for device type"""
        if device_type in self.device_ip_ranges:
            range_str = self.device_ip_ranges[device_type]
            base_ip, ip_range = range_str.split('-')
            base_parts = base_ip.split('.')
            start_ip = int(base_parts[-1])
            end_ip = int(ip_range)
            
            last_octet = random.randint(start_ip, end_ip)
            return f"{'.'.join(base_parts[:-1])}.{last_octet}"
        
        return "192.168.1.100"  # Default
    
    def _generate_external_ip(self) -> str:
        """Generate external IP address from cache"""
        if self.external_ip_cache:
            return random.choice(self.external_ip_cache)
        
        # Fallback if cache is empty
        external_ranges = ["8.8.8", "1.1.1", "208.67.222"]
        base = random.choice(external_ranges)
        last_octet = random.randint(1, 254)
        return f"{base}.{last_octet}"
    
    def _generate_internal_ip(self) -> str:
        """Generate internal network IP address"""
        return f"192.168.1.{random.randint(1, 254)}"
    
    def _generate_tcp_flags(self, protocol: str, attack_type: str = None) -> str:
        """Generate TCP flags based on protocol and attack type"""
        if protocol != 'TCP':
            return ""
        
        normal_flags = ['SYN', 'ACK', 'FIN', 'PSH', 'RST']
        
        if attack_type == 'reconnaissance':
            # Port scanning often uses specific flag combinations
            scan_flags = ['SYN', 'ACK', 'FIN', 'NULL', 'XMAS', 'SYN+ACK', 'FIN+PSH+URG']
            return random.choice(scan_flags)
        elif attack_type == 'exploitation':
            # Exploitation might have unusual flag combinations
            if random.random() < 0.3:  # 30% chance of unusual flags
                return random.choice(['URG', 'PSH+URG', 'FIN+PSH', 'SYN+FIN'])
        elif attack_type == 'denial_of_service':
            # DoS attacks might use unusual flag combinations
            dos_flags = ['SYN', 'ACK', 'FIN+ACK', 'RST+ACK', 'SYN+FIN+URG+PSH']
            return random.choice(dos_flags)
        
        return random.choice(normal_flags)
    
    def _calculate_phase_flows(self, attack_type: str, duration_minutes: int) -> int:
        """Calculate number of flows for attack phase"""
        base_flows = {
            'reconnaissance': 100,  # High volume scanning
            'exploitation': 8,      # Focused attempts
            'lateral_movement': 25,  # Multiple connection attempts
            'data_exfiltration': 5,  # Few large transfers
            'command_control': 12,   # Periodic communications
            'denial_of_service': 200  # Flood attacks
        }
        
        base = base_flows.get(attack_type, 15)
        
        # Scale by duration (more flows for longer phases)
        scaling_factor = min(duration_minutes / 10.0, 5.0)  # Cap at 5x
        
        return max(1, int(base * scaling_factor * random.uniform(0.8, 1.2)))

class DeviceBehaviorSimulator:
    """Simulates device behavior patterns for ML training"""
    
    def __init__(self):
        self.device_behaviors = self._load_device_behaviors()
    
    def _load_device_behaviors(self) -> Dict[str, Dict]:
        """Load normal behavior patterns for each device"""
        return {
            'smart_camera': {
                'normal_actions': ['stream_video', 'detect_motion', 'record_clip', 'send_alert', 'adjust_quality', 'night_vision'],
                'frequency_range': (0.1, 2.0),  # Actions per minute
                'data_size_range': (100, 5000),  # KB
                'energy_range': (5, 15),  # Watts
                'status_values': ['active', 'standby', 'recording', 'motion_detected']
            },
            'smart_thermostat': {
                'normal_actions': ['read_temperature', 'adjust_hvac', 'send_status', 'receive_schedule', 'humidity_check', 'energy_save'],
                'frequency_range': (0.05, 0.5),
                'data_size_range': (1, 50),
                'energy_range': (2, 8),
                'status_values': ['heating', 'cooling', 'idle', 'maintenance', 'eco_mode']
            },
            'smart_doorbell': {
                'normal_actions': ['detect_visitor', 'stream_video', 'send_notification', 'two_way_audio', 'motion_alert', 'ring_chime'],
                'frequency_range': (0.01, 1.0),  # Event-driven
                'data_size_range': (50, 2000),
                'energy_range': (3, 10),
                'status_values': ['active', 'standby', 'streaming', 'offline', 'visitor_detected']
            },
            'smart_lock': {
                'normal_actions': ['authenticate_user', 'lock_unlock', 'send_status', 'battery_check', 'access_log', 'security_scan'],
                'frequency_range': (0.001, 0.1),  # Very low frequency
                'data_size_range': (1, 20),
                'energy_range': (1, 5),
                'status_values': ['locked', 'unlocked', 'tamper_alert', 'low_battery', 'access_denied']
            },
            'smart_hub': {
                'normal_actions': ['route_traffic', 'manage_devices', 'sync_cloud', 'security_scan', 'update_firmware', 'health_check'],
                'frequency_range': (0.5, 5.0),
                'data_size_range': (10, 500),
                'energy_range': (8, 20),
                'status_values': ['online', 'syncing', 'updating', 'error', 'maintenance']
            },
            'smart_speaker': {
                'normal_actions': ['voice_recognition', 'play_audio', 'smart_home_control', 'web_query', 'timer_alarm', 'volume_adjust'],
                'frequency_range': (0.05, 2.0),
                'data_size_range': (20, 1000),
                'energy_range': (3, 12),
                'status_values': ['listening', 'playing', 'idle', 'processing', 'muted']
            },
            'smart_tv': {
                'normal_actions': ['stream_content', 'change_channel', 'adjust_volume', 'app_launch', 'screen_mirroring', 'power_toggle'],
                'frequency_range': (0.1, 3.0),
                'data_size_range': (500, 10000),
                'energy_range': (50, 200),
                'status_values': ['on', 'off', 'streaming', 'standby', 'app_mode']
            },
            'smart_bulb': {
                'normal_actions': ['brightness_adjust', 'color_change', 'schedule_update', 'energy_monitor', 'scene_activate', 'dimming'],
                'frequency_range': (0.01, 0.5),
                'data_size_range': (1, 10),
                'energy_range': (5, 60),
                'status_values': ['on', 'off', 'dimmed', 'color_mode', 'scheduled']
            }
        }
    
    def generate_normal_behavior(self, device_type: str, duration_hours: int, 
                                start_time: datetime) -> List[DeviceBehavior]:
        """Generate normal device behavior records"""
        behaviors = []
        
        if device_type not in self.device_behaviors:
            return behaviors
        
        pattern = self.device_behaviors[device_type]
        current_time = start_time
        end_time = start_time + timedelta(hours=duration_hours)
        
        device_id = f"{device_type}_{random.randint(1000, 9999)}"
        
        while current_time < end_time:
            behavior = self._create_normal_behavior(device_id, device_type, pattern, current_time)
            behaviors.append(behavior)
            
            # Calculate next action time
            freq_range = pattern['frequency_range']
            frequency = random.uniform(freq_range[0], freq_range[1])
            next_interval = 60.0 / frequency  # Convert freq/min to seconds
            
            # Add time-of-day variation
            hour = current_time.hour
            if device_type in ['smart_tv', 'smart_speaker']:
                if 0 <= hour <= 6:  # Night - less activity
                    next_interval *= random.uniform(2.0, 5.0)
                elif 18 <= hour <= 23:  # Evening - more activity
                    next_interval *= random.uniform(0.5, 0.8)
            
            current_time += timedelta(seconds=next_interval)
        
        return behaviors
    
    def generate_malicious_behavior(self, scenario: AttackScenario, 
                                   start_time: datetime) -> List[DeviceBehavior]:
        """Generate malicious device behavior based on attack scenario"""
        behaviors = []
        current_time = start_time
        
        for device_type in scenario.target_devices:
            device_id = f"{device_type}_{random.randint(1000, 9999)}"
            
            for phase in scenario.timeline:
                phase_behaviors = self._generate_malicious_phase_behavior(
                    device_id, device_type, phase, current_time
                )
                behaviors.extend(phase_behaviors)
                
                duration_minutes = phase.get('duration_minutes', 10)
                current_time += timedelta(minutes=duration_minutes)
        
        return behaviors
    
    def _create_normal_behavior(self, device_id: str, device_type: str, 
                               pattern: Dict, timestamp: datetime) -> DeviceBehavior:
        """Create normal device behavior record"""
        
        action = random.choice(pattern['normal_actions'])
        frequency = random.uniform(*pattern['frequency_range'])
        data_size = random.randint(*pattern['data_size_range'])
        energy = random.uniform(*pattern['energy_range'])
        status = random.choice(pattern['status_values'])
        
        # Normal behavior has low anomaly score
        anomaly_score = random.uniform(0.0, 0.3)
        
        return DeviceBehavior(
            timestamp=timestamp.isoformat(),
            device_id=device_id,
            device_type=device_type,
            action=action,
            frequency=frequency,
            data_size=data_size,
            energy_consumption=energy,
            status=status,
            anomaly_score=anomaly_score,
            behavior_label='normal'
        )
    
    def _generate_malicious_phase_behavior(self, device_id: str, device_type: str, 
                                          phase: Dict, start_time: datetime) -> List[DeviceBehavior]:
        """Generate malicious behavior for attack phase"""
        behaviors = []
        phase_name = phase.get('phase', 'unknown')
        duration_minutes = phase.get('duration_minutes', 10)
        
        # Define malicious actions based on phase
        malicious_actions = {
            'reconnaissance': ['port_scan', 'service_enum', 'version_detect', 'network_map', 'device_discovery'],
            'initial_access': ['exploit_attempt', 'auth_bypass', 'buffer_overflow', 'credential_brute', 'firmware_exploit'],
            'lateral_movement': ['credential_spray', 'protocol_abuse', 'trust_exploit', 'pivot_attempt', 'network_crawl'],
            'persistence': ['backdoor_install', 'firmware_modify', 'service_create', 'autostart_add', 'rootkit_deploy'],
            'impact': ['data_steal', 'service_disrupt', 'device_control', 'ransomware_deploy', 'botnet_join'],
            'vulnerability_exploit': ['rce_attempt', 'payload_delivery', 'shell_spawn', 'privilege_escalate', 'code_injection'],
            'device_compromise': ['admin_takeover', 'config_change', 'access_escalate', 'credential_harvest', 'log_clear'],
            'data_exfiltration': ['file_steal', 'keylog_capture', 'screen_capture', 'network_sniff', 'sensitive_access'],
            'command_control': ['beacon_send', 'command_receive', 'tunnel_establish', 'proxy_setup', 'remote_shell']
        }
        
        # Map phase name to actions
        phase_lower = phase_name.lower()
        actions = []
        for key, action_list in malicious_actions.items():
            if key in phase_lower or any(word in phase_lower for word in key.split('_')):
                actions.extend(action_list)
        
        if not actions:
            actions = malicious_actions.get('device_compromise', ['malicious_activity'])
        
        # Generate 3-8 malicious behaviors per phase
        num_behaviors = random.randint(3, 8)
        
        for i in range(num_behaviors):
            behavior_time = start_time + timedelta(
                minutes=random.uniform(0, duration_minutes)
            )
            
            action = random.choice(actions)
            
            # Malicious behavior has different characteristics
            frequency = random.uniform(1.0, 15.0)  # Higher frequency
            data_size = random.randint(1, 50000)    # Variable data size
            energy = random.uniform(1, 50)          # Potentially higher energy
            status = random.choice(['compromised', 'exploited', 'suspicious', 'error', 'unauthorized', 'breached'])
            
            # High anomaly score for malicious behavior
            anomaly_score = random.uniform(0.6, 1.0)
            
            behavior = DeviceBehavior(
                timestamp=behavior_time.isoformat(),
                device_id=device_id,
                device_type=device_type,
                action=action,
                frequency=frequency,
                data_size=data_size,
                energy_consumption=energy,
                status=status,
                anomaly_score=anomaly_score,
                behavior_label='malicious',
                attack_phase=phase_name
            )
            
            behaviors.append(behavior)
        
        return behaviors

class DataQualityAnalyzer:
    """Analyzes and validates dataset quality"""
    
    def __init__(self):
        pass
    
    def analyze_dataset_quality(self, flows: List[NetworkFlow], 
                               behaviors: List[DeviceBehavior]) -> Dict[str, Any]:
        """Comprehensive dataset quality analysis"""
        quality_metrics = {}
        
        # Network flow analysis
        if flows:
            quality_metrics['network_flows'] = self._analyze_network_flows(flows)
        
        # Device behavior analysis
        if behaviors:
            quality_metrics['device_behaviors'] = self._analyze_device_behaviors(behaviors)
        
        # Overall quality score
        quality_metrics['overall_score'] = self._calculate_overall_quality(quality_metrics)
        
        return quality_metrics
    
    def _analyze_network_flows(self, flows: List[NetworkFlow]) -> Dict[str, Any]:
        """Analyze network flow data quality"""
        flow_analysis = {}
        
        # Basic statistics
        total_flows = len(flows)
        normal_flows = len([f for f in flows if f.flow_label == 'normal'])
        attack_flows = len([f for f in flows if f.flow_label == 'attack'])
        
        flow_analysis['total_flows'] = total_flows
        flow_analysis['normal_flows'] = normal_flows
        flow_analysis['attack_flows'] = attack_flows
        flow_analysis['balance_ratio'] = normal_flows / max(attack_flows, 1)
        
        # Protocol distribution
        protocols = {}
        for flow in flows:
            protocols[flow.protocol] = protocols.get(flow.protocol, 0) + 1
        flow_analysis['protocol_distribution'] = protocols
        
        # Port diversity
        ports = set(f.dst_port for f in flows)
        flow_analysis['unique_ports'] = len(ports)
        
        # Temporal distribution
        timestamps = [datetime.fromisoformat(f.timestamp) for f in flows]
        if timestamps:
            time_span = max(timestamps) - min(timestamps)
            flow_analysis['time_span_hours'] = time_span.total_seconds() / 3600
        
        # Attack type distribution
        attack_types = {}
        for flow in flows:
            if flow.flow_label == 'attack' and flow.attack_type:
                attack_types[flow.attack_type] = attack_types.get(flow.attack_type, 0) + 1
        flow_analysis['attack_type_distribution'] = attack_types
        
        # Data volume statistics
        byte_counts = [f.byte_count for f in flows]
        if byte_counts:
            flow_analysis['data_volume_stats'] = {
                'min_bytes': min(byte_counts),
                'max_bytes': max(byte_counts),
                'avg_bytes': sum(byte_counts) / len(byte_counts),
                'total_gb': sum(byte_counts) / (1024**3)
            }
        
        return flow_analysis
    
    def _analyze_device_behaviors(self, behaviors: List[DeviceBehavior]) -> Dict[str, Any]:
        """Analyze device behavior data quality"""
        behavior_analysis = {}
        
        # Basic statistics
        total_behaviors = len(behaviors)
        normal_behaviors = len([b for b in behaviors if b.behavior_label == 'normal'])
        malicious_behaviors = len([b for b in behaviors if b.behavior_label == 'malicious'])
        
        behavior_analysis['total_behaviors'] = total_behaviors
        behavior_analysis['normal_behaviors'] = normal_behaviors
        behavior_analysis['malicious_behaviors'] = malicious_behaviors
        behavior_analysis['balance_ratio'] = normal_behaviors / max(malicious_behaviors, 1)
        
        # Device type distribution
        device_types = {}
        for behavior in behaviors:
            device_types[behavior.device_type] = device_types.get(behavior.device_type, 0) + 1
        behavior_analysis['device_type_distribution'] = device_types
        
        # Action diversity
        actions = set(b.action for b in behaviors)
        behavior_analysis['unique_actions'] = len(actions)
        
        # Anomaly score distribution
        anomaly_scores = [b.anomaly_score for b in behaviors]
        if anomaly_scores:
            behavior_analysis['anomaly_score_stats'] = {
                'min_score': min(anomaly_scores),
                'max_score': max(anomaly_scores),
                'avg_score': sum(anomaly_scores) / len(anomaly_scores)
            }
        
        # Attack phase distribution
        attack_phases = {}
        for behavior in behaviors:
            if behavior.behavior_label == 'malicious' and behavior.attack_phase:
                attack_phases[behavior.attack_phase] = attack_phases.get(behavior.attack_phase, 0) + 1
        behavior_analysis['attack_phase_distribution'] = attack_phases
        
        return behavior_analysis
    
    def _calculate_overall_quality(self, quality_metrics: Dict[str, Any]) -> float:
        """Calculate overall dataset quality score"""
        scores = []
        
        # Network flow quality
        if 'network_flows' in quality_metrics:
            nf = quality_metrics['network_flows']
            
            # Balance score (closer to 1:1 is better, but some imbalance is realistic)
            balance_score = min(1.0, 1.0 / max(nf.get('balance_ratio', 1), 1.0/nf.get('balance_ratio', 1)))
            scores.append(balance_score * 0.8)  # Slight imbalance is acceptable
            
            # Diversity score
            diversity_score = min(1.0, nf.get('unique_ports', 0) / 100)  # Up to 100 ports
            scores.append(diversity_score)
            
            # Attack type coverage
            attack_types = len(nf.get('attack_type_distribution', {}))
            coverage_score = min(1.0, attack_types / 5)  # Up to 5 attack types
            scores.append(coverage_score)
        
        # Device behavior quality
        if 'device_behaviors' in quality_metrics:
            db = quality_metrics['device_behaviors']
            
            # Balance score
            balance_score = min(1.0, 1.0 / max(db.get('balance_ratio', 1), 1.0/db.get('balance_ratio', 1)))
            scores.append(balance_score * 0.8)
            
            # Device diversity
            device_types = len(db.get('device_type_distribution', {}))
            diversity_score = min(1.0, device_types / 8)  # Up to 8 device types
            scores.append(diversity_score)
            
            # Action diversity
            actions = db.get('unique_actions', 0)
            action_score = min(1.0, actions / 50)  # Up to 50 unique actions
            scores.append(action_score)
        
        return sum(scores) / max(len(scores), 1) if scores else 0.0

class DatasetExporter:
    """Exports synthetic data in various ML-ready formats"""
    
    def __init__(self, output_dir: str = "data/datasets"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.traffic_synthesizer = NetworkTrafficSynthesizer()
        self.behavior_simulator = DeviceBehaviorSimulator()
        self.quality_analyzer = DataQualityAnalyzer()
    
    def export_scenario_dataset(self, scenarios: List[AttackScenario], 
                               config: Dict[str, Any]) -> Dict[str, str]:
        """Export complete dataset from attack scenarios"""
        
        try:
            # Generate dataset ID
            dataset_id = f"DH_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Extract configuration
            normal_hours = config.get('normal_traffic_hours', 24)
            include_network_flows = config.get('include_network_flows', True)
            include_device_behavior = config.get('include_device_behavior', True)
            export_formats = config.get('export_formats', ['csv', 'json'])
            create_ml_splits = config.get('create_ml_splits', True)
            feature_engineering = config.get('feature_engineering', True)
            
            # Generate base timestamp
            start_time = datetime.now() - timedelta(hours=normal_hours + 12)
            
            # Collect all data
            all_network_flows = []
            all_device_behaviors = []
            
            # Generate normal baseline data
            logger.info("Generating normal baseline data...")
            normal_flows, normal_behaviors = self._generate_normal_baseline(
                normal_hours, start_time
            )
            all_network_flows.extend(normal_flows)
            all_device_behaviors.extend(normal_behaviors)
            
            # Generate attack data from scenarios
            logger.info(f"Generating attack data from {len(scenarios)} scenarios...")
            attack_time = start_time + timedelta(hours=normal_hours)
            
            for scenario in scenarios:
                if include_network_flows:
                    attack_flows = self.traffic_synthesizer.generate_attack_traffic(
                        scenario, attack_time
                    )
                    all_network_flows.extend(attack_flows)
                
                if include_device_behavior:
                    attack_behaviors = self.behavior_simulator.generate_malicious_behavior(
                        scenario, attack_time
                    )
                    all_device_behaviors.extend(attack_behaviors)
                
                # Space out attacks
                attack_time += timedelta(hours=random.uniform(1, 4))
            
            # Perform quality analysis
            logger.info("Analyzing dataset quality...")
            quality_metrics = self.quality_analyzer.analyze_dataset_quality(
                all_network_flows, all_device_behaviors
            )
            
            # Create metadata
            metadata = self._create_dataset_metadata(
                dataset_id, scenarios, all_network_flows, all_device_behaviors, 
                config, quality_metrics
            )
            
            # Apply feature engineering if requested
            if feature_engineering:
                logger.info("Applying feature engineering...")
                all_network_flows, all_device_behaviors = self._apply_feature_engineering(
                    all_network_flows, all_device_behaviors
                )
            
            # Export in requested formats
            export_files = {}
            
            for format_type in export_formats:
                if format_type == 'csv':
                    csv_files = self._export_csv(
                        dataset_id, all_network_flows, all_device_behaviors, metadata
                    )
                    export_files.update(csv_files)
                
                elif format_type == 'json':
                    json_file = self._export_json(
                        dataset_id, all_network_flows, all_device_behaviors, metadata
                    )
                    export_files['json'] = json_file
                
                elif format_type == 'arff':
                    arff_files = self._export_arff(
                        dataset_id, all_network_flows, all_device_behaviors
                    )
                    export_files.update(arff_files)
                
                elif format_type == 'parquet':
                    parquet_files = self._export_parquet(
                        dataset_id, all_network_flows, all_device_behaviors, metadata
                    )
                    export_files.update(parquet_files)
            
            # Create ML-ready train/test splits if requested
            if create_ml_splits:
                logger.info("Creating ML train/test splits...")
                split_files = self._create_ml_splits(
                    dataset_id, all_network_flows, all_device_behaviors
                )
                export_files.update(split_files)
            
            # Update metadata with file paths
            metadata.file_paths = export_files
            metadata.data_statistics = quality_metrics
            
            # Export updated metadata
            self._export_metadata(dataset_id, metadata)
            
            logger.info(f"Dataset {dataset_id} exported successfully with quality score: {quality_metrics.get('overall_score', 0):.3f}")
            return export_files
            
        except Exception as e:
            logger.error(f"Error exporting dataset: {e}")
            return {}
    
    def _generate_normal_baseline(self, hours: int, start_time: datetime) -> Tuple[List[NetworkFlow], List[DeviceBehavior]]:
        """Generate normal baseline traffic and behavior"""
        device_types = ['smart_camera', 'smart_thermostat', 'smart_doorbell', 
                       'smart_lock', 'smart_hub', 'smart_speaker', 'smart_tv', 'smart_bulb']
        
        all_flows = []
        all_behaviors = []
        
        for device_type in device_types:
            # Generate normal traffic
            flows = self.traffic_synthesizer.generate_normal_traffic(
                device_type, hours, start_time
            )
            all_flows.extend(flows)
            
            # Generate normal behavior
            behaviors = self.behavior_simulator.generate_normal_behavior(
                device_type, hours, start_time
            )
            all_behaviors.extend(behaviors)
        
        # Shuffle to mix device types temporally
        random.shuffle(all_flows)
        random.shuffle(all_behaviors)
        
        return all_flows, all_behaviors
    
    def _apply_feature_engineering(self, flows: List[NetworkFlow], 
                                  behaviors: List[DeviceBehavior]) -> Tuple[List[NetworkFlow], List[DeviceBehavior]]:
        """Apply feature engineering to enhance ML readiness"""
        
        # For network flows - add derived features
        enhanced_flows = []
        for flow in flows:
            # Calculate additional features
            bytes_per_packet = flow.byte_count / max(flow.packet_count, 1)
            packets_per_second = flow.packet_count / max(flow.duration, 0.001)
            bytes_per_second = flow.byte_count / max(flow.duration, 0.001)
            
            # Add time-based features
            timestamp = datetime.fromisoformat(flow.timestamp)
            hour_of_day = timestamp.hour
            day_of_week = timestamp.weekday()
            is_weekend = day_of_week >= 5
            
            # Create enhanced flow (using dictionary for flexibility)
            enhanced_flow = asdict(flow)
            enhanced_flow.update({
                'bytes_per_packet': bytes_per_packet,
                'packets_per_second': packets_per_second,
                'bytes_per_second': bytes_per_second,
                'hour_of_day': hour_of_day,
                'day_of_week': day_of_week,
                'is_weekend': is_weekend,
                'src_ip_class': self._get_ip_class(flow.src_ip),
                'dst_ip_class': self._get_ip_class(flow.dst_ip),
                'port_category': self._categorize_port(flow.dst_port)
            })
            enhanced_flows.append(enhanced_flow)
        
        # For device behaviors - add contextual features
        enhanced_behaviors = []
        for behavior in behaviors:
            # Calculate additional features
            timestamp = datetime.fromisoformat(behavior.timestamp)
            hour_of_day = timestamp.hour
            day_of_week = timestamp.weekday()
            is_business_hours = 9 <= hour_of_day <= 17
            
            # Create enhanced behavior
            enhanced_behavior = asdict(behavior)
            enhanced_behavior.update({
                'hour_of_day': hour_of_day,
                'day_of_week': day_of_week,
                'is_business_hours': is_business_hours,
                'energy_per_kb': behavior.energy_consumption / max(behavior.data_size, 1),
                'activity_level': self._categorize_frequency(behavior.frequency),
                'data_size_category': self._categorize_data_size(behavior.data_size)
            })
            enhanced_behaviors.append(enhanced_behavior)
        
        return enhanced_flows, enhanced_behaviors
    
    def _get_ip_class(self, ip: str) -> str:
        """Classify IP address type"""
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return 'private'
        elif ip.startswith('127.'):
            return 'loopback'
        else:
            return 'public'
    
    def _categorize_port(self, port: int) -> str:
        """Categorize port numbers"""
        if port < 1024:
            return 'well_known'
        elif port < 49152:
            return 'registered'
        else:
            return 'dynamic'
    
    def _categorize_frequency(self, frequency: float) -> str:
        """Categorize activity frequency"""
        if frequency < 0.1:
            return 'very_low'
        elif frequency < 1.0:
            return 'low'
        elif frequency < 5.0:
            return 'moderate'
        else:
            return 'high'
    
    def _categorize_data_size(self, size: int) -> str:
        """Categorize data size"""
        if size < 100:
            return 'small'
        elif size < 1000:
            return 'medium'
        elif size < 10000:
            return 'large'
        else:
            return 'very_large'
    
    def _create_dataset_metadata(self, dataset_id: str, scenarios: List[AttackScenario],
                                flows: List[NetworkFlow], behaviors: List[DeviceBehavior],
                                config: Dict, quality_metrics: Dict) -> DatasetMetadata:
        """Create comprehensive dataset metadata"""
        
        # Count normal vs attack samples
        normal_flows = len([f for f in flows if f.flow_label == 'normal'])
        attack_flows = len([f for f in flows if f.flow_label == 'attack'])
        
        normal_behaviors = len([b for b in behaviors if b.behavior_label == 'normal'])
        malicious_behaviors = len([b for b in behaviors if b.behavior_label == 'malicious'])
        
        # Get time range
        all_timestamps = [f.timestamp for f in flows] + [b.timestamp for b in behaviors]
        if all_timestamps:
            time_range = {
                'start': min(all_timestamps),
                'end': max(all_timestamps)
            }
        else:
            time_range = {'start': '', 'end': ''}
        
        # Get device types and attack types
        device_types = list(set(b.device_type for b in behaviors))
        attack_types = list(set(s.attack_vector for s in scenarios))
        
        # Calculate quality score
        quality_score = quality_metrics.get('overall_score', 0.0)
        
        return DatasetMetadata(
            dataset_id=dataset_id,
            creation_date=datetime.now().isoformat(),
            scenarios_count=len(scenarios),
            normal_samples=normal_flows + normal_behaviors,
            attack_samples=attack_flows + malicious_behaviors,
            time_range=time_range,
            device_types=device_types,
            attack_types=attack_types,
            quality_score=quality_score,
            generation_parameters=config,
            data_statistics=quality_metrics
        )
    
    def _export_csv(self, dataset_id: str, flows: List[Union[NetworkFlow, Dict]], 
                   behaviors: List[Union[DeviceBehavior, Dict]], metadata: DatasetMetadata) -> Dict[str, str]:
        """Export data in CSV format"""
        files = {}
        
        # Convert to dictionaries if needed
        flows_dict = [f if isinstance(f, dict) else asdict(f) for f in flows]
        behaviors_dict = [b if isinstance(b, dict) else asdict(b) for b in behaviors]
        
        # Export network flows
        if flows_dict:
            flows_file = self.output_dir / f"{dataset_id}_network_flows.csv"
            flows_df = pd.DataFrame(flows_dict)
            flows_df.to_csv(flows_file, index=False)
            files['network_flows_csv'] = str(flows_file)
            
            logger.info(f"Exported {len(flows_dict)} network flows to CSV")
        
        # Export device behaviors
        if behaviors_dict:
            behaviors_file = self.output_dir / f"{dataset_id}_device_behaviors.csv"
            behaviors_df = pd.DataFrame(behaviors_dict)
            behaviors_df.to_csv(behaviors_file, index=False)
            files['device_behaviors_csv'] = str(behaviors_file)
            
            logger.info(f"Exported {len(behaviors_dict)} device behaviors to CSV")
        
        return files
    
    def _export_json(self, dataset_id: str, flows: List[Union[NetworkFlow, Dict]], 
                    behaviors: List[Union[DeviceBehavior, Dict]], metadata: DatasetMetadata) -> str:
        """Export data in JSON format"""
        
        # Convert to dictionaries if needed
        flows_dict = [f if isinstance(f, dict) else asdict(f) for f in flows]
        behaviors_dict = [b if isinstance(b, dict) else asdict(b) for b in behaviors]
        
        export_data = {
            'metadata': asdict(metadata),
            'network_flows': flows_dict,
            'device_behaviors': behaviors_dict,
            'export_info': {
                'total_records': len(flows_dict) + len(behaviors_dict),
                'export_timestamp': datetime.now().isoformat(),
                'format_version': '2.0'
            }
        }
        
        json_file = self.output_dir / f"{dataset_id}_complete.json"
        
        with open(json_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Exported complete dataset to JSON")
        return str(json_file)
    
    def _export_parquet(self, dataset_id: str, flows: List[Union[NetworkFlow, Dict]], 
                       behaviors: List[Union[DeviceBehavior, Dict]], metadata: DatasetMetadata) -> Dict[str, str]:
        """Export data in Parquet format for efficient storage and processing"""
        files = {}
        
        try:
            # Convert to dictionaries if needed
            flows_dict = [f if isinstance(f, dict) else asdict(f) for f in flows]
            behaviors_dict = [b if isinstance(b, dict) else asdict(b) for b in behaviors]
            
            # Export network flows
            if flows_dict:
                flows_file = self.output_dir / f"{dataset_id}_network_flows.parquet"
                flows_df = pd.DataFrame(flows_dict)
                flows_df.to_parquet(flows_file, index=False)
                files['network_flows_parquet'] = str(flows_file)
                
                logger.info(f"Exported {len(flows_dict)} network flows to Parquet")
            
            # Export device behaviors
            if behaviors_dict:
                behaviors_file = self.output_dir / f"{dataset_id}_device_behaviors.parquet"
                behaviors_df = pd.DataFrame(behaviors_dict)
                behaviors_df.to_parquet(behaviors_file, index=False)
                files['device_behaviors_parquet'] = str(behaviors_file)
                
                logger.info(f"Exported {len(behaviors_dict)} device behaviors to Parquet")
                
        except ImportError:
            logger.warning("Parquet export requires pyarrow or fastparquet. Skipping parquet export.")
        
        return files
    
    def _export_arff(self, dataset_id: str, flows: List[Union[NetworkFlow, Dict]], 
                    behaviors: List[Union[DeviceBehavior, Dict]]) -> Dict[str, str]:
        """Export data in ARFF format for Weka"""
        files = {}
        
        # Convert to dictionaries if needed
        flows_dict = [f if isinstance(f, dict) else asdict(f) for f in flows]
        behaviors_dict = [b if isinstance(b, dict) else asdict(b) for b in behaviors]
        
        # Network flows ARFF
        if flows_dict:
            flows_arff = self.output_dir / f"{dataset_id}_network_flows.arff"
            self._write_flows_arff(flows_dict, flows_arff)
            files['network_flows_arff'] = str(flows_arff)
        
        # Device behaviors ARFF
        if behaviors_dict:
            behaviors_arff = self.output_dir / f"{dataset_id}_device_behaviors.arff"
            self._write_behaviors_arff(behaviors_dict, behaviors_arff)
            files['device_behaviors_arff'] = str(behaviors_arff)
        
        return files
    
    def _create_ml_splits(self, dataset_id: str, flows: List[Union[NetworkFlow, Dict]], 
                         behaviors: List[Union[DeviceBehavior, Dict]]) -> Dict[str, str]:
        """Create train/validation/test splits for ML"""
        files = {}
        
        try:
            # Convert to dictionaries if needed
            flows_dict = [f if isinstance(f, dict) else asdict(f) for f in flows]
            behaviors_dict = [b if isinstance(b, dict) else asdict(b) for b in behaviors]
            
            # Split network flows
            if flows_dict:
                flows_df = pd.DataFrame(flows_dict)
                
                # Stratified split based on flow_label
                if 'flow_label' in flows_df.columns:
                    train_flows, temp_flows = train_test_split(
                        flows_df, test_size=0.4, stratify=flows_df['flow_label'], random_state=42
                    )
                    val_flows, test_flows = train_test_split(
                        temp_flows, test_size=0.5, stratify=temp_flows['flow_label'], random_state=42
                    )
                    
                    # Save splits
                    train_flows.to_csv(self.output_dir / f"{dataset_id}_network_flows_train.csv", index=False)
                    val_flows.to_csv(self.output_dir / f"{dataset_id}_network_flows_val.csv", index=False)
                    test_flows.to_csv(self.output_dir / f"{dataset_id}_network_flows_test.csv", index=False)
                    
                    files['network_flows_train'] = str(self.output_dir / f"{dataset_id}_network_flows_train.csv")
                    files['network_flows_val'] = str(self.output_dir / f"{dataset_id}_network_flows_val.csv")
                    files['network_flows_test'] = str(self.output_dir / f"{dataset_id}_network_flows_test.csv")
            
            # Split device behaviors
            if behaviors_dict:
                behaviors_df = pd.DataFrame(behaviors_dict)
                
                # Stratified split based on behavior_label
                if 'behavior_label' in behaviors_df.columns:
                    train_behaviors, temp_behaviors = train_test_split(
                        behaviors_df, test_size=0.4, stratify=behaviors_df['behavior_label'], random_state=42
                    )
                    val_behaviors, test_behaviors = train_test_split(
                        temp_behaviors, test_size=0.5, stratify=temp_behaviors['behavior_label'], random_state=42
                    )
                    
                    # Save splits
                    train_behaviors.to_csv(self.output_dir / f"{dataset_id}_device_behaviors_train.csv", index=False)
                    val_behaviors.to_csv(self.output_dir / f"{dataset_id}_device_behaviors_val.csv", index=False)
                    test_behaviors.to_csv(self.output_dir / f"{dataset_id}_device_behaviors_test.csv", index=False)
                    
                    files['device_behaviors_train'] = str(self.output_dir / f"{dataset_id}_device_behaviors_train.csv")
                    files['device_behaviors_val'] = str(self.output_dir / f"{dataset_id}_device_behaviors_val.csv")
                    files['device_behaviors_test'] = str(self.output_dir / f"{dataset_id}_device_behaviors_test.csv")
            
            logger.info("Created ML train/validation/test splits")
            
        except Exception as e:
            logger.error(f"Error creating ML splits: {e}")
        
        return files
    
    def _write_flows_arff(self, flows: List[Dict], filepath: Path):
        """Write network flows in ARFF format"""
        with open(filepath, 'w') as f:
            f.write("@relation network_flows\n\n")
            
            # Determine attributes from first flow
            if flows:
                sample_flow = flows[0]
                
                # Standard attributes
                f.write("@attribute src_ip string\n")
                f.write("@attribute dst_ip string\n")
                f.write("@attribute src_port numeric\n")
                f.write("@attribute dst_port numeric\n")
                f.write("@attribute protocol {TCP,UDP,ICMP}\n")
                f.write("@attribute packet_count numeric\n")
                f.write("@attribute byte_count numeric\n")
                f.write("@attribute duration numeric\n")
                f.write("@attribute flags string\n")
                
                # Optional enhanced attributes
                if 'bytes_per_packet' in sample_flow:
                    f.write("@attribute bytes_per_packet numeric\n")
                if 'packets_per_second' in sample_flow:
                    f.write("@attribute packets_per_second numeric\n")
                if 'bytes_per_second' in sample_flow:
                    f.write("@attribute bytes_per_second numeric\n")
                if 'hour_of_day' in sample_flow:
                    f.write("@attribute hour_of_day numeric\n")
                if 'day_of_week' in sample_flow:
                    f.write("@attribute day_of_week numeric\n")
                if 'is_weekend' in sample_flow:
                    f.write("@attribute is_weekend {True,False}\n")
                if 'src_ip_class' in sample_flow:
                    f.write("@attribute src_ip_class {private,public,loopback}\n")
                if 'dst_ip_class' in sample_flow:
                    f.write("@attribute dst_ip_class {private,public,loopback}\n")
                if 'port_category' in sample_flow:
                    f.write("@attribute port_category {well_known,registered,dynamic}\n")
                
                f.write("@attribute class {normal,attack}\n\n")
                f.write("@data\n")
                
                # Data
                for flow in flows:
                    values = []
                    values.extend([
                        f'"{flow.get("src_ip", "")}"',
                        f'"{flow.get("dst_ip", "")}"',
                        str(flow.get('src_port', 0)),
                        str(flow.get('dst_port', 0)),
                        flow.get('protocol', 'TCP'),
                        str(flow.get('packet_count', 0)),
                        str(flow.get('byte_count', 0)),
                        str(flow.get('duration', 0)),
                        f'"{flow.get("flags", "")}"'
                    ])
                    
                    # Add enhanced features if present
                    if 'bytes_per_packet' in flow:
                        values.append(str(flow['bytes_per_packet']))
                    if 'packets_per_second' in flow:
                        values.append(str(flow['packets_per_second']))
                    if 'bytes_per_second' in flow:
                        values.append(str(flow['bytes_per_second']))
                    if 'hour_of_day' in flow:
                        values.append(str(flow['hour_of_day']))
                    if 'day_of_week' in flow:
                        values.append(str(flow['day_of_week']))
                    if 'is_weekend' in flow:
                        values.append(str(flow['is_weekend']))
                    if 'src_ip_class' in flow:
                        values.append(flow['src_ip_class'])
                    if 'dst_ip_class' in flow:
                        values.append(flow['dst_ip_class'])
                    if 'port_category' in flow:
                        values.append(flow['port_category'])
                    
                    values.append(flow.get('flow_label', 'normal'))
                    
                    f.write(','.join(values) + '\n')
    
    def _write_behaviors_arff(self, behaviors: List[Dict], filepath: Path):
        """Write device behaviors in ARFF format"""
        with open(filepath, 'w') as f:
            f.write("@relation device_behaviors\n\n")
            
            # Determine attributes from first behavior
            if behaviors:
                sample_behavior = behaviors[0]
                
                # Standard attributes
                f.write("@attribute device_type string\n")
                f.write("@attribute action string\n")
                f.write("@attribute frequency numeric\n")
                f.write("@attribute data_size numeric\n")
                f.write("@attribute energy_consumption numeric\n")
                f.write("@attribute status string\n")
                f.write("@attribute anomaly_score numeric\n")
                
                # Optional enhanced attributes
                if 'hour_of_day' in sample_behavior:
                    f.write("@attribute hour_of_day numeric\n")
                if 'day_of_week' in sample_behavior:
                    f.write("@attribute day_of_week numeric\n")
                if 'is_business_hours' in sample_behavior:
                    f.write("@attribute is_business_hours {True,False}\n")
                if 'energy_per_kb' in sample_behavior:
                    f.write("@attribute energy_per_kb numeric\n")
                if 'activity_level' in sample_behavior:
                    f.write("@attribute activity_level {very_low,low,moderate,high}\n")
                if 'data_size_category' in sample_behavior:
                    f.write("@attribute data_size_category {small,medium,large,very_large}\n")
                
                f.write("@attribute class {normal,malicious}\n\n")
                f.write("@data\n")
                
                # Data
                for behavior in behaviors:
                    values = []
                    values.extend([
                        f'"{behavior.get("device_type", "")}"',
                        f'"{behavior.get("action", "")}"',
                        str(behavior.get('frequency', 0)),
                        str(behavior.get('data_size', 0)),
                        str(behavior.get('energy_consumption', 0)),
                        f'"{behavior.get("status", "")}"',
                        str(behavior.get('anomaly_score', 0))
                    ])
                    
                    # Add enhanced features if present
                    if 'hour_of_day' in behavior:
                        values.append(str(behavior['hour_of_day']))
                    if 'day_of_week' in behavior:
                        values.append(str(behavior['day_of_week']))
                    if 'is_business_hours' in behavior:
                        values.append(str(behavior['is_business_hours']))
                    if 'energy_per_kb' in behavior:
                        values.append(str(behavior['energy_per_kb']))
                    if 'activity_level' in behavior:
                        values.append(behavior['activity_level'])
                    if 'data_size_category' in behavior:
                        values.append(behavior['data_size_category'])
                    
                    values.append(behavior.get('behavior_label', 'normal'))
                    
                    f.write(','.join(values) + '\n')
    
    def _export_metadata(self, dataset_id: str, metadata: DatasetMetadata):
        """Export comprehensive metadata"""
        
        # JSON metadata
        metadata_json = self.output_dir / f"{dataset_id}_metadata.json"
        with open(metadata_json, 'w') as f:
            json.dump(asdict(metadata), f, indent=2, default=str)
        
        # CSV metadata for easy viewing
        metadata_csv = self.output_dir / f"{dataset_id}_metadata.csv"
        metadata_df = pd.DataFrame([asdict(metadata)])
        metadata_df.to_csv(metadata_csv, index=False)
        
        # Create a human-readable report
        report_file = self.output_dir / f"{dataset_id}_report.txt"
        self._create_dataset_report(metadata, report_file)
        
        logger.info("Exported comprehensive metadata")
    
    def _create_dataset_report(self, metadata: DatasetMetadata, report_file: Path):
        """Create a human-readable dataset report"""
        with open(report_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write(f"DATASET REPORT: {metadata.dataset_id}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Creation Date: {metadata.creation_date}\n")
            f.write(f"Quality Score: {metadata.quality_score:.3f}/1.000\n")
            f.write(f"Scenarios Count: {metadata.scenarios_count}\n\n")
            
            f.write("DATA SUMMARY:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Normal Samples: {metadata.normal_samples:,}\n")
            f.write(f"Attack Samples: {metadata.attack_samples:,}\n")
            f.write(f"Total Samples: {metadata.normal_samples + metadata.attack_samples:,}\n")
            f.write(f"Attack Ratio: {metadata.attack_samples/(metadata.normal_samples + metadata.attack_samples):.1%}\n\n")
            
            f.write("TIME RANGE:\n")
            f.write("-" * 15 + "\n")
            f.write(f"Start: {metadata.time_range.get('start', 'N/A')}\n")
            f.write(f"End: {metadata.time_range.get('end', 'N/A')}\n\n")
            
            f.write("DEVICE TYPES:\n")
            f.write("-" * 15 + "\n")
            for device_type in metadata.device_types:
                f.write(f"  • {device_type}\n")
            f.write("\n")
            
            f.write("ATTACK TYPES:\n")
            f.write("-" * 15 + "\n")
            for attack_type in metadata.attack_types:
                f.write(f"  • {attack_type}\n")
            f.write("\n")
            
            if metadata.data_statistics:
                f.write("QUALITY METRICS:\n")
                f.write("-" * 20 + "\n")
                
                if 'network_flows' in metadata.data_statistics:
                    nf = metadata.data_statistics['network_flows']
                    f.write("Network Flows:\n")
                    f.write(f"  Total Flows: {nf.get('total_flows', 0):,}\n")
                    f.write(f"  Balance Ratio: {nf.get('balance_ratio', 0):.2f}\n")
                    f.write(f"  Unique Ports: {nf.get('unique_ports', 0)}\n")
                    f.write(f"  Time Span: {nf.get('time_span_hours', 0):.1f} hours\n\n")
                
                if 'device_behaviors' in metadata.data_statistics:
                    db = metadata.data_statistics['device_behaviors']
                    f.write("Device Behaviors:\n")
                    f.write(f"  Total Behaviors: {db.get('total_behaviors', 0):,}\n")
                    f.write(f"  Balance Ratio: {db.get('balance_ratio', 0):.2f}\n")
                    f.write(f"  Unique Actions: {db.get('unique_actions', 0)}\n\n")
            
            f.write("GENERATION PARAMETERS:\n")
            f.write("-" * 25 + "\n")
            for key, value in metadata.generation_parameters.items():
                f.write(f"  {key}: {value}\n")
            f.write("\n")
            
            if metadata.file_paths:
                f.write("EXPORTED FILES:\n")
                f.write("-" * 18 + "\n")
                for file_type, filepath in metadata.file_paths.items():
                    f.write(f"  {file_type}: {Path(filepath).name}\n")

class DatasetValidator:
    """Validates dataset integrity and ML readiness"""
    
    def __init__(self):
        pass
    
    def validate_dataset(self, dataset_files: Dict[str, str]) -> Dict[str, Any]:
        """Comprehensive dataset validation"""
        validation_results = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'recommendations': []
        }
        
        try:
            # Validate file existence
            for file_type, filepath in dataset_files.items():
                if not Path(filepath).exists():
                    validation_results['errors'].append(f"Missing file: {filepath}")
                    validation_results['is_valid'] = False
            
            # Validate CSV files if they exist
            csv_files = {k: v for k, v in dataset_files.items() if k.endswith('_csv')}
            for file_type, filepath in csv_files.items():
                try:
                    df = pd.read_csv(filepath)
                    file_validation = self._validate_csv_file(df, file_type)
                    validation_results['errors'].extend(file_validation['errors'])
                    validation_results['warnings'].extend(file_validation['warnings'])
                    validation_results['recommendations'].extend(file_validation['recommendations'])
                except Exception as e:
                    validation_results['errors'].append(f"Error reading {filepath}: {e}")
                    validation_results['is_valid'] = False
            
            # ML readiness checks
            ml_readiness = self._check_ml_readiness(dataset_files)
            validation_results.update(ml_readiness)
            
            if validation_results['errors']:
                validation_results['is_valid'] = False
            
        except Exception as e:
            validation_results['errors'].append(f"Validation error: {e}")
            validation_results['is_valid'] = False
        
        return validation_results
    
    def _validate_csv_file(self, df: pd.DataFrame, file_type: str) -> Dict[str, List]:
        """Validate individual CSV file"""
        results = {'errors': [], 'warnings': [], 'recommendations': []}
        
        # Check for empty dataset
        if df.empty:
            results['errors'].append(f"{file_type}: Dataset is empty")
            return results
        
        # Check for required columns based on file type
        if 'network_flows' in file_type:
            required_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'flow_label']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                results['errors'].append(f"{file_type}: Missing required columns: {missing_cols}")
        
        elif 'device_behaviors' in file_type:
            required_cols = ['device_type', 'action', 'behavior_label']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                results['errors'].append(f"{file_type}: Missing required columns: {missing_cols}")
        
        # Check for missing values
        missing_percentage = (df.isnull().sum() / len(df)) * 100
        high_missing = missing_percentage[missing_percentage > 10]
        if not high_missing.empty:
            results['warnings'].append(f"{file_type}: High missing values in columns: {high_missing.to_dict()}")
        
        # Check label distribution
        if 'flow_label' in df.columns:
            label_dist = df['flow_label'].value_counts()
            if len(label_dist) < 2:
                results['errors'].append(f"{file_type}: Only one class present in labels")
            else:
                min_class_pct = label_dist.min() / len(df) * 100
                if min_class_pct < 5:
                    results['warnings'].append(f"{file_type}: Severe class imbalance - minority class: {min_class_pct:.1f}%")
        
        if 'behavior_label' in df.columns:
            label_dist = df['behavior_label'].value_counts()
            if len(label_dist) < 2:
                results['errors'].append(f"{file_type}: Only one class present in labels")
            else:
                min_class_pct = label_dist.min() / len(df) * 100
                if min_class_pct < 5:
                    results['warnings'].append(f"{file_type}: Severe class imbalance - minority class: {min_class_pct:.1f}%")
        
        # Data quality checks
        if 'packet_count' in df.columns:
            if (df['packet_count'] <= 0).any():
                results['warnings'].append(f"{file_type}: Non-positive packet counts detected")
        
        if 'byte_count' in df.columns:
            if (df['byte_count'] <= 0).any():
                results['warnings'].append(f"{file_type}: Non-positive byte counts detected")
        
        if 'anomaly_score' in df.columns:
            if not ((df['anomaly_score'] >= 0) & (df['anomaly_score'] <= 1)).all():
                results['warnings'].append(f"{file_type}: Anomaly scores outside [0,1] range")
        
        return results
    
    def _check_ml_readiness(self, dataset_files: Dict[str, str]) -> Dict[str, List]:
        """Check ML readiness of dataset"""
        results = {'warnings': [], 'recommendations': []}
        
        # Check if train/test splits exist
        has_train_splits = any('_train' in k for k in dataset_files.keys())
        if not has_train_splits:
            results['recommendations'].append("Consider creating train/test splits for ML readiness")
        
        # Check for multiple formats
        has_csv = any('_csv' in k for k in dataset_files.keys())
        has_json = any('json' in k for k in dataset_files.keys())
        has_arff = any('arff' in k for k in dataset_files.keys())
        
        if not has_csv:
            results['recommendations'].append("CSV format recommended for broad ML framework compatibility")
        
        if not has_arff:
            results['recommendations'].append("ARFF format recommended for Weka compatibility")
        
        # Check dataset size
        for file_type, filepath in dataset_files.items():
            if file_type.endswith('_csv'):
                try:
                    df = pd.read_csv(filepath)
                    if len(df) < 1000:
                        results['warnings'].append(f"{file_type}: Small dataset size ({len(df)} samples) may limit ML performance")
                    elif len(df) < 100:
                        results['warnings'].append(f"{file_type}: Very small dataset size ({len(df)} samples) inadequate for ML")
                except:
                    pass
        
        return results

# Enhanced example usage and testing
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Mock AttackScenarioGenerator for testing
    class MockAttackScenarioGenerator:
        def generate_scenario(self, threat_data: Dict) -> AttackScenario:
            return AttackScenario(
                scenario_id=f"scenario_{random.randint(1000, 9999)}",
                attack_vector=threat_data.get('attack_vector', 'remote_access'),
                target_devices=['smart_camera', 'smart_hub'],
                timeline=[
                    {'phase': 'reconnaissance', 'duration_minutes': 15},
                    {'phase': 'initial_access', 'duration_minutes': 10},
                    {'phase': 'lateral_movement', 'duration_minutes': 20},
                    {'phase': 'data_exfiltration', 'duration_minutes': 30}
                ],
                quality_score=random.uniform(0.7, 0.95)
            )
    
    # Test the enhanced system
    print("Testing Enhanced Dataset Export System")
    print("=" * 50)
    
    # Initialize systems
    scenario_generator = MockAttackScenarioGenerator()
    dataset_exporter = DatasetExporter()
    validator = DatasetValidator()
    
    # Sample threat data with more variety
    sample_threats = [
        {
            'cve_id': 'CVE-2024-12345',
            'attack_vector': 'remote_code_execution',
            'description': 'Buffer overflow in smart camera firmware allows remote code execution',
            'severity': {'cvss_v3_score': 8.5, 'cvss_v3_severity': 'HIGH'},
            'nlp_analysis': {'devices': ['camera'], 'attack_types': ['remote_access']}
        },
        {
            'cve_id': 'CVE-2024-12346', 
            'attack_vector': 'authentication_bypass',
            'description': 'Authentication bypass in smart lock via Bluetooth vulnerability',
            'severity': {'cvss_v3_score': 7.2, 'cvss_v3_severity': 'HIGH'},
            'nlp_analysis': {'devices': ['lock'], 'attack_types': ['auth_bypass']}
        },
        {
            'cve_id': 'CVE-2024-12347',
            'attack_vector': 'denial_of_service',
            'description': 'DoS attack on smart hub through malformed packets',
            'severity': {'cvss_v3_score': 6.8, 'cvss_v3_severity': 'MEDIUM'},
            'nlp_analysis': {'devices': ['hub'], 'attack_types': ['dos']}
        }
    ]
    
    # Generate scenarios
    scenarios = []
    for threat in sample_threats:
        scenario = scenario_generator.generate_scenario(threat)
        if scenario:
            scenarios.append(scenario)
    
    # Enhanced export configuration
    export_config = {
        'normal_traffic_hours': 48,  # Longer baseline
        'include_network_flows': True,
        'include_device_behavior': True,
        'export_formats': ['csv', 'json', 'arff', 'parquet'],
        'create_ml_splits': True,
        'feature_engineering': True,
        'quality_analysis': True
    }
    
    # Export dataset
    if scenarios:
        print(f"Generating dataset from {len(scenarios)} scenarios...")
        files = dataset_exporter.export_scenario_dataset(scenarios, export_config)
        
        if files:
            print(f"\nDataset exported successfully with {len(files)} files:")
            for file_type, filepath in files.items():
                file_size = Path(filepath).stat().st_size if Path(filepath).exists() else 0
                print(f"  {file_type:25}: {Path(filepath).name} ({file_size:,} bytes)")
            
            # Validate the dataset
            print("\nValidating dataset...")
            validation_results = validator.validate_dataset(files)
            
            print(f"Dataset Valid: {validation_results['is_valid']}")
            
            if validation_results['errors']:
                print("Errors:")
                for error in validation_results['errors']:
                    print(f"  ❌ {error}")
            
            if validation_results['warnings']:
                print("Warnings:")
                for warning in validation_results['warnings']:
                    print(f"  ⚠️  {warning}")
            
            if validation_results['recommendations']:
                print("Recommendations:")
                for rec in validation_results['recommendations']:
                    print(f"  💡 {rec}")
        else:
            print("❌ Dataset export failed")
    else:
        print("❌ No scenarios generated for export")
    
    print("\n" + "=" * 50)
    print("Enhanced Dataset Export System Test Complete")