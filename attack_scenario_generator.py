# attack_scenario_generator.py - Core LLM-based attack scenario generation
import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import random
import re
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class SmartHomeDevice:
    """Smart home device specification"""
    name: str
    category: str
    protocols: List[str]
    common_vulnerabilities: List[str]
    attack_vectors: List[str]
    network_behavior: Dict[str, Any]

@dataclass
class AttackScenario:
    """Generated attack scenario structure"""
    scenario_id: str
    cve_id: str
    attack_name: str
    target_devices: List[str]
    attack_vector: str
    complexity: str
    impact_level: str
    timeline: List[Dict[str, Any]]
    network_indicators: Dict[str, Any]
    mitigation_strategies: List[str]
    scenario_narrative: str
    technical_details: Dict[str, Any]
    quality_score: float

class SmartHomeContextEngine:
    """Translates CVE threats into smart home device contexts"""
    
    def __init__(self):
        self.device_catalog = self._load_device_catalog()
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
    def _load_device_catalog(self) -> Dict[str, SmartHomeDevice]:
        """Load smart home device specifications"""
        return {
            "smart_camera": SmartHomeDevice(
                name="Smart Security Camera",
                category="security",
                protocols=["WiFi", "RTSP", "HTTP", "MQTT"],
                common_vulnerabilities=["buffer_overflow", "auth_bypass", "firmware_backdoor"],
                attack_vectors=["network_access", "firmware_exploit", "credential_attack"],
                network_behavior={"ports": [80, 443, 554, 1883], "traffic_pattern": "streaming"}
            ),
            "smart_thermostat": SmartHomeDevice(
                name="Smart Thermostat",
                category="hvac",
                protocols=["WiFi", "Zigbee", "HTTP", "MQTT"],
                common_vulnerabilities=["weak_auth", "unencrypted_comm", "update_bypass"],
                attack_vectors=["network_access", "protocol_exploit", "social_engineering"],
                network_behavior={"ports": [80, 443, 1883], "traffic_pattern": "periodic"}
            ),
            "smart_doorbell": SmartHomeDevice(
                name="Smart Video Doorbell",
                category="security",
                protocols=["WiFi", "HTTP", "RTSP", "Cloud"],
                common_vulnerabilities=["video_stream_hijack", "motion_bypass", "cloud_leak"],
                attack_vectors=["stream_intercept", "cloud_attack", "local_network"],
                network_behavior={"ports": [80, 443, 554], "traffic_pattern": "event_driven"}
            ),
            "smart_lock": SmartHomeDevice(
                name="Smart Door Lock",
                category="access_control",
                protocols=["Bluetooth", "WiFi", "Zigbee"],
                common_vulnerabilities=["bluetooth_attack", "replay_attack", "bypass"],
                attack_vectors=["proximity_attack", "network_exploit", "physical_bypass"],
                network_behavior={"ports": [443, 1883], "traffic_pattern": "command_response"}
            ),
            "smart_hub": SmartHomeDevice(
                name="Smart Home Hub",
                category="controller",
                protocols=["WiFi", "Zigbee", "Z-Wave", "HTTP"],
                common_vulnerabilities=["admin_takeover", "device_spoofing", "update_hijack"],
                attack_vectors=["web_exploit", "protocol_attack", "supply_chain"],
                network_behavior={"ports": [80, 443, 1883, 5683], "traffic_pattern": "hub_coordinator"}
            )
        }
    
    def _load_vulnerability_patterns(self) -> Dict[str, Dict]:
        """Load patterns that map CVE types to smart home contexts"""
        return {
            "buffer_overflow": {
                "devices": ["smart_camera", "smart_thermostat", "smart_hub"],
                "attack_methods": ["firmware_exploit", "network_packet_craft", "input_overflow"],
                "severity_mapping": {"HIGH": "device_takeover", "MEDIUM": "service_crash", "LOW": "info_leak"}
            },
            "authentication_bypass": {
                "devices": ["smart_lock", "smart_camera", "smart_hub"],
                "attack_methods": ["credential_bypass", "session_hijack", "token_forge"],
                "severity_mapping": {"HIGH": "full_access", "MEDIUM": "limited_access", "LOW": "info_access"}
            },
            "remote_code_execution": {
                "devices": ["smart_hub", "smart_camera", "smart_thermostat"],
                "attack_methods": ["firmware_inject", "web_shell", "command_injection"],
                "severity_mapping": {"HIGH": "full_control", "MEDIUM": "limited_shell", "LOW": "read_access"}
            },
            "information_disclosure": {
                "devices": ["smart_camera", "smart_doorbell", "smart_thermostat"],
                "attack_methods": ["data_exfiltration", "stream_intercept", "log_access"],
                "severity_mapping": {"HIGH": "sensitive_data", "MEDIUM": "usage_data", "LOW": "metadata"}
            },
            "denial_of_service": {
                "devices": ["smart_lock", "smart_camera", "smart_hub"],
                "attack_methods": ["resource_exhaust", "crash_exploit", "network_flood"],
                "severity_mapping": {"HIGH": "system_offline", "MEDIUM": "service_degraded", "LOW": "temp_unavail"}
            }
        }
    
    def map_cve_to_smart_home(self, threat_data: Dict) -> Dict[str, Any]:
        """Map CVE threat to smart home device context"""
        try:
            cve_id = threat_data.get('cve_id', 'Unknown')
            description = threat_data.get('description', '').lower()
            severity = threat_data.get('severity', {}).get('cvss_v3_severity', 'UNKNOWN')
            nlp_analysis = threat_data.get('nlp_analysis', {})
            
            # Identify vulnerability type from description
            vuln_type = self._identify_vulnerability_type(description)
            
            # Get relevant devices based on NLP analysis and vulnerability type
            relevant_devices = self._get_relevant_devices(nlp_analysis, vuln_type)
            
            # Generate context mapping
            context = {
                'cve_id': cve_id,
                'vulnerability_type': vuln_type,
                'severity': severity,
                'target_devices': relevant_devices,
                'attack_methods': self._get_attack_methods(vuln_type, severity),
                'impact_assessment': self._assess_impact(vuln_type, severity, relevant_devices),
                'smart_home_relevance': self._calculate_relevance(description, relevant_devices)
            }
            
            logger.debug(f"Mapped {cve_id} to smart home context: {context['target_devices']}")
            return context
            
        except Exception as e:
            logger.error(f"Error mapping CVE to smart home context: {e}")
            return {}
    
    def _identify_vulnerability_type(self, description: str) -> str:
        """Identify the primary vulnerability type from CVE description"""
        vuln_patterns = {
            'buffer_overflow': ['buffer overflow', 'stack overflow', 'heap overflow', 'memory corruption'],
            'authentication_bypass': ['authentication bypass', 'auth bypass', 'login bypass', 'access control'],
            'remote_code_execution': ['remote code execution', 'rce', 'code injection', 'command injection'],
            'information_disclosure': ['information disclosure', 'data leak', 'sensitive data', 'exposure'],
            'denial_of_service': ['denial of service', 'dos', 'crash', 'hang', 'resource exhaustion']
        }
        
        for vuln_type, patterns in vuln_patterns.items():
            if any(pattern in description for pattern in patterns):
                return vuln_type
        
        return 'unknown'
    
    def _get_relevant_devices(self, nlp_analysis: Dict, vuln_type: str) -> List[str]:
        """Determine which smart home devices are relevant to this vulnerability"""
        relevant_devices = []
        
        # Use NLP analysis to identify specific devices
        identified_devices = nlp_analysis.get('devices', [])
        device_mapping = {
            'camera': 'smart_camera',
            'thermostat': 'smart_thermostat',
            'doorbell': 'smart_doorbell',
            'lock': 'smart_lock',
            'hub': 'smart_hub',
            'router': 'smart_hub'
        }
        
        for device in identified_devices:
            if device in device_mapping:
                relevant_devices.append(device_mapping[device])
        
        # If no specific devices identified, use vulnerability type mapping
        if not relevant_devices and vuln_type in self.vulnerability_patterns:
            relevant_devices = self.vulnerability_patterns[vuln_type]['devices'][:2]
        
        # Default fallback
        if not relevant_devices:
            relevant_devices = ['smart_hub', 'smart_camera']
        
        return relevant_devices
    
    def _get_attack_methods(self, vuln_type: str, severity: str) -> List[str]:
        """Get possible attack methods for this vulnerability type"""
        if vuln_type in self.vulnerability_patterns:
            pattern = self.vulnerability_patterns[vuln_type]
            return pattern['attack_methods']
        return ['network_exploit', 'local_access']
    
    def _assess_impact(self, vuln_type: str, severity: str, devices: List[str]) -> Dict[str, str]:
        """Assess the potential impact of the vulnerability"""
        impact_levels = {
            'HIGH': 'critical',
            'MEDIUM': 'significant', 
            'LOW': 'limited',
            'UNKNOWN': 'assessment_needed'
        }
        
        device_criticality = {
            'smart_lock': 'high',
            'smart_camera': 'high',
            'smart_hub': 'critical',
            'smart_thermostat': 'medium',
            'smart_doorbell': 'medium'
        }
        
        max_device_impact = max([device_criticality.get(device, 'low') for device in devices], 
                               key=lambda x: ['low', 'medium', 'high', 'critical'].index(x))
        
        return {
            'severity_impact': impact_levels.get(severity, 'unknown'),
            'device_impact': max_device_impact,
            'overall_risk': self._calculate_overall_risk(severity, max_device_impact)
        }
    
    def _calculate_overall_risk(self, severity: str, device_impact: str) -> str:
        """Calculate overall risk level"""
        severity_score = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 1}.get(severity, 1)
        device_score = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(device_impact, 1)
        
        total_score = severity_score + device_score
        
        if total_score >= 6:
            return 'critical'
        elif total_score >= 4:
            return 'high'
        elif total_score >= 3:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_relevance(self, description: str, devices: List[str]) -> float:
        """Calculate how relevant this CVE is to smart home environments"""
        smart_home_keywords = [
            'iot', 'smart home', 'connected device', 'home automation',
            'wireless', 'remote access', 'camera', 'thermostat', 'doorbell',
            'lock', 'sensor', 'gateway', 'hub'
        ]
        
        keyword_count = sum(1 for keyword in smart_home_keywords if keyword in description)
        device_relevance = len(devices) * 0.2
        
        relevance = min((keyword_count * 0.15) + device_relevance, 1.0)
        return relevance

class AttackVectorGenerator:
    """Generates realistic attack sequences for smart home scenarios"""
    
    def __init__(self, context_engine: SmartHomeContextEngine):
        self.context_engine = context_engine
        self.attack_templates = self._load_attack_templates()
    
    def _load_attack_templates(self) -> Dict[str, Dict]:
        """Load attack sequence templates"""
        return {
            "network_infiltration": {
                "phases": ["reconnaissance", "initial_access", "lateral_movement", "persistence", "impact"],
                "duration": "2-6 hours",
                "complexity": "medium",
                "detection_difficulty": "medium"
            },
            "device_takeover": {
                "phases": ["target_selection", "vulnerability_exploit", "device_compromise", "privilege_escalation", "control"],
                "duration": "30 minutes - 2 hours", 
                "complexity": "high",
                "detection_difficulty": "low"
            },
            "data_exfiltration": {
                "phases": ["access_gain", "data_discovery", "collection", "staging", "exfiltration"],
                "duration": "1-4 hours",
                "complexity": "medium",
                "detection_difficulty": "high"
            },
            "service_disruption": {
                "phases": ["target_analysis", "attack_vector_prep", "service_attack", "impact_assessment"],
                "duration": "15 minutes - 1 hour",
                "complexity": "low",
                "detection_difficulty": "low"
            }
        }
    
        
    def generate_realistic_attack_sequence(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate realistic attack with failures and delays"""
        
        # Attack success rates (realistic failure rates)
        success_rates = {
            'reconnaissance': 0.95,
            'initial_access': 0.3,    # Most attacks fail here
            'lateral_movement': 0.6,
            'persistence': 0.7,
            'impact': 0.8
        }
        
        timeline = []
        current_time = 0
        
        # Generate each phase with realistic success/failure
        phases = ['reconnaissance', 'initial_access', 'lateral_movement', 'persistence', 'impact']
        
        for i, phase in enumerate(phases):
            # Random delays between phases (1-24 hours)
            if i > 0:
                delay_hours = random.uniform(1, 24)
                current_time += delay_hours * 60  # Convert to minutes
            
            # Check if this phase succeeds
            success = random.random() < success_rates[phase]
            
            phase_data = {
                'phase': phase,
                'phase_number': i + 1,
                'start_time_minutes': current_time,
                'duration_minutes': random.randint(5, 60),
                'success': success,
                'actions': self._get_phase_actions(phase, success),
                'flows_generated': random.randint(5, 50) if success else random.randint(1, 5)
            }
            
            timeline.append(phase_data)
            current_time += phase_data['duration_minutes']
            
            # If phase fails critically, stop the attack
            if not success and phase in ['initial_access', 'lateral_movement']:
                if random.random() < 0.3:  # 30% chance attack stops on failure
                    break
        
        return {
            'attack_type': 'realistic_multi_phase',
            'timeline': timeline,
            'total_duration_hours': current_time / 60,
            'overall_success': any(p['success'] for p in timeline[-2:])  # Success if later phases succeed
        }

    def _get_phase_actions(self, phase: str, success: bool) -> List[str]:
        """Get realistic actions for each phase"""
        actions_map = {
            'reconnaissance': [
                'Network port scanning',
                'Service enumeration',
                'OS fingerprinting'
            ],
            'initial_access': [
                'Exploit vulnerability attempt',
                'Credential brute force',
                'Phishing attack'
            ] if success else [
                'Failed exploit attempt',
                'Blocked by firewall',
                'Incorrect target version'
            ],
            'lateral_movement': [
                'Internal network scanning',
                'Credential harvesting',
                'Device compromise'
            ] if success else [
                'Access denied',
                'Limited privileges',
                'Network segmentation blocked'
            ]
        }
        
        base_actions = actions_map.get(phase, ['Generic action'])
        return base_actions[:3]  # Limit to 3 actions
        
        
    def generate_attack_sequence(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed attack sequence based on context"""
        try:
            vuln_type = context.get('vulnerability_type', 'unknown')
            severity = context.get('severity', 'UNKNOWN')
            target_devices = context.get('target_devices', [])
            
            # Select appropriate attack template
            attack_type = self._select_attack_type(vuln_type, severity)
            template = self.attack_templates[attack_type]
            
            # Generate detailed timeline
            timeline = self._generate_attack_timeline(attack_type, template, target_devices, context)
            
            # Generate network indicators
            network_indicators = self._generate_network_indicators(attack_type, target_devices, context)
            
            sequence = {
                'attack_type': attack_type,
                'template_used': template,
                'timeline': timeline,
                'network_indicators': network_indicators,
                'complexity_rating': template['complexity'],
                'estimated_duration': template['duration'],
                'detection_difficulty': template['detection_difficulty']
            }
            
            return sequence
            
        except Exception as e:
            logger.error(f"Error generating attack sequence: {e}")
            return {}
    
    def _select_attack_type(self, vuln_type: str, severity: str) -> str:
        """Select appropriate attack type based on vulnerability"""
        mapping = {
            'remote_code_execution': 'device_takeover',
            'authentication_bypass': 'network_infiltration', 
            'information_disclosure': 'data_exfiltration',
            'denial_of_service': 'service_disruption',
            'buffer_overflow': 'device_takeover'
        }
        
        return mapping.get(vuln_type, 'network_infiltration')
    
    def _generate_attack_timeline(self, attack_type: str, template: Dict, devices: List[str], context: Dict) -> List[Dict]:
        """Generate detailed attack timeline with specific actions"""
        timeline = []
        phases = template['phases']
        
        phase_generators = {
            'reconnaissance': self._generate_recon_phase,
            'initial_access': self._generate_initial_access_phase,
            'lateral_movement': self._generate_lateral_movement_phase,
            'persistence': self._generate_persistence_phase,
            'impact': self._generate_impact_phase,
            'target_selection': self._generate_target_selection_phase,
            'vulnerability_exploit': self._generate_exploit_phase,
            'device_compromise': self._generate_compromise_phase,
            'privilege_escalation': self._generate_privilege_escalation_phase,
            'control': self._generate_control_phase,
            'access_gain': self._generate_access_gain_phase,
            'data_discovery': self._generate_data_discovery_phase,
            'collection': self._generate_collection_phase,
            'staging': self._generate_staging_phase,
            'exfiltration': self._generate_exfiltration_phase,
            'target_analysis': self._generate_target_analysis_phase,
            'attack_vector_prep': self._generate_vector_prep_phase,
            'service_attack': self._generate_service_attack_phase,
            'impact_assessment': self._generate_impact_assessment_phase
        }
        
        for i, phase in enumerate(phases):
            if phase in phase_generators:
                phase_data = phase_generators[phase](devices, context, i)
                timeline.append(phase_data)
        
        return timeline
    
    def _generate_recon_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        """Generate reconnaissance phase details"""
        return {
            'phase': 'reconnaissance',
            'phase_number': phase_num + 1,
            'duration_minutes': random.randint(10, 30),
            'actions': [
                'Network scanning to identify smart home devices',
                f'Port scanning on target devices: {", ".join(devices)}',
                'Service fingerprinting and version detection',
                'Identifying device manufacturers and firmware versions'
            ],
            'tools_used': ['nmap', 'masscan', 'shodan'],
            'network_activity': {
                'scan_patterns': ['TCP SYN scan', 'UDP scan', 'service detection'],
                'target_ports': [80, 443, 22, 23, 1883, 5683],
                'traffic_volume': 'low_moderate'
            }
        }
    
    def _generate_initial_access_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        """Generate initial access phase details"""
        vuln_type = context.get('vulnerability_type', 'unknown')
        
        exploit_methods = {
            'authentication_bypass': 'Exploit authentication bypass vulnerability',
            'buffer_overflow': 'Trigger buffer overflow in device firmware',
            'remote_code_execution': 'Execute arbitrary code via RCE vulnerability'
        }
        
        return {
            'phase': 'initial_access',
            'phase_number': phase_num + 1, 
            'duration_minutes': random.randint(5, 20),
            'actions': [
                exploit_methods.get(vuln_type, 'Exploit identified vulnerability'),
                f'Gain initial foothold on {devices[0] if devices else "target device"}',
                'Establish command and control channel'
            ],
            'exploit_details': {
                'vulnerability_type': vuln_type,
                'cve_exploited': context.get('cve_id', 'Unknown'),
                'success_probability': 0.8 if context.get('severity') == 'HIGH' else 0.6
            }
        }
    
    def _generate_lateral_movement_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        """Generate lateral movement phase details"""
        return {
            'phase': 'lateral_movement',
            'phase_number': phase_num + 1,
            'duration_minutes': random.randint(15, 45),
            'actions': [
                'Enumerate other devices on the smart home network',
                'Attempt credential reuse across devices',
                'Exploit trust relationships between devices',
                f'Compromise additional devices: {", ".join(devices[1:]) if len(devices) > 1 else "network infrastructure"}'
            ],
            'techniques': ['credential_stuffing', 'protocol_exploitation', 'trust_abuse']
        }
    
    def _generate_persistence_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        """Generate persistence phase details"""
        return {
            'phase': 'persistence',
            'phase_number': phase_num + 1,
            'duration_minutes': random.randint(10, 25),
            'actions': [
                'Install backdoor on compromised devices',
                'Modify device firmware for persistent access',
                'Create scheduled tasks or services',
                'Establish alternative communication channels'
            ],
            'persistence_methods': ['firmware_modification', 'scheduled_tasks', 'network_backdoor']
        }
    
    def _generate_impact_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        """Generate impact phase details"""
        impact_actions = {
            'smart_camera': ['Access live video streams', 'Disable recording capabilities', 'Manipulate motion detection'],
            'smart_lock': ['Unlock doors remotely', 'Change access codes', 'Disable lock mechanisms'],
            'smart_thermostat': ['Manipulate temperature settings', 'Access usage patterns', 'Disable HVAC system'],
            'smart_hub': ['Control all connected devices', 'Access stored credentials', 'Monitor all network traffic']
        }
        
        actions = []
        for device in devices:
            actions.extend(impact_actions.get(device, ['Manipulate device functionality']))
        
        return {
            'phase': 'impact',
            'phase_number': phase_num + 1,
            'duration_minutes': random.randint(5, 60),
            'actions': actions[:4],  # Limit to 4 actions
            'impact_type': context.get('impact_assessment', {}).get('overall_risk', 'medium')
        }
    
    # Additional phase generators with similar structure...
    def _generate_target_selection_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {
            'phase': 'target_selection',
            'phase_number': phase_num + 1,
            'duration_minutes': random.randint(5, 15),
            'actions': [f'Identify vulnerable {device} device' for device in devices[:2]],
            'selection_criteria': ['vulnerability_severity', 'access_level', 'impact_potential']
        }
    
    def _generate_exploit_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {
            'phase': 'vulnerability_exploit',
            'phase_number': phase_num + 1,
            'duration_minutes': random.randint(2, 10),
            'actions': [f'Exploit {context.get("cve_id", "vulnerability")} on target device'],
            'exploit_success_rate': 0.9 if context.get('severity') == 'HIGH' else 0.7
        }
    
    # Simplified versions of other phase generators...
    def _generate_compromise_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'device_compromise', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(1, 5), 'actions': ['Gain control of target device']}
    
    def _generate_privilege_escalation_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'privilege_escalation', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(5, 15), 'actions': ['Escalate privileges to admin level']}
        
    def _generate_control_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'control', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(2, 30), 'actions': ['Establish full device control']}
        
    def _generate_access_gain_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'access_gain', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(5, 20), 'actions': ['Gain access to device data stores']}
        
    def _generate_data_discovery_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'data_discovery', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(10, 30), 'actions': ['Discover sensitive data locations']}
        
    def _generate_collection_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'collection', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(15, 45), 'actions': ['Collect target data']}
        
    def _generate_staging_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'staging', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(5, 20), 'actions': ['Stage data for exfiltration']}
        
    def _generate_exfiltration_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'exfiltration', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(10, 60), 'actions': ['Exfiltrate collected data']}
        
    def _generate_target_analysis_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'target_analysis', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(5, 15), 'actions': ['Analyze target service architecture']}
        
    def _generate_vector_prep_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'attack_vector_prep', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(5, 15), 'actions': ['Prepare DoS attack vectors']}
        
    def _generate_service_attack_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'service_attack', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(1, 30), 'actions': ['Execute service disruption attack']}
        
    def _generate_impact_assessment_phase(self, devices: List[str], context: Dict, phase_num: int) -> Dict:
        return {'phase': 'impact_assessment', 'phase_number': phase_num + 1, 'duration_minutes': random.randint(2, 10), 'actions': ['Assess attack impact and success']}
    
    def _generate_network_indicators(self, attack_type: str, devices: List[str], context: Dict) -> Dict:
        """Generate network-level indicators for the attack"""
        return {
            'suspicious_traffic_patterns': [
                'Unusual port scanning activity',
                'Abnormal device communication patterns',
                'Unexpected outbound connections'
            ],
            'protocol_anomalies': [
                'Malformed MQTT messages',
                'Unexpected HTTP requests',
                'Invalid authentication attempts'
            ],
            'timing_indicators': {
                'attack_duration': self.attack_templates[attack_type]['duration'],
                'peak_activity_periods': ['initial_access', 'lateral_movement']
            }
        }

class AttackScenarioGenerator:
    """Main class that orchestrates attack scenario generation"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.context_engine = SmartHomeContextEngine()
        self.vector_generator = AttackVectorGenerator(self.context_engine)
        
    def generate_scenario(self, threat_data: Dict) -> Optional[AttackScenario]:
        """Generate complete attack scenario from threat data"""
        try:
            # Map CVE to smart home context
            context = self.context_engine.map_cve_to_smart_home(threat_data)
            
            if not context or context.get('smart_home_relevance', 0) < 0.3:
                logger.debug(f"Threat {threat_data.get('cve_id')} not relevant to smart home")
                return None
            
            # Generate attack sequence
            attack_sequence = self.vector_generator.generate_attack_sequence(context)
            
            # Create scenario narrative
            narrative = self._generate_scenario_narrative(context, attack_sequence, threat_data)
            
            # Generate scenario ID
            scenario_id = f"DH-{threat_data.get('cve_id', 'UNK').replace('CVE-', '')}-{int(time.time())}"
            
            # Calculate quality score
            quality_score = self._calculate_quality_score(context, attack_sequence, threat_data)
            
            scenario = AttackScenario(
                scenario_id=scenario_id,
                cve_id=threat_data.get('cve_id', 'Unknown'),
                attack_name=self._generate_attack_name(context, attack_sequence),
                target_devices=context.get('target_devices', []),
                attack_vector=attack_sequence.get('attack_type', 'unknown'),
                complexity=attack_sequence.get('complexity_rating', 'medium'),
                impact_level=context.get('impact_assessment', {}).get('overall_risk', 'medium'),
                timeline=attack_sequence.get('timeline', []),
                network_indicators=attack_sequence.get('network_indicators', {}),
                mitigation_strategies=self._generate_mitigations(context, attack_sequence),
                scenario_narrative=narrative,
                technical_details=self._compile_technical_details(context, attack_sequence, threat_data),
                quality_score=quality_score
            )
            
            logger.info(f"Generated scenario {scenario_id} for {threat_data.get('cve_id')}")
            return scenario
            
        except Exception as e:
            logger.error(f"Error generating attack scenario: {e}")
            return None
    
    def _generate_scenario_narrative(self, context: Dict, attack_sequence: Dict, threat_data: Dict) -> str:
        """Generate human-readable scenario narrative"""
        cve_id = threat_data.get('cve_id', 'Unknown CVE')
        devices = context.get('target_devices', ['smart devices'])
        attack_type = attack_sequence.get('attack_type', 'network attack')
        severity = context.get('severity', 'UNKNOWN')
        
        narrative = f"""
Attack Scenario: Exploitation of {cve_id} in Smart Home Environment

An attacker discovers and exploits {cve_id}, a {severity.lower()} severity vulnerability 
affecting {', '.join(devices)} in a smart home network. 

The attack follows a {attack_type} pattern, leveraging the vulnerability to:
- Gain unauthorized access to targeted smart home devices
- Potentially compromise the broader home network
- Impact the security and privacy of residents

This scenario demonstrates how CVE vulnerabilities can be weaponized against 
smart home infrastructure, highlighting the need for prompt patching and 
robust security measures in IoT environments.
        """.strip()
        
        return narrative
    
    def _generate_attack_name(self, context: Dict, attack_sequence: Dict) -> str:
        """Generate descriptive attack name"""
        vuln_type = context.get('vulnerability_type', 'exploit')
        devices = context.get('target_devices', ['device'])
        attack_type = attack_sequence.get('attack_type', 'attack')
        
        # Create descriptive name
        device_part = devices[0].replace('smart_', '').replace('_', ' ').title()
        vuln_part = vuln_type.replace('_', ' ').title()
        
        return f"{device_part} {vuln_part} via {attack_type.replace('_', ' ').title()}"
    
    def _generate_mitigations(self, context: Dict, attack_sequence: Dict) -> List[str]:
        """Generate mitigation strategies for the attack"""
        base_mitigations = [
            "Apply security patches and firmware updates promptly",
            "Implement network segmentation for IoT devices", 
            "Enable device authentication and encryption",
            "Monitor network traffic for anomalous patterns",
            "Use strong, unique passwords for all devices"
        ]
        
        vuln_specific = {
            'buffer_overflow': ["Enable address space layout randomization", "Implement stack canaries"],
            'authentication_bypass': ["Implement multi-factor authentication", "Use certificate-based authentication"],
            'remote_code_execution': ["Enable code signing verification", "Implement application sandboxing"],
            'information_disclosure': ["Encrypt sensitive data at rest and in transit", "Implement data loss prevention"],
            'denial_of_service': ["Implement rate limiting", "Deploy DDoS protection services"]
        }
        
        vuln_type = context.get('vulnerability_type', 'unknown')
        if vuln_type in vuln_specific:
            base_mitigations.extend(vuln_specific[vuln_type])
        
        return base_mitigations[:6]  # Return top 6 mitigations
    
    def _compile_technical_details(self, context: Dict, attack_sequence: Dict, threat_data: Dict) -> Dict:
        """Compile technical details for the scenario"""
        return {
            'vulnerability_details': {
                'cve_id': threat_data.get('cve_id'),
                'cvss_score': threat_data.get('severity', {}).get('cvss_v3_score'),
                'cvss_severity': threat_data.get('severity', {}).get('cvss_v3_severity'),
                'vulnerability_type': context.get('vulnerability_type'),
                'affected_protocols': self._get_affected_protocols(context.get('target_devices', []))
            },
            'attack_details': {
                'attack_vector': attack_sequence.get('attack_type'),
                'complexity': attack_sequence.get('complexity_rating'),
                'estimated_duration': attack_sequence.get('estimated_duration'),
                'detection_difficulty': attack_sequence.get('detection_difficulty'),
                'required_access': self._determine_required_access(context, attack_sequence)
            },
            'impact_assessment': context.get('impact_assessment', {}),
            'smart_home_context': {
                'target_devices': context.get('target_devices', []),
                'relevance_score': context.get('smart_home_relevance', 0),
                'device_categories': self._get_device_categories(context.get('target_devices', []))
            }
        }
    
    def _get_affected_protocols(self, devices: List[str]) -> List[str]:
        """Get protocols affected by the attack"""
        protocols = set()
        for device_name in devices:
            if device_name in self.context_engine.device_catalog:
                device = self.context_engine.device_catalog[device_name]
                protocols.update(device.protocols)
        return list(protocols)
    
    def _get_device_categories(self, devices: List[str]) -> List[str]:
        """Get categories of affected devices"""
        categories = set()
        for device_name in devices:
            if device_name in self.context_engine.device_catalog:
                device = self.context_engine.device_catalog[device_name]
                categories.add(device.category)
        return list(categories)
    
    def _determine_required_access(self, context: Dict, attack_sequence: Dict) -> str:
        """Determine the access level required for the attack"""
        attack_type = attack_sequence.get('attack_type', '')
        complexity = attack_sequence.get('complexity_rating', 'medium')
        
        if 'network' in attack_type and complexity == 'low':
            return 'network_access'
        elif complexity == 'high':
            return 'physical_access_or_insider'
        else:
            return 'remote_network_access'
    
    def _calculate_quality_score(self, context: Dict, attack_sequence: Dict, threat_data: Dict) -> float:
        """Calculate quality score for the generated scenario"""
        score = 0.0
        
        # Relevance to smart home (30%)
        relevance = context.get('smart_home_relevance', 0)
        score += relevance * 0.3
        
        # Completeness of attack sequence (25%)
        timeline = attack_sequence.get('timeline', [])
        sequence_completeness = min(len(timeline) / 5.0, 1.0)  # Expect ~5 phases
        score += sequence_completeness * 0.25
        
        # Technical detail richness (20%)
        technical_richness = min(len(str(attack_sequence)) / 1000.0, 1.0)  # Rough measure
        score += technical_richness * 0.2
        
        # CVE data quality (15%)
        cve_quality = 0.5
        if threat_data.get('severity', {}).get('cvss_v3_score'):
            cve_quality += 0.25
        if threat_data.get('nlp_analysis', {}).get('devices'):
            cve_quality += 0.25
        score += cve_quality * 0.15
        
        # Novelty/uniqueness (10%)
        novelty = 0.7  # Base novelty score
        score += novelty * 0.1
        
        return min(score, 1.0)

# Example usage and testing
if __name__ == "__main__":
    # Test the attack scenario generator
    generator = AttackScenarioGenerator()
    
    # Example threat data (would come from your existing pipeline)
    sample_threat = {
        'cve_id': 'CVE-2024-12345',
        'description': 'Buffer overflow vulnerability in smart camera firmware allows remote code execution via malformed RTSP requests',
        'severity': {'cvss_v3_score': 8.5, 'cvss_v3_severity': 'HIGH'},
        'nlp_analysis': {
            'devices': ['camera'],
            'attack_types': ['remote_access', 'code_execution'],
            'protocols': ['rtsp', 'http']
        }
    }
    
    scenario = generator.generate_scenario(sample_threat)
    
    if scenario:
        print(f"Generated scenario: {scenario.attack_name}")
        print(f"Quality score: {scenario.quality_score:.2f}")
        print(f"Target devices: {scenario.target_devices}")
        print(f"Timeline phases: {len(scenario.timeline)}")
    else:
        print("No scenario generated (low relevance)")