# ai_pipeline.py - Enhanced with comprehensive error handling and fallbacks
import json
import os
import logging
import time
import signal
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter
from typing import Optional, List, Dict, Any, Tuple
import pandas as pd
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import psutil

# Import our custom modules with error handling
try:
    from threat_collector import ThreatCollector, ThreatCollectionError
    from ai_classifier import IoTThreatClassifier
except ImportError as e:
    logging.error(f"Failed to import required modules: {e}")
    raise

# Configure comprehensive logging
def setup_logging():
    """Set up comprehensive logging configuration"""
    log_dir = Path("data/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Create handlers separately and set levels correctly
    main_handler = logging.FileHandler(log_dir / 'ai_pipeline.log')
    main_handler.setLevel(logging.INFO)
    
    error_handler = logging.FileHandler(log_dir / 'ai_pipeline_errors.log')
    error_handler.setLevel(logging.ERROR)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Configure basic logging with the correctly configured handlers
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            main_handler,
            error_handler,
            console_handler
        ]
    )

# Initialize logging and create module-level logger
setup_logging()
logger = logging.getLogger(__name__)

class AIModelError(Exception):
    """AI model operation errors"""
    pass

class PipelineTimeoutError(Exception):
    """Pipeline operation timeout"""
    pass

class DataProcessingError(Exception):
    """Data processing errors"""
    pass

class AdvancedNLPProcessor:
    """Enhanced NLP processor with error handling and fallbacks"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.nlp = None
        self.model_loaded = False
        self.fallback_mode = False
        self.load_timeout = self.config.get('model_load_timeout', 120)  # 2 minutes
        
        # Initialize with timeout and fallback
        self._initialize_with_fallback()
        
        # Define patterns with validation
        self.device_types = self._validate_patterns({
            'camera': ['camera', 'webcam', 'surveillance', 'cctv'],
            'thermostat': ['thermostat', 'hvac', 'temperature', 'climate'],
            'doorbell': ['doorbell', 'door bell', 'video doorbell'],
            'lock': ['smart lock', 'door lock', 'electronic lock', 'deadbolt'],
            'light': ['smart light', 'led light', 'lighting', 'bulb'],
            'speaker': ['smart speaker', 'voice assistant', 'alexa', 'google home', 'echo'],
            'router': ['router', 'gateway', 'access point', 'wifi'],
            'hub': ['smart hub', 'home hub', 'control hub', 'controller']
        })
        
        self.attack_types = self._validate_patterns({
            'remote_access': ['remote access', 'unauthorized access', 'remote control', 'rce'],
            'data_theft': ['data theft', 'information disclosure', 'data leak', 'data breach'],
            'denial_service': ['denial of service', 'dos', 'ddos', 'crash', 'hang'],
            'privilege_escalation': ['privilege escalation', 'root access', 'admin', 'sudo'],
            'code_execution': ['code execution', 'command injection', 'shell', 'exploit']
        })
        
        logger.info(f"AdvancedNLPProcessor initialized (fallback_mode: {self.fallback_mode})")

    def _initialize_with_fallback(self):
        """Initialize spaCy model with timeout and fallback handling"""
        def load_model():
            try:
                import spacy
                self.nlp = spacy.load("en_core_web_sm")
                self.model_loaded = True
                logger.info("spaCy model loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load spaCy model: {e}")
                raise AIModelError(f"spaCy model loading failed: {e}")
        
        try:
            # Use thread with timeout for model loading
            model_thread = threading.Thread(target=load_model)
            model_thread.daemon = True
            model_thread.start()
            model_thread.join(timeout=self.load_timeout)
            
            if model_thread.is_alive():
                logger.warning(f"Model loading timeout after {self.load_timeout}s, using fallback mode")
                self.fallback_mode = True
            elif not self.model_loaded:
                logger.warning("Model loading failed, using fallback mode")
                self.fallback_mode = True
                
        except Exception as e:
            logger.error(f"Error during model initialization: {e}")
            self.fallback_mode = True

    def _validate_patterns(self, patterns: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Validate and clean pattern definitions"""
        validated = {}
        for category, keywords in patterns.items():
            if isinstance(keywords, list) and keywords:
                # Clean and validate keywords
                clean_keywords = []
                for keyword in keywords:
                    if isinstance(keyword, str) and keyword.strip():
                        clean_keywords.append(keyword.strip().lower())
                
                if clean_keywords:
                    validated[category] = clean_keywords
                else:
                    logger.warning(f"No valid keywords for category: {category}")
            else:
                logger.warning(f"Invalid pattern definition for category: {category}")
        
        return validated

    def analyze_vulnerability(self, text: str, timeout: int = 30) -> Dict[str, Any]:
        """Extract detailed information from vulnerability text with error handling"""
        if not text or not isinstance(text, str):
            logger.warning("Invalid or empty text provided for analysis")
            return self._get_empty_analysis()
        
        try:
            # Set up timeout handling
            def analysis_worker():
                return {
                    'devices': self.identify_devices(text),
                    'attack_types': self.identify_attack_types(text),
                    'protocols': self.identify_protocols(text),
                    'entities': self.extract_entities(text),
                    'severity_indicators': self.find_severity_words(text),
                    'processing_method': 'fallback' if self.fallback_mode else 'full_nlp',
                    'analysis_timestamp': datetime.now().isoformat()
                }
            
            # Execute with timeout
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(analysis_worker)
                try:
                    result = future.result(timeout=timeout)
                    logger.debug("Vulnerability analysis completed successfully")
                    return result
                except FutureTimeoutError:
                    logger.warning(f"Analysis timeout after {timeout}s, returning partial results")
                    return self._get_partial_analysis(text)
                
        except Exception as e:
            logger.error(f"Error during vulnerability analysis: {e}")
            return self._get_error_analysis(str(e))

    def _get_empty_analysis(self) -> Dict[str, Any]:
        """Return empty analysis structure"""
        return {
            'devices': [],
            'attack_types': [],
            'protocols': [],
            'entities': {'organizations': [], 'products': [], 'versions': []},
            'severity_indicators': 'unknown',
            'processing_method': 'empty_input',
            'analysis_timestamp': datetime.now().isoformat()
        }

    def _get_partial_analysis(self, text: str) -> Dict[str, Any]:
        """Return partial analysis when full analysis times out"""
        try:
            return {
                'devices': self.identify_devices(text),
                'attack_types': self.identify_attack_types(text),
                'protocols': self.identify_protocols(text),
                'entities': {'organizations': [], 'products': [], 'versions': []},
                'severity_indicators': self.find_severity_words(text),
                'processing_method': 'partial_timeout',
                'analysis_timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error in partial analysis: {e}")
            return self._get_error_analysis(str(e))

    def _get_error_analysis(self, error_msg: str) -> Dict[str, Any]:
        """Return error analysis structure"""
        return {
            'devices': [],
            'attack_types': [],
            'protocols': [],
            'entities': {'organizations': [], 'products': [], 'versions': []},
            'severity_indicators': 'unknown',
            'processing_method': 'error',
            'error': error_msg,
            'analysis_timestamp': datetime.now().isoformat()
        }

    def identify_devices(self, text: str) -> List[str]:
        """Find specific device types mentioned with error handling"""
        try:
            if not text:
                return []
            
            text_lower = text.lower()
            found_devices = []
            
            for device_type, keywords in self.device_types.items():
                try:
                    for keyword in keywords:
                        if keyword in text_lower:
                            found_devices.append(device_type)
                            break
                except Exception as e:
                    logger.debug(f"Error checking device type {device_type}: {e}")
                    continue
            
            return list(set(found_devices))
            
        except Exception as e:
            logger.error(f"Error in device identification: {e}")
            return []

    def identify_attack_types(self, text: str) -> List[str]:
        """Identify the type of attack described with error handling"""
        try:
            if not text:
                return []
            
            text_lower = text.lower()
            found_attacks = []
            
            for attack_type, keywords in self.attack_types.items():
                try:
                    for keyword in keywords:
                        if keyword in text_lower:
                            found_attacks.append(attack_type)
                            break
                except Exception as e:
                    logger.debug(f"Error checking attack type {attack_type}: {e}")
                    continue
            
            return list(set(found_attacks))
            
        except Exception as e:
            logger.error(f"Error in attack type identification: {e}")
            return []

    def identify_protocols(self, text: str) -> List[str]:
        """Find network protocols mentioned with error handling"""
        try:
            if not text:
                return []
            
            protocols = ['wifi', 'bluetooth', 'zigbee', 'z-wave', 'http', 'https', 'mqtt', 'coap', 'ssl', 'tls']
            text_lower = text.lower()
            
            found_protocols = []
            for protocol in protocols:
                try:
                    if protocol in text_lower:
                        found_protocols.append(protocol)
                except Exception as e:
                    logger.debug(f"Error checking protocol {protocol}: {e}")
                    continue
            
            return found_protocols
            
        except Exception as e:
            logger.error(f"Error in protocol identification: {e}")
            return []

    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract named entities with fallback handling"""
        entities = {
            'organizations': [],
            'products': [],
            'versions': []
        }
        
        try:
            if not text or self.fallback_mode or not self.model_loaded:
                # Use simple fallback method
                return self._extract_entities_fallback(text)
            
            # Use spaCy for full entity extraction
            doc = self.nlp(text)
            
            for ent in doc.ents:
                try:
                    if ent.label_ == "ORG":
                        entities['organizations'].append(ent.text)
                    elif ent.label_ in ["PRODUCT", "WORK_OF_ART"]:
                        entities['products'].append(ent.text)
                    elif ent.label_ in ["CARDINAL", "ORDINAL"]:
                        entities['versions'].append(ent.text)
                except Exception as e:
                    logger.debug(f"Error processing entity {ent.text}: {e}")
                    continue
            
            # Remove duplicates
            for key in entities:
                entities[key] = list(set(entities[key]))
            
            return entities
            
        except Exception as e:
            logger.error(f"Error in entity extraction: {e}")
            return self._extract_entities_fallback(text)

    def _extract_entities_fallback(self, text: str) -> Dict[str, List[str]]:
        """Fallback entity extraction using simple patterns"""
        entities = {
            'organizations': [],
            'products': [],
            'versions': []
        }
        
        try:
            if not text:
                return entities
            
            # Simple pattern matching for common IoT vendors
            common_orgs = ['samsung', 'google', 'amazon', 'apple', 'microsoft', 'cisco', 'tp-link', 'netgear', 'linksys']
            text_lower = text.lower()
            
            for org in common_orgs:
                if org in text_lower:
                    entities['organizations'].append(org.title())
            
            # Simple version pattern matching
            import re
            version_patterns = [r'v?\d+\.\d+', r'version \d+\.\d+', r'firmware \d+\.\d+']
            
            for pattern in version_patterns:
                matches = re.findall(pattern, text.lower())
                entities['versions'].extend(matches)
            
            # Remove duplicates
            for key in entities:
                entities[key] = list(set(entities[key]))
            
            return entities
            
        except Exception as e:
            logger.error(f"Error in fallback entity extraction: {e}")
            return {
                'organizations': [],
                'products': [],
                'versions': []
            }

    def find_severity_words(self, text: str) -> str:
        """Find words that indicate severity with error handling"""
        try:
            if not text:
                return 'unknown'
            
            high_severity = ['critical', 'severe', 'dangerous', 'exploit', 'remote code execution', 'rce']
            medium_severity = ['moderate', 'medium', 'potential', 'vulnerability', 'flaw']
            low_severity = ['minor', 'low', 'minimal', 'information disclosure']
            
            text_lower = text.lower()
            
            # Check in order of severity
            for word in high_severity:
                if word in text_lower:
                    return 'high'
            
            for word in medium_severity:
                if word in text_lower:
                    return 'medium'
            
            for word in low_severity:
                if word in text_lower:
                    return 'low'
            
            return 'unknown'
            
        except Exception as e:
            logger.error(f"Error in severity word detection: {e}")
            return 'unknown'


class CompleteThreatPipeline:
    """Enhanced threat intelligence pipeline with comprehensive error handling"""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the complete AI-enhanced threat intelligence pipeline"""
        self.config = config or self._load_default_config()
        
        logger.info("Initializing Complete Threat Intelligence Pipeline")
        logger.info("=" * 60)
        
        # Initialize statistics tracking
        self.stats = {
            'total_vulnerabilities': 0,
            'iot_relevant': 0,
            'processed_successfully': 0,
            'errors': 0,
            'processing_time': 0,
            'last_run': None
        }
        
        # Initialize components with error handling
        self.threat_collector = None
        self.iot_classifier = None
        self.nlp_processor = None
        
        self._initialize_components()
        
        # Ensure output directories exist
        self._setup_directories()
        
        # Set up signal handlers for graceful shutdown
        self._setup_signal_handlers()
        
        logger.info("Pipeline initialized successfully!")

    def _load_default_config(self) -> Dict:
        """Load default configuration with environment variable support"""
        return {
            'component_timeout': int(os.getenv('DYNOHOME_COMPONENT_TIMEOUT', '120')),
            'max_processing_errors': float(os.getenv('DYNOHOME_MAX_ERROR_RATE', '0.1')),
            'enable_fallback': os.getenv('DYNOHOME_ENABLE_FALLBACK', 'true').lower() == 'true',
            'batch_size': int(os.getenv('DYNOHOME_BATCH_SIZE', '10')),
            'memory_limit_mb': int(os.getenv('DYNOHOME_MEMORY_LIMIT', '2048'))
        }

    def _initialize_components(self):
        """Initialize AI components with error handling and fallbacks"""
        
        # Initialize threat collector
        try:
            logger.info("Initializing threat collector...")
            self.threat_collector = ThreatCollector()
            logger.info("✓ Threat collector initialized")
        except Exception as e:
            logger.error(f"Failed to initialize threat collector: {e}")
            raise AIModelError(f"Threat collector initialization failed: {e}")
        
        # Initialize IoT classifier with timeout
        try:
            logger.info("Initializing IoT classifier...")
            
            def init_classifier():
                self.iot_classifier = IoTThreatClassifier()
            
            # Use timeout for classifier initialization
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(init_classifier)
                try:
                    future.result(timeout=self.config['component_timeout'])
                    logger.info("✓ IoT classifier initialized")
                except FutureTimeoutError:
                    logger.error("IoT classifier initialization timeout")
                    if self.config['enable_fallback']:
                        logger.warning("Using fallback classification mode")
                        self.iot_classifier = None
                    else:
                        raise AIModelError("IoT classifier initialization timeout")
                        
        except Exception as e:
            logger.error(f"Failed to initialize IoT classifier: {e}")
            if self.config['enable_fallback']:
                logger.warning("Using fallback classification mode")
                self.iot_classifier = None
            else:
                raise AIModelError(f"IoT classifier initialization failed: {e}")
        
        # Initialize NLP processor
        try:
            logger.info("Initializing NLP processor...")
            self.nlp_processor = AdvancedNLPProcessor(self.config)
            logger.info("✓ NLP processor initialized")
        except Exception as e:
            logger.error(f"Failed to initialize NLP processor: {e}")
            if self.config['enable_fallback']:
                logger.warning("Using basic NLP fallback")
                self.nlp_processor = AdvancedNLPProcessor({'fallback_mode': True})
            else:
                raise AIModelError(f"NLP processor initialization failed: {e}")

    def _setup_directories(self):
        """Set up required directories with error handling"""
        directories = [
            Path("data/processed"),
            Path("data/reports"),
            Path("data/logs"),
            Path("data/backups")
        ]
        
        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                logger.error(f"Permission denied creating directory: {directory}")
                raise
            except Exception as e:
                logger.error(f"Error creating directory {directory}: {e}")
                raise

   
        
        
        
        
     # Fix for ai_pipeline.py - Replace the _setup_signal_handlers method with this version:

    def _setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown (only in main thread)"""
        try:
            import threading
            
            # Check if we're in the main thread
            if threading.current_thread() is threading.main_thread():
                def signal_handler(signum, frame):
                    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
                    self._cleanup_resources()
                    exit(0)
                
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)
                logger.debug("Signal handlers configured successfully")
            else:
                logger.debug("Skipping signal handler setup - not in main thread (likely running in Streamlit)")
                
        except Exception as e:
            logger.warning(f"Could not setup signal handlers: {e}")
            logger.debug("Continuing without signal handlers (normal when running in web framework)")   
            
        
        
        

    def _cleanup_resources(self):
        """Clean up resources during shutdown"""
        logger.info("Cleaning up resources...")
        # Add any cleanup logic here
        logger.info("Resource cleanup complete")

    def _check_memory_usage(self) -> Dict[str, Any]:
        """Monitor memory usage and return status"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            
            status = {
                'memory_mb': round(memory_mb, 2),
                'memory_limit_mb': self.config['memory_limit_mb'],
                'memory_ok': memory_mb < self.config['memory_limit_mb']
            }
            
            if not status['memory_ok']:
                logger.warning(f"Memory usage {memory_mb:.1f}MB exceeds limit {self.config['memory_limit_mb']}MB")
            
            return status
            
        except Exception as e:
            logger.error(f"Error checking memory usage: {e}")
            return {'memory_mb': 0, 'memory_limit_mb': 0, 'memory_ok': True}

    def run_daily_collection(self, days_back: int = 1, max_results: int = 50) -> Optional[List[Dict]]:
        """Run complete daily threat intelligence collection with enhanced error handling"""
        
        start_time = datetime.now()
        logger.info(f"Starting Daily Threat Collection")
        logger.info(f"Date range: {days_back} days back, max {max_results} results")
        logger.info("=" * 60)
        
        # Reset statistics
        self.stats = {
            'total_vulnerabilities': 0,
            'iot_relevant': 0,
            'processed_successfully': 0,
            'errors': 0,
            'processing_time': 0,
            'last_run': start_time.isoformat()
        }
        
        try:
            # Check system resources
            memory_status = self._check_memory_usage()
            if not memory_status['memory_ok']:
                logger.error("Insufficient memory to proceed safely")
                return None
            
            # Step 1: Download raw vulnerabilities
            logger.info("Step 1: Downloading recent vulnerabilities...")
            try:
                raw_vulnerabilities = self.threat_collector.get_recent_cves(
                    days_back=days_back, 
                    max_results=max_results
                )
                
                if not raw_vulnerabilities:
                    logger.warning("No vulnerabilities downloaded. Exiting.")
                    return None
                
                self.stats['total_vulnerabilities'] = len(raw_vulnerabilities)
                logger.info(f"Downloaded {len(raw_vulnerabilities)} vulnerabilities")
                
            except ThreatCollectionError as e:
                logger.error(f"Threat collection failed: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error in threat collection: {e}")
                return None
            
            # Step 2: Extract basic CVE information
            logger.info("Step 2: Extracting CVE information...")
            extracted_threats = []
            extraction_errors = 0
            
            for vuln in raw_vulnerabilities:
                try:
                    threat_info = self.threat_collector.extract_cve_info(vuln)
                    if threat_info:
                        extracted_threats.append(threat_info)
                    else:
                        extraction_errors += 1
                except Exception as e:
                    logger.debug(f"Error extracting CVE info: {e}")
                    extraction_errors += 1
            
            logger.info(f"Extracted information from {len(extracted_threats)} vulnerabilities ({extraction_errors} errors)")
            
            if extraction_errors / len(raw_vulnerabilities) > self.config['max_processing_errors']:
                logger.error(f"Too many extraction errors ({extraction_errors}/{len(raw_vulnerabilities)})")
                return None
            
            # Step 3: Filter for IoT-related threats
            logger.info("Step 3: Classifying IoT-related threats...")
            iot_threats = []
            classification_errors = 0
            
            # Process in batches to manage memory
            batch_size = self.config['batch_size']
            
            for i in range(0, len(extracted_threats), batch_size):
                batch = extracted_threats[i:i + batch_size]
                
                for threat in batch:
                    try:
                        if self.iot_classifier:
                            # Use AI classifier
                            classification = self.iot_classifier.classify_threat(threat)
                            if classification:
                                iot_threats.append(classification)
                                self.stats['iot_relevant'] += 1
                                logger.debug(f"IoT threat found: {threat['cve_id']}")
                        else:
                            # Use fallback keyword-based classification
                            if self._fallback_iot_classification(threat):
                                iot_threats.append({
                                    'original_data': threat,
                                    'confidence': 0.5,
                                    'classification_method': 'fallback_keywords',
                                    'device_info': {'device_types': [], 'protocols': []},
                                    'entities': {}
                                })
                                self.stats['iot_relevant'] += 1
                                logger.debug(f"IoT threat found (fallback): {threat['cve_id']}")
                    
                    except Exception as e:
                        logger.debug(f"Classification error for {threat.get('cve_id', 'unknown')}: {e}")
                        classification_errors += 1
                        self.stats['errors'] += 1
                
                # Check memory after each batch
                memory_status = self._check_memory_usage()
                if not memory_status['memory_ok']:
                    logger.warning("Memory usage high, continuing with caution")
            
            logger.info(f"Identified {len(iot_threats)} IoT-related threats ({classification_errors} errors)")
            
            # Step 4: Enhanced analysis with advanced NLP
            logger.info("Step 4: Running advanced NLP analysis...")
            analyzed_threats = []
            nlp_errors = 0
            
            for threat in iot_threats:
                try:
                    # Get the original description
                    description = threat['original_data']['description']
                    
                    # Run advanced NLP analysis with timeout
                    nlp_analysis = self.nlp_processor.analyze_vulnerability(description, timeout=30)
                    
                    # Combine all analysis results
                    enhanced_threat = {
                        'cve_id': threat['original_data']['cve_id'],
                        'description': description,
                        'published_date': threat['original_data']['published_date'],
                        'severity': threat['original_data']['severity'],
                        'references': threat['original_data']['references'],
                        
                        # IoT classification results
                        'iot_classification': {
                            'confidence': threat['confidence'],
                            'method': threat['classification_method'],
                            'device_info': threat['device_info'],
                            'entities': threat['entities']
                        },
                        
                        # Advanced NLP analysis
                        'nlp_analysis': nlp_analysis,
                        
                        # Processing metadata
                        'processing_date': datetime.now().isoformat(),
                        'pipeline_version': '1.1.0'
                    }
                    
                    analyzed_threats.append(enhanced_threat)
                    self.stats['processed_successfully'] += 1
                    
                except Exception as e:
                    logger.debug(f"NLP analysis error for {threat.get('original_data', {}).get('cve_id', 'unknown')}: {e}")
                    nlp_errors += 1
                    self.stats['errors'] += 1
            
            logger.info(f"Completed analysis for {len(analyzed_threats)} threats ({nlp_errors} errors)")
            
            # Step 5: Save processed data
            logger.info("Step 5: Saving processed data...")
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"data/processed/iot_threats_{timestamp}.json"
                
                # Add metadata wrapper
                output_data = {
                    'metadata': {
                        'generation_timestamp': datetime.now().isoformat(),
                        'pipeline_version': '1.1.0',
                        'processing_stats': self.stats,
                        'configuration': self.config
                    },
                    'threats': analyzed_threats
                }
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)
                
                logger.info(f"Saved processed data to {output_file}")
                
            except Exception as e:
                logger.error(f"Error saving processed data: {e}")
                return analyzed_threats  # Return data even if save fails
            
            # Step 6: Generate summary report
            try:
                report_file = self.generate_summary_report(analyzed_threats, timestamp)
                logger.info(f"Summary report saved to {report_file}")
            except Exception as e:
                logger.error(f"Error generating summary report: {e}")
            
            # Step 7: Calculate final statistics
            end_time = datetime.now()
            processing_time = end_time - start_time
            self.stats['processing_time'] = processing_time.total_seconds()
            
            logger.info(f"Processing Complete!")
            logger.info(f"Time taken: {processing_time}")
            logger.info(f"Success rate: {self.stats['processed_successfully']}/{self.stats['total_vulnerabilities']}")
            
            return analyzed_threats
            
        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            logger.error(traceback.format_exc())
            return None

    def _fallback_iot_classification(self, threat: Dict) -> bool:
        """Fallback IoT classification using simple keyword matching"""
        try:
            description = threat.get('description', '').lower()
            
            iot_keywords = [
                'iot', 'smart home', 'smart device', 'connected device',
                'router', 'camera', 'thermostat', 'doorbell', 'sensor',
                'wifi', 'bluetooth', 'zigbee', 'smart'
            ]
            
            return any(keyword in description for keyword in iot_keywords)
            
        except Exception as e:
            logger.error(f"Error in fallback classification: {e}")
            return False

    def generate_summary_report(self, threats: List[Dict], timestamp: str) -> Optional[str]:
        """Generate a human-readable summary report with error handling"""
        report_file = f"data/reports/threat_report_{timestamp}.txt"
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("IoT Threat Intelligence Report\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Pipeline Version: 1.1.0\n\n")
                
                # Summary statistics
                f.write("SUMMARY STATISTICS\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total vulnerabilities analyzed: {self.stats['total_vulnerabilities']}\n")
                f.write(f"IoT-related threats found: {self.stats['iot_relevant']}\n")
                f.write(f"Successfully processed: {self.stats['processed_successfully']}\n")
                f.write(f"Processing errors: {self.stats['errors']}\n")
                f.write(f"Processing time: {self.stats['processing_time']:.1f} seconds\n\n")
                
                if threats:
                    # Analysis results
                    all_devices = []
                    all_attacks = []
                    all_protocols = []
                    severity_counts = Counter()
                    
                    for threat in threats:
                        nlp_analysis = threat.get('nlp_analysis', {})
                        all_devices.extend(nlp_analysis.get('devices', []))
                        all_attacks.extend(nlp_analysis.get('attack_types', []))
                        all_protocols.extend(nlp_analysis.get('protocols', []))
                        
                        # Count severities
                        severity = threat.get('severity', {}).get('cvss_v3_severity', 'Unknown')
                        severity_counts[severity] += 1
                    
                    f.write("DEVICE ANALYSIS\n")
                    f.write("-" * 15 + "\n")
                    device_counts = Counter(all_devices)
                    for device, count in device_counts.most_common(10):
                        f.write(f"{device}: {count}\n")
                    
                    f.write("\nATTACK TYPE ANALYSIS\n")
                    f.write("-" * 20 + "\n")
                    attack_counts = Counter(all_attacks)
                    for attack, count in attack_counts.most_common(10):
                        f.write(f"{attack}: {count}\n")
                    
                    f.write("\nPROTOCOL ANALYSIS\n")
                    f.write("-" * 17 + "\n")
                    protocol_counts = Counter(all_protocols)
                    for protocol, count in protocol_counts.most_common(10):
                        f.write(f"{protocol}: {count}\n")
                    
                    f.write("\nSEVERITY DISTRIBUTION\n")
                    f.write("-" * 21 + "\n")
                    for severity, count in severity_counts.most_common():
                        f.write(f"{severity}: {count}\n")
                    
                    # Recent threats details
                    f.write("\nRECENT THREATS (TOP 5)\n")
                    f.write("-" * 22 + "\n")
                    for i, threat in enumerate(threats[:5]):
                        f.write(f"{i+1}. {threat['cve_id']}\n")
                        f.write(f"   Severity: {threat.get('severity', {}).get('cvss_v3_severity', 'Unknown')}\n")
                        devices = threat.get('nlp_analysis', {}).get('devices', [])
                        f.write(f"   Devices: {', '.join(devices) if devices else 'Unknown'}\n")
                        f.write(f"   Description: {threat['description'][:100]}...\n\n")
            
            return report_file
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None

    def get_statistics(self) -> Dict[str, Any]:
        """Return current processing statistics"""
        return self.stats.copy()

    def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive system health check"""
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'status': 'healthy',
            'components': {},
            'warnings': [],
            'errors': []
        }
        
        try:
            # Check threat collector
            if self.threat_collector:
                try:
                    collector_health = self.threat_collector.health_check()
                    health_status['components']['threat_collector'] = collector_health['status']
                    if collector_health['status'] != 'healthy':
                        health_status['warnings'].extend(collector_health.get('warnings', []))
                        health_status['errors'].extend(collector_health.get('errors', []))
                except Exception as e:
                    health_status['components']['threat_collector'] = 'error'
                    health_status['errors'].append(f"Threat collector health check failed: {e}")
            else:
                health_status['components']['threat_collector'] = 'not_initialized'
                health_status['warnings'].append("Threat collector not initialized")
            
            # Check IoT classifier
            health_status['components']['iot_classifier'] = 'ok' if self.iot_classifier else 'fallback'
            if not self.iot_classifier:
                health_status['warnings'].append("IoT classifier using fallback mode")
            
            # Check NLP processor
            if self.nlp_processor:
                nlp_status = 'fallback' if self.nlp_processor.fallback_mode else 'ok'
                health_status['components']['nlp_processor'] = nlp_status
                if self.nlp_processor.fallback_mode:
                    health_status['warnings'].append("NLP processor using fallback mode")
            else:
                health_status['components']['nlp_processor'] = 'not_initialized'
                health_status['errors'].append("NLP processor not initialized")
            
            # Check memory usage
            memory_status = self._check_memory_usage()
            health_status['components']['memory'] = 'ok' if memory_status['memory_ok'] else 'warning'
            health_status['memory_usage_mb'] = memory_status['memory_mb']
            
            if not memory_status['memory_ok']:
                health_status['warnings'].append(f"High memory usage: {memory_status['memory_mb']:.1f}MB")
            
            # Determine overall status
            if health_status['errors']:
                health_status['status'] = 'unhealthy'
            elif health_status['warnings']:
                health_status['status'] = 'warning'
            
            return health_status
            
        except Exception as e:
            logger.error(f"Error during health check: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'status': 'error',
                'error': str(e)
            }


# Main execution script
if __name__ == "__main__":
    logger.info("DynaHome AI-Enhanced Threat Intelligence Pipeline")
    logger.info("=" * 60)
    
    try:
        # Initialize pipeline
        pipeline = CompleteThreatPipeline()
        
        # Perform health check
        health = pipeline.health_check()
        logger.info(f"Health check status: {health['status']}")
        
        if health['status'] == 'unhealthy':
            logger.error("System health check failed:")
            for error in health.get('errors', []):
                logger.error(f"  - {error}")
            exit(1)
        
        if health.get('warnings'):
            logger.warning("Health check warnings:")
            for warning in health.get('warnings', []):
                logger.warning(f"  - {warning}")
        
        # Run collection with error handling
        logger.info("Running test collection (2 days, max 20 results)...")
        threats = pipeline.run_daily_collection(days_back=2, max_results=20)
        
        if threats:
            logger.info(f"Processing successful! Found {len(threats)} IoT threats")
            
            # Show sample results
            logger.info("Sample Results:")
            logger.info("-" * 40)
            
            for i, threat in enumerate(threats[:3]):
                logger.info(f"{i+1}. {threat['cve_id']}")
                logger.info(f"   Confidence: {threat['iot_classification']['confidence']:.2f}")
                logger.info(f"   Devices: {threat['nlp_analysis']['devices']}")
                logger.info(f"   Attack types: {threat['nlp_analysis']['attack_types']}")
                logger.info(f"   Processing method: {threat['nlp_analysis']['processing_method']}")
            
            # Show statistics
            stats = pipeline.get_statistics()
            logger.info(f"Final Statistics:")
            logger.info(f"  Total processed: {stats['total_vulnerabilities']}")
            logger.info(f"  IoT relevant: {stats['iot_relevant']} ({stats['iot_relevant']/stats['total_vulnerabilities']*100:.1f}%)")
            logger.info(f"  Successful: {stats['processed_successfully']}")
            logger.info(f"  Errors: {stats['errors']}")
            logger.info(f"  Processing time: {stats['processing_time']:.1f}s")
            
        else:
            logger.error("Processing failed or returned no results")
        
    except Exception as e:
        logger.error(f"Pipeline execution failed: {e}")
        logger.error(traceback.format_exc())
        exit(1)
    
    logger.info("Pipeline execution complete!")