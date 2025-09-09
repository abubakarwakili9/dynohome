# threat_collector.py - Enhanced with comprehensive error handling
import requests
import json
import time
import random
import logging
from datetime import datetime, timedelta
from pathlib import Path
import os
from typing import Optional, List, Dict, Any
import hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/threat_collector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatCollectionError(Exception):
    """Custom exception for threat collection errors"""
    pass

class APIError(ThreatCollectionError):
    """API-specific errors"""
    pass

class DataValidationError(ThreatCollectionError):
    """Data validation errors"""
    pass

class ThreatCollector:
    def __init__(self, config: Optional[Dict] = None):
        """Initialize threat intelligence collector with enhanced error handling"""
        self.config = config or self._load_default_config()
        self.cve_api = self.config.get('cve_api_url', "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.collected_threats = []
        
        # Configuration parameters
        self.request_timeout = self.config.get('request_timeout', 30)
        self.max_retries = self.config.get('max_retries', 3)
        self.base_delay = self.config.get('base_delay', 2)
        self.max_delay = self.config.get('max_delay', 60)
        
        # Enhanced request configuration with fallback
        try:
            # Try to create robust session with retry strategy
            self.session = self._create_robust_session()
            logger.info("HTTP session created with enhanced retry strategy")
        except Exception as e:
            # Fallback to basic session if robust session fails
            logger.warning(f"Failed to create robust session: {e}")
            logger.info("Creating basic HTTP session as fallback")
            
            self.session = requests.Session()
            self.session.timeout = self.request_timeout
            self.session.headers.update({
                'User-Agent': self.config.get('user_agent', 'DynaHome-ThreatCollector/1.1'),
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate'
            })
        
        # Ensure data directory exists
        self.data_dir = Path(self.config.get('data_dir', 'data'))
        self.data_dir.mkdir(exist_ok=True)
        
        # Rate limiting tracking
        self.last_request_time = 0
        self.min_request_interval = self.config.get('min_request_interval', 1.0)
        
        logger.info("ThreatCollector initialized with enhanced error handling")

    def _load_default_config(self) -> Dict:
        """Load default configuration with fallback values"""
        return {
            'cve_api_url': "https://services.nvd.nist.gov/rest/json/cves/2.0",
            'request_timeout': 30,
            'max_retries': 3,
            'base_delay': 2,
            'max_delay': 60,
            'min_request_interval': 1.0,
            'data_dir': 'data',
            'max_results_per_request': 2000,
            'validate_data': True,
            'user_agent': 'DynaHome-ThreatCollector/1.1'
        }

    def _create_robust_session(self):
        """Create a robust HTTP session with retry strategy and timeouts"""
        try:
            session = requests.Session()
            
            # Check urllib3 version for compatibility
            try:
                import urllib3
                urllib3_version = tuple(map(int, urllib3.__version__.split('.')))
                use_allowed_methods = urllib3_version >= (1, 26, 0)
            except:
                # If version check fails, assume newer version
                use_allowed_methods = True
            
            # Create retry strategy with version-compatible parameters
            if use_allowed_methods:
                retry_strategy = Retry(
                    total=self.max_retries,
                    status_forcelist=[429, 500, 502, 503, 504],
                    allowed_methods=["HEAD", "GET", "OPTIONS"],
                    backoff_factor=1,
                    raise_on_status=False
                )
            else:
                retry_strategy = Retry(
                    total=self.max_retries,
                    status_forcelist=[429, 500, 502, 503, 504],
                    method_whitelist=["HEAD", "GET", "OPTIONS"],
                    backoff_factor=1,
                    raise_on_status=False
                )
            
            # Mount adapters with retry strategy
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            # Configure session settings
            session.timeout = self.request_timeout
            session.headers.update({
                'User-Agent': self.config.get('user_agent', 'DynaHome-ThreatCollector/1.1'),
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            })
            
            return session
            
        except ImportError as e:
            logger.warning(f"Required packages not available for robust session: {e}")
            raise
        except Exception as e:
            logger.error(f"Error creating robust session: {e}")
            raise

    def _exponential_backoff_delay(self, attempt: int) -> float:
        """Calculate exponential backoff delay with jitter"""
        delay = min(self.base_delay * (2 ** attempt), self.max_delay)
        jitter = random.uniform(0, 0.1) * delay
        return delay + jitter

    def _rate_limit_delay(self):
        """Implement rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()

    def safe_api_request(self, url: str, params: Optional[Dict] = None, max_retries: Optional[int] = None) -> Optional[Dict]:
        """Make API request with comprehensive error handling and retry logic"""
        if max_retries is None:
            max_retries = self.max_retries

        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                # Apply rate limiting
                self._rate_limit_delay()
                
                logger.debug(f"API request attempt {attempt + 1}/{max_retries + 1} to {url}")
                
                # Make the request with timeout
                response = self.session.get(
                    url, 
                    params=params, 
                    timeout=self.request_timeout
                )
                
                # Handle different response codes
                if response.status_code == 200:
                    try:
                        data = response.json()
                        logger.debug(f"Successful API response received")
                        return data
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON response: {e}")
                        raise APIError(f"Invalid JSON response: {e}")
                
                elif response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue
                
                elif response.status_code == 403:
                    logger.error("Access forbidden - check API permissions")
                    raise APIError(f"Access forbidden (403): {response.text}")
                
                elif response.status_code == 404:
                    logger.error("API endpoint not found")
                    raise APIError(f"API endpoint not found (404): {url}")
                
                elif response.status_code >= 500:
                    logger.warning(f"Server error {response.status_code}, will retry")
                    raise APIError(f"Server error ({response.status_code}): {response.text}")
                
                else:
                    logger.error(f"Unexpected status code: {response.status_code}")
                    raise APIError(f"HTTP {response.status_code}: {response.text}")
                
            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout on attempt {attempt + 1}")
                last_exception = APIError("Request timeout")
                
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error on attempt {attempt + 1}: {e}")
                last_exception = APIError(f"Connection error: {e}")
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Request exception on attempt {attempt + 1}: {e}")
                last_exception = APIError(f"Request exception: {e}")
            
            except APIError:
                # Re-raise API errors without wrapping
                raise
            
            except Exception as e:
                logger.error(f"Unexpected error on attempt {attempt + 1}: {e}")
                last_exception = ThreatCollectionError(f"Unexpected error: {e}")
            
            # Apply exponential backoff if not the last attempt
            if attempt < max_retries:
                delay = self._exponential_backoff_delay(attempt)
                logger.info(f"Retrying in {delay:.1f} seconds...")
                time.sleep(delay)
        
        # All retries exhausted
        logger.error(f"All {max_retries + 1} attempts failed")
        if last_exception:
            raise last_exception
        else:
            raise ThreatCollectionError("All retry attempts failed with unknown error")

    def validate_cve_data(self, vulnerability: Dict) -> bool:
        """Validate CVE data structure and content"""
        try:
            # Check required top-level structure
            if not isinstance(vulnerability, dict):
                logger.warning("Vulnerability data is not a dictionary")
                return False
            
            cve_data = vulnerability.get('cve')
            if not cve_data:
                logger.warning("Missing 'cve' key in vulnerability data")
                return False
            
            # Validate CVE ID
            cve_id = cve_data.get('id')
            if not cve_id or not cve_id.startswith('CVE-'):
                logger.warning(f"Invalid CVE ID: {cve_id}")
                return False
            
            # Check for description
            descriptions = cve_data.get('descriptions', [])
            if not descriptions:
                logger.warning(f"No descriptions found for {cve_id}")
                return False
            
            # Validate at least one English description
            english_desc = None
            for desc in descriptions:
                if desc.get('lang') == 'en' and desc.get('value'):
                    english_desc = desc['value']
                    break
            
            if not english_desc:
                logger.warning(f"No English description found for {cve_id}")
                return False
            
            # Check description length (should be substantial)
            if len(english_desc.strip()) < 10:
                logger.warning(f"Description too short for {cve_id}")
                return False
            
            # Validate timestamps
            published = cve_data.get('published')
            if published:
                try:
                    datetime.fromisoformat(published.replace('Z', '+00:00'))
                except ValueError:
                    logger.warning(f"Invalid published date format for {cve_id}: {published}")
                    return False
            
            logger.debug(f"CVE data validation passed for {cve_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error during CVE data validation: {e}")
            return False

    def get_recent_cves(self, days_back: int = 7, max_results: int = 100) -> List[Dict]:
        """Download recent CVE vulnerabilities with enhanced error handling"""
        try:
            logger.info(f"Starting CVE collection for last {days_back} days, max {max_results} results")
            
            # Validate input parameters
            if days_back <= 0 or days_back > 365:
                raise ValueError(f"Invalid days_back parameter: {days_back}. Must be 1-365.")
            
            if max_results <= 0 or max_results > 5000:
                raise ValueError(f"Invalid max_results parameter: {max_results}. Must be 1-5000.")
            
            # Calculate date range with timezone handling
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            # Format dates for API (ISO 8601 format)
            start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            logger.info(f"Searching CVEs from {start_str} to {end_str}")
            
            # Prepare API parameters with validation
            params = {
                'pubStartDate': start_str,
                'pubEndDate': end_str,
                'resultsPerPage': min(max_results, self.config.get('max_results_per_request', 2000)),
                'startIndex': 0
            }
            
            # Make API request
            data = self.safe_api_request(self.cve_api, params)
            
            if not data:
                logger.error("No data received from API")
                return []
            
            # Extract vulnerabilities with validation
            vulnerabilities = data.get('vulnerabilities', [])
            total_results = data.get('totalResults', 0)
            
            logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities out of {total_results} total")
            
            # Validate data if enabled
            if self.config.get('validate_data', True):
                valid_vulnerabilities = []
                validation_errors = 0
                
                for vuln in vulnerabilities:
                    if self.validate_cve_data(vuln):
                        valid_vulnerabilities.append(vuln)
                    else:
                        validation_errors += 1
                
                logger.info(f"Data validation: {len(valid_vulnerabilities)} valid, {validation_errors} invalid")
                vulnerabilities = valid_vulnerabilities
            
            # Save raw data for debugging and backup
            self.save_raw_data(data, f"raw_cves_{days_back}days")
            
            return vulnerabilities
            
        except ValueError as e:
            logger.error(f"Parameter validation error: {e}")
            raise ThreatCollectionError(f"Invalid parameters: {e}")
        
        except APIError:
            # Re-raise API errors
            raise
        
        except Exception as e:
            logger.error(f"Unexpected error in get_recent_cves: {e}")
            raise ThreatCollectionError(f"Failed to retrieve CVEs: {e}")

    def save_raw_data(self, data: Dict, filename_prefix: str) -> Optional[str]:
        """Save raw API response with error handling"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.data_dir / f"{filename_prefix}_{timestamp}.json"
            
            # Ensure directory exists
            filename.parent.mkdir(parents=True, exist_ok=True)
            
            # Calculate data hash for integrity checking
            data_str = json.dumps(data, sort_keys=True)
            data_hash = hashlib.md5(data_str.encode()).hexdigest()
            
            # Add metadata
            save_data = {
                'metadata': {
                    'timestamp': timestamp,
                    'data_hash': data_hash,
                    'record_count': len(data.get('vulnerabilities', [])),
                    'total_results': data.get('totalResults', 0),
                    'collector_version': '1.0.0'
                },
                'data': data
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Raw data saved to {filename} (hash: {data_hash[:8]})")
            return str(filename)
            
        except PermissionError:
            logger.error(f"Permission denied writing to {filename}")
            return None
        
        except OSError as e:
            logger.error(f"OS error saving raw data: {e}")
            return None
        
        except Exception as e:
            logger.error(f"Unexpected error saving raw data: {e}")
            return None

    def save_threats(self, threats: List[Dict], filename: Optional[str] = None) -> Optional[str]:
        """Save processed threats with enhanced error handling"""
        try:
            if not threats:
                logger.warning("No threats to save")
                return None
            
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = self.data_dir / f"threats_{timestamp}.json"
            else:
                filename = Path(filename)
            
            # Ensure directory exists
            filename.parent.mkdir(parents=True, exist_ok=True)
            
            # Add metadata wrapper
            save_data = {
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'threat_count': len(threats),
                    'collector_version': '1.0.0',
                    'data_hash': hashlib.md5(
                        json.dumps(threats, sort_keys=True).encode()
                    ).hexdigest()
                },
                'threats': threats
            }
            
            # Atomic write operation
            temp_filename = filename.with_suffix('.tmp')
            
            with open(temp_filename, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, indent=2, ensure_ascii=False)
            
            # Rename to final filename (atomic on most filesystems)
            temp_filename.rename(filename)
            
            logger.info(f"Saved {len(threats)} threats to {filename}")
            return str(filename)
            
        except PermissionError:
            logger.error(f"Permission denied writing to {filename}")
            return None
        
        except OSError as e:
            logger.error(f"OS error saving threats: {e}")
            return None
        
        except Exception as e:
            logger.error(f"Unexpected error saving threats: {e}")
            return None

    def extract_cve_info(self, vulnerability: Dict) -> Optional[Dict]:
        """Extract key information from CVE data with error handling"""
        try:
            if not self.validate_cve_data(vulnerability):
                return None
            
            cve_data = vulnerability.get('cve', {})
            
            # Basic info extraction with fallbacks
            cve_id = cve_data.get('id', 'Unknown')
            published_date = cve_data.get('published', '')
            last_modified = cve_data.get('lastModified', '')
            
            # Description extraction with validation
            descriptions = cve_data.get('descriptions', [])
            description_text = ""
            
            for desc in descriptions:
                if desc.get('lang') == 'en' and desc.get('value'):
                    description_text = desc['value'].strip()
                    break
            
            if not description_text:
                logger.warning(f"No valid English description found for {cve_id}")
                return None
            
            # CVSS scores with error handling
            severity_info = self.extract_severity_info(vulnerability)
            
            # References extraction with limits
            references = []
            ref_data = cve_data.get('references', [])
            
            for ref in ref_data[:5]:  # Limit to prevent excessive data
                try:
                    ref_info = {
                        'url': ref.get('url', ''),
                        'source': ref.get('source', ''),
                        'tags': ref.get('tags', [])
                    }
                    
                    # Validate URL format
                    if ref_info['url'] and ref_info['url'].startswith(('http://', 'https://')):
                        references.append(ref_info)
                        
                except Exception as e:
                    logger.debug(f"Error processing reference for {cve_id}: {e}")
                    continue
            
            extracted_info = {
                'cve_id': cve_id,
                'description': description_text,
                'published_date': published_date,
                'last_modified': last_modified,
                'severity': severity_info,
                'references': references,
                'extraction_timestamp': datetime.now().isoformat(),
                'raw_data': vulnerability  # Keep for advanced processing
            }
            
            logger.debug(f"Successfully extracted info for {cve_id}")
            return extracted_info
            
        except Exception as e:
            cve_id = vulnerability.get('cve', {}).get('id', 'Unknown')
            logger.error(f"Error extracting CVE info for {cve_id}: {e}")
            return None

    def extract_severity_info(self, vulnerability: Dict) -> Dict:
        """Extract comprehensive severity information with error handling"""
        try:
            metrics = vulnerability.get('cve', {}).get('metrics', {})
            severity_info = {
                'cvss_v3_score': None,
                'cvss_v3_severity': None,
                'cvss_v2_score': None,
                'cvss_v2_severity': None,
                'extraction_errors': []
            }
            
            # CVSS v3 extraction
            try:
                cvss_v3 = metrics.get('cvssMetricV3', [])
                if cvss_v3 and isinstance(cvss_v3, list):
                    v3_data = cvss_v3[0].get('cvssData', {})
                    
                    score = v3_data.get('baseScore')
                    severity = v3_data.get('baseSeverity')
                    
                    # Validate score range
                    if isinstance(score, (int, float)) and 0.0 <= score <= 10.0:
                        severity_info['cvss_v3_score'] = float(score)
                    
                    if isinstance(severity, str) and severity.upper() in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                        severity_info['cvss_v3_severity'] = severity.upper()
                        
            except Exception as e:
                severity_info['extraction_errors'].append(f"CVSS v3 error: {e}")
            
            # CVSS v2 extraction (fallback)
            try:
                cvss_v2 = metrics.get('cvssMetricV2', [])
                if cvss_v2 and isinstance(cvss_v2, list):
                    v2_data = cvss_v2[0].get('cvssData', {})
                    
                    score = v2_data.get('baseScore')
                    severity = v2_data.get('baseSeverity')
                    
                    # Validate score range
                    if isinstance(score, (int, float)) and 0.0 <= score <= 10.0:
                        severity_info['cvss_v2_score'] = float(score)
                    
                    if isinstance(severity, str):
                        severity_info['cvss_v2_severity'] = severity.upper()
                        
            except Exception as e:
                severity_info['extraction_errors'].append(f"CVSS v2 error: {e}")
            
            # Clean up errors list if empty
            if not severity_info['extraction_errors']:
                del severity_info['extraction_errors']
            
            return severity_info
            
        except Exception as e:
            logger.error(f"Error extracting severity info: {e}")
            return {
                'cvss_v3_score': None,
                'cvss_v3_severity': None,
                'cvss_v2_score': None,
                'cvss_v2_severity': None,
                'extraction_error': str(e)
            }

    def health_check(self) -> Dict[str, Any]:
        """Perform system health check"""
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'status': 'healthy',
            'checks': {},
            'warnings': [],
            'errors': []
        }
        
        try:
            # Check API connectivity
            try:
                test_params = {
                    'pubStartDate': (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000"),
                    'pubEndDate': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000"),
                    'resultsPerPage': 1
                }
                
                response = self.safe_api_request(self.cve_api, test_params)
                health_status['checks']['api_connectivity'] = 'ok' if response else 'failed'
                
            except Exception as e:
                health_status['checks']['api_connectivity'] = 'failed'
                health_status['errors'].append(f"API connectivity: {e}")
            
            # Check data directory
            try:
                self.data_dir.mkdir(exist_ok=True)
                test_file = self.data_dir / '.health_check'
                test_file.write_text('test')
                test_file.unlink()
                health_status['checks']['data_directory'] = 'ok'
                
            except Exception as e:
                health_status['checks']['data_directory'] = 'failed'
                health_status['errors'].append(f"Data directory: {e}")
            
            # Check session configuration
            health_status['checks']['session_config'] = 'ok'
            health_status['checks']['rate_limiting'] = 'ok'
            
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


# Test the enhanced collector
if __name__ == "__main__":
    logger.info("Starting ThreatCollector test with enhanced error handling")
    
    try:
        collector = ThreatCollector()
        
        # Perform health check
        health = collector.health_check()
        logger.info(f"Health check: {health['status']}")
        
        if health['status'] != 'healthy':
            logger.warning(f"Health issues detected: {health}")
        
        # Test with a smaller time range first
        logger.info("Testing with 2 days of data...")
        vulnerabilities = collector.get_recent_cves(days_back=2, max_results=10)
        
        if vulnerabilities:
            logger.info(f"Processing {len(vulnerabilities)} vulnerabilities...")
            
            processed_threats = []
            processing_errors = 0
            
            for vuln in vulnerabilities:
                try:
                    threat_info = collector.extract_cve_info(vuln)
                    if threat_info:
                        processed_threats.append(threat_info)
                    else:
                        processing_errors += 1
                        
                except Exception as e:
                    logger.error(f"Error processing vulnerability: {e}")
                    processing_errors += 1
            
            logger.info(f"Successfully processed {len(processed_threats)} threats, {processing_errors} errors")
            
            # Save processed threats
            if processed_threats:
                saved_file = collector.save_threats(processed_threats)
                logger.info(f"Enhanced threat collection test complete!")
                logger.info(f"Processed data saved to: {saved_file}")
            
        else:
            logger.warning("No vulnerabilities retrieved - this may indicate an issue")
            
    except ThreatCollectionError as e:
        logger.error(f"Threat collection error: {e}")
    
    except Exception as e:
        logger.error(f"Unexpected error during test: {e}")
        import traceback
        logger.error(traceback.format_exc())