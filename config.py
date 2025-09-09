# config.py - Centralized configuration management for DynaHome
import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Union, List
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
import shutil

@dataclass
class APIConfiguration:
    """API configuration settings"""
    cve_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    request_timeout: int = 30
    max_retries: int = 3
    rate_limit_delay: float = 2.0
    max_delay: int = 60
    user_agent: str = "DynaHome-ThreatCollector/1.1"

@dataclass
class AIConfiguration:
    """AI model configuration settings"""
    model_load_timeout: int = 120
    classification_threshold: float = 0.7
    enable_fallback: bool = True
    batch_size: int = 10
    memory_limit_mb: int = 2048
    huggingface_model_cache: str = "~/.cache/huggingface"

@dataclass
class DataConfiguration:
    """Data handling configuration"""
    data_directory: str = "data"
    processed_directory: str = "data/processed"
    reports_directory: str = "data/reports"
    logs_directory: str = "data/logs"
    backup_directory: str = "data/backups"
    max_file_size_mb: int = 100
    backup_retention_days: int = 30

@dataclass
class WebAppConfiguration:
    """Web application configuration"""
    port: int = 8501
    host: str = "localhost"
    enable_debug: bool = False
    session_timeout_minutes: int = 60
    max_upload_size_mb: int = 200
    enable_analytics: bool = True

@dataclass
class SecurityConfiguration:
    """Security settings"""
    enable_logging: bool = True
    log_sensitive_data: bool = False
    api_key_rotation_days: int = 90
    session_encryption: bool = True
    allowed_file_types: List[str] = None

    def __post_init__(self):
        if self.allowed_file_types is None:
            self.allowed_file_types = ['.json', '.csv', '.txt', '.log']

@dataclass
class PerformanceConfiguration:
    """Performance tuning settings"""
    thread_pool_size: int = 4
    cache_size_mb: int = 512
    enable_compression: bool = True
    async_processing: bool = True
    metrics_collection_interval: int = 300

class DynaHomeConfig:
    """Centralized configuration management system"""
    
    def __init__(self, config_file: Optional[str] = None, environment: str = "development"):
        self.environment = environment
        self.config_file = config_file or self._find_config_file()
        self.config_dir = Path("config")
        
        # Initialize configuration objects
        self.api = APIConfiguration()
        self.ai = AIConfiguration()
        self.data = DataConfiguration()
        self.webapp = WebAppConfiguration()
        self.security = SecurityConfiguration()
        self.performance = PerformanceConfiguration()
        
        # Load configuration
        self._load_configuration()
        
        # Validate configuration
        self._validate_configuration()
        
        # Setup logging
        self._setup_logging()
        
        self.logger = logging.getLogger('dynohome.config')
        self.logger.info(f"Configuration loaded for environment: {environment}")

    def _find_config_file(self) -> Optional[str]:
        """Find configuration file in standard locations"""
        possible_locations = [
            f"config/{self.environment}.yaml",
            f"config/{self.environment}.json",
            "config/default.yaml",
            "config/default.json",
            ".env"
        ]
        
        for location in possible_locations:
            if Path(location).exists():
                return location
        
        return None

    def _load_configuration(self):
        """Load configuration from file and environment variables"""
        
        # Load from file if available
        if self.config_file and Path(self.config_file).exists():
            self._load_from_file()
        
        # Override with environment variables
        self._load_from_environment()
        
        # Apply environment-specific settings
        self._apply_environment_settings()

    def _load_from_file(self):
        """Load configuration from YAML or JSON file"""
        try:
            config_path = Path(self.config_file)
            
            with open(config_path, 'r') as f:
                if config_path.suffix in ['.yaml', '.yml']:
                    config_data = yaml.safe_load(f)
                elif config_path.suffix == '.json':
                    config_data = json.load(f)
                else:
                    # Try to parse as JSON first, then YAML
                    content = f.read()
                    try:
                        config_data = json.loads(content)
                    except json.JSONDecodeError:
                        config_data = yaml.safe_load(content)
            
            self._apply_config_data(config_data)
            
        except Exception as e:
            print(f"Warning: Failed to load config file {self.config_file}: {e}")

    def _load_from_environment(self):
        """Load configuration from environment variables"""
        
        # API Configuration
        self.api.cve_api_url = os.getenv('DYNOHOME_CVE_API_URL', self.api.cve_api_url)
        self.api.request_timeout = int(os.getenv('DYNOHOME_REQUEST_TIMEOUT', self.api.request_timeout))
        self.api.max_retries = int(os.getenv('DYNOHOME_MAX_RETRIES', self.api.max_retries))
        self.api.rate_limit_delay = float(os.getenv('DYNOHOME_RATE_LIMIT_DELAY', self.api.rate_limit_delay))
        
        # AI Configuration
        self.ai.model_load_timeout = int(os.getenv('DYNOHOME_MODEL_TIMEOUT', self.ai.model_load_timeout))
        self.ai.classification_threshold = float(os.getenv('DYNOHOME_CLASSIFICATION_THRESHOLD', self.ai.classification_threshold))
        self.ai.enable_fallback = os.getenv('DYNOHOME_ENABLE_FALLBACK', 'true').lower() == 'true'
        self.ai.batch_size = int(os.getenv('DYNOHOME_BATCH_SIZE', self.ai.batch_size))
        self.ai.memory_limit_mb = int(os.getenv('DYNOHOME_MEMORY_LIMIT', self.ai.memory_limit_mb))
        
        # Data Configuration
        self.data.data_directory = os.getenv('DYNOHOME_DATA_DIR', self.data.data_directory)
        self.data.processed_directory = os.getenv('DYNOHOME_PROCESSED_DIR', self.data.processed_directory)
        self.data.reports_directory = os.getenv('DYNOHOME_REPORTS_DIR', self.data.reports_directory)
        self.data.logs_directory = os.getenv('DYNOHOME_LOGS_DIR', self.data.logs_directory)
        
        # Web App Configuration
        self.webapp.port = int(os.getenv('DYNOHOME_PORT', self.webapp.port))
        self.webapp.host = os.getenv('DYNOHOME_HOST', self.webapp.host)
        self.webapp.enable_debug = os.getenv('DYNOHOME_DEBUG', 'false').lower() == 'true'
        
        # Security Configuration
        self.security.enable_logging = os.getenv('DYNOHOME_ENABLE_LOGGING', 'true').lower() == 'true'
        self.security.log_sensitive_data = os.getenv('DYNOHOME_LOG_SENSITIVE', 'false').lower() == 'true'
        
        # Performance Configuration
        self.performance.thread_pool_size = int(os.getenv('DYNOHOME_THREAD_POOL_SIZE', self.performance.thread_pool_size))
        self.performance.cache_size_mb = int(os.getenv('DYNOHOME_CACHE_SIZE', self.performance.cache_size_mb))

    def _apply_config_data(self, config_data: Dict[str, Any]):
        """Apply configuration data from file"""
        
        if 'api' in config_data:
            api_config = config_data['api']
            for key, value in api_config.items():
                if hasattr(self.api, key):
                    setattr(self.api, key, value)
        
        if 'ai' in config_data:
            ai_config = config_data['ai']
            for key, value in ai_config.items():
                if hasattr(self.ai, key):
                    setattr(self.ai, key, value)
        
        if 'data' in config_data:
            data_config = config_data['data']
            for key, value in data_config.items():
                if hasattr(self.data, key):
                    setattr(self.data, key, value)
        
        if 'webapp' in config_data:
            webapp_config = config_data['webapp']
            for key, value in webapp_config.items():
                if hasattr(self.webapp, key):
                    setattr(self.webapp, key, value)
        
        if 'security' in config_data:
            security_config = config_data['security']
            for key, value in security_config.items():
                if hasattr(self.security, key):
                    setattr(self.security, key, value)
        
        if 'performance' in config_data:
            performance_config = config_data['performance']
            for key, value in performance_config.items():
                if hasattr(self.performance, key):
                    setattr(self.performance, key, value)

    def _apply_environment_settings(self):
        """Apply environment-specific settings"""
        
        if self.environment == "development":
            self.webapp.enable_debug = True
            self.security.log_sensitive_data = True
            self.ai.enable_fallback = True
            
        elif self.environment == "production":
            self.webapp.enable_debug = False
            self.security.log_sensitive_data = False
            self.ai.enable_fallback = False
            self.performance.async_processing = True
            
        elif self.environment == "testing":
            self.api.max_retries = 1
            self.api.request_timeout = 10
            self.ai.model_load_timeout = 30
            self.performance.metrics_collection_interval = 60

    def _validate_configuration(self):
        """Validate configuration settings"""
        
        # Validate API settings
        if self.api.request_timeout <= 0:
            raise ValueError("API request timeout must be positive")
        
        if self.api.max_retries < 0:
            raise ValueError("API max retries cannot be negative")
        
        # Validate AI settings
        if not 0 <= self.ai.classification_threshold <= 1:
            raise ValueError("Classification threshold must be between 0 and 1")
        
        if self.ai.memory_limit_mb <= 0:
            raise ValueError("Memory limit must be positive")
        
        # Validate data directories
        self._ensure_directories_exist()
        
        # Validate performance settings
        if self.performance.thread_pool_size <= 0:
            raise ValueError("Thread pool size must be positive")

    def _ensure_directories_exist(self):
        """Ensure all required directories exist"""
        directories = [
            self.data.data_directory,
            self.data.processed_directory,
            self.data.reports_directory,
            self.data.logs_directory,
            self.data.backup_directory
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    def _setup_logging(self):
        """Setup basic logging configuration"""
        if self.security.enable_logging:
            log_level = logging.DEBUG if self.webapp.enable_debug else logging.INFO
            
            logging.basicConfig(
                level=log_level,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(Path(self.data.logs_directory) / 'config.log'),
                    logging.StreamHandler()
                ]
            )

    def save_configuration(self, output_file: Optional[str] = None) -> bool:
        """Save current configuration to file"""
        try:
            if output_file is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"config/config_backup_{timestamp}.yaml"
            
            config_data = {
                'api': asdict(self.api),
                'ai': asdict(self.ai),
                'data': asdict(self.data),
                'webapp': asdict(self.webapp),
                'security': asdict(self.security),
                'performance': asdict(self.performance),
                'metadata': {
                    'environment': self.environment,
                    'created_at': datetime.now().isoformat(),
                    'version': '1.1.0'
                }
            }
            
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                yaml.dump(config_data, f, indent=2, default_flow_style=False)
            
            return True
            
        except Exception as e:
            print(f"Failed to save configuration: {e}")
            return False

    def backup_configuration(self) -> bool:
        """Create a backup of the current configuration"""
        try:
            backup_dir = Path(self.data.backup_directory) / "config"
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = backup_dir / f"config_backup_{timestamp}.yaml"
            
            return self.save_configuration(str(backup_file))
            
        except Exception as e:
            print(f"Failed to backup configuration: {e}")
            return False

    def reload_configuration(self) -> bool:
        """Reload configuration from file"""
        try:
            self._load_configuration()
            self._validate_configuration()
            return True
            
        except Exception as e:
            print(f"Failed to reload configuration: {e}")
            return False

    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get a summary of current configuration"""
        return {
            'environment': self.environment,
            'config_file': self.config_file,
            'api': asdict(self.api),
            'ai': asdict(self.ai),
            'data': asdict(self.data),
            'webapp': asdict(self.webapp),
            'security': {k: v for k, v in asdict(self.security).items() if k != 'log_sensitive_data'},
            'performance': asdict(self.performance)
        }

    def update_setting(self, section: str, key: str, value: Any) -> bool:
        """Update a specific configuration setting"""
        try:
            section_obj = getattr(self, section, None)
            if section_obj is None:
                raise ValueError(f"Unknown configuration section: {section}")
            
            if not hasattr(section_obj, key):
                raise ValueError(f"Unknown setting: {section}.{key}")
            
            setattr(section_obj, key, value)
            
            # Re-validate after update
            self._validate_configuration()
            
            return True
            
        except Exception as e:
            print(f"Failed to update setting {section}.{key}: {e}")
            return False

    def create_sample_config(self, output_file: str = "config/sample.yaml"):
        """Create a sample configuration file"""
        try:
            sample_config = {
                'api': {
                    'cve_api_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                    'request_timeout': 30,
                    'max_retries': 3,
                    'rate_limit_delay': 2.0
                },
                'ai': {
                    'model_load_timeout': 120,
                    'classification_threshold': 0.7,
                    'enable_fallback': True,
                    'batch_size': 10,
                    'memory_limit_mb': 2048
                },
                'data': {
                    'data_directory': 'data',
                    'processed_directory': 'data/processed',
                    'reports_directory': 'data/reports',
                    'logs_directory': 'data/logs'
                },
                'webapp': {
                    'port': 8501,
                    'host': 'localhost',
                    'enable_debug': False
                },
                'security': {
                    'enable_logging': True,
                    'log_sensitive_data': False,
                    'allowed_file_types': ['.json', '.csv', '.txt']
                },
                'performance': {
                    'thread_pool_size': 4,
                    'cache_size_mb': 512,
                    'enable_compression': True
                }
            }
            
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                yaml.dump(sample_config, f, indent=2, default_flow_style=False)
            
            print(f"Sample configuration created: {output_file}")
            return True
            
        except Exception as e:
            print(f"Failed to create sample config: {e}")
            return False


# Global configuration instance
_config_instance = None

def get_config(environment: str = None) -> DynaHomeConfig:
    """Get the global configuration instance"""
    global _config_instance
    
    if _config_instance is None:
        env = environment or os.getenv('DYNOHOME_ENV', 'development')
        _config_instance = DynaHomeConfig(environment=env)
    
    return _config_instance

def setup_config(config_file: str = None, environment: str = "development") -> DynaHomeConfig:
    """Setup the global configuration system"""
    global _config_instance
    _config_instance = DynaHomeConfig(config_file, environment)
    return _config_instance


# Usage example and testing
if __name__ == "__main__":
    # Create sample configuration
    config = DynaHomeConfig()
    config.create_sample_config()
    
    # Test configuration loading
    print("Configuration Summary:")
    summary = config.get_configuration_summary()
    print(json.dumps(summary, indent=2))
    
    # Test configuration updates
    config.update_setting('ai', 'batch_size', 20)
    print(f"Updated batch size: {config.ai.batch_size}")
    
    # Test configuration backup
    config.backup_configuration()
    print("Configuration backup created")
    
    # Test environment-specific settings
    prod_config = DynaHomeConfig(environment="production")
    print(f"Production debug mode: {prod_config.webapp.enable_debug}")