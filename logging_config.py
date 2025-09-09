# logging_config.py - Comprehensive logging system for DynaHome
import logging
import logging.handlers
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional
import threading
import time
from collections import defaultdict, deque

class DynaHomeLogger:
    """Enhanced logging system with metrics tracking and error analysis"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._load_default_config()
        self.log_dir = Path(self.config.get('log_directory', 'data/logs'))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Metrics tracking
        self.metrics = defaultdict(int)
        self.error_counts = defaultdict(int)
        self.performance_logs = deque(maxlen=1000)  # Keep last 1000 performance entries
        self.metrics_lock = threading.Lock()
        
        # Setup loggers
        self.setup_loggers()
        
        # Start metrics collector thread
        self.metrics_thread = threading.Thread(target=self._metrics_collector, daemon=True)
        self.metrics_thread.start()
        
        self.logger = logging.getLogger('dynohome.main')
        self.logger.info("DynaHome logging system initialized")

    def _load_default_config(self) -> Dict:
        """Load default logging configuration"""
        return {
            'log_directory': 'data/logs',
            'log_level': 'INFO',
            'max_file_size': 10 * 1024 * 1024,  # 10MB
            'backup_count': 5,
            'metrics_interval': 300,  # 5 minutes
            'error_alert_threshold': 10,  # Alert after 10 errors in interval
            'performance_log_interval': 60,  # Log performance every minute
            'enable_console_output': True
        }

    def setup_loggers(self):
        """Set up comprehensive logging configuration"""
        
        # Main application logger
        self._setup_application_logger()
        
        # Pipeline operations logger
        self._setup_pipeline_logger()
        
        # User interaction logger
        self._setup_user_logger()
        
        # Performance metrics logger
        self._setup_performance_logger()
        
        # Error tracking logger
        self._setup_error_logger()
        
        # Security events logger
        self._setup_security_logger()

    def _setup_application_logger(self):
        """Set up main application logger"""
        logger = logging.getLogger('dynohome.main')
        logger.setLevel(getattr(logging, self.config['log_level']))
        
        # Clear existing handlers
        logger.handlers = []
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'application.log',
            maxBytes=self.config['max_file_size'],
            backupCount=self.config['backup_count']
        )
        
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Console handler (optional)
        if self.config['enable_console_output']:
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%H:%M:%S'
            )
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)

    def _setup_pipeline_logger(self):
        """Set up pipeline operations logger"""
        logger = logging.getLogger('dynohome.pipeline')
        logger.setLevel(logging.INFO)
        logger.handlers = []
        
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'pipeline.log',
            maxBytes=self.config['max_file_size'],
            backupCount=self.config['backup_count']
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - PIPELINE - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    def _setup_user_logger(self):
        """Set up user interaction logger"""
        logger = logging.getLogger('dynohome.user')
        logger.setLevel(logging.INFO)
        logger.handlers = []
        
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'user_interactions.log',
            maxBytes=self.config['max_file_size'],
            backupCount=self.config['backup_count']
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - USER - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    def _setup_performance_logger(self):
        """Set up performance metrics logger"""
        logger = logging.getLogger('dynohome.performance')
        logger.setLevel(logging.INFO)
        logger.handlers = []
        
        # Daily rotating file handler
        file_handler = logging.handlers.TimedRotatingFileHandler(
            self.log_dir / 'performance.log',
            when='midnight',
            interval=1,
            backupCount=30  # Keep 30 days of performance logs
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - PERF - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    def _setup_error_logger(self):
        """Set up error tracking logger"""
        logger = logging.getLogger('dynohome.error')
        logger.setLevel(logging.ERROR)
        logger.handlers = []
        
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'errors.log',
            maxBytes=self.config['max_file_size'],
            backupCount=self.config['backup_count']
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - ERROR - %(name)s - %(funcName)s:%(lineno)d - %(message)s - %(exc_info)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    def _setup_security_logger(self):
        """Set up security events logger"""
        logger = logging.getLogger('dynohome.security')
        logger.setLevel(logging.WARNING)
        logger.handlers = []
        
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'security.log',
            maxBytes=self.config['max_file_size'],
            backupCount=self.config['backup_count']
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    def log_threat_processing(self, cve_count: int, iot_found: int, processing_time: float, errors: int = 0):
        """Log threat processing metrics"""
        logger = logging.getLogger('dynohome.pipeline')
        
        metrics = {
            'operation': 'threat_processing',
            'cve_count': cve_count,
            'iot_threats_found': iot_found,
            'processing_time_seconds': processing_time,
            'errors': errors,
            'success_rate': (cve_count - errors) / max(cve_count, 1),
            'iot_detection_rate': iot_found / max(cve_count, 1)
        }
        
        logger.info(f"Threat processing completed: {json.dumps(metrics)}")
        
        # Update internal metrics
        with self.metrics_lock:
            self.metrics['total_cves_processed'] += cve_count
            self.metrics['total_iot_threats_found'] += iot_found
            self.metrics['total_processing_errors'] += errors
            self.performance_logs.append({
                'timestamp': datetime.now().isoformat(),
                'operation': 'threat_processing',
                'duration': processing_time,
                'success': errors == 0
            })

    def log_dataset_generation(self, config: Dict, quality_score: float, file_size: int, generation_time: float):
        """Log dataset generation metrics"""
        logger = logging.getLogger('dynohome.pipeline')
        
        metrics = {
            'operation': 'dataset_generation',
            'normal_samples': config.get('num_normal', 0),
            'attack_samples': config.get('num_attack', 0),
            'quality_score': quality_score,
            'file_size_bytes': file_size,
            'generation_time_seconds': generation_time,
            'samples_per_second': (config.get('num_normal', 0) + config.get('num_attack', 0)) / max(generation_time, 1)
        }
        
        logger.info(f"Dataset generation completed: {json.dumps(metrics)}")
        
        # Update internal metrics
        with self.metrics_lock:
            self.metrics['total_datasets_generated'] += 1
            self.metrics['total_samples_generated'] += config.get('num_normal', 0) + config.get('num_attack', 0)
            self.performance_logs.append({
                'timestamp': datetime.now().isoformat(),
                'operation': 'dataset_generation',
                'duration': generation_time,
                'quality_score': quality_score
            })

    def log_user_action(self, action: str, details: Dict[str, Any] = None):
        """Log user interactions"""
        logger = logging.getLogger('dynohome.user')
        
        log_entry = {
            'action': action,
            'timestamp': datetime.now().isoformat(),
            'details': details or {}
        }
        
        logger.info(json.dumps(log_entry))
        
        # Update metrics
        with self.metrics_lock:
            self.metrics[f'user_action_{action}'] += 1

    def log_error(self, error_type: str, error_message: str, context: Dict[str, Any] = None):
        """Log errors with context"""
        logger = logging.getLogger('dynohome.error')
        
        error_entry = {
            'error_type': error_type,
            'error_message': error_message,
            'context': context or {},
            'timestamp': datetime.now().isoformat()
        }
        
        logger.error(json.dumps(error_entry))
        
        # Update error tracking
        with self.metrics_lock:
            self.error_counts[error_type] += 1
            self.metrics['total_errors'] += 1
            
            # Check for error threshold
            if self.error_counts[error_type] >= self.config['error_alert_threshold']:
                self._trigger_error_alert(error_type, self.error_counts[error_type])

    def log_security_event(self, event_type: str, severity: str, details: Dict[str, Any] = None):
        """Log security-related events"""
        logger = logging.getLogger('dynohome.security')
        
        security_entry = {
            'event_type': event_type,
            'severity': severity,
            'details': details or {},
            'timestamp': datetime.now().isoformat()
        }
        
        if severity.upper() == 'CRITICAL':
            logger.critical(json.dumps(security_entry))
        elif severity.upper() == 'HIGH':
            logger.error(json.dumps(security_entry))
        else:
            logger.warning(json.dumps(security_entry))

    def log_performance_metric(self, operation: str, duration: float, success: bool, metadata: Dict[str, Any] = None):
        """Log performance metrics"""
        logger = logging.getLogger('dynohome.performance')
        
        perf_entry = {
            'operation': operation,
            'duration_seconds': duration,
            'success': success,
            'metadata': metadata or {},
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(json.dumps(perf_entry))
        
        # Update performance tracking
        with self.metrics_lock:
            self.performance_logs.append(perf_entry)

    def _trigger_error_alert(self, error_type: str, count: int):
        """Trigger alert for high error frequency"""
        logger = logging.getLogger('dynohome.main')
        logger.critical(f"Error threshold exceeded: {error_type} occurred {count} times")
        
        # You could extend this to send notifications, emails, etc.

    def _metrics_collector(self):
        """Background thread to collect and log periodic metrics"""
        while True:
            try:
                time.sleep(self.config['metrics_interval'])
                self._log_periodic_metrics()
            except Exception as e:
                # Avoid logging errors in the logger itself
                print(f"Error in metrics collector: {e}")

    def _log_periodic_metrics(self):
        """Log periodic system metrics"""
        logger = logging.getLogger('dynohome.performance')
        
        with self.metrics_lock:
            current_metrics = dict(self.metrics)
            recent_performance = list(self.performance_logs)[-10:]  # Last 10 operations
        
        # Calculate performance statistics
        if recent_performance:
            avg_duration = sum(p.get('duration', 0) for p in recent_performance) / len(recent_performance)
            success_rate = sum(1 for p in recent_performance if p.get('success', False)) / len(recent_performance)
        else:
            avg_duration = 0
            success_rate = 0
        
        periodic_metrics = {
            'type': 'periodic_metrics',
            'interval_minutes': self.config['metrics_interval'] / 60,
            'cumulative_metrics': current_metrics,
            'recent_performance': {
                'average_duration_seconds': avg_duration,
                'success_rate': success_rate,
                'operations_count': len(recent_performance)
            },
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(json.dumps(periodic_metrics))

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get current metrics summary"""
        with self.metrics_lock:
            current_metrics = dict(self.metrics)
            error_summary = dict(self.error_counts)
            
            # Calculate recent performance
            recent_operations = [p for p in self.performance_logs 
                               if datetime.fromisoformat(p['timestamp']) > datetime.now() - timedelta(hours=1)]
            
            if recent_operations:
                avg_duration = sum(p.get('duration', 0) for p in recent_operations) / len(recent_operations)
                success_rate = sum(1 for p in recent_operations if p.get('success', False)) / len(recent_operations)
            else:
                avg_duration = 0
                success_rate = 0
        
        return {
            'cumulative_metrics': current_metrics,
            'error_summary': error_summary,
            'recent_performance': {
                'average_duration_seconds': avg_duration,
                'success_rate': success_rate,
                'operations_last_hour': len(recent_operations)
            },
            'timestamp': datetime.now().isoformat()
        }

    def export_logs(self, output_file: str, hours_back: int = 24) -> bool:
        """Export recent logs to a file for analysis"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours_back)
            export_data = {
                'export_timestamp': datetime.now().isoformat(),
                'time_range_hours': hours_back,
                'metrics_summary': self.get_metrics_summary(),
                'recent_performance': [p for p in self.performance_logs 
                                     if datetime.fromisoformat(p['timestamp']) > cutoff_time]
            }
            
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting logs: {e}")
            return False

    def cleanup_old_logs(self, days_to_keep: int = 30):
        """Clean up old log files"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            for log_file in self.log_dir.glob('*.log*'):
                try:
                    file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
                    if file_time < cutoff_date:
                        log_file.unlink()
                        print(f"Cleaned up old log file: {log_file}")
                except Exception as e:
                    print(f"Error cleaning up {log_file}: {e}")
                    
        except Exception as e:
            print(f"Error during log cleanup: {e}")


# Global logger instance
_logger_instance = None

def get_logger_system() -> DynaHomeLogger:
    """Get the global DynaHomeLogger instance for metrics tracking"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = DynaHomeLogger()
    return _logger_instance

def get_logger(name: str = None):
    """
    Get a standard Python logger for a specific module
    This provides compatibility with your web app's expected interface
    """
    if name is None:
        name = 'dynohome.main'
    
    # Ensure the logger is properly configured
    logger = logging.getLogger(name)
    
    # If no handlers are set and no global logging is configured, use fallback
    if not logger.handlers and not logging.getLogger().handlers:
        # Basic fallback configuration
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logger = logging.getLogger(name)
    
    return logger

def setup_logging(config_summary: Dict = None) -> DynaHomeLogger:
    """
    Setup the comprehensive logging system
    Returns the DynaHomeLogger instance for metrics tracking
    """
    global _logger_instance
    
    # Create configuration from summary if provided
    if config_summary:
        logging_config = {
            'log_directory': config_summary.get('data', {}).get('logs_directory', 'data/logs'),
            'log_level': 'DEBUG' if config_summary.get('webapp', {}).get('enable_debug') else 'INFO',
            'enable_console_output': config_summary.get('webapp', {}).get('enable_debug', True),
            'max_file_size': 10 * 1024 * 1024,  # 10MB
            'backup_count': 5,
            'metrics_interval': 300,  # 5 minutes
            'error_alert_threshold': 10,
            'performance_log_interval': 60
        }
    else:
        logging_config = None
    
    _logger_instance = DynaHomeLogger(logging_config)
    return _logger_instance


# Usage example and testing
if __name__ == "__main__":
    # Initialize logging
    logger_system = setup_logging()
    
    # Test different log types
    logger_system.log_user_action("test_action", {"test": "data"})
    logger_system.log_threat_processing(50, 5, 120.5, 2)
    logger_system.log_dataset_generation(
        {"num_normal": 1000, "num_attack": 500}, 
        0.87, 
        1024000, 
        45.2
    )
    logger_system.log_error("test_error", "This is a test error", {"context": "testing"})
    logger_system.log_security_event("unauthorized_access", "HIGH", {"ip": "192.168.1.100"})
    logger_system.log_performance_metric("test_operation", 2.5, True, {"test": True})
    
    # Test compatibility functions
    logger = get_logger('test.module')
    logger.info("Testing compatibility logger")
    
    # Get metrics summary
    summary = logger_system.get_metrics_summary()
    print("Metrics Summary:")
    print(json.dumps(summary, indent=2))
    
    # Export logs
    logger_system.export_logs("test_export.json", hours_back=1)
    print("Log export completed")