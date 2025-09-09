# web_app/main_app.py - Enhanced with comprehensive error handling and UX improvements

import streamlit as st
import sys
import os
from pathlib import Path

# === CRITICAL FIX: Setup path BEFORE any custom imports ===
# Add parent directory to path to import our modules
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
sys.path.insert(0, str(parent_dir))  # Use insert(0, ...) for higher priority

# Fix Unicode encoding for Windows console
if sys.platform.startswith('win'):
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Now import standard libraries
import json
import time
import traceback
import logging
import random  # FIXED: Added missing import
from datetime import datetime, timedelta  # FIXED: Added timedelta import
import pandas as pd
from typing import Optional, Dict, Any, List
from dataclasses import dataclass  # FIXED: Added dataclass import
import hashlib
import threading

# Import configuration and logging systems
try:
    from config import get_config, setup_config
    from logging_config import get_logger, setup_logging
    CONFIG_SYSTEMS_AVAILABLE = True
except ImportError as e:
    CONFIG_SYSTEMS_AVAILABLE = False
    config_import_error = e
    # Fallback logging setup
    log_dir = Path("../data/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'webapp.log'),
            logging.FileHandler(log_dir / 'webapp_errors.log', level=logging.ERROR),
        ]
    )

# Import our AI pipeline components with error handling
try:
    from ai_pipeline import CompleteThreatPipeline, AIModelError
    from ai_classifier import IoTThreatClassifier
    from threat_collector import ThreatCollector, ThreatCollectionError
    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False
    import_error = e

# === Import new scenario generation & dataset export modules ===
try:
    from attack_scenario_generator import (
        SmartHomeContextEngine, 
        AttackVectorGenerator, 
        AttackScenario as BaseAttackScenario
    )
    from dataset_export_system import (
        NetworkTrafficSynthesizer, 
        DeviceBehaviorSimulator, 
        NetworkFlow,
        DatasetExporter
    )
    SCENARIO_MODULES_AVAILABLE = True
except ImportError as e:
    SCENARIO_MODULES_AVAILABLE = False
    scenario_import_error = e
    # Log the error for debugging
    logging.getLogger(__name__).error(f"Failed to import scenario modules: {e}")

# FIXED: Add the GeneratedAttackScenario dataclass for compatibility
@dataclass
class GeneratedAttackScenario:
    """Attack scenario structure used by main_app.py"""
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

# Configure Streamlit page
st.set_page_config(
    page_title="DynaHome: AI-Powered IoT Security Framework",
    page_icon="🏠",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling and error display
st.markdown("""
<style>
    .reportview-container {
        margin-top: -2em;
    }
    .stDeployButton {display:none;}
    .stDecoration {display:none;}
    
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 0.25rem;
        padding: 0.75rem;
        margin: 1rem 0;
    }
    
    .error-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 0.25rem;
        padding: 0.75rem;
        margin: 1rem 0;
    }
    
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 0.25rem;
        padding: 0.75rem;
        margin: 1rem 0;
    }
    
    .loading-spinner {
        border: 4px solid #f3f3f3;
        border-top: 4px solid #3498db;
        border-radius: 50%;
        width: 30px;
        height: 30px;
        animation: spin 2s linear infinite;
        margin: 20px auto;
    }
    
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def initialize_app_systems():
    """Initialize configuration and logging systems (cached for performance)"""
    try:
        if not CONFIG_SYSTEMS_AVAILABLE:
            # Fallback to basic logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Config systems not available: {config_import_error}")
            return None, None, logger
        
        # Detect environment
        environment = os.getenv('DYNOHOME_ENV', 'development')
        
        # Initialize config and logging
        config = setup_config(environment=environment)
        logger_system = setup_logging(config.get_configuration_summary())
        logger = get_logger('dynohome.webapp')
        
        logger.info("=== DynaHome Web App Starting ===")
        logger.info(f"Environment: {environment}")
        logger.info("Configuration and logging systems initialized successfully")
        
        return config, logger_system, logger
        
    except Exception as e:
        # Fallback logger
        fallback_logger = logging.getLogger(__name__)
        fallback_logger.error(f"Failed to initialize app systems: {e}")
        fallback_logger.error(traceback.format_exc())
        
        st.error("❌ Failed to initialize configuration systems")
        st.error(f"Error: {e}")
        
        return None, None, fallback_logger

# Initialize systems at module level
config, logger_system, logger = initialize_app_systems()

@st.cache_resource
def initialize_generation_engines():
    """Initialize scenario generation engines with proper error handling and traffic pattern loading"""
    try:
        if not SCENARIO_MODULES_AVAILABLE:
            logger = logging.getLogger(__name__)
            logger.error(f"Scenario modules not available: {scenario_import_error}")
            return None, None, None, None
        
        # Initialize context engine
        ctx = SmartHomeContextEngine()
        logger.info("SmartHomeContextEngine initialized")
        
        # Initialize attack vector generator
        gen = AttackVectorGenerator(ctx)
        logger.info("AttackVectorGenerator initialized")
        
        # Initialize traffic synthesizer with proper pattern loading
        traffic = NetworkTrafficSynthesizer()
        logger.info("NetworkTrafficSynthesizer initialized with traffic patterns")
        
        # Initialize device behavior simulator
        behavior = DeviceBehaviorSimulator()
        logger.info("DeviceBehaviorSimulator initialized")
        
        # Validate that traffic patterns are properly loaded
        if hasattr(traffic, 'normal_traffic_patterns') and traffic.normal_traffic_patterns:
            logger.info(f"Normal traffic patterns loaded for {len(traffic.normal_traffic_patterns)} device types")
        else:
            logger.warning("Normal traffic patterns not properly loaded")
            
        if hasattr(traffic, 'attack_traffic_patterns') and traffic.attack_traffic_patterns:
            logger.info(f"Attack traffic patterns loaded for {len(traffic.attack_traffic_patterns)} attack types")
        else:
            logger.warning("Attack traffic patterns not properly loaded")
        
        logger.info("All scenario generation engines initialized successfully")
        
        return ctx, gen, traffic, behavior
        
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to init generation engines: {e}")
        logger.error(traceback.format_exc())
        return None, None, None, None

# Initialize scenario engines
context_engine, attack_generator, traffic_synth, behavior_sim = initialize_generation_engines()

# Display module availability status
def show_module_status():
    """Show the status of all imported modules"""
    st.sidebar.markdown("### 📊 System Status")
    
    # Core modules
    if MODULES_AVAILABLE:
        st.sidebar.success("✅ Core AI modules loaded")
    else:
        st.sidebar.error("❌ Core AI modules failed")
        st.sidebar.error(f"Error: {import_error}")
    
    # Scenario modules
    if SCENARIO_MODULES_AVAILABLE:
        st.sidebar.success("✅ Scenario generation modules loaded")
        
        # Check traffic synthesizer status
        if traffic_synth:
            if hasattr(traffic_synth, 'normal_traffic_patterns') and traffic_synth.normal_traffic_patterns:
                st.sidebar.success("✅ Traffic patterns loaded")
            else:
                st.sidebar.warning("⚠️ Traffic patterns missing")
        else:
            st.sidebar.error("❌ Traffic synthesizer not initialized")
    else:
        st.sidebar.error("❌ Scenario generation modules failed")
        st.sidebar.error(f"Error: {scenario_import_error}")
        
        # Show helpful troubleshooting
        with st.sidebar.expander("🔧 Troubleshooting"):
            st.write("**Missing files:**")
            st.write("- attack_scenario_generator.py")
            st.write("- dataset_export_system.py")
            st.write("\n**Check:**")
            st.write("- Files exist in project root")
            st.write("- Files have no syntax errors")
            st.write("- All dependencies installed")
    
    # Config modules
    if CONFIG_SYSTEMS_AVAILABLE:
        st.sidebar.success("✅ Configuration system loaded")
    else:
        st.sidebar.warning("⚠️ Using fallback configuration")

# Rest of your existing code (WebAppError, SessionStateManager, etc.)
class WebAppError(Exception):
    """Custom exception for web app errors"""
    pass

class SessionStateManager:
    """Manage session state with recovery and validation"""
    
    @staticmethod
    def initialize_session_state():
        """Initialize session state with default values and recovery"""
        try:
            # Core pipeline state
            if 'pipeline' not in st.session_state:
                st.session_state.pipeline = None
            if 'pipeline_status' not in st.session_state:
                st.session_state.pipeline_status = 'not_loaded'
            if 'pipeline_error' not in st.session_state:
                st.session_state.pipeline_error = None
            
            # Configuration state
            if 'config' not in st.session_state:
                st.session_state.config = config
            if 'logger_system' not in st.session_state:
                st.session_state.logger_system = logger_system
            
            # Data state
            if 'threats_data' not in st.session_state:
                st.session_state.threats_data = []
            if 'generated_scenarios' not in st.session_state:
                st.session_state.generated_scenarios = []
            if 'datasets' not in st.session_state:
                st.session_state.datasets = []
            
            # UI state
            if 'last_error' not in st.session_state:
                st.session_state.last_error = None
            if 'error_timestamp' not in st.session_state:
                st.session_state.error_timestamp = None
            if 'operation_in_progress' not in st.session_state:
                st.session_state.operation_in_progress = False
            if 'last_successful_operation' not in st.session_state:
                st.session_state.last_successful_operation = None
                
            # Performance tracking
            if 'performance_stats' not in st.session_state:
                st.session_state.performance_stats = {
                    'total_operations': 0,
                    'successful_operations': 0,
                    'failed_operations': 0,
                    'average_processing_time': 0
                }
            
            logger.debug("Session state initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing session state: {e}")
            st.error("Failed to initialize application state. Please refresh the page.")

    @staticmethod
    def recover_session_state():
        """Attempt to recover session state from backup or reset gracefully"""
        try:
            # Try to load from backup file
            backup_file = Path("../data/session_backup.json")
            if backup_file.exists():
                with open(backup_file, 'r') as f:
                    backup_data = json.load(f)
                
                # Restore critical data only
                if 'threats_data' in backup_data:
                    st.session_state.threats_data = backup_data['threats_data']
                if 'generated_scenarios' in backup_data:
                    st.session_state.generated_scenarios = backup_data['generated_scenarios']
                
                logger.info("Session state recovered from backup")
                return True
                
        except Exception as e:
            logger.error(f"Error recovering session state: {e}")
        
        # If recovery fails, reset to clean state
        logger.info("Resetting session state to clean defaults")
        SessionStateManager.initialize_session_state()
        return False

    @staticmethod
    def backup_session_state():
        """Backup critical session state data"""
        try:
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'threats_data': st.session_state.get('threats_data', []),
                'generated_scenarios': st.session_state.get('generated_scenarios', []),
                'performance_stats': st.session_state.get('performance_stats', {})
            }
            
            backup_file = Path("../data/session_backup.json")
            backup_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
            
            logger.debug("Session state backed up successfully")
            
        except Exception as e:
            logger.warning(f"Failed to backup session state: {e}")

def handle_error(func):
    """Decorator to handle errors gracefully in Streamlit with user-friendly messages"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ThreatCollectionError as e:
            error_msg = f"Threat collection error: {str(e)}"
            logger.error(error_msg)
            if logger_system:
                logger_system.log_error("threat_collection_error", str(e), {"function": func.__name__})
            st.error("❌ **Threat Collection Failed**")
            st.error(f"Unable to collect threat intelligence: {str(e)}")
            st.info("💡 **Suggested Actions:**\n- Check your internet connection\n- Try reducing the number of days or results\n- Wait a few minutes and try again")
            _record_error(error_msg)
            
        except AIModelError as e:
            error_msg = f"AI model error: {str(e)}"
            logger.error(error_msg)
            if logger_system:
                logger_system.log_error("ai_model_error", str(e), {"function": func.__name__})
            st.error("❌ **AI Model Error**")
            st.error(f"AI processing failed: {str(e)}")
            st.info("💡 **Suggested Actions:**\n- Restart the application\n- Check system resources\n- Try using fallback mode")
            _record_error(error_msg)
            
        except FileNotFoundError as e:
            error_msg = f"File not found: {str(e)}"
            logger.error(error_msg)
            if logger_system:
                logger_system.log_error("file_not_found", str(e), {"function": func.__name__})
            st.error("❌ **File Access Error**")
            st.error("Required files or directories are missing")
            st.info("💡 **Suggested Actions:**\n- Check file permissions\n- Ensure all required files are present\n- Contact system administrator")
            _record_error(error_msg)
            
        except PermissionError as e:
            error_msg = f"Permission error: {str(e)}"
            logger.error(error_msg)
            if logger_system:
                logger_system.log_error("permission_error", str(e), {"function": func.__name__})
            st.error("❌ **Permission Denied**")
            st.error("Insufficient permissions to access required resources")
            st.info("💡 **Suggested Actions:**\n- Check file/folder permissions\n- Run with appropriate privileges\n- Contact system administrator")
            _record_error(error_msg)
            
        except ConnectionError as e:
            error_msg = f"Connection error: {str(e)}"
            logger.error(error_msg)
            if logger_system:
                logger_system.log_error("connection_error", str(e), {"function": func.__name__})
            st.error("❌ **Connection Failed**")
            st.error("Unable to connect to external services")
            st.info("💡 **Suggested Actions:**\n- Check internet connection\n- Verify firewall settings\n- Try again in a few minutes")
            _record_error(error_msg)
            
        except json.JSONDecodeError as e:
            error_msg = f"JSON parsing error: {str(e)}"
            logger.error(error_msg)
            if logger_system:
                logger_system.log_error("json_decode_error", str(e), {"function": func.__name__})
            st.error("❌ **Data Format Error**")
            st.error("Invalid data format encountered")
            st.info("💡 **Suggested Actions:**\n- Check input data format\n- Try downloading fresh data\n- Report this issue if it persists")
            _record_error(error_msg)
            
        except Exception as e:
            error_msg = f"Unexpected error in {func.__name__}: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            if logger_system:
                logger_system.log_error("unexpected_error", str(e), {
                    "function": func.__name__,
                    "traceback": traceback.format_exc()
                })
            
            st.error("❌ **Unexpected Error**")
            st.error(f"An unexpected error occurred: {str(e)}")
            
            with st.expander("🔧 Technical Details (for developers)"):
                st.code(traceback.format_exc())
            
            st.info("💡 **Suggested Actions:**\n- Refresh the page and try again\n- Check the application logs\n- Report this issue with the technical details")
            _record_error(error_msg)
    
    return wrapper

def _record_error(error_msg: str):
    """Record error in session state for tracking"""
    try:
        st.session_state.last_error = error_msg
        st.session_state.error_timestamp = datetime.now().isoformat()
        
        # Update error statistics
        if 'performance_stats' in st.session_state:
            st.session_state.performance_stats['failed_operations'] += 1
        
    except Exception as e:
        logger.error(f"Failed to record error: {e}")

@handle_error
def load_ai_pipeline():
    """Load AI pipeline with enhanced error handling and progress tracking"""
    if not MODULES_AVAILABLE:
        raise WebAppError(f"Required modules not available: {import_error}")
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        status_text.text("🔧 Initializing AI pipeline...")
        progress_bar.progress(20)
        
        # Initialize with timeout
        pipeline = CompleteThreatPipeline()
        progress_bar.progress(60)
        
        status_text.text("🧪 Running health check...")
        health = pipeline.health_check()
        progress_bar.progress(80)
        
        if health['status'] == 'unhealthy':
            raise AIModelError(f"Pipeline health check failed: {health.get('errors', [])}")
        
        status_text.text("✅ Pipeline ready!")
        progress_bar.progress(100)
        
        # Update session state
        st.session_state.pipeline = pipeline
        st.session_state.pipeline_status = 'loaded'
        st.session_state.pipeline_error = None
        
        # Log pipeline initialization
        if logger_system:
            logger_system.log_user_action("pipeline_initialization", {
                "status": "success",
                "health_status": health.get('status')
            })
        
        # Show health warnings if any
        if health.get('warnings'):
            st.warning("⚠️ **Pipeline Warnings:**")
            for warning in health['warnings']:
                st.warning(f"• {warning}")
        
        time.sleep(1)  # Let user see the success message
        progress_bar.empty()
        status_text.empty()
        
        return pipeline, True
        
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        
        st.session_state.pipeline_status = 'failed'
        st.session_state.pipeline_error = str(e)
        
        if logger_system:
            logger_system.log_error("pipeline_load_failure", str(e))
        
        raise

@handle_error
def safe_file_operation(operation_func, *args, **kwargs):
    """Safely perform file operations with error handling"""
    try:
        return operation_func(*args, **kwargs)
    except PermissionError:
        raise PermissionError("Unable to access file - check permissions")
    except FileNotFoundError:
        raise FileNotFoundError("Required file not found")
    except OSError as e:
        raise OSError(f"File system error: {e}")

class ProgressTracker:
    """Track and display progress for long-running operations"""
    
    def __init__(self, total_steps: int, operation_name: str):
        self.total_steps = total_steps
        self.current_step = 0
        self.operation_name = operation_name
        self.start_time = time.time()
        
        # Create UI elements
        self.progress_bar = st.progress(0)
        self.status_text = st.empty()
        self.time_text = st.empty()
        
        # Mark operation as in progress
        st.session_state.operation_in_progress = True
        
        logger.info(f"Started operation: {operation_name}")

    def update(self, step_name: str, increment: int = 1):
        """Update progress with current step information"""
        try:
            self.current_step += increment
            progress = min(self.current_step / self.total_steps, 1.0)
            
            # Update progress bar
            self.progress_bar.progress(progress)
            
            # Update status text
            self.status_text.text(f"🔄 {step_name}...")
            
            # Update time estimate
            elapsed_time = time.time() - self.start_time
            if progress > 0.1:  # Only show estimate after 10% completion
                estimated_total = elapsed_time / progress
                remaining_time = estimated_total - elapsed_time
                self.time_text.text(f"⏱️ Estimated time remaining: {remaining_time:.0f}s")
            
            logger.debug(f"Progress update: {progress:.1%} - {step_name}")
            
        except Exception as e:
            logger.error(f"Error updating progress: {e}")

    def complete(self, success: bool = True, message: str = None):
        """Complete the progress tracking"""
        try:
            elapsed_time = time.time() - self.start_time
            
            if success:
                self.progress_bar.progress(1.0)
                self.status_text.text(f"✅ {message or 'Operation completed successfully!'}")
                self.time_text.text(f"⏱️ Completed in {elapsed_time:.1f}s")
                
                # Update success statistics
                if 'performance_stats' in st.session_state:
                    st.session_state.performance_stats['successful_operations'] += 1
                    st.session_state.performance_stats['total_operations'] += 1
                    
                    # Update average processing time
                    stats = st.session_state.performance_stats
                    current_avg = stats.get('average_processing_time', 0)
                    total_ops = stats['total_operations']
                    new_avg = ((current_avg * (total_ops - 1)) + elapsed_time) / total_ops
                    stats['average_processing_time'] = new_avg
                
                st.session_state.last_successful_operation = {
                    'name': self.operation_name,
                    'timestamp': datetime.now().isoformat(),
                    'duration': elapsed_time
                }
                
                # Log performance metric
                if logger_system:
                    logger_system.log_performance_metric(
                        self.operation_name, elapsed_time, True
                    )
                
                logger.info(f"Operation completed successfully: {self.operation_name} ({elapsed_time:.1f}s)")
                
            else:
                self.status_text.text(f"❌ {message or 'Operation failed'}")
                self.time_text.text(f"⏱️ Failed after {elapsed_time:.1f}s")
                
                # Update failure statistics
                if 'performance_stats' in st.session_state:
                    st.session_state.performance_stats['failed_operations'] += 1
                    st.session_state.performance_stats['total_operations'] += 1
                
                # Log performance metric
                if logger_system:
                    logger_system.log_performance_metric(
                        self.operation_name, elapsed_time, False
                    )
                
                logger.error(f"Operation failed: {self.operation_name} ({elapsed_time:.1f}s)")
            
            # Clean up after a delay
            time.sleep(2)
            self.progress_bar.empty()
            self.status_text.empty()
            self.time_text.empty()
            
            st.session_state.operation_in_progress = False
            
        except Exception as e:
            logger.error(f"Error completing progress tracking: {e}")
            st.session_state.operation_in_progress = False

def _ensure_data_dir():
    """Ensure data directory exists with proper error handling"""
    try:
        base = Path('../data')
        base.mkdir(parents=True, exist_ok=True)
        (base / 'outputs').mkdir(parents=True, exist_ok=True)
        return base
    except Exception as e:
        logger.warning(f"Could not create data directory: {e}")
        return Path('.')

@handle_error
def generate_scenarios_from_threats(threats):
    """Use context engine & generator to create scenarios from threat list."""
    if not (context_engine and attack_generator):
        raise WebAppError("Scenario engines not initialized")
    
    scenarios = []
    for i, threat in enumerate(threats[:5]):  # limit for demo
        try:
            # Map threat to smart home context
            ctx = context_engine.map_cve_to_smart_home(threat)
            
            if not ctx or ctx.get('smart_home_relevance', 0) < 0.3:
                logger.debug(f"Threat {threat.get('cve_id')} not relevant to smart home")
                continue
            
            # Generate attack sequence
            seq = attack_generator.generate_attack_sequence(ctx)
            
            # Create scenario structure compatible with traffic synthesizer
            scenario = GeneratedAttackScenario(
                scenario_id=threat.get('cve_id', f'SCN-{i+1}'),
                cve_id=threat.get('cve_id', 'Unknown'),
                attack_name=f"{ctx.get('vulnerability_type', 'Unknown')} Attack",
                target_devices=ctx.get('target_devices', ['smart_hub']),
                attack_vector=seq.get('attack_type', 'network_infiltration'),
                complexity=seq.get('complexity_rating', 'medium'),
                impact_level=ctx.get('impact_assessment', {}).get('overall_risk', 'medium'),
                timeline=seq.get('timeline', [
                    {'phase': 'reconnaissance', 'duration_minutes': 10},
                    {'phase': 'exploitation', 'duration_minutes': 15},
                    {'phase': 'impact', 'duration_minutes': 5}
                ]),
                network_indicators=seq.get('network_indicators', {}),
                mitigation_strategies=[],
                scenario_narrative="",
                technical_details={},
                quality_score=0.9
            )
            
            scenarios.append(scenario)
            logger.info(f"Generated scenario for {threat.get('cve_id')}")
            
        except Exception as e:
            logger.warning(f"Scenario generation failed for {threat.get('cve_id','?')}: {e}")
            continue
    
    logger.info(f"Generated {len(scenarios)} scenarios from {len(threats)} threats")
    return scenarios

@handle_error
def create_dataset_from_scenarios(scenarios):
    """FIXED: Create realistic dataset with 95% normal traffic using proper traffic synthesizer"""
    if not traffic_synth:
        raise WebAppError("Traffic synthesizer not initialized")
    
    # Verify traffic patterns are loaded
    if not hasattr(traffic_synth, 'normal_traffic_patterns') or not traffic_synth.normal_traffic_patterns:
        raise WebAppError("Traffic patterns not properly loaded in synthesizer")
    
    base = _ensure_data_dir() / 'outputs'
    all_rows = []
    
    logger.info("Starting dataset creation with realistic traffic distribution")
    
    # STEP 1: Generate lots of normal traffic (95% of dataset)
    logger.info("Generating normal baseline traffic...")
    
    device_types = ['smart_camera', 'smart_thermostat', 'smart_doorbell', 
                   'smart_lock', 'smart_hub', 'smart_tv', 'smartphone', 'laptop']
    
    # Generate 48 hours of normal traffic
    normal_start_time = datetime.now() - timedelta(hours=48)
    
    for device_type in device_types:
        try:
            normal_flows = traffic_synth.generate_normal_traffic(
                device_type, 48, normal_start_time
            )
            logger.info(f"Generated {len(normal_flows)} normal flows for {device_type}")
            
            # Convert NetworkFlow objects to dict rows
            for flow in normal_flows:
                all_rows.append({
                    'timestamp': flow.timestamp,
                    'src_ip': flow.src_ip,
                    'dst_ip': flow.dst_ip,
                    'src_port': flow.src_port,
                    'dst_port': flow.dst_port,
                    'protocol': flow.protocol,
                    'packet_count': flow.packet_count,
                    'byte_count': flow.byte_count,
                    'duration': flow.duration,
                    'flags': flow.flags,
                    'flow_label': flow.flow_label,
                    'attack_type': getattr(flow, 'attack_type', None),
                    'scenario_id': 'normal_traffic'
                })
        except Exception as e:
            logger.error(f"Error generating normal traffic for {device_type}: {e}")
            continue
    
    # STEP 2: Add attack traffic (5% of dataset)
    logger.info(f"Processing {len(scenarios)} attack scenarios...")
    
    for i, scenario in enumerate(scenarios[:3]):  # Limit to 3 scenarios for realistic ratio
        try:
            # Generate attack traffic
            attack_time = datetime.now() - timedelta(hours=random.randint(6, 42))
            flows = traffic_synth.generate_attack_traffic(scenario, attack_time)
            logger.info(f"Generated {len(flows)} attack flows for scenario {scenario.scenario_id}")
            
            # Convert NetworkFlow objects to dict rows
            for flow in flows:
                all_rows.append({
                    'timestamp': flow.timestamp,
                    'src_ip': flow.src_ip,
                    'dst_ip': flow.dst_ip,
                    'src_port': flow.src_port,
                    'dst_port': flow.dst_port,
                    'protocol': flow.protocol,
                    'packet_count': flow.packet_count,
                    'byte_count': flow.byte_count,
                    'duration': flow.duration,
                    'flags': flow.flags,
                    'flow_label': flow.flow_label,
                    'attack_type': getattr(flow, 'attack_type', None),
                    'scenario_id': scenario.scenario_id
                })
                
        except Exception as e:
            logger.error(f"Error processing scenario {i}: {e}")
            continue
    
    logger.info(f"Total rows generated: {len(all_rows)}")
    
    # STEP 3: Apply realistic constraints and validation
    logger.info("Applying data validation and constraints...")
    
    valid_rows = []
    for row in all_rows:
        try:
            # Validate and fix data ranges
            if row['byte_count'] > 50000000:  # 50MB max per flow
                row['byte_count'] = random.randint(1000000, 50000000)
                row['packet_count'] = max(1, row['byte_count'] // 1400)
            
            # Ensure minimum values
            row['packet_count'] = max(1, row['packet_count'])
            row['byte_count'] = max(64, row['byte_count'])
            row['duration'] = max(0.1, row['duration'])
            
            valid_rows.append(row)
        except Exception as e:
            logger.warning(f"Skipping invalid row: {e}")
            continue
    
    # STEP 4: Sort by time and save
    valid_rows.sort(key=lambda x: x['timestamp'])
    
    if not valid_rows:
        logger.error("No valid data generated - check scenario processing")
        return None
    
    try:
        df = pd.DataFrame(valid_rows)
        
        base.mkdir(parents=True, exist_ok=True)
        timestamp = int(datetime.now().timestamp())
        out_path = base / f"realistic_flows_{timestamp}.csv"
        df.to_csv(out_path, index=False)
        
        # Calculate and log statistics
        normal_count = len(df[df['flow_label'] == 'normal'])
        attack_count = len(df[df['flow_label'] == 'attack'])
        total_count = len(df)
        
        logger.info(f"Dataset saved to {out_path}")
        logger.info(f"Total rows: {total_count}")
        logger.info(f"Normal traffic: {normal_count} ({normal_count/total_count*100:.1f}%)")
        logger.info(f"Attack traffic: {attack_count} ({attack_count/total_count*100:.1f}%)")
        logger.info(f"Columns: {list(df.columns)}")
        
        return str(out_path)
        
    except Exception as e:
        logger.error(f"Error saving CSV: {e}")
        return None

def show_home_page():
    """Home page with overview and quick actions"""
    st.title("🏠 DynaHome: AI-Powered IoT Security Framework")
    st.markdown("*Automatically convert threat intelligence into synthetic attack datasets using AI*")
    
    # Show configuration status
    if config and CONFIG_SYSTEMS_AVAILABLE:
        with st.expander("🔧 System Configuration", expanded=False):
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"**Environment:** {config.environment}")
                st.info(f"**Debug Mode:** {config.webapp.enable_debug}")
            with col2:
                st.info(f"**Pipeline Threads:** {config.performance.thread_pool_size}")
                st.info(f"**Memory Limit:** {config.ai.memory_limit_mb}MB")
    
    # Check for any previous errors
    if st.session_state.get('last_error'):
        with st.expander("⚠️ Recent Error Information"):
            st.error(f"Last error: {st.session_state.last_error}")
            st.text(f"Time: {st.session_state.error_timestamp}")
            if st.button("Clear Error Log"):
                st.session_state.last_error = None
                st.session_state.error_timestamp = None
                st.rerun()
    
    # System status with health monitoring
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        pipeline_status = st.session_state.get('pipeline_status', 'not_loaded')
        if pipeline_status == 'loaded':
            st.metric("AI Pipeline", "Ready", delta="✅")
        elif pipeline_status == 'failed':
            st.metric("AI Pipeline", "Failed", delta="❌")
        else:
            st.metric("AI Pipeline", "Loading", delta="⏳")
    
    with col2:
        # Count threat files with error handling
        try:
            if config:
                data_dir = Path(config.data.data_directory)
            else:
                data_dir = Path("../data")
            
            if data_dir.exists():
                threat_files = len(list(data_dir.glob("*threats*.json")))
                st.metric("Threat Files", threat_files, delta="Available")
            else:
                st.metric("Threat Files", "0", delta="No data dir")
        except Exception as e:
            logger.error(f"Error counting threat files: {e}")
            st.metric("Threat Files", "Error", delta="❌")
    
    with col3:
        scenarios_count = len(st.session_state.get('generated_scenarios', []))
        st.metric("Attack Scenarios", scenarios_count, delta="Generated")
    
    with col4:
        datasets_count = len(st.session_state.get('datasets', []))
        st.metric("Datasets", datasets_count, delta="Created")
    
    # Performance statistics
    if st.session_state.get('performance_stats'):
        stats = st.session_state.performance_stats
        total_ops = stats.get('total_operations', 0)
        success_rate = (stats.get('successful_operations', 0) / max(total_ops, 1)) * 100
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Success Rate", f"{success_rate:.1f}%")
        with col2:
            st.metric("Total Operations", total_ops)
        with col3:
            avg_time = stats.get('average_processing_time', 0)
            st.metric("Avg Processing Time", f"{avg_time:.1f}s")
    
    st.markdown("---")
    
    # Quick actions with enhanced error handling
    st.subheader("Quick Start")
    
    # Show module status
    show_module_status()
    
    # Add debugging section if engines aren't initialized
    if not (context_engine and attack_generator and traffic_synth and behavior_sim):
        st.error("⚠️ **Engine Initialization Failed**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔧 Run Diagnostics", use_container_width=True):
                diagnose_imports()
        
        with col2:
            if st.button("🔄 Force Reinitialize", use_container_width=True):
                with st.spinner("Reinitializing engines..."):
                    try:
                        context_engine, attack_generator, traffic_synth, behavior_sim = manual_initialize_engines()
                        if context_engine and attack_generator and traffic_synth and behavior_sim:
                            st.success("✅ Engines reinitialized successfully!")
                            st.rerun()
                        else:
                            st.error("❌ Reinitialization failed")
                    except Exception as e:
                        st.error(f"❌ Reinitialization error: {e}")
        
        # Quick file check
        st.subheader("📁 File Check")
        
        files_to_check = [
            "attack_scenario_generator.py",
            "dataset_export_system.py"
        ]
        
        for file in files_to_check:
            file_path = Path(f"../{file}")
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    st.success(f"✅ {file} exists ({len(content)} chars)")
                except Exception as e:
                    st.warning(f"⚠️ {file} exists but can't read: {e}")
            else:
                st.error(f"❌ {file} missing")
        
        return  # Don't show the rest of the page if engines aren't working
    
    # Prevent multiple operations
    if st.session_state.get('operation_in_progress'):
        st.warning("⏳ An operation is currently in progress. Please wait for it to complete.")
        if st.button("🛑 Force Stop Operation"):
            st.session_state.operation_in_progress = False
            st.rerun()
        return
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔄 Collect Latest Threats", use_container_width=True, type="primary"):
            if st.session_state.pipeline and st.session_state.pipeline_status == 'loaded':
                progress = ProgressTracker(5, "Threat Collection")
                
                try:
                    progress.update("Initializing threat collection", 1)
                    
                    # Use configuration if available
                    if config:
                        days_back = 3
                        max_results = 20
                    else:
                        days_back = 3
                        max_results = 20
                    
                    threats = st.session_state.pipeline.run_daily_collection(
                        days_back=days_back, max_results=max_results
                    )
                    
                    progress.update("Processing results", 2)
                    
                    if threats:
                        st.session_state.threats_data = threats
                        
                        # Log threat collection
                        if logger_system:
                            logger_system.log_threat_processing(
                                len(threats), len(threats), progress.start_time, 0
                            )
                        
                        progress.complete(True, f"Collected {len(threats)} IoT threats!")
                        
                        # Backup session state
                        SessionStateManager.backup_session_state()
                        
                        st.rerun()
                    else:
                        progress.complete(False, "No threats found. Try increasing the date range.")
                        
                except Exception as e:
                    progress.complete(False, f"Collection failed: {str(e)}")
                    raise
            else:
                st.error("❌ AI pipeline not loaded. Please wait for initialization.")
    
    with col2:
        if st.button("⚡ Generate Attack Scenarios", use_container_width=True):
            if st.session_state.threats_data:
                progress = ProgressTracker(3, "Attack Scenario Generation")
                try:
                    progress.update("Mapping CVEs to smart home context", 1)
                    scenarios = generate_scenarios_from_threats(st.session_state.threats_data)
                    progress.update("Storing scenarios", 1)
                    st.session_state.generated_scenarios = scenarios
                    SessionStateManager.backup_session_state()
                    progress.complete(True, f"Generated {len(scenarios)} scenarios")
                    st.rerun()
                except Exception as e:
                    progress.complete(False, f"Scenario generation failed: {e}")
                    raise
            else:
                st.info("💡 Collect threats first to generate attack scenarios")
    
    with col3:
        if st.button("📊 Create Dataset", use_container_width=True):
            if st.session_state.get('generated_scenarios'):
                progress = ProgressTracker(4, "Dataset Creation")
                try:
                    progress.update("Synthesizing network flows", 1)
                    out_csv = create_dataset_from_scenarios(st.session_state.generated_scenarios)
                    progress.update("Saving dataset", 1)
                    if out_csv:
                        # Read file to get actual row count
                        try:
                            df = pd.read_csv(out_csv)
                            row_count = len(df)
                        except Exception:
                            row_count = "unknown"
                        
                        st.session_state.datasets.append({
                            "path": out_csv, 
                            "rows": row_count,
                            "timestamp": datetime.now().isoformat()
                        })
                        SessionStateManager.backup_session_state()
                        progress.complete(True, f"Dataset saved: {Path(out_csv).name}")
                        st.rerun()
                    else:
                        progress.complete(False, "No flows were generated")
                except Exception as e:
                    progress.complete(False, f"Dataset creation failed: {e}")
                    raise
            else:
                st.info("💡 Generate attack scenarios first to create datasets")
    
    # Recent activity with error handling
    st.markdown("---")
    st.subheader("Recent Activity")
    
    try:
        if st.session_state.threats_data:
            st.write("**Latest Threats Found:**")
            recent_threats = st.session_state.threats_data[:5]
            
            for threat in recent_threats:
                try:
                    with st.expander(f"🔍 {threat['cve_id']} - {threat.get('severity', {}).get('cvss_v3_severity', 'Unknown')} Severity"):
                        st.write(f"**Description:** {threat['description'][:200]}...")
                        
                        if 'nlp_analysis' in threat:
                            analysis = threat['nlp_analysis']
                            if analysis.get('devices'):
                                st.write(f"**Devices:** {', '.join(analysis['devices'])}")
                            if analysis.get('attack_types'):
                                st.write(f"**Attack Types:** {', '.join(analysis['attack_types'])}")
                                
                except Exception as e:
                    logger.error(f"Error displaying threat {threat.get('cve_id', 'unknown')}: {e}")
                    st.error(f"Error displaying threat data")
        else:
            st.info("No recent threats. Use 'Collect Latest Threats' to get started.")
            
        # Show recent datasets
        if st.session_state.get('datasets'):
            st.write("**Recent Datasets:**")
            for dataset in st.session_state.datasets[-3:]:  # Show last 3
                st.write(f"📊 {Path(dataset['path']).name} - {dataset['rows']} rows")
            
    except Exception as e:
        logger.error(f"Error in recent activity section: {e}")
        st.error("Unable to display recent activity")
    
    # Last successful operation info
    if st.session_state.get('last_successful_operation'):
        last_op = st.session_state.last_successful_operation
        st.success(f"✅ Last successful operation: {last_op['name']} completed in {last_op['duration']:.1f}s")

@handle_error  
def show_threat_intelligence_page():
    """Enhanced threat intelligence page with better error handling"""
    st.header("🔍 AI Threat Intelligence Dashboard")
    
    # Check pipeline status
    if not st.session_state.pipeline or st.session_state.pipeline_status != 'loaded':
        st.error("❌ AI pipeline not loaded")
        
        if st.session_state.get('pipeline_error'):
            st.error(f"Error: {st.session_state.pipeline_error}")
        
        st.info("💡 Please wait for pipeline initialization on the Home page, or restart the application.")
        return
    
    # Control panel with validation
    col1, col2, col3 = st.columns(3)
    
    with col1:
        days_back = st.number_input("Days to look back:", min_value=1, max_value=30, value=3)
    
    with col2:
        max_results = st.number_input("Max results:", min_value=10, max_value=100, value=20)
    
    with col3:
        if st.button("🔄 Refresh Threats", use_container_width=True, type="primary"):
            if st.session_state.get('operation_in_progress'):
                st.warning("Another operation is in progress. Please wait.")
                return
            
            progress = ProgressTracker(4, "Threat Intelligence Refresh")
            
            try:
                progress.update("Downloading vulnerabilities", 1)
                threats = st.session_state.pipeline.run_daily_collection(
                    days_back=days_back, 
                    max_results=max_results
                )
                
                progress.update("Saving results", 1)
                
                if threats:
                    st.session_state.threats_data = threats
                    
                    # Log threat processing
                    if logger_system:
                        logger_system.log_threat_processing(
                            len(threats), len(threats), 
                            time.time() - progress.start_time, 0
                        )
                    
                    SessionStateManager.backup_session_state()
                    progress.complete(True, f"Found {len(threats)} IoT threats")
                    st.rerun()
                else:
                    progress.complete(False, "No IoT threats found in the specified time range")
                    
            except Exception as e:
                progress.complete(False, f"Collection failed: {str(e)}")
                raise
    
    # Display current threats with enhanced error handling
    if st.session_state.threats_data:
        st.markdown("---")
        st.subheader(f"Current IoT Threats ({len(st.session_state.threats_data)} found)")
        
        # Display threats table
        try:
            threat_df_data = []
            for threat in st.session_state.threats_data:
                threat_df_data.append({
                    'CVE ID': threat.get('cve_id', 'Unknown'),
                    'Severity': threat.get('severity', {}).get('cvss_v3_severity', 'Unknown'),
                    'Score': threat.get('severity', {}).get('cvss_v3_score', 'N/A'),
                    'Published': threat.get('published_date', 'Unknown')[:10] if threat.get('published_date') else 'Unknown',
                    'Description': threat.get('description', '')[:100] + '...' if len(threat.get('description', '')) > 100 else threat.get('description', '')
                })
            
            if threat_df_data:
                threat_df = pd.DataFrame(threat_df_data)
                st.dataframe(threat_df, use_container_width=True)
                
        except Exception as e:
            logger.error(f"Error creating threats dataframe: {e}")
            st.error("Unable to display threats table")
        
    else:
        st.info("No threat data loaded. Click 'Refresh Threats' to collect the latest intelligence.")

def main():
    """Main application function with comprehensive error handling"""
    try:
        # Initialize session state with recovery
        SessionStateManager.initialize_session_state()
        
        # Check if we need to recover from a crash
        if st.session_state.get('pipeline_status') == 'crashed':
            if st.button("🔄 Recover from Crash"):
                SessionStateManager.recover_session_state()
                st.rerun()
            return
        
        # Show configuration warnings if needed
        if not CONFIG_SYSTEMS_AVAILABLE:
            st.sidebar.warning("⚠️ Config systems unavailable")
            st.sidebar.info("Using fallback configuration")
        
        # Load AI pipeline if not already loaded
        if st.session_state.pipeline is None and st.session_state.pipeline_status != 'failed':
            with st.spinner("Initializing AI pipeline..."):
                try:
                    pipeline, success = load_ai_pipeline()
                    if success:
                        st.success("✅ AI pipeline loaded successfully!")
                        time.sleep(1)
                        st.rerun()
                except Exception as e:
                    logger.error(f"Pipeline initialization failed: {e}")
                    st.session_state.pipeline_status = 'failed'
                    return
        
        # Sidebar navigation with status
        st.sidebar.title("🏠 DynaHome Navigation")
        
        # Show module availability status
        if not MODULES_AVAILABLE:
            st.sidebar.error("❌ Required modules not available")
            st.sidebar.info("Please check installation")
        
        # Show configuration status
        if config and CONFIG_SYSTEMS_AVAILABLE:
            st.sidebar.success("✅ Configuration: Loaded")
            st.sidebar.info(f"Environment: {config.environment}")
        else:
            st.sidebar.warning("⚠️ Configuration: Fallback")
        
        # Page selection
        page = st.sidebar.selectbox(
            "Choose a page:",
            ["🏠 Home", "🔍 Threat Intelligence", "⚡ Attack Generator", "📊 Dataset Creator", "📈 Analytics"]
        )
        
        # System status in sidebar
        st.sidebar.markdown("---")
        st.sidebar.subheader("System Status")
        
        pipeline_status = st.session_state.get('pipeline_status', 'not_loaded')
        if pipeline_status == 'loaded':
            st.sidebar.success("✅ AI Pipeline: Ready")
        elif pipeline_status == 'failed':
            st.sidebar.error("❌ AI Pipeline: Failed")
        else:
            st.sidebar.warning("⏳ AI Pipeline: Loading...")
        
        # Traffic synthesizer status
        if traffic_synth and hasattr(traffic_synth, 'normal_traffic_patterns'):
            if traffic_synth.normal_traffic_patterns:
                st.sidebar.success("✅ Traffic Patterns: Loaded")
            else:
                st.sidebar.warning("⚠️ Traffic Patterns: Missing")
        else:
            st.sidebar.error("❌ Traffic Synthesizer: Not Ready")
        
        # Data status
        st.sidebar.info(f"📊 Threats: {len(st.session_state.get('threats_data', []))}")
        st.sidebar.info(f"⚡ Scenarios: {len(st.session_state.get('generated_scenarios', []))}")
        st.sidebar.info(f"📈 Datasets: {len(st.session_state.get('datasets', []))}")
        
        # Performance info
        if st.session_state.get('performance_stats'):
            stats = st.session_state.performance_stats
            success_rate = (stats.get('successful_operations', 0) / max(stats.get('total_operations', 1), 1)) * 100
            st.sidebar.metric("Success Rate", f"{success_rate:.1f}%")
        
        # Route to appropriate page
        if page == "🏠 Home":
            if logger_system:
                logger_system.log_user_action("view_home_page")
            show_home_page()
        elif page == "🔍 Threat Intelligence":
            if logger_system:
                logger_system.log_user_action("view_threat_intelligence")
            show_threat_intelligence_page()
        elif page == "⚡ Attack Generator":
            if logger_system:
                logger_system.log_user_action("view_attack_generator")
            st.header("⚡ Attack Generator")
            st.info("This page is under construction. Use the files in the pages/ directory for full functionality.")
        elif page == "📊 Dataset Creator":
            if logger_system:
                logger_system.log_user_action("view_dataset_creator")
            st.header("📊 Dataset Creator")
            st.info("This page is under construction. Use the files in the pages/ directory for full functionality.")
        elif page == "📈 Analytics":
            if logger_system:
                logger_system.log_user_action("view_analytics")
            st.header("📈 Analytics")
            st.info("This page is under construction. Use the files in the pages/ directory for full functionality.")
        
    except Exception as e:
        logger.error(f"Critical error in main application: {e}")
        logger.error(traceback.format_exc())
        
        if logger_system:
            logger_system.log_error("critical_webapp_error", str(e), {
                "traceback": traceback.format_exc()
            })
        
        st.error("🚨 **Critical Application Error**")
        st.error("The application encountered a critical error and needs to be restarted.")
        
        with st.expander("Error Details"):
            st.code(traceback.format_exc())
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 Restart Application"):
                # Clear session state and restart
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()
        
        with col2:
            if st.button("💾 Save Error Log"):
                error_log = {
                    'timestamp': datetime.now().isoformat(),
                    'error': str(e),
                    'traceback': traceback.format_exc(),
                    'session_state': dict(st.session_state)
                }
                
                try:
                    log_dir = Path("../data/logs")
                    log_dir.mkdir(parents=True, exist_ok=True)
                    with open(log_dir / f"crash_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
                        json.dump(error_log, f, indent=2)
                    st.success("Error log saved")
                except Exception as save_error:
                    st.error(f"Failed to save error log: {save_error}")

if __name__ == "__main__":
    main()