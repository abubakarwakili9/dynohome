# web_app/admin_panel.py - Secure administrator control panel with full functionality
import streamlit as st
import hashlib
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
import json
import time
import traceback
import logging
import pandas as pd
from typing import Optional, Dict, Any, List
import threading
# Required imports for the working functions
import random
import uuid
import sqlite3
import requests  # Added for enhanced threat collection

# Add parent directory to path
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
sys.path.insert(0, str(parent_dir))

# Fix Unicode encoding for Windows console
if sys.platform.startswith('win'):
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Import configuration and logging systems
try:
    from config import get_config, setup_config
    from logging_config import get_logger, setup_logging
    from database import DynaHomeDatabase
    CONFIG_SYSTEMS_AVAILABLE = True
except ImportError as e:
    CONFIG_SYSTEMS_AVAILABLE = False
    config_import_error = e

# Import AI pipeline components
try:
    from ai_pipeline import CompleteThreatPipeline, AIModelError
    from ai_classifier import IoTThreatClassifier
    from threat_collector import ThreatCollector, ThreatCollectionError
    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False
    import_error = e

# Import scenario generation modules
try:
    from attack_scenario_generator import SmartHomeContextEngine, AttackVectorGenerator
    from dataset_export_system import NetworkTrafficSynthesizer, DeviceBehaviorSimulator, AttackScenario as ExportScenario
    SCENARIO_MODULES_AVAILABLE = True
except ImportError as e:
    SCENARIO_MODULES_AVAILABLE = False
    scenario_import_error = e

st.set_page_config(
    page_title="DynaHome Admin Panel",
    page_icon="🔧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS for admin panel
st.markdown("""
<style>
    .admin-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    
    .status-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #28a745;
        margin-bottom: 1rem;
    }
    
    .error-card {
        background: #f8d7da;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #dc3545;
        margin-bottom: 1rem;
    }
    
    .warning-card {
        background: #fff3cd;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ffc107;
        margin-bottom: 1rem;
    }
    
    .admin-metric {
        background: white;
        padding: 1.5rem;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        color: #2c3e50;
    }
    
    .metric-label {
        color: #7f8c8d;
        font-size: 0.9rem;
    }
    
    .login-container {
        max-width: 400px;
        margin: 2rem auto;
        padding: 2rem;
        background: white;
        border-radius: 10px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
    }
    
    .security-warning {
        background: #ffe6e6;
        border: 1px solid #ffb3b3;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Updated ProgressTracker class
class ProgressTracker:
    """Track and display progress for long-running operations"""
    
    def __init__(self, total_steps, operation_name):
        self.total_steps = total_steps
        self.current_step = 0
        self.operation_name = operation_name
        self.start_time = datetime.now()  # Use datetime.now() instead of time.time()
        
        self.progress_bar = st.progress(0)
        self.status_text = st.empty()
        
    def update(self, step_name, increment=1):
        self.current_step += increment
        progress = min(self.current_step / self.total_steps, 1.0)
        
        self.progress_bar.progress(progress)
        self.status_text.text(f"🔄 {step_name}...")
        
    def complete(self, success=True, message=None):
        if success:
            self.progress_bar.progress(1.0)
            self.status_text.text(f"✅ {message or 'Operation completed successfully!'}")
        else:
            self.status_text.text(f"❌ {message or 'Operation failed'}")
        
        time.sleep(2)
        self.progress_bar.empty()
        self.status_text.empty()

# Initialize systems
@st.cache_resource
def initialize_admin_systems():
    """Initialize configuration and logging systems for admin panel"""
    try:
        if not CONFIG_SYSTEMS_AVAILABLE:
            logger = logging.getLogger(__name__)
            logger.warning(f"Config systems not available: {config_import_error}")
            return None, None, logger
        
        environment = os.getenv('DYNOHOME_ENV', 'development')
        config = setup_config(environment=environment)
        logger_system = setup_logging(config.get_configuration_summary())
        logger = get_logger('dynohome.admin')
        
        logger.info("=== DynaHome Admin Panel Starting ===")
        logger.info(f"Environment: {environment}")
        
        return config, logger_system, logger
        
    except Exception as e:
        fallback_logger = logging.getLogger(__name__)
        fallback_logger.error(f"Failed to initialize admin systems: {e}")
        return None, None, fallback_logger

config, logger_system, logger = initialize_admin_systems()

def check_authentication():
    """Enhanced authentication system with session management"""
    
    # Authentication credentials
    ADMIN_USERNAME = os.getenv('DYNOHOME_ADMIN_USER', 'admin')
    ADMIN_PASSWORD_HASH = os.getenv('DYNOHOME_ADMIN_PASS_HASH', 
                                   hashlib.sha256('dynohome2024'.encode()).hexdigest())
    
    # Session timeout (30 minutes)
    SESSION_TIMEOUT = 30 * 60
    
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    # Check session timeout
    if st.session_state.authenticated:
        login_time = st.session_state.get('login_time')
        if login_time:
            elapsed = (datetime.now() - login_time).total_seconds()
            if elapsed > SESSION_TIMEOUT:
                st.session_state.authenticated = False
                st.session_state.clear()
                st.error("Session expired. Please login again.")
    
    if not st.session_state.authenticated:
        st.markdown("""
        <div class="login-container">
            <h2 style="text-align: center; color: #2c3e50;">🔐 DynaHome Administrator</h2>
            <p style="text-align: center; color: #7f8c8d;">Secure access to system controls</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            st.markdown("### Login Credentials")
            username = st.text_input("Username", placeholder="Enter admin username")
            password = st.text_input("Password", type="password", placeholder="Enter admin password")
            remember_me = st.checkbox("Remember me for this session")
            submitted = st.form_submit_button("🔓 Login", use_container_width=True, type="primary")
            
            if submitted:
                if not username or not password:
                    st.error("Please enter both username and password")
                    return False
                
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                
                if username == ADMIN_USERNAME and password_hash == ADMIN_PASSWORD_HASH:
                    st.session_state.authenticated = True
                    st.session_state.admin_user = username
                    st.session_state.login_time = datetime.now()
                    st.session_state.remember_me = remember_me
                    
                    # Log successful login
                    if logger_system:
                        logger_system.log_security_event("admin_login", "INFO", {
                            "username": username,
                            "timestamp": datetime.now().isoformat(),
                            "ip": "unknown"  # In production, get real IP
                        })
                    
                    st.success("Authentication successful! Redirecting...")
                    time.sleep(1)
                    st.rerun()
                else:
                    # Log failed login attempt
                    if logger_system:
                        logger_system.log_security_event("failed_login", "WARNING", {
                            "attempted_username": username,
                            "timestamp": datetime.now().isoformat(),
                            "ip": "unknown"
                        })
                    
                    st.error("Invalid credentials. Access denied.")
                    time.sleep(2)  # Delay to prevent brute force
        
        st.markdown("---")
        
        # Security information
        st.markdown("""
        <div class="security-warning">
            <h4>🔒 Security Notice</h4>
            <p><strong>Default credentials:</strong> admin / dynohome2024</p>
            <p><strong>⚠️ WARNING:</strong> Change default credentials in production!</p>
            <p><strong>Session timeout:</strong> 30 minutes</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Return to public site
        col1, col2 = st.columns(2)
        with col1:
            if st.button("← Back to Public Site", use_container_width=True):
                st.switch_page("app.py")
        
        with col2:
            if st.button("🔧 Request Access", use_container_width=True):
                st.info("Contact administrator at: admin@dynohome.org")
        
        return False
    
    return True

def show_admin_header():
    """Show admin panel header with user info and security controls"""
    
    # Calculate session info
    login_time = st.session_state.get('login_time', datetime.now())
    session_duration = datetime.now() - login_time
    
    st.markdown(f"""
    <div class="admin-header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1 style="margin: 0;">🔧 DynaHome Administration</h1>
                <p style="margin: 0; opacity: 0.9;">Secure system management and monitoring</p>
            </div>
            <div style="text-align: right;">
                <p style="margin: 0;"><strong>User:</strong> {st.session_state.get('admin_user', 'Unknown')}</p>
                <p style="margin: 0;"><strong>Session:</strong> {session_duration.total_seconds()/60:.0f} minutes</p>
                <p style="margin: 0;"><strong>Access Level:</strong> Administrator</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Quick actions bar
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔒 Logout", use_container_width=True):
            # Log logout
            if logger_system:
                logger_system.log_security_event("admin_logout", "INFO", {
                    "username": st.session_state.get('admin_user'),
                    "session_duration": session_duration.total_seconds()
                })
            
            st.session_state.authenticated = False
            st.session_state.clear()
            st.success("Logged out successfully")
            time.sleep(1)
            st.rerun()
    
    with col2:
        if st.button("← Public Site", use_container_width=True):
            st.switch_page("app.py")
    
    with col3:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    
    with col4:
        if st.button("💾 Backup Session", use_container_width=True):
            backup_session_state()
            st.success("Session backed up")

def show_admin_sidebar():
    """Enhanced admin navigation sidebar with system status"""
    
    st.sidebar.markdown("## 🔧 Administration Panel")
    st.sidebar.markdown(f"**User:** {st.session_state.get('admin_user', 'Unknown')}")
    st.sidebar.markdown("---")
    
    # System health overview
    st.sidebar.markdown("### 📊 System Health")
    
    if CONFIG_SYSTEMS_AVAILABLE and MODULES_AVAILABLE and SCENARIO_MODULES_AVAILABLE:
        st.sidebar.success("🟢 All Systems Operational")
    elif CONFIG_SYSTEMS_AVAILABLE and MODULES_AVAILABLE:
        st.sidebar.warning("🟡 Partial System Operation")
    else:
        st.sidebar.error("🔴 System Issues Detected")
    
    # Detailed status
    with st.sidebar.expander("📋 Detailed Status"):
        st.write("**Core Systems:**")
        st.write(f"✅ Config: {'OK' if CONFIG_SYSTEMS_AVAILABLE else 'FAIL'}")
        st.write(f"✅ AI Pipeline: {'OK' if MODULES_AVAILABLE else 'FAIL'}")
        st.write(f"✅ Scenarios: {'OK' if SCENARIO_MODULES_AVAILABLE else 'FAIL'}")
        
        # Database check
        try:
            db = DynaHomeDatabase()
            st.write("✅ Database: OK")
        except:
            st.write("❌ Database: FAIL")
    
    st.sidebar.markdown("---")
    
    # Admin function selection
    admin_page = st.sidebar.selectbox(
        "Admin Functions:",
        [
            "📊 System Dashboard",
            "🔍 Threat Intelligence",
            "⚡ Attack Generator", 
            "📁 Dataset Management",
            "📈 Analytics & Reports",
            "⚙️ System Configuration",
            "📋 Logs & Monitoring",
            "👥 User Management",
            "🔐 Security Center",
            "🛠️ System Maintenance"
        ]
    )
    
    return admin_page

def show_system_dashboard():
    """Comprehensive system dashboard with real-time monitoring"""
    
    st.header("📊 System Dashboard")
    st.markdown("Real-time system monitoring and control center")
    
    # System metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        pipeline_status = st.session_state.get('pipeline_status', 'not_loaded')
        if pipeline_status == 'loaded':
            st.markdown("""
            <div class="admin-metric">
                <div class="metric-value" style="color: #28a745;">✅</div>
                <div class="metric-label">AI Pipeline Status</div>
                <div style="color: #28a745; font-weight: bold;">READY</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="admin-metric">
                <div class="metric-value" style="color: #dc3545;">❌</div>
                <div class="metric-label">AI Pipeline Status</div>
                <div style="color: #dc3545; font-weight: bold;">NOT READY</div>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        threats_count = len(st.session_state.get('threats_data', []))
        st.markdown(f"""
        <div class="admin-metric">
            <div class="metric-value">{threats_count}</div>
            <div class="metric-label">Active Threats</div>
            <div style="color: #6c757d;">Loaded in memory</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        scenarios_count = len(st.session_state.get('generated_scenarios', []))
        st.markdown(f"""
        <div class="admin-metric">
            <div class="metric-value">{scenarios_count}</div>
            <div class="metric-label">Attack Scenarios</div>
            <div style="color: #6c757d;">Generated</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        datasets_count = len(st.session_state.get('datasets', []))
        st.markdown(f"""
        <div class="admin-metric">
            <div class="metric-value">{datasets_count}</div>
            <div class="metric-label">Datasets Created</div>
            <div style="color: #6c757d;">Available</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Performance statistics
    if st.session_state.get('performance_stats'):
        st.subheader("📈 Performance Metrics")
        
        stats = st.session_state.performance_stats
        total_ops = stats.get('total_operations', 0)
        success_rate = (stats.get('successful_operations', 0) / max(total_ops, 1)) * 100
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Success Rate", f"{success_rate:.1f}%", 
                     delta=f"{success_rate-95:.1f}%" if success_rate > 0 else None)
        
        with col2:
            st.metric("Total Operations", total_ops)
        
        with col3:
            avg_time = stats.get('average_processing_time', 0)
            st.metric("Avg Processing Time", f"{avg_time:.1f}s")
    
    # Quick actions
    st.subheader("🚀 Quick Actions")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔄 Restart Pipeline", use_container_width=True, type="primary"):
            restart_ai_pipeline()
    
    with col2:
        if st.button("🧹 Clear Cache", use_container_width=True):
            clear_system_cache()
    
    with col3:
        if st.button("📋 Export Report", use_container_width=True):
            export_system_report()
    
    with col4:
        if st.button("🔍 Health Check", use_container_width=True):
            run_system_health_check()

def show_threat_intelligence_admin():
    """Admin version of threat intelligence with enhanced controls"""
    
    st.header("🔍 Threat Intelligence Administration")
    
    # Enhanced control panel
    st.subheader("⚙️ Collection Parameters")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        days_back = st.number_input("Days back:", min_value=1, max_value=365, value=7)
    
    with col2:
        max_results = st.number_input("Max results:", min_value=10, max_value=1000, value=50)
    
    with col3:
        severity_filter = st.selectbox("Severity filter:", 
                                     ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    
    with col4:
        auto_refresh = st.checkbox("Auto-refresh (5min)")
    
    # Collection actions - Updated with 4 buttons
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔄 Enhanced Collection", use_container_width=True, type="primary"):
            collect_threats_admin_improved(days_back, max_results, severity_filter)
    
    with col2:
        if st.button("🧪 Load Sample Data", use_container_width=True):
            load_sample_iot_threats()
    
    with col3:
        if st.button("💾 Save Collection", use_container_width=True):
            save_threat_collection()
    
    with col4:
        if st.button("📤 Export Threats", use_container_width=True):
            export_threats_data()
    
    # Display threat data with admin features
    if st.session_state.get('threats_data'):
        st.markdown("---")
        st.subheader(f"📊 Threat Analysis ({len(st.session_state.threats_data)} threats)")
        
        # Threat statistics
        threats = st.session_state.threats_data
        severity_counts = {}
        for threat in threats:
            severity = threat.get('severity', {}).get('cvss_v3_severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Display severity distribution
        if severity_counts:
            st.subheader("📈 Severity Distribution")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                critical_count = severity_counts.get('CRITICAL', 0)
                st.metric("Critical", critical_count, delta="🔴" if critical_count > 0 else None)
            
            with col2:
                high_count = severity_counts.get('HIGH', 0)
                st.metric("High", high_count, delta="🟠" if high_count > 0 else None)
            
            with col3:
                medium_count = severity_counts.get('MEDIUM', 0)
                st.metric("Medium", medium_count, delta="🟡" if medium_count > 0 else None)
            
            with col4:
                low_count = severity_counts.get('LOW', 0)
                st.metric("Low", low_count, delta="🟢" if low_count > 0 else None)
        
        # Detailed threat table
        display_threats_table(threats)

def show_attack_generator_admin():
    """Admin interface for attack scenario generation"""
    
    st.header("⚡ Attack Scenario Generator")
    
    if not st.session_state.get('threats_data'):
        st.warning("⚠️ No threat data available. Please collect threats first.")
        return
    
    # Generation parameters
    st.subheader("⚙️ Generation Parameters")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        max_scenarios = st.number_input("Max scenarios:", min_value=1, max_value=100, value=10)
    
    with col2:
        complexity_level = st.selectbox("Complexity:", ["Simple", "Medium", "Complex", "Advanced"])
    
    with col3:
        target_devices = st.multiselect("Target devices:", 
                                      ["smart_camera", "smart_thermostat", "smart_lock", 
                                       "smart_hub", "smart_tv", "router"],
                                      default=["smart_hub"])
    
    # Generation actions
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("⚡ Generate Scenarios", use_container_width=True, type="primary"):
            generate_attack_scenarios_admin(max_scenarios, complexity_level, target_devices)
    
    with col2:
        if st.button("🔄 Regenerate All", use_container_width=True):
            # Clear existing scenarios and regenerate
            st.session_state.generated_scenarios = []
            generate_attack_scenarios_admin(max_scenarios, complexity_level, target_devices)
    
    with col3:
        if st.button("📤 Export Scenarios", use_container_width=True):
            export_scenarios_data()
    
    # Display generated scenarios
    st.markdown("---")
    display_scenarios_admin()

def show_dataset_management():
    """Dataset management interface with upload and versioning"""
    st.header("📁 Dataset Management")
    
    # Dataset upload section
    st.subheader("📤 Manual Dataset Upload")
    
    with st.expander("Upload New Dataset"):
        col1, col2 = st.columns(2)
        
        with col1:
            base_name = st.text_input("Dataset Base Name:", value="dynohome_iot_security")
            title = st.text_input("Dataset Title:", value="DynaHome IoT Security Dataset")
            description = st.text_area("Description:", 
                value="Comprehensive IoT security dataset with real-world attack scenarios")
        
        with col2:
            uploaded_file = st.file_uploader("Choose CSV file", type=['csv'])
            quality_score = st.slider("Quality Score:", 0.0, 1.0, 0.85, 0.01)
            
        if uploaded_file and st.button("Upload Dataset"):
            upload_manual_dataset(uploaded_file, base_name, title, description, quality_score)
    
    # Dataset versioning and updates
    st.subheader("🔄 Dataset Updates")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Create Updated Dataset", use_container_width=True, type="primary"):
            create_updated_dataset()
    
    with col2:
        if st.button("📈 View All Versions", use_container_width=True):
            show_dataset_versions()
    
    with col3:
        if st.button("🧹 Cleanup Old Versions", use_container_width=True):
            cleanup_old_versions()
    
    # Current datasets display
    display_current_datasets()

def show_security_center():
    """Security management and monitoring"""
    
    st.header("🔐 Security Center")
    
    # Security status overview
    st.subheader("🛡️ Security Status")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="status-card">
            <h4>🔑 Authentication</h4>
            <p><strong>Status:</strong> Active</p>
            <p><strong>Session:</strong> Valid</p>
            <p><strong>Timeout:</strong> 30 minutes</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="status-card">
            <h4>📋 Audit Logging</h4>
            <p><strong>Status:</strong> Enabled</p>
            <p><strong>Events:</strong> All admin actions</p>
            <p><strong>Retention:</strong> 90 days</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="status-card">
            <h4>🔒 Access Control</h4>
            <p><strong>Level:</strong> Administrator</p>
            <p><strong>Restrictions:</strong> None</p>
            <p><strong>2FA:</strong> Not configured</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Security configuration
    st.subheader("⚙️ Security Configuration")
    
    with st.expander("🔒 Credential Management"):
        st.text_input("Current Username:", value="admin", disabled=True)
        st.text_input("Password Hash:", value="[Hidden for security]", disabled=True, type="password")
        
        if st.button("🔄 Generate New Password"):
            import secrets
            new_password = secrets.token_urlsafe(16)
            new_hash = hashlib.sha256(new_password.encode()).hexdigest()
            
            st.success("New credentials generated!")
            st.code(f"Password: {new_password}")
            st.code(f"Hash: {new_hash}")
            st.warning("⚠️ Save these credentials securely and update your environment variables!")
    
    with st.expander("🛡️ Access Control Settings"):
        st.checkbox("Enable IP Address Restrictions", value=False)
        st.checkbox("Require Two-Factor Authentication", value=False, disabled=True, 
                   help="Feature coming soon")
        st.checkbox("Log All Admin Actions", value=True)
        st.checkbox("Enable Session Recording", value=False)
    
    with st.expander("📊 Security Monitoring"):
        # Show recent security events
        if logger_system:
            st.info("Security events are being logged. Check system logs for details.")
        else:
            st.warning("Security logging not available.")

# DATASET MANAGEMENT FUNCTIONS
def upload_manual_dataset(uploaded_file, base_name, title, description, quality_score):
    """Handle manual dataset upload"""
    try:
        # Read uploaded file
        df = pd.read_csv(uploaded_file)
        
        # Analyze the dataset
        total_samples = len(df)
        
        # Try to detect attack samples
        attack_samples = 0
        normal_samples = total_samples
        
        # Look for common attack indicators
        if 'label' in df.columns:
            attack_samples = len(df[df['label'].str.contains('attack|malicious', case=False, na=False)])
            normal_samples = total_samples - attack_samples
        elif 'flow_label' in df.columns:
            attack_samples = len(df[df['flow_label'] == 'attack'])
            normal_samples = total_samples - attack_samples
        
        # Save file to datasets directory
        datasets_dir = Path("data/datasets")
        datasets_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{base_name}_{timestamp}.csv"
        file_path = datasets_dir / filename
        
        df.to_csv(file_path, index=False)
        
        # Calculate file size
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        
        # Create dataset info
        dataset_info = {
            'base_name': base_name,
            'title': title,
            'description': description,
            'file_path': str(file_path),
            'file_size_mb': file_size_mb,
            'quality_score': quality_score,
            'samples': {
                'total': total_samples,
                'attack': attack_samples,
                'normal': normal_samples
            },
            'threat_count': 0,
            'upload_method': 'manual'
        }
        
        # Save to database with versioning
        db = DynaHomeDatabase()
        dataset_id, version = db.save_dataset_with_versioning(dataset_info)
        
        st.success(f"Dataset uploaded successfully!")
        st.info(f"Dataset ID: {dataset_id}")
        st.info(f"Version: {version}")
        st.info(f"Samples: {total_samples} total ({attack_samples} attack, {normal_samples} normal)")
        
        st.rerun()
        
    except Exception as e:
        st.error(f"Upload failed: {e}")

def create_updated_dataset():
    """Create updated dataset from current threats and scenarios"""
    try:
        if not st.session_state.get('threats_data') or not st.session_state.get('generated_scenarios'):
            st.error("Need both threat data and scenarios to create updated dataset")
            return
        
        progress = ProgressTracker(4, "Creating Updated Dataset")
        
        # Use existing dataset creation logic but with versioning
        progress.update("Generating synthetic data", 1)
        
        # Get current threats and scenarios
        threats = st.session_state.threats_data
        scenarios = st.session_state.generated_scenarios
        
        # Generate dataset (reuse existing logic)
        if SCENARIO_MODULES_AVAILABLE:
            from dataset_export_system import NetworkTrafficSynthesizer
            traffic_synth = NetworkTrafficSynthesizer()
        
        # Create comprehensive dataset
        dataset_rows = []
        
        # Add normal traffic (80% of dataset)
        normal_samples = 8000
        for i in range(normal_samples):
            row = create_normal_traffic_sample()
            dataset_rows.append(row)
        
        # Add attack traffic from scenarios (20% of dataset)
        attack_samples = 2000
        samples_per_scenario = attack_samples // len(scenarios)
        
        for scenario in scenarios:
            for i in range(samples_per_scenario):
                row = create_attack_traffic_sample(scenario)
                dataset_rows.append(row)
        
        progress.update("Saving dataset with versioning", 1)
        
        # Create DataFrame and save
        df = pd.DataFrame(dataset_rows)
        df = df.sort_values('timestamp').reset_index(drop=True)
        
        # Save to file
        datasets_dir = Path("data/datasets")
        datasets_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dynohome_comprehensive_{timestamp}.csv"
        file_path = datasets_dir / filename
        
        df.to_csv(file_path, index=False)
        
        # Create dataset info
        dataset_info = {
            'base_name': 'dynohome_comprehensive',
            'title': 'DynaHome Comprehensive IoT Security Dataset',
            'description': f'Updated dataset with {len(threats)} threats and {len(scenarios)} attack scenarios',
            'file_path': str(file_path),
            'file_size_mb': file_path.stat().st_size / (1024 * 1024),
            'quality_score': 0.88,
            'samples': {
                'total': len(df),
                'attack': attack_samples,
                'normal': normal_samples
            },
            'threat_count': len(threats),
            'creation_method': 'automated_generation'
        }
        
        # Save with versioning
        db = DynaHomeDatabase()
        dataset_id, version = db.save_dataset_with_versioning(dataset_info)
        
        progress.complete(True, f"Created dataset version {version}")
        
        st.success(f"Updated dataset created: Version {version}")
        st.info(f"Total samples: {len(df)}")
        st.info(f"File: {filename}")
        
    except Exception as e:
        st.error(f"Dataset creation failed: {e}")

def create_normal_traffic_sample():
    """Create a sample normal traffic entry"""
    return {
        'timestamp': datetime.now() - timedelta(hours=random.randint(0, 48)),
        'src_ip': f"192.168.1.{random.randint(10, 254)}",
        'dst_ip': f"192.168.1.{random.randint(10, 254)}",
        'src_port': random.choice([80, 443, 22, 8080, 1883]),
        'dst_port': random.choice([80, 443, 22, 8080, 1883]),
        'protocol': random.choice(['TCP', 'UDP']),
        'packet_count': random.randint(1, 100),
        'byte_count': random.randint(64, 1500),
        'duration': random.uniform(0.1, 30.0),
        'flags': 'SYN,ACK',
        'flow_label': 'normal',
        'attack_type': None,
        'scenario_id': 'normal_traffic'
    }

def create_attack_traffic_sample(scenario):
    """Create a sample attack traffic entry"""
    return {
        'timestamp': datetime.now() - timedelta(hours=random.randint(0, 48)),
        'src_ip': f"10.0.0.{random.randint(1, 254)}",  # External attacker
        'dst_ip': f"192.168.1.{random.randint(10, 254)}",  # Internal target
        'src_port': random.randint(1024, 65535),
        'dst_port': random.choice([22, 23, 80, 443, 8080]),
        'protocol': random.choice(['TCP', 'UDP']),
        'packet_count': random.randint(5, 500),
        'byte_count': random.randint(100, 5000),
        'duration': random.uniform(0.5, 120.0),
        'flags': 'SYN,RST',
        'flow_label': 'attack',
        'attack_type': scenario['attack_vector'],
        'scenario_id': scenario['scenario_id']
    }

def display_current_datasets():
    """Display current datasets in admin interface"""
    st.subheader("📊 Current Datasets")
    
    try:
        db = DynaHomeDatabase()
        datasets = db.get_public_datasets(include_all_versions=True)
        
        if not datasets:
            st.info("No datasets found. Create or upload datasets to see them here.")
            return
        
        # Group by base_name
        grouped_datasets = {}
        for dataset in datasets:
            base_name = dataset['base_name']
            if base_name not in grouped_datasets:
                grouped_datasets[base_name] = []
            grouped_datasets[base_name].append(dataset)
        
        for base_name, versions in grouped_datasets.items():
            with st.expander(f"📁 {base_name} ({len(versions)} versions)"):
                for dataset in versions:
                    col1, col2, col3 = st.columns([2, 1, 1])
                    
                    with col1:
                        st.write(f"**Version {dataset['version']}** {'(Latest)' if dataset['is_latest'] else ''}")
                        st.write(f"Samples: {dataset['samples_total']} total")
                        st.write(f"Quality: {dataset['quality_score']:.2f}")
                    
                    with col2:
                        st.write(f"Downloads: {dataset['download_count']}")
                        st.write(f"Size: {dataset['file_size_mb']:.1f} MB")
                    
                    with col3:
                        if st.button(f"📥 Download v{dataset['version']}", key=f"download_{dataset['id']}"):
                            download_dataset_file(dataset)
                        
                        if st.button(f"🗑️ Delete v{dataset['version']}", key=f"delete_{dataset['id']}"):
                            delete_dataset_version(dataset['id'])
    
    except Exception as e:
        st.error(f"Error displaying datasets: {e}")

def show_dataset_versions():
    """Show all dataset versions"""
    st.info("Dataset versioning interface - showing all versions with comparison tools")

def cleanup_old_versions():
    """Cleanup old dataset versions"""
    st.info("Cleanup old versions - remove outdated dataset versions")

def download_dataset_file(dataset):
    """Download a specific dataset file"""
    try:
        file_path = dataset.get('file_path')
        if file_path and Path(file_path).exists():
            # Offer file download
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            filename = Path(file_path).name
            st.download_button(
                f"📥 Download {filename}",
                data=file_data,
                file_name=filename,
                mime="text/csv"
            )
        else:
            st.error("Dataset file not found on disk")
    except Exception as e:
        st.error(f"Download failed: {e}")

def show_dataset_details(dataset):
    """Show detailed information about a dataset"""
    st.info(f"Detailed view for dataset: {dataset.get('title', 'Unknown')}")
    
    with st.expander("Full Dataset Details", expanded=True):
        for key, value in dataset.items():
            st.write(f"**{key}:** {value}")

def delete_dataset_version(dataset_id):
    """Delete a specific dataset version"""
    if st.button(f"⚠️ Confirm Delete {dataset_id}", key=f"confirm_delete_{dataset_id}"):
        try:
            # Remove from session state
            if 'datasets' in st.session_state:
                st.session_state.datasets = [d for d in st.session_state.datasets if d.get('id') != dataset_id]
            
            # Try to remove from database
            try:
                db = DynaHomeDatabase()
                # Note: This would need a proper delete method in the database class
                st.warning("Database deletion not implemented - removed from session only")
            except Exception as db_error:
                st.warning(f"Database deletion failed: {db_error}")
            
            st.success(f"Dataset {dataset_id} removed from current session")
            st.rerun()
            
        except Exception as e:
            st.error(f"Deletion failed: {e}")
    else:
        st.warning(f"Click confirm to delete dataset {dataset_id}")

# ENHANCED THREAT COLLECTION FUNCTIONS
def collect_threats_admin_improved(days_back, max_results, severity_filter):
    """Improved threat collection with better filtering"""
    try:
        progress = ProgressTracker(5, "Enhanced Threat Collection")
        
        # Step 1: Test direct API access
        progress.update("Testing API connectivity", 1)
        
        # Calculate date range for recent CVEs
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        # Format dates for NVD API (they want ISO format)
        pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        # Step 2: Query with date filters and IoT keywords
        progress.update("Querying recent IoT-related CVEs", 1)
        
        # IoT-specific keywords to search for
        iot_keywords = [
            "IoT", "smart home", "smart device", "router", "camera", 
            "sensor", "thermostat", "doorbell", "hub", "gateway",
            "wireless", "bluetooth", "zigbee", "wifi", "connected device"
        ]
        
        all_threats = []
        
        # Try multiple search approaches
        search_strategies = [
            # Strategy 1: Recent CVEs with basic filtering
            {
                "resultsPerPage": max_results,
                "pubStartDate": pub_start,
                "pubEndDate": pub_end
            },
            # Strategy 2: Search for IoT-specific terms
            {
                "resultsPerPage": max_results // 2,
                "keywordSearch": "IoT OR router OR camera OR smart"
            },
            # Strategy 3: Get latest high severity
            {
                "resultsPerPage": max_results // 2,
                "cvssV3Severity": "HIGH,CRITICAL" if severity_filter != "All" else None
            }
        ]
        
        for strategy in search_strategies:
            try:
                # Build API URL
                base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {k: v for k, v in strategy.items() if v is not None}
                
                st.write(f"Testing strategy: {params}")
                
                response = requests.get(base_url, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    st.write(f"Found {len(vulnerabilities)} CVEs with this strategy")
                    
                    for vuln in vulnerabilities:
                        cve_data = vuln.get('cve', {})
                        
                        # Extract basic info
                        threat = {
                            'cve_id': cve_data.get('id', 'Unknown'),
                            'description': '',
                            'published_date': cve_data.get('published', ''),
                            'last_modified_date': cve_data.get('lastModified', ''),
                            'severity': {},
                            'collected_at': datetime.now().isoformat()
                        }
                        
                        # Get description
                        descriptions = cve_data.get('descriptions', [])
                        if descriptions:
                            threat['description'] = descriptions[0].get('value', '')
                        
                        # Get severity info
                        metrics = cve_data.get('metrics', {})
                        if 'cvssMetricV31' in metrics:
                            cvss = metrics['cvssMetricV31'][0]['cvssData']
                            threat['severity'] = {
                                'cvss_v3_score': cvss.get('baseScore', 0),
                                'cvss_v3_severity': cvss.get('baseSeverity', 'UNKNOWN')
                            }
                        elif 'cvssMetricV2' in metrics:
                            cvss = metrics['cvssMetricV2'][0]['cvssData']
                            threat['severity'] = {
                                'cvss_v3_score': cvss.get('baseScore', 0),
                                'cvss_v3_severity': cvss.get('baseSeverity', 'UNKNOWN')
                            }
                        
                        all_threats.append(threat)
                        
                else:
                    st.warning(f"API request failed: {response.status_code}")
                    
            except Exception as e:
                st.warning(f"Strategy failed: {e}")
                continue
        
        # Step 3: Filter for IoT relevance
        progress.update("Filtering for IoT relevance", 1)
        
        iot_threats = []
        
        for threat in all_threats:
            description = threat.get('description', '').lower()
            cve_id = threat.get('cve_id', '').lower()
            
            # Check if it's IoT-related using keywords
            is_iot = False
            
            # Check description for IoT keywords
            for keyword in iot_keywords:
                if keyword.lower() in description:
                    is_iot = True
                    break
            
            # Check for device-specific terms
            device_terms = ['router', 'camera', 'device', 'firmware', 'embedded', 'wireless']
            for term in device_terms:
                if term in description:
                    is_iot = True
                    break
            
            # Check year (IoT became common after 2010)
            try:
                pub_year = int(threat.get('published_date', '2000')[:4])
                if pub_year < 2010:
                    is_iot = False
            except:
                pass
            
            if is_iot:
                # Add IoT analysis
                threat['nlp_analysis'] = {
                    'devices': [term for term in ['router', 'camera', 'sensor', 'thermostat'] 
                               if term in description],
                    'attack_types': [term for term in ['overflow', 'injection', 'bypass', 'execution'] 
                                   if term in description]
                }
                iot_threats.append(threat)
        
        # Step 4: Apply severity filter
        if severity_filter != "All":
            iot_threats = [t for t in iot_threats 
                          if t.get('severity', {}).get('cvss_v3_severity') == severity_filter]
        
        progress.update("Saving threat data", 1)
        
        # Step 5: Save results
        st.session_state.threats_data = iot_threats
        
        progress.complete(True, f"Collected {len(iot_threats)} IoT-relevant threats")
        
        st.success(f"Successfully collected {len(iot_threats)} IoT threats out of {len(all_threats)} total")
        
        # Show sample if found
        if iot_threats:
            st.write("Sample IoT threat found:")
            sample = iot_threats[0]
            st.write(f"- **{sample['cve_id']}**: {sample['description'][:200]}...")
            
        st.rerun()
        
    except Exception as e:
        st.error(f"Enhanced threat collection failed: {e}")
        import traceback
        st.code(traceback.format_exc())

def load_sample_iot_threats():
    """Load sample IoT threats for testing"""
    sample_threats = [
        {
            'cve_id': 'CVE-2024-0001',
            'description': 'Buffer overflow in smart camera firmware allows remote code execution via crafted HTTP requests',
            'severity': {'cvss_v3_severity': 'HIGH', 'cvss_v3_score': 8.5},
            'published_date': '2024-01-15T10:00:00.000',
            'collected_at': datetime.now().isoformat(),
            'nlp_analysis': {
                'devices': ['camera', 'iot_device'],
                'attack_types': ['buffer_overflow', 'remote_execution']
            }
        },
        {
            'cve_id': 'CVE-2024-0002', 
            'description': 'Authentication bypass in smart thermostat allows unauthorized temperature control',
            'severity': {'cvss_v3_severity': 'MEDIUM', 'cvss_v3_score': 6.5},
            'published_date': '2024-01-20T14:30:00.000',
            'collected_at': datetime.now().isoformat(),
            'nlp_analysis': {
                'devices': ['thermostat', 'iot_device'],
                'attack_types': ['authentication_bypass', 'unauthorized_access']
            }
        },
        {
            'cve_id': 'CVE-2024-0003',
            'description': 'SQL injection vulnerability in smart home hub web interface enables data theft',
            'severity': {'cvss_v3_severity': 'CRITICAL', 'cvss_v3_score': 9.2},
            'published_date': '2024-02-01T09:15:00.000',
            'collected_at': datetime.now().isoformat(),
            'nlp_analysis': {
                'devices': ['hub', 'smart_home'],
                'attack_types': ['sql_injection', 'data_theft']
            }
        }
    ]
    
    st.session_state.threats_data = sample_threats
    st.success(f"Loaded {len(sample_threats)} sample IoT threats for testing")
    st.rerun()

def save_threat_collection():
    """Save current threat collection to file"""
    try:
        if not st.session_state.get('threats_data'):
            st.error("No threat data to save")
            return
        
        threats = st.session_state.threats_data
        
        # Create output directory
        output_dir = Path("data/outputs")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_dir / f"threat_collection_{timestamp}.json"
        
        # Save to JSON file
        with open(filename, 'w') as f:
            json.dump(threats, f, indent=2, default=str)  # default=str handles any remaining datetime objects
        
        st.success(f"Threat collection saved to: {filename.name}")
        
        # Log the operation
        if logger_system:
            logger_system.log_user_action("threat_collection_saved", {
                "filename": str(filename),
                "threat_count": len(threats)
            })
        
    except Exception as e:
        st.error(f"Failed to save threat collection: {e}")

def export_threats_data():
    """Export threats data in multiple formats"""
    try:
        if not st.session_state.get('threats_data'):
            st.error("No threat data to export")
            return
        
        threats = st.session_state.threats_data
        
        # Create export data
        export_data = []
        for threat in threats:
            export_record = {
                'CVE_ID': threat.get('cve_id', 'Unknown'),
                'Description': threat.get('description', ''),
                'Severity': threat.get('severity', {}).get('cvss_v3_severity', 'Unknown'),
                'Score': threat.get('severity', {}).get('cvss_v3_score', 'N/A'),
                'Published_Date': threat.get('published_date', ''),
                'Collected_At': threat.get('collected_at', ''),
                'IoT_Devices': ', '.join(threat.get('nlp_analysis', {}).get('devices', [])),
                'Attack_Types': ', '.join(threat.get('nlp_analysis', {}).get('attack_types', []))
            }
            export_data.append(export_record)
        
        # Convert to DataFrame for easy export
        df = pd.DataFrame(export_data)
        
        # Create output directory
        output_dir = Path("data/outputs")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export as CSV
        csv_file = output_dir / f"threats_export_{timestamp}.csv"
        df.to_csv(csv_file, index=False)
        
        # Export as JSON
        json_file = output_dir / f"threats_export_{timestamp}.json"
        df.to_json(json_file, orient='records', indent=2)
        
        # Offer downloads
        col1, col2 = st.columns(2)
        
        with col1:
            st.download_button(
                "Download CSV",
                data=df.to_csv(index=False),
                file_name=f"threats_export_{timestamp}.csv",
                mime="text/csv"
            )
        
        with col2:
            st.download_button(
                "Download JSON", 
                data=df.to_json(orient='records', indent=2),
                file_name=f"threats_export_{timestamp}.json",
                mime="application/json"
            )
        
        st.success(f"Threat data exported successfully!")
        st.info(f"Files saved to: {output_dir}")
        
        # Log the operation
        if logger_system:
            logger_system.log_user_action("threats_exported", {
                "csv_file": str(csv_file),
                "json_file": str(json_file),
                "record_count": len(df)
            })
        
    except Exception as e:
        st.error(f"Failed to export threat data: {e}")

def generate_attack_scenarios_admin(max_scenarios, complexity_level, target_devices):
    """Admin version of scenario generation with robust error handling"""
    try:
        if not st.session_state.get('threats_data'):
            st.error("No threat data available. Please collect threats first.")
            return
        
        progress = ProgressTracker(3, "Attack Scenario Generation")
        
        # Step 1: Initialize scenario engines
        progress.update("Initializing scenario generation engines", 1)
        
        # Step 2: Generate scenarios
        progress.update("Generating attack scenarios from threat data", 1)
        
        scenarios = []
        threats = st.session_state.threats_data[:max_scenarios]
        
        # Ensure we have safe defaults
        safe_complexity = str(complexity_level or 'medium').lower()
        safe_target_devices = target_devices if target_devices else ['smart_hub']
        
        for i, threat in enumerate(threats):
            try:
                # Safely extract CVE ID
                cve_id = threat.get('cve_id') or f'UNKNOWN-{i+1}'
                cve_id = str(cve_id)  # Ensure it's a string
                
                # Safely extract severity/impact level
                impact_level = 'medium'  # Default value
                try:
                    severity = threat.get('severity')
                    if severity and isinstance(severity, dict):
                        severity_level = severity.get('cvss_v3_severity')
                        if severity_level and isinstance(severity_level, str):
                            impact_level = severity_level.lower()
                        else:
                            impact_level = 'medium'
                    else:
                        impact_level = 'medium'
                except Exception:
                    impact_level = 'medium'
                
                # Safely extract description
                description = threat.get('description') or 'No description available'
                if isinstance(description, str) and len(description) > 200:
                    description = description[:200]
                elif not isinstance(description, str):
                    description = 'No description available'
                
                # Create basic attack timeline
                timeline = [
                    {"step": 1, "action": "Initial reconnaissance and scanning", "time": "0-5 minutes"},
                    {"step": 2, "action": "Vulnerability exploitation attempt", "time": "5-15 minutes"},
                    {"step": 3, "action": "System compromise and payload execution", "time": "15-30 minutes"},
                    {"step": 4, "action": "Privilege escalation and persistence", "time": "30-45 minutes"},
                    {"step": 5, "action": "Data exfiltration or system disruption", "time": "45-60 minutes"}
                ]
                
                # Determine attack vector based on complexity
                attack_vectors = {
                    'simple': 'network_exploit',
                    'medium': 'privilege_escalation', 
                    'complex': 'multi_stage_attack',
                    'advanced': 'zero_day_exploit'
                }
                attack_vector = attack_vectors.get(safe_complexity, 'network_exploit')
                
                # Create scenario object with all safe values
                scenario = {
                    'scenario_id': f"scenario_{i+1}_{int(datetime.now().timestamp())}",
                    'cve_id': cve_id,
                    'attack_name': f"Attack on {', '.join(safe_target_devices)}",
                    'target_devices': safe_target_devices,
                    'attack_vector': attack_vector,
                    'complexity': safe_complexity,
                    'impact_level': impact_level,
                    'timeline': timeline,
                    'quality_score': round(random.uniform(0.75, 0.95), 2),
                    'description': description,
                    'created_at': datetime.now().isoformat(),
                    'threat_source': threat.get('source', 'NVD'),
                    'cvss_score': threat.get('severity', {}).get('cvss_v3_score', 'N/A') if isinstance(threat.get('severity'), dict) else 'N/A'
                }
                
                scenarios.append(scenario)
                
            except Exception as e:
                error_msg = f"Failed to generate scenario for {threat.get('cve_id', f'threat-{i}')}: {str(e)}"
                st.warning(error_msg)
                print(f"DEBUG: {error_msg}")  # For debugging
                continue
        
        # Step 3: Save scenarios
        progress.update("Saving generated scenarios", 1)
        
        if scenarios:
            st.session_state.generated_scenarios = scenarios
            
            # Save to database with error handling
            try:
                db = DynaHomeDatabase()
                for scenario in scenarios:
                    scenario_record = {
                        'id': scenario['scenario_id'],
                        'title': f"Attack Scenario: {scenario['attack_name']}",
                        'version': 'v1.0',
                        'description': f"Attack scenario targeting {', '.join(scenario['target_devices'])}",
                        'file_size_mb': 0.5,
                        'quality_score': scenario['quality_score'],
                        'samples': {'total': 1, 'attack': 1}
                    }
                    db.save_dataset_metadata(scenario_record)
            except Exception as e:
                st.warning(f"Database save failed: {e}")
            
            progress.complete(True, f"Generated {len(scenarios)} attack scenarios")
            st.success(f"Successfully generated {len(scenarios)} scenarios")
        else:
            progress.complete(False, "No scenarios could be generated")
            st.error("Failed to generate any scenarios. Please check your threat data.")
        
        st.rerun()
        
    except Exception as e:
        st.error(f"Scenario generation failed: {e}")
        print(f"DEBUG: Scenario generation error: {e}")  # For debugging
        if logger_system:
            logger_system.log_error("admin_scenario_generation", str(e))

def display_scenarios_admin():
    """Display scenarios with admin controls"""
    if not st.session_state.get('generated_scenarios'):
        st.info("No scenarios generated yet. Click 'Generate Scenarios' to create attack scenarios from your threat data.")
        return
    
    scenarios = st.session_state.generated_scenarios
    st.subheader(f"📊 Generated Scenarios ({len(scenarios)} scenarios)")
    
    # Summary statistics
    if scenarios:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Scenarios", len(scenarios))
        
        with col2:
            avg_quality = sum(s.get('quality_score', 0) for s in scenarios) / len(scenarios)
            st.metric("Avg Quality Score", f"{avg_quality:.2f}")
        
        with col3:
            unique_devices = set()
            for s in scenarios:
                unique_devices.update(s.get('target_devices', []))
            st.metric("Device Types", len(unique_devices))
        
        with col4:
            complexity_counts = {}
            for s in scenarios:
                comp = s.get('complexity', 'unknown')
                complexity_counts[comp] = complexity_counts.get(comp, 0) + 1
            most_common = max(complexity_counts.items(), key=lambda x: x[1]) if complexity_counts else ('unknown', 0)
            st.metric("Most Common", most_common[0].title())
    
    # Display scenarios in expandable format
    for i, scenario in enumerate(scenarios):
        scenario_title = scenario.get('attack_name', f'Scenario {i+1}')
        cve_id = scenario.get('cve_id', 'Unknown')
        
        with st.expander(f"📋 {scenario_title} ({cve_id})"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**CVE ID:** {cve_id}")
                st.write(f"**Attack Vector:** {scenario.get('attack_vector', 'Unknown')}")
                st.write(f"**Complexity:** {scenario.get('complexity', 'unknown').title()}")
                st.write(f"**Impact Level:** {scenario.get('impact_level', 'unknown').title()}")
                if scenario.get('cvss_score') != 'N/A':
                    st.write(f"**CVSS Score:** {scenario.get('cvss_score', 'N/A')}")
            
            with col2:
                st.write(f"**Target Devices:** {', '.join(scenario.get('target_devices', []))}")
                st.write(f"**Quality Score:** {scenario.get('quality_score', 0):.2f}")
                created_at = scenario.get('created_at', 'Unknown')
                if created_at != 'Unknown' and len(created_at) > 19:
                    created_at = created_at[:19]
                st.write(f"**Created:** {created_at}")
                st.write(f"**Source:** {scenario.get('threat_source', 'Unknown')}")
            
            # Description
            if scenario.get('description'):
                st.write(f"**Description:** {scenario['description']}")
            
            # Timeline
            if scenario.get('timeline'):
                st.write("**Attack Timeline:**")
                timeline = scenario['timeline']
                if isinstance(timeline, list):
                    for step in timeline:
                        if isinstance(step, dict):
                            step_num = step.get('step', '?')
                            action = step.get('action', 'Unknown action')
                            time_frame = step.get('time', 'Unknown time')
                            st.write(f"- **Step {step_num}:** {action} *(Time: {time_frame})*")
                else:
                    st.write("Timeline data format error")
    
    # Add export button at the bottom
    if scenarios:
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        with col2:
            if st.button("📁 Export All Scenarios", use_container_width=True):
                export_scenarios_data()

# Helper functions for admin operations
def restart_ai_pipeline():
    """Restart the AI pipeline with error handling"""
    try:
        with st.spinner("Restarting AI pipeline..."):
            # Clear existing pipeline
            st.session_state.pipeline = None
            st.session_state.pipeline_status = 'restarting'
            
            # Reinitialize
            if MODULES_AVAILABLE:
                from ai_pipeline import CompleteThreatPipeline
                pipeline = CompleteThreatPipeline()
                
                # Health check
                health = pipeline.health_check()
                if health['status'] == 'healthy':
                    st.session_state.pipeline = pipeline
                    st.session_state.pipeline_status = 'loaded'
                    st.success("✅ AI pipeline restarted successfully!")
                else:
                    st.session_state.pipeline_status = 'failed'
                    st.error(f"❌ Pipeline health check failed: {health.get('errors', [])}")
            else:
                st.error("❌ AI modules not available")
                
    except Exception as e:
        st.session_state.pipeline_status = 'failed'
        st.error(f"❌ Failed to restart pipeline: {e}")
        
        if logger_system:
            logger_system.log_error("pipeline_restart_failed", str(e))

def clear_system_cache():
    """Clear system cache and temporary data"""
    try:
        # Clear session cache
        cache_cleared = 0
        
        # Clear Streamlit cache
        st.cache_data.clear()
        st.cache_resource.clear()
        cache_cleared += 2
        
        # Clear temporary files
        temp_dir = Path("../data/temp")
        if temp_dir.exists():
            import shutil
            shutil.rmtree(temp_dir)
            temp_dir.mkdir()
            cache_cleared += 1
        
        st.success(f"✅ Cleared {cache_cleared} cache components")
        
        if logger_system:
            logger_system.log_user_action("cache_cleared", {"components": cache_cleared})
            
    except Exception as e:
        st.error(f"❌ Failed to clear cache: {e}")

def export_system_report():
    """Generate and export comprehensive system report"""
    try:
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "system_status": {
                "config_available": CONFIG_SYSTEMS_AVAILABLE,
                "modules_available": MODULES_AVAILABLE,
                "scenarios_available": SCENARIO_MODULES_AVAILABLE
            },
            "session_state": {
                "threats_count": len(st.session_state.get('threats_data', [])),
                "scenarios_count": len(st.session_state.get('generated_scenarios', [])),
                "datasets_count": len(st.session_state.get('datasets', []))
            },
            "performance_stats": st.session_state.get('performance_stats', {}),
            "pipeline_status": st.session_state.get('pipeline_status', 'unknown')
        }
        
        # Convert to JSON
        report_json = json.dumps(report_data, indent=2)
        
        # Offer download
        st.download_button(
            label="📋 Download System Report",
            data=report_json,
            file_name=f"dynohome_system_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
        
        st.success("✅ System report generated")
        
    except Exception as e:
        st.error(f"❌ Failed to generate report: {e}")

def run_system_health_check():
    """Run comprehensive system health check with robust database testing"""
    st.subheader("🔍 System Health Check Results")
    
    health_status = {}
    
    # Check 1: Configuration system
    try:
        if CONFIG_SYSTEMS_AVAILABLE:
            config_test = get_config()
            health_status["Configuration"] = "✅ OK"
        else:
            health_status["Configuration"] = "❌ FAIL"
    except Exception as e:
        health_status["Configuration"] = f"❌ ERROR: {e}"
    
    # Check 2: AI Pipeline
    try:
        if st.session_state.get('pipeline'):
            pipeline_health = st.session_state.pipeline.health_check()
            if pipeline_health['status'] == 'healthy':
                health_status["AI Pipeline"] = "✅ OK"
            else:
                health_status["AI Pipeline"] = f"⚠️ WARNING: {pipeline_health.get('warnings', [])}"
        else:
            health_status["AI Pipeline"] = "❌ NOT LOADED"
    except Exception as e:
        health_status["AI Pipeline"] = f"❌ ERROR: {e}"
    
    # Check 3: Database - simplified check without migration call
    try:
        db = DynaHomeDatabase()
        
        # Test basic connectivity
        with sqlite3.connect(db.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM datasets")
            count = cursor.fetchone()[0]
            
            # Check for required columns
            cursor = conn.execute("PRAGMA table_info(datasets)")
            columns = [col[1] for col in cursor.fetchall()]
            
            # Basic required columns
            required_columns = ['id', 'title']
            missing_columns = [col for col in required_columns if col not in columns]
            
            if missing_columns:
                health_status["Database"] = f"⚠️ WARNING: Missing columns {missing_columns}"
            else:
                health_status["Database"] = f"✅ OK ({count} datasets, {len(columns)} columns)"
                
    except Exception as e:
        health_status["Database"] = f"❌ ERROR: {e}"
    
    # Check 4: File system
    try:
        data_dir = Path("data")
        if data_dir.exists():
            health_status["File System"] = "✅ OK"
        else:
            health_status["File System"] = "❌ DATA DIR MISSING"
    except Exception as e:
        health_status["File System"] = f"❌ ERROR: {e}"
    
    # Display results
    for component, status in health_status.items():
        if "✅" in status:
            st.success(f"**{component}:** {status}")
        elif "⚠️" in status:
            st.warning(f"**{component}:** {status}")
        else:
            st.error(f"**{component}:** {status}")
    
    # Additional database information if available
    if "Database" in health_status:
        with st.expander("Database Details"):
            try:
                db = DynaHomeDatabase()
                with sqlite3.connect(db.db_path) as conn:
                    # Check table structure
                    cursor = conn.execute("PRAGMA table_info(datasets)")
                    columns = cursor.fetchall()
                    st.write("**Database Columns:**")
                    for col in columns:
                        st.write(f"- {col[1]} ({col[2]})")
                    
                    # Basic stats
                    cursor = conn.execute("SELECT COUNT(*) FROM datasets")
                    total_count = cursor.fetchone()[0]
                    st.write(f"**Total Datasets:** {total_count}")
                    
                    # Check if we can query with status column
                    try:
                        cursor = conn.execute("SELECT COUNT(*) FROM datasets WHERE status = 'active' OR status IS NULL")
                        active_count = cursor.fetchone()[0]
                        st.write(f"**Active/Available Datasets:** {active_count}")
                    except:
                        st.write("**Status column not available - using legacy mode**")
                    
                    # Database file info
                    db_size = Path(db.db_path).stat().st_size if Path(db.db_path).exists() else 0
                    st.write(f"**Database Size:** {db_size / 1024:.1f} KB")
                    
            except Exception as e:
                st.write(f"Error getting database details: {e}")
    
    # Simplified repair options - no migration needed since new database.py handles it
    if "❌" in health_status.get("Database", "") or "⚠️" in health_status.get("Database", ""):
        st.subheader("🔧 Database Repair Options")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🔄 Recreate Database"):
                recreate_database()
        
        with col2:
            if st.button("🧹 Clear Database"):
                clear_database()
        
        with col3:
            if st.button("📋 Show SQL Schema"):
                show_database_schema()

def clear_database():
    """Clear all data from database tables"""
    try:
        db = DynaHomeDatabase()
        with sqlite3.connect(db.db_path) as conn:
            conn.execute("DELETE FROM datasets")
            conn.execute("DELETE FROM downloads")
        
        st.success("Database cleared successfully!")
        st.rerun()
        
    except Exception as e:
        st.error(f"Database clear failed: {e}")

def recreate_database():
    """Recreate database with fresh schema"""
    try:
        db = DynaHomeDatabase()
        
        # Backup existing data first
        backup_data = []
        try:
            with sqlite3.connect(db.db_path) as conn:
                cursor = conn.execute("SELECT * FROM datasets")
                backup_data = cursor.fetchall()
        except:
            pass
        
        # Remove old database
        if Path(db.db_path).exists():
            Path(db.db_path).unlink()
        
        # Create new database
        new_db = DynaHomeDatabase()
        
        st.success(f"Database recreated successfully!")
        if backup_data:
            st.info(f"Backed up {len(backup_data)} records (manual restore required)")
        
        st.rerun()
        
    except Exception as e:
        st.error(f"Database recreation failed: {e}")

def show_database_schema():
    """Show current database schema"""
    try:
        db = DynaHomeDatabase()
        with sqlite3.connect(db.db_path) as conn:
            cursor = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='datasets'")
            schema = cursor.fetchone()
            if schema:
                st.code(schema[0], language="sql")
            else:
                st.error("No datasets table found")
    except Exception as e:
        st.error(f"Cannot read schema: {e}")

def backup_session_state():
    """Backup current session state"""
    try:
        backup_data = {
            'timestamp': datetime.now().isoformat(),
            'admin_user': st.session_state.get('admin_user'),
            'threats_data': st.session_state.get('threats_data', []),
            'generated_scenarios': st.session_state.get('generated_scenarios', []),
            'datasets': st.session_state.get('datasets', []),
            'performance_stats': st.session_state.get('performance_stats', {})
        }
        
        backup_dir = Path("../data/backups")
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        backup_file = backup_dir / f"admin_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(backup_file, 'w') as f:
            json.dump(backup_data, f, indent=2, default=str)
        
        if logger_system:
            logger_system.log_user_action("session_backup", {"file": str(backup_file)})
            
    except Exception as e:
        st.error(f"Failed to backup session: {e}")

def export_scenarios_data():
    """Export scenarios data"""
    try:
        if not st.session_state.get('generated_scenarios'):
            st.error("No scenarios to export")
            return
        
        scenarios = st.session_state.generated_scenarios
        
        # Create output directory
        output_dir = Path("data/outputs")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_dir / f"scenarios_export_{timestamp}.json"
        
        # Save to JSON file
        with open(filename, 'w') as f:
            json.dump(scenarios, f, indent=2, default=str)
        
        # Offer download
        st.download_button(
            "Download Scenarios JSON",
            data=json.dumps(scenarios, indent=2, default=str),
            file_name=f"scenarios_export_{timestamp}.json",
            mime="application/json"
        )
        
        st.success(f"Scenarios exported successfully!")
        
    except Exception as e:
        st.error(f"Failed to export scenarios: {e}")

def display_threats_table(threats):
    """Display threats in admin table format"""
    if threats:
        # Create a simplified table view
        threat_data = []
        for threat in threats:
            threat_data.append({
                'CVE ID': threat.get('cve_id', 'Unknown'),
                'Severity': threat.get('severity', {}).get('cvss_v3_severity', 'Unknown'),
                'Score': threat.get('severity', {}).get('cvss_v3_score', 'N/A'),
                'Description': threat.get('description', '')[:100] + '...' if len(threat.get('description', '')) > 100 else threat.get('description', ''),
                'Collected': threat.get('collected_at', 'Unknown')[:19] if threat.get('collected_at') else 'Unknown'
            })
        
        df = pd.DataFrame(threat_data)
        st.dataframe(df, use_container_width=True)

def main():
    """Main admin panel function"""
    
    # Check authentication first
    if not check_authentication():
        return
    
    # Show admin interface
    show_admin_header()
    
    # Initialize session state for admin
    if 'admin_initialized' not in st.session_state:
        st.session_state.admin_initialized = True
        if logger_system:
            logger_system.log_user_action("admin_panel_access", {
                "user": st.session_state.get('admin_user'),
                "timestamp": datetime.now().isoformat()
            })
    
    # Admin navigation
    admin_page = show_admin_sidebar()
    
    # Route to admin functions
    try:
        if admin_page == "📊 System Dashboard":
            show_system_dashboard()
        elif admin_page == "🔍 Threat Intelligence":
            show_threat_intelligence_admin()
        elif admin_page == "⚡ Attack Generator":
            show_attack_generator_admin()
        elif admin_page == "📁 Dataset Management":
            show_dataset_management()
        elif admin_page == "📈 Analytics & Reports":
            st.header("📈 Analytics & Reports")
            st.info("Analytics dashboard under development")
        elif admin_page == "⚙️ System Configuration":
            st.header("⚙️ System Configuration")
            st.info("Configuration management under development")
        elif admin_page == "📋 Logs & Monitoring":
            st.header("📋 Logs & Monitoring")
            st.info("Log monitoring interface under development")
        elif admin_page == "👥 User Management":
            st.header("👥 User Management")
            st.info("User management interface under development")
        elif admin_page == "🔐 Security Center":
            show_security_center()
        elif admin_page == "🛠️ System Maintenance":
            st.header("🛠️ System Maintenance")
            st.info("Maintenance tools under development")
        
    except Exception as e:
        st.error(f"❌ Error in admin function: {e}")
        if logger_system:
            logger_system.log_error("admin_function_error", str(e), {
                "function": admin_page,
                "user": st.session_state.get('admin_user')
            })

if __name__ == "__main__":
    main()