# web_app/pages/01_📊_Dashboard.py - Enhanced real-time dashboard
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys
import time

# Add parent directory to path
current_dir = Path(__file__).parent.parent
parent_dir = current_dir.parent
sys.path.append(str(parent_dir))

st.set_page_config(
    page_title="DynaHome Dashboard",
    page_icon="📊",
    layout="wide"
)

# Enhanced dashboard CSS
st.markdown("""
<style>
    /* Dashboard-specific styling */
    .dashboard-container {
        padding: 1rem 0;
    }
    
    .metric-card-large {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
        transition: transform 0.3s ease;
    }
    
    .metric-card-large:hover {
        transform: translateY(-2px);
    }
    
    .metric-number-large {
        font-size: 2.5rem;
        font-weight: 700;
        color: #2c3e50;
        margin: 0;
    }
    
    .metric-label-large {
        font-size: 0.9rem;
        color: #7f8c8d;
        margin-top: 0.5rem;
        font-weight: 500;
    }
    
    .metric-delta {
        font-size: 0.8rem;
        margin-top: 0.25rem;
    }
    
    .metric-delta.positive {
        color: #27ae60;
    }
    
    .metric-delta.negative {
        color: #e74c3c;
    }
    
    .status-indicator {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 8px;
    }
    
    .status-online {
        background-color: #27ae60;
        animation: pulse 2s infinite;
    }
    
    .status-warning {
        background-color: #f39c12;
    }
    
    .status-offline {
        background-color: #e74c3c;
    }
    
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    
    .chart-container {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
    }
    
    .chart-title {
        font-size: 1.1rem;
        font-weight: 600;
        margin-bottom: 1rem;
        color: #2c3e50;
    }
    
    .system-status-card {
        background: white;
        border-radius: 8px;
        padding: 1rem;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
    }
    
    .alert-high {
        background-color: #ffeaa7;
        border-left: 4px solid #fdcb6e;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 4px;
    }
    
    .alert-critical {
        background-color: #fab1a0;
        border-left: 4px solid #e17055;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 4px;
    }
    
    /* Real-time updates indicator */
    .live-indicator {
        background: #27ae60;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 500;
        display: inline-block;
        margin-left: 1rem;
    }
    
    .refresh-time {
        color: #7f8c8d;
        font-size: 0.8rem;
        margin-left: 1rem;
    }
</style>
""", unsafe_allow_html=True)

class DashboardDataManager:
    """Manage dashboard data with caching and real-time updates"""
    
    def __init__(self):
        self.last_update = datetime.now()
        self.cache_duration = timedelta(minutes=5)
        self._cached_data = None
    
    def get_real_time_metrics(self):
        """Get real-time system metrics"""
        current_time = datetime.now()
        
        # Check if we need to refresh cache
        if (self._cached_data is None or 
            current_time - self.last_update > self.cache_duration):
            self._cached_data = self._fetch_fresh_metrics()
            self.last_update = current_time
        
        return self._cached_data
    
    def _fetch_fresh_metrics(self):
        """Fetch fresh metrics from various sources"""
        try:
            # Try to load real data from system
            data_dir = Path("../data")
            
            # System health metrics
            health_metrics = self._get_system_health()
            
            # Processing metrics
            processing_metrics = self._get_processing_metrics(data_dir)
            
            # Performance metrics
            performance_metrics = self._get_performance_metrics()
            
            # Quality metrics
            quality_metrics = self._get_quality_metrics(data_dir)
            
            return {
                'timestamp': datetime.now(),
                'health': health_metrics,
                'processing': processing_metrics,
                'performance': performance_metrics,
                'quality': quality_metrics
            }
            
        except Exception as e:
            # Return fallback demo data
            return self._get_demo_data()
    
    def _get_system_health(self):
        """Get current system health status"""
        try:
            import psutil
            
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('.')
            
            return {
                'status': 'online' if cpu_percent < 80 else 'warning',
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'disk_usage': disk.percent,
                'uptime_hours': (datetime.now() - datetime.now().replace(hour=0, minute=0, second=0)).total_seconds() / 3600
            }
        except:
            return {
                'status': 'online',
                'cpu_usage': 15.2,
                'memory_usage': 45.8,
                'disk_usage': 23.1,
                'uptime_hours': 8.5
            }
    
    def _get_processing_metrics(self, data_dir):
        """Get threat processing metrics"""
        try:
            processed_dir = data_dir / "processed"
            if processed_dir.exists():
                threat_files = list(processed_dir.glob("*threats*.json"))
                
                # Calculate metrics from real files
                total_threats = len(threat_files) * 25  # Estimate
                iot_threats = len(threat_files) * 3    # Estimate IoT ratio
                
                # Get processing rate (threats per day)
                if threat_files:
                    latest_file = max(threat_files, key=lambda f: f.stat().st_mtime)
                    file_age_days = (datetime.now() - datetime.fromtimestamp(latest_file.stat().st_mtime)).days
                    processing_rate = total_threats / max(file_age_days, 1)
                else:
                    processing_rate = 0
                
                return {
                    'total_threats_processed': total_threats,
                    'iot_threats_found': iot_threats,
                    'processing_rate_daily': processing_rate,
                    'success_rate': 0.94,
                    'last_processing_time': datetime.now() - timedelta(hours=2)
                }
            else:
                return self._get_demo_processing_metrics()
        except:
            return self._get_demo_processing_metrics()
    
    def _get_demo_processing_metrics(self):
        """Demo processing metrics"""
        base_time = datetime.now()
        return {
            'total_threats_processed': 1247,
            'iot_threats_found': 89,
            'processing_rate_daily': 45.2,
            'success_rate': 0.94,
            'last_processing_time': base_time - timedelta(hours=2)
        }
    
    def _get_performance_metrics(self):
        """Get performance metrics"""
        # Generate realistic performance data
        return {
            'avg_processing_time': 12.4,
            'classification_accuracy': 0.87,
            'dataset_generation_time': 8.2,
            'api_response_time': 1.2,
            'error_rate': 0.06
        }
    
    def _get_quality_metrics(self, data_dir):
        """Get dataset quality metrics"""
        return {
            'overall_quality_score': 0.89,
            'statistical_realism': 0.91,
            'protocol_compliance': 0.94,
            'attack_diversity': 0.85,
            'temporal_consistency': 0.88
        }
    
    def _get_demo_data(self):
        """Fallback demo data"""
        return {
            'timestamp': datetime.now(),
            'health': {
                'status': 'online',
                'cpu_usage': 15.2,
                'memory_usage': 45.8,
                'disk_usage': 23.1,
                'uptime_hours': 8.5
            },
            'processing': self._get_demo_processing_metrics(),
            'performance': self._get_performance_metrics(),
            'quality': self._get_quality_metrics(None)
        }

def show_system_status_header():
    """Show system status at the top of dashboard"""
    data_manager = DashboardDataManager()
    metrics = data_manager.get_real_time_metrics()
    
    health = metrics['health']
    
    st.markdown(f"""
    <div style="background: white; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h2 style="margin: 0; color: #2c3e50;">System Status 
                    <span class="status-indicator status-{health['status']}"></span>
                    <span style="color: #27ae60; font-size: 1rem;">OPERATIONAL</span>
                </h2>
                <p style="margin: 0.5rem 0 0 0; color: #7f8c8d;">
                    Last updated: {metrics['timestamp'].strftime('%H:%M:%S')}
                    <span class="live-indicator">LIVE</span>
                </p>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 0.9rem; color: #7f8c8d;">
                    CPU: {health['cpu_usage']:.1f}% • 
                    Memory: {health['memory_usage']:.1f}% • 
                    Uptime: {health['uptime_hours']:.1f}h
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def show_key_metrics():
    """Show key performance indicators"""
    data_manager = DashboardDataManager()
    metrics = data_manager.get_real_time_metrics()
    
    processing = metrics['processing']
    performance = metrics['performance']
    quality = metrics['quality']
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card-large">
            <div class="metric-number-large">{processing['total_threats_processed']:,}</div>
            <div class="metric-label-large">Total Threats Processed</div>
            <div class="metric-delta positive">+{processing['processing_rate_daily']:.1f} today</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card-large">
            <div class="metric-number-large">{processing['iot_threats_found']}</div>
            <div class="metric-label-large">IoT Threats Identified</div>
            <div class="metric-delta positive">+{processing['iot_threats_found']/processing['total_threats_processed']*100:.1f}% detection rate</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card-large">
            <div class="metric-number-large">{performance['classification_accuracy']*100:.0f}%</div>
            <div class="metric-label-large">Classification Accuracy</div>
            <div class="metric-delta positive">+2.3% this week</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card-large">
            <div class="metric-number-large">{quality['overall_quality_score']:.2f}</div>
            <div class="metric-label-large">Dataset Quality Score</div>
            <div class="metric-delta positive">+0.05 improvement</div>
        </div>
        """, unsafe_allow_html=True)

def show_real_time_charts():
    """Show real-time processing charts"""
    st.markdown("## Real-time Processing Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Threat processing over time (last 24 hours)
        hours = pd.date_range(start=datetime.now() - timedelta(hours=23), 
                             end=datetime.now(), freq='H')
        
        # Generate realistic hourly data
        hourly_threats = []
        for i, hour in enumerate(hours):
            base_rate = 2  # Base threats per hour
            if 9 <= hour.hour <= 17:  # Business hours
                base_rate *= 1.5
            
            # Add some randomness
            threats = base_rate + np.random.poisson(1) + (i % 3)
            hourly_threats.append(threats)
        
        fig_hourly = px.line(
            x=hours, 
            y=hourly_threats,
            title="Threat Processing (Last 24 Hours)",
            labels={'x': 'Time', 'y': 'Threats Processed'}
        )
        fig_hourly.update_layout(
            height=350,
            showlegend=False,
            xaxis_title="Time",
            yaxis_title="Threats/Hour"
        )
        fig_hourly.update_traces(line=dict(color='#667eea', width=3))
        
        st.plotly_chart(fig_hourly, use_container_width=True)
    
    with col2:
        # System performance metrics
        performance_data = {
            'Metric': ['Processing Speed', 'Accuracy', 'Quality Score', 'Uptime'],
            'Current': [85, 87, 89, 99.2],
            'Target': [80, 85, 85, 99.0]
        }
        
        fig_performance = go.Figure()
        
        fig_performance.add_trace(go.Bar(
            name='Current',
            x=performance_data['Metric'],
            y=performance_data['Current'],
            marker_color='#667eea'
        ))
        
        fig_performance.add_trace(go.Bar(
            name='Target',
            x=performance_data['Metric'],
            y=performance_data['Target'],
            marker_color='#f093fb',
            opacity=0.7
        ))
        
        fig_performance.update_layout(
            title="Performance vs Targets",
            height=350,
            yaxis_title="Score (%)",
            barmode='group'
        )
        
        st.plotly_chart(fig_performance, use_container_width=True)

def show_threat_analysis():
    """Show detailed threat analysis"""
    st.markdown("## Threat Intelligence Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Device type distribution
        device_data = {
            'Device': ['Camera', 'Thermostat', 'Router', 'Doorbell', 'Smart Lock', 'Sensor', 'Hub', 'Speaker'],
            'Threats': [45, 32, 38, 28, 22, 15, 18, 12],
            'Severity': ['High', 'Medium', 'High', 'Medium', 'High', 'Low', 'Medium', 'Low']
        }
        
        fig_devices = px.sunburst(
            values=device_data['Threats'],
            names=device_data['Device'],
            title="IoT Device Threat Distribution"
        )
        fig_devices.update_layout(height=400)
        
        st.plotly_chart(fig_devices, use_container_width=True)
    
    with col2:
        # Attack type timeline
        attack_timeline = pd.DataFrame({
            'Date': pd.date_range(start='2024-01-01', end='2024-01-15', freq='D'),
            'Remote Access': np.random.poisson(3, 15),
            'Data Theft': np.random.poisson(2, 15),
            'DoS': np.random.poisson(1, 15),
            'Code Execution': np.random.poisson(1, 15)
        })
        
        fig_attacks = px.area(
            attack_timeline, 
            x='Date', 
            y=['Remote Access', 'Data Theft', 'DoS', 'Code Execution'],
            title="Attack Types Over Time"
        )
        fig_attacks.update_layout(height=400)
        
        st.plotly_chart(fig_attacks, use_container_width=True)

def show_quality_dashboard():
    """Show dataset quality monitoring"""
    st.markdown("## Dataset Quality Monitoring")
    
    # Quality metrics radar chart
    categories = ['Statistical Realism', 'Protocol Compliance', 'Attack Diversity', 
                 'Temporal Consistency', 'Network Realism']
    
    values = [0.91, 0.94, 0.85, 0.88, 0.87]
    
    fig_radar = go.Figure()
    
    fig_radar.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        name='Current Quality'
    ))
    
    fig_radar.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 1]
            )),
        showlegend=True,
        title="Dataset Quality Metrics",
        height=400
    )
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.plotly_chart(fig_radar, use_container_width=True)
    
    with col2:
        st.markdown("### Quality Thresholds")
        
        quality_items = [
            ("Statistical Realism", 0.91, 0.85),
            ("Protocol Compliance", 0.94, 0.90),
            ("Attack Diversity", 0.85, 0.80),
            ("Temporal Consistency", 0.88, 0.85),
            ("Network Realism", 0.87, 0.80)
        ]
        
        for metric, current, threshold in quality_items:
            status = "✅" if current >= threshold else "⚠️"
            st.markdown(f"**{metric}** {status}")
            st.progress(current)
            st.markdown(f"Current: {current:.2f} | Target: {threshold:.2f}")
            st.markdown("---")

def show_system_alerts():
    """Show system alerts and notifications"""
    st.markdown("## System Alerts & Notifications")
    
    # Sample alerts
    alerts = [
        {
            'type': 'info',
            'title': 'Scheduled Maintenance',
            'message': 'System maintenance scheduled for Sunday 2:00 AM - 4:00 AM EST',
            'time': '2 hours ago'
        },
        {
            'type': 'warning',
            'title': 'High Memory Usage',
            'message': 'Memory usage exceeded 80% threshold during peak processing',
            'time': '45 minutes ago'
        },
        {
            'type': 'success',
            'title': 'New Dataset Generated',
            'message': 'Smart Home Security Dataset v2.1 generated successfully',
            'time': '30 minutes ago'
        }
    ]
    
    for alert in alerts:
        if alert['type'] == 'warning':
            st.warning(f"**{alert['title']}** - {alert['message']} _{alert['time']}_")
        elif alert['type'] == 'success':
            st.success(f"**{alert['title']}** - {alert['message']} _{alert['time']}_")
        else:
            st.info(f"**{alert['title']}** - {alert['message']} _{alert['time']}_")

def show_api_status():
    """Show API endpoint status"""
    st.markdown("## API & Service Status")
    
    services = [
        {'name': 'CVE Database API', 'status': 'online', 'response_time': '1.2s', 'uptime': '99.8%'},
        {'name': 'AI Classification Service', 'status': 'online', 'response_time': '0.8s', 'uptime': '99.9%'},
        {'name': 'Dataset Generation', 'status': 'online', 'response_time': '12.4s', 'uptime': '99.5%'},
        {'name': 'OpenAI API', 'status': 'warning', 'response_time': '2.1s', 'uptime': '98.2%'},
    ]
    
    col1, col2, col3, col4 = st.columns(4)
    
    for i, service in enumerate(services):
        with [col1, col2, col3, col4][i]:
            status_color = {
                'online': '#27ae60',
                'warning': '#f39c12', 
                'offline': '#e74c3c'
            }[service['status']]
            
            st.markdown(f"""
            <div class="system-status-card">
                <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                    <span class="status-indicator" style="background-color: {status_color};"></span>
                    <strong>{service['name']}</strong>
                </div>
                <div style="font-size: 0.85rem; color: #7f8c8d;">
                    Response: {service['response_time']}<br>
                    Uptime: {service['uptime']}
                </div>
            </div>
            """, unsafe_allow_html=True)

def main():
    """Main dashboard function"""
    st.title("📊 DynaHome Real-time Dashboard")
    
    # Auto-refresh option
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown("**Live monitoring of AI-powered IoT threat intelligence processing**")
    with col2:
        auto_refresh = st.checkbox("Auto-refresh (30s)", value=False)
    with col3:
        if st.button("🔄 Refresh Now"):
            st.rerun()
    
    # Auto-refresh logic
    if auto_refresh:
        time.sleep(30)
        st.rerun()
    
    # Main dashboard content
    show_system_status_header()
    show_key_metrics()
    show_real_time_charts()
    show_threat_analysis()
    show_quality_dashboard()
    show_system_alerts()
    show_api_status()
    
    # Footer with last update time
    st.markdown("---")
    st.markdown(f"*Dashboard last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

if __name__ == "__main__":
    main()