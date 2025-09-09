# web_app/pages/02_📥_Dataset_Center.py - Public Dataset Distribution Center
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
from pathlib import Path
import hashlib
import zipfile
import io
import sys

# Add parent directory to path
current_dir = Path(__file__).parent.parent
parent_dir = current_dir.parent
sys.path.append(str(parent_dir))

st.set_page_config(
    page_title="DynaHome Dataset Center",
    page_icon="📥",
    layout="wide"
)

# Enhanced CSS for dataset center
st.markdown("""
<style>
    /* Dataset card styling */
    .dataset-card {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        border: 1px solid #e0e6ed;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .dataset-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        border-color: #667eea;
    }
    
    .dataset-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        margin-bottom: 1rem;
    }
    
    .dataset-title {
        font-size: 1.3rem;
        font-weight: 700;
        color: #2c3e50;
        margin: 0;
        line-height: 1.3;
    }
    
    .dataset-version {
        background: #667eea;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    
    .dataset-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
        gap: 1rem;
        margin: 1rem 0;
        padding: 1rem;
        background: #f8f9fa;
        border-radius: 8px;
    }
    
    .stat-item {
        text-align: center;
    }
    
    .stat-number {
        font-size: 1.2rem;
        font-weight: 700;
        color: #2c3e50;
        display: block;
    }
    
    .stat-label {
        font-size: 0.8rem;
        color: #7f8c8d;
        margin-top: 0.25rem;
    }
    
    .quality-badge {
        position: absolute;
        top: 1rem;
        right: 1rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 25px;
        font-size: 0.85rem;
        font-weight: 600;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    }
    
    .download-section {
        background: #f8f9fa;
        border-radius: 8px;
        padding: 1rem;
        margin-top: 1rem;
    }
    
    .download-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 0.75rem;
        margin-top: 1rem;
    }
    
    .format-badge {
        display: inline-block;
        background: #ecf0f1;
        color: #2c3e50;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-right: 0.5rem;
        margin-bottom: 0.25rem;
    }
    
    .filter-section {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        margin-bottom: 2rem;
        border: 1px solid #e0e6ed;
    }
    
    .citation-section {
        background: #f8f9fa;
        border-left: 4px solid #667eea;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0 8px 8px 0;
    }
    
    .citation-text {
        font-family: 'Courier New', monospace;
        font-size: 0.85rem;
        background: white;
        padding: 0.75rem;
        border-radius: 4px;
        border: 1px solid #ddd;
        margin-top: 0.5rem;
    }
    
    /* Publication status indicators */
    .status-published {
        background: #27ae60;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    .status-preprint {
        background: #f39c12;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    .status-development {
        background: #3498db;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    /* Usage analytics */
    .usage-chart {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    /* Search and filters */
    .search-section {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 2rem;
        border-radius: 12px;
        margin-bottom: 2rem;
        text-align: center;
    }
    
    .search-title {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 1rem;
    }
    
    /* Mobile responsiveness */
    @media (max-width: 768px) {
        .dataset-header {
            flex-direction: column;
            gap: 1rem;
        }
        
        .dataset-stats {
            grid-template-columns: repeat(2, 1fr);
        }
        
        .download-grid {
            grid-template-columns: 1fr;
        }
        
        .search-title {
            font-size: 1.5rem;
        }
    }
</style>
""", unsafe_allow_html=True)

class DatasetManager:
    """Manage dataset catalog and metadata"""
    
    def __init__(self):
        self.datasets = self._load_dataset_catalog()
        self.download_stats = self._load_download_stats()
    
    def _load_dataset_catalog(self):
        """Load dataset catalog with metadata"""
        # In production, this would load from a database or API
        return [
            {
                "id": "dynohome_smart_home_v2_1",
                "title": "DynaHome Smart Home Security Dataset v2.1",
                "version": "v2.1.0",
                "description": "Comprehensive dataset covering camera, thermostat, doorbell, and smart lock vulnerabilities with realistic attack scenarios and synthetic network traffic.",
                "release_date": "2024-01-15",
                "last_updated": "2024-01-15",
                "status": "published",
                "samples": {
                    "total": 2500,
                    "normal": 1750,
                    "attack": 750
                },
                "quality_score": 0.89,
                "file_size_mb": 15.2,
                "devices": ["Camera", "Thermostat", "Doorbell", "Smart Lock"],
                "attack_types": ["Remote Access", "Data Theft", "Privilege Escalation"],
                "protocols": ["WiFi", "Zigbee", "HTTP/HTTPS"],
                "formats": ["CSV", "JSON", "PCAP"],
                "downloads": 342,
                "citations": 12,
                "doi": "10.5281/zenodo.123456",
                "license": "CC BY 4.0",
                "keywords": ["IoT", "Smart Home", "Security", "Dataset", "Machine Learning"],
                "methodology": "AI-powered threat intelligence processing with BERT classification and GPT scenario generation",
                "validation": "Expert evaluation, statistical similarity testing, protocol compliance verification"
            },
            {
                "id": "iot_protocol_attacks_v1_3",
                "title": "IoT Network Protocol Attacks Dataset v1.3",
                "version": "v1.3.2",
                "description": "Specialized dataset focusing on WiFi, Zigbee, and Z-Wave protocol vulnerabilities with detailed attack patterns and network traces.",
                "release_date": "2024-01-12",
                "last_updated": "2024-01-14",
                "status": "published",
                "samples": {
                    "total": 1800,
                    "normal": 1200,
                    "attack": 600
                },
                "quality_score": 0.91,
                "file_size_mb": 12.8,
                "devices": ["Router", "Hub", "Sensor", "Gateway"],
                "attack_types": ["Protocol Exploit", "Man-in-the-Middle", "Replay Attack"],
                "protocols": ["WiFi", "Zigbee", "Z-Wave", "MQTT"],
                "formats": ["CSV", "JSON", "PCAP"],
                "downloads": 198,
                "citations": 8,
                "doi": "10.5281/zenodo.123457",
                "license": "CC BY 4.0",
                "keywords": ["IoT", "Protocol", "Network", "Security", "Wireless"],
                "methodology": "Protocol-specific vulnerability analysis with automated traffic generation",
                "validation": "Protocol compliance testing, traffic pattern analysis"
            },
            {
                "id": "smart_home_persistence_v1_0",
                "title": "Smart Home Persistence Attacks Dataset v1.0",
                "version": "v1.0.1",
                "description": "Advanced persistent threat scenarios targeting smart home ecosystems with multi-stage attack chains and lateral movement patterns.",
                "release_date": "2024-01-10",
                "last_updated": "2024-01-11",
                "status": "published",
                "samples": {
                    "total": 1200,
                    "normal": 800,
                    "attack": 400
                },
                "quality_score": 0.85,
                "file_size_mb": 9.4,
                "devices": ["Multi-device scenarios"],
                "attack_types": ["Persistent Access", "Lateral Movement", "Command & Control"],
                "protocols": ["Multiple"],
                "formats": ["CSV", "JSON"],
                "downloads": 124,
                "citations": 5,
                "doi": "10.5281/zenodo.123458",
                "license": "CC BY 4.0",
                "keywords": ["IoT", "APT", "Persistence", "Multi-stage", "Advanced"],
                "methodology": "Multi-stage attack scenario modeling with temporal consistency",
                "validation": "Attack chain validation, temporal analysis"
            },
            {
                "id": "dynohome_baseline_v1_0",
                "title": "DynaHome Baseline Comparison Dataset v1.0",
                "version": "v1.0.0",
                "description": "Baseline dataset for comparing DynaHome-generated synthetic data with traditional static datasets.",
                "release_date": "2024-01-08",
                "last_updated": "2024-01-08",
                "status": "preprint",
                "samples": {
                    "total": 5000,
                    "normal": 3500,
                    "attack": 1500
                },
                "quality_score": 0.87,
                "file_size_mb": 22.1,
                "devices": ["Camera", "Thermostat", "Router", "Sensor", "Hub"],
                "attack_types": ["All categories"],
                "protocols": ["WiFi", "Zigbee", "Z-Wave", "Bluetooth"],
                "formats": ["CSV", "JSON"],
                "downloads": 89,
                "citations": 3,
                "doi": "Pending",
                "license": "CC BY 4.0",
                "keywords": ["IoT", "Baseline", "Comparison", "Benchmark", "Evaluation"],
                "methodology": "Comprehensive comparison methodology with statistical validation",
                "validation": "Cross-validation with existing datasets, performance benchmarking"
            }
        ]
    
    def _load_download_stats(self):
        """Load download statistics"""
        return {
            "total_downloads": 753,
            "unique_institutions": 45,
            "countries": 18,
            "research_papers": 28
        }
    
    def get_filtered_datasets(self, device_filter=None, attack_filter=None, status_filter=None, quality_min=0.0):
        """Filter datasets based on criteria"""
        filtered = self.datasets.copy()
        
        if device_filter and device_filter != "All":
            filtered = [d for d in filtered if device_filter in d['devices']]
        
        if attack_filter and attack_filter != "All":
            filtered = [d for d in filtered if attack_filter in d['attack_types']]
        
        if status_filter and status_filter != "All":
            filtered = [d for d in filtered if d['status'] == status_filter.lower()]
        
        filtered = [d for d in filtered if d['quality_score'] >= quality_min]
        
        return filtered
    
    def get_dataset_by_id(self, dataset_id):
        """Get specific dataset by ID"""
        return next((d for d in self.datasets if d['id'] == dataset_id), None)

def show_search_header():
    """Show search and filter header"""
    st.markdown("""
    <div class="search-section">
        <div class="search-title">DynaHome Dataset Distribution Center</div>
        <p style="font-size: 1.1rem; margin: 0; opacity: 0.9;">
            Access cutting-edge IoT security datasets generated by AI-powered threat intelligence
        </p>
    </div>
    """, unsafe_allow_html=True)

def show_filters_and_search():
    """Show dataset filters and search"""
    st.markdown("### Filter Datasets")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        device_filter = st.selectbox(
            "Device Type",
            ["All", "Camera", "Thermostat", "Doorbell", "Smart Lock", "Router", "Hub", "Sensor", "Gateway"]
        )
    
    with col2:
        attack_filter = st.selectbox(
            "Attack Type",
            ["All", "Remote Access", "Data Theft", "Privilege Escalation", "Protocol Exploit", "Man-in-the-Middle", "Persistent Access"]
        )
    
    with col3:
        status_filter = st.selectbox(
            "Status",
            ["All", "Published", "Preprint", "Development"]
        )
    
    with col4:
        quality_min = st.slider(
            "Min Quality Score",
            min_value=0.0,
            max_value=1.0,
            value=0.8,
            step=0.05
        )
    
    return device_filter, attack_filter, status_filter, quality_min

def show_usage_statistics():
    """Show dataset usage statistics"""
    st.markdown("### Global Usage Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Downloads", "753", delta="↑42 this week")
    
    with col2:
        st.metric("Research Institutions", "45", delta="↑3 new")
    
    with col3:
        st.metric("Countries", "18", delta="↑2 new")
    
    with col4:
        st.metric("Published Papers", "28", delta="↑5 citing DynaHome")

def show_download_trends():
    """Show download trends visualization"""
    # Generate sample download data
    dates = pd.date_range(start='2024-01-01', end='2024-01-15', freq='D')
    downloads = [5, 8, 12, 15, 22, 18, 25, 30, 28, 35, 42, 38, 45, 52, 48]
    
    fig = px.line(
        x=dates,
        y=downloads,
        title="Dataset Downloads Over Time",
        labels={'x': 'Date', 'y': 'Daily Downloads'}
    )
    fig.update_traces(line=dict(color='#667eea', width=3))
    fig.update_layout(height=300)
    
    st.plotly_chart(fig, use_container_width=True)

def generate_citation(dataset, format_type="bibtex"):
    """Generate citation for dataset"""
    if format_type == "bibtex":
        return f"""@dataset{{{dataset['id']},
  title={{{dataset['title']}}},
  author={{DynaHome Research Team}},
  year={{2024}},
  version={{{dataset['version']}}},
  doi={{{dataset['doi']}}},
  url={{https://datasets.dynohome.org/{dataset['id']}}},
  publisher={{DynaHome}},
  note={{Accessed: {datetime.now().strftime('%Y-%m-%d')}}}
}}"""
    elif format_type == "apa":
        return f"DynaHome Research Team. (2024). {dataset['title']} ({dataset['version']}) [Dataset]. DynaHome. {dataset['doi']}. Retrieved {datetime.now().strftime('%B %d, %Y')}, from https://datasets.dynohome.org/{dataset['id']}"
    elif format_type == "ieee":
        return f"DynaHome Research Team, \"{dataset['title']},\" DynaHome, {dataset['version']}, {dataset['release_date'][:4]}. [Online]. Available: https://datasets.dynohome.org/{dataset['id']}. [Accessed: {datetime.now().strftime('%d-%b-%Y')}]."

def create_sample_data(dataset):
    """Create sample data for download demonstration"""
    if "CSV" in dataset['formats']:
        # Create sample CSV data
        sample_data = {
            'timestamp': pd.date_range('2024-01-01', periods=10, freq='1min'),
            'source_ip': ['192.168.1.' + str(i) for i in range(100, 110)],
            'dest_ip': ['192.168.1.' + str(i) for i in range(50, 60)],
            'protocol': ['TCP', 'UDP', 'ICMP'] * 4 + ['TCP'] * 2,
            'port': [80, 443, 22, 8080, 1883] * 2,
            'packet_size': [64, 128, 256, 512, 1024] * 2,
            'label': ['normal'] * 7 + ['attack'] * 3,
            'device_type': dataset['devices'][0] if dataset['devices'] else 'unknown'
        }
        return pd.DataFrame(sample_data).to_csv(index=False)
    
    return "Sample data would be generated here"

def show_dataset_card(dataset):
    """Display a comprehensive dataset card"""
    
    # Determine status styling
    status_class = f"status-{dataset['status']}"
    
    st.markdown(f"""
    <div class="dataset-card">
        <div class="quality-badge">Quality: {dataset['quality_score']:.2f}</div>
        
        <div class="dataset-header">
            <div>
                <h3 class="dataset-title">{dataset['title']}</h3>
                <p style="color: #7f8c8d; margin: 0.5rem 0;">{dataset['description']}</p>
                <div style="margin-top: 0.5rem;">
                    <span class="{status_class}">{dataset['status'].upper()}</span>
                    <span class="dataset-version">{dataset['version']}</span>
                </div>
            </div>
        </div>
        
        <div class="dataset-stats">
            <div class="stat-item">
                <span class="stat-number">{dataset['samples']['total']:,}</span>
                <span class="stat-label">Total Samples</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{dataset['samples']['attack']:,}</span>
                <span class="stat-label">Attack Samples</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{dataset['file_size_mb']:.1f} MB</span>
                <span class="stat-label">File Size</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{dataset['downloads']:,}</span>
                <span class="stat-label">Downloads</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{dataset['citations']}</span>
                <span class="stat-label">Citations</span>
            </div>
        </div>
        
        <div style="margin: 1rem 0;">
            <strong>Device Types:</strong> {', '.join(dataset['devices'])}<br>
            <strong>Attack Types:</strong> {', '.join(dataset['attack_types'])}<br>
            <strong>Protocols:</strong> {', '.join(dataset['protocols'])}<br>
            <strong>Keywords:</strong> {', '.join(dataset['keywords'])}
        </div>
        
        <div style="margin: 1rem 0;">
            <strong>Available Formats:</strong><br>
            {''.join([f'<span class="format-badge">{fmt}</span>' for fmt in dataset['formats']])}
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Download section
    st.markdown("#### Download Options")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if "CSV" in dataset['formats']:
            sample_csv = create_sample_data(dataset)
            st.download_button(
                "📊 Download CSV",
                data=sample_csv,
                file_name=f"{dataset['id']}.csv",
                mime="text/csv",
                help=f"Download {dataset['title']} in CSV format"
            )
    
    with col2:
        if "JSON" in dataset['formats']:
            sample_json = json.dumps({
                "metadata": {
                    "dataset_id": dataset['id'],
                    "version": dataset['version'],
                    "total_samples": dataset['samples']['total']
                },
                "sample_data": "Full JSON data would be here"
            }, indent=2)
            st.download_button(
                "📋 Download JSON",
                data=sample_json,
                file_name=f"{dataset['id']}.json",
                mime="application/json",
                help=f"Download {dataset['title']} in JSON format"
            )
    
    with col3:
        metadata_json = json.dumps(dataset, indent=2)
        st.download_button(
            "📄 Metadata",
            data=metadata_json,
            file_name=f"{dataset['id']}_metadata.json",
            mime="application/json",
            help="Download dataset metadata and documentation"
        )
    
    with col4:
        if st.button(f"📈 View Details", key=f"details_{dataset['id']}"):
            show_dataset_details(dataset)
    
    # Citation section
    with st.expander("📚 Citation Information"):
        citation_format = st.selectbox(
            "Citation Format",
            ["BibTeX", "APA", "IEEE"],
            key=f"citation_format_{dataset['id']}"
        )
        
        citation_text = generate_citation(dataset, citation_format.lower().replace("tex", "tex"))
        
        st.markdown(f"""
        <div class="citation-section">
            <div class="citation-text">{citation_text}</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.download_button(
            "📥 Download Citation",
            data=citation_text,
            file_name=f"{dataset['id']}_citation.txt",
            mime="text/plain",
            key=f"citation_download_{dataset['id']}"
        )

def show_dataset_details(dataset):
    """Show detailed dataset information"""
    st.markdown(f"### {dataset['title']} - Detailed Information")
    
    tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Methodology", "Validation", "Usage"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Dataset Information**")
            st.write(f"**Release Date:** {dataset['release_date']}")
            st.write(f"**Last Updated:** {dataset['last_updated']}")
            st.write(f"**DOI:** {dataset['doi']}")
            st.write(f"**License:** {dataset['license']}")
            st.write(f"**File Size:** {dataset['file_size_mb']} MB")
        
        with col2:
            st.markdown("**Sample Distribution**")
            fig = px.pie(
                values=[dataset['samples']['normal'], dataset['samples']['attack']],
                names=['Normal', 'Attack'],
                title="Sample Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.markdown("**Methodology**")
        st.write(dataset['methodology'])
        
        st.markdown("**Data Generation Process**")
        st.write("1. Automated threat intelligence collection from CVE databases")
        st.write("2. AI-powered IoT relevance classification using BERT")
        st.write("3. Attack scenario generation using GPT-3.5")
        st.write("4. Synthetic network traffic generation")
        st.write("5. Quality validation and expert review")
    
    with tab3:
        st.markdown("**Validation Methods**")
        st.write(dataset['validation'])
        
        st.markdown("**Quality Metrics**")
        quality_metrics = {
            'Statistical Realism': 0.91,
            'Protocol Compliance': 0.94,
            'Attack Diversity': 0.85,
            'Temporal Consistency': 0.88
        }
        
        for metric, score in quality_metrics.items():
            st.write(f"**{metric}:** {score:.2f}")
            st.progress(score)
    
    with tab4:
        st.markdown(f"**Download Statistics**")
        st.write(f"Total Downloads: {dataset['downloads']}")
        st.write(f"Academic Citations: {dataset['citations']}")
        
        # Show usage over time
        usage_dates = pd.date_range(start='2024-01-01', periods=15, freq='D')
        usage_counts = np.random.poisson(dataset['downloads']/15, 15)
        
        fig = px.bar(
            x=usage_dates,
            y=usage_counts,
            title="Download Activity"
        )
        st.plotly_chart(fig, use_container_width=True)

def main():
    """Main dataset center function"""
    
    # Initialize dataset manager
    dataset_manager = DatasetManager()
    
    # Show header
    show_search_header()
    
    # Show global statistics
    show_usage_statistics()
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Show filters
        device_filter, attack_filter, status_filter, quality_min = show_filters_and_search()
    
    with col2:
        # Show download trends
        show_download_trends()
    
    # Get filtered datasets
    filtered_datasets = dataset_manager.get_filtered_datasets(
        device_filter, attack_filter, status_filter, quality_min
    )
    
    st.markdown(f"### Available Datasets ({len(filtered_datasets)} found)")
    
    if not filtered_datasets:
        st.warning("No datasets match your current filters. Try adjusting the criteria.")
        return
    
    # Show dataset cards
    for dataset in filtered_datasets:
        show_dataset_card(dataset)
        st.markdown("---")
    
    # Footer information
    st.markdown("## About DynaHome Datasets")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Quality Assurance**
        - All datasets undergo multi-layer validation
        - Statistical similarity testing with real-world data
        - Expert evaluation by IoT security researchers
        - Continuous quality monitoring and improvement
        """)
    
    with col2:
        st.markdown("""
        **Open Science Commitment**
        - All datasets released under CC BY 4.0 license
        - Comprehensive metadata and documentation
        - Reproducible generation methodology
        - Community feedback integration
        """)
    
    st.markdown("""
    ---
    **Need Help?** 
    - 📧 Contact: datasets@dynohome.org
    - 📚 Documentation: [docs.dynohome.org](https://docs.dynohome.org)
    - 💬 Community: [github.com/dynohome/community](https://github.com/dynohome/community)
    """)

if __name__ == "__main__":
    main()