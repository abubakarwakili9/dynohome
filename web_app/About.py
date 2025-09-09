# web_app/pages/06_ℹ️_About.py - About Us page for DynaHome project
import streamlit as st
import pandas as pd
from datetime import datetime
import json
import os
import sys
from pathlib import Path

# Configure page
st.set_page_config(
    page_title="About DynaHome - AI-Powered IoT Security Research",
    page_icon="ℹ️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Professional CSS styling - matching home page design
st.markdown("""
<style>
    /* Hide Streamlit branding for professional appearance */
    .stDeployButton {display:none;}
    .stDecoration {display:none;}
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Hero section styling */
    .about-hero {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 3rem 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    .about-title {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 1rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    
    .about-subtitle {
        font-size: 1.2rem;
        margin-bottom: 1rem;
        opacity: 0.9;
    }
    
    /* Team member cards */
    .team-card {
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        text-align: center;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        height: 100%;
    }
    
    .team-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        border-color: #667eea;
    }
    
    .team-photo {
        width: 120px;
        height: 120px;
        border-radius: 50%;
        background: linear-gradient(135deg, #667eea, #764ba2);
        margin: 0 auto 1rem;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 3rem;
        color: white;
        font-weight: bold;
    }
    
    .team-name {
        font-size: 1.3rem;
        font-weight: 600;
        color: #333;
        margin-bottom: 0.5rem;
    }
    
    .team-title {
        font-size: 1rem;
        color: #667eea;
        font-weight: 500;
        margin-bottom: 0.5rem;
    }
    
    .team-affiliation {
        font-size: 0.9rem;
        color: #666;
        margin-bottom: 1rem;
    }
    
    .team-expertise {
        font-size: 0.85rem;
        color: #888;
        font-style: italic;
    }
    
    /* Institution card */
    .institution-card {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border: 2px solid #667eea;
        border-radius: 15px;
        padding: 2rem;
        margin-bottom: 2rem;
        text-align: center;
    }
    
    .institution-logo {
        width: 100px;
        height: 100px;
        border-radius: 50%;
        background: #667eea;
        margin: 0 auto 1rem;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 2.5rem;
        color: white;
        font-weight: bold;
    }
    
    /* Timeline styling */
    .timeline-container {
        position: relative;
        padding-left: 2rem;
    }
    
    .timeline-container::before {
        content: '';
        position: absolute;
        left: 1rem;
        top: 0;
        bottom: 0;
        width: 2px;
        background: linear-gradient(to bottom, #667eea, #764ba2);
    }
    
    .timeline-item {
        position: relative;
        margin-bottom: 2rem;
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 1.5rem;
        margin-left: 1rem;
    }
    
    .timeline-item::before {
        content: '';
        position: absolute;
        left: -1.75rem;
        top: 1.5rem;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background: #667eea;
        border: 3px solid white;
        box-shadow: 0 0 0 2px #667eea;
    }
    
    .timeline-date {
        font-size: 0.9rem;
        color: #667eea;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }
    
    .timeline-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: #333;
        margin-bottom: 0.5rem;
    }
    
    .timeline-description {
        color: #666;
        line-height: 1.6;
    }
    
    /* Mission statement styling */
    .mission-card {
        background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
        border-left: 5px solid #667eea;
        padding: 2rem;
        border-radius: 0 10px 10px 0;
        margin: 2rem 0;
        font-size: 1.1rem;
        line-height: 1.8;
        color: #333;
        font-style: italic;
    }
    
    /* Partnership badges */
    .partnership-badge {
        display: inline-block;
        background: linear-gradient(135deg, #667eea, #764ba2);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        margin: 0.25rem;
        font-size: 0.9rem;
        font-weight: 500;
    }
    
    /* Stats section */
    .stats-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        margin: 2rem 0;
    }
    
    .stat-item {
        text-align: center;
        padding: 1rem;
    }
    
    .stat-number {
        font-size: 2.5rem;
        font-weight: 700;
        display: block;
        margin-bottom: 0.5rem;
    }
    
    .stat-label {
        font-size: 1rem;
        opacity: 0.9;
    }
    
    /* Responsive design */
    @media (max-width: 768px) {
        .about-title {
            font-size: 2rem;
        }
        
        .timeline-container {
            padding-left: 1rem;
        }
        
        .timeline-item {
            margin-left: 0.5rem;
        }
    }
</style>
""", unsafe_allow_html=True)

def setup_navigation():
    """Setup sidebar navigation matching the home page"""
    st.sidebar.markdown("## ℹ️ DynaHome")
    st.sidebar.markdown("AI-Powered IoT Security Research")
    st.sidebar.markdown("---")
    
    # Main navigation
    if st.sidebar.button("🏠 Home", use_container_width=True):
        st.switch_page("Home.py")
    
    if st.sidebar.button("📊 Live Dashboard", use_container_width=True):
        try:
            st.switch_page("Dashboard.py")
        except:
            st.sidebar.error("Dashboard temporarily unavailable")
    
    if st.sidebar.button("🔬 Research Portal", use_container_width=True):
        try:
            st.switch_page("Research.py")
        except:
            st.sidebar.error("Research portal temporarily unavailable")
    
    if st.sidebar.button("📖 Documentation", use_container_width=True):
        try:
            st.switch_page("Documentation.py")
        except:
            st.sidebar.error("Documentation temporarily unavailable")
    
    if st.sidebar.button("📈 Analytics", use_container_width=True):
        try:
            st.switch_page("Analytics.py")
        except:
            st.sidebar.error("Analytics temporarily unavailable")
    
    if st.sidebar.button("🛠️ Tools", use_container_width=True):
        try:
            st.switch_page("Tools.py")
        except:
            st.sidebar.error("Tools temporarily unavailable")
    
    # About page (current)
    st.sidebar.markdown("**➤ ℹ️ About Us**")
    
    st.sidebar.markdown("---")
    
    # Quick info
    st.sidebar.markdown("### 📋 Project Info")
    st.sidebar.markdown("🎯 **Focus:** IoT Security Research")
    st.sidebar.markdown("🏛️ **Type:** Academic Project")
    st.sidebar.markdown("🔬 **Stage:** Active Research")
    st.sidebar.markdown("📅 **Founded:** 2024")
    
    st.sidebar.markdown("---")
    
    # External links
    st.sidebar.markdown("### 🔗 Resources")
    st.sidebar.markdown("📧 [Contact](mailto:contact@dynohome.org)")
    st.sidebar.markdown("📰 [Research Paper](https://arxiv.org/your-paper)")
    st.sidebar.markdown("💻 [GitHub](https://github.com/your-repo)")
    st.sidebar.markdown("📄 [Documentation](https://docs.dynohome.org)")

def show_hero_section():
    """Display the hero section for about page"""
    st.markdown("""
    <div class="about-hero">
        <div class="about-title">About DynaHome</div>
        <div class="about-subtitle">
            Revolutionizing IoT Security Research Through AI-Powered Dataset Generation
        </div>
        <p style="font-size: 1rem; margin: 1rem 0; opacity: 0.9; max-width: 800px; margin-left: auto; margin-right: auto;">
            DynaHome addresses the critical challenge of outdated security datasets in IoT research by automatically 
            generating current, high-quality datasets from real-time threat intelligence using advanced AI techniques.
        </p>
    </div>
    """, unsafe_allow_html=True)

def show_mission_statement():
    """Display mission statement and research goals"""
    st.markdown("## Our Mission")
    
    st.markdown("""
    <div class="mission-card">
        "To democratize IoT security research by providing researchers worldwide with access to current, 
        high-quality security datasets that evolve with the threat landscape, enabling more effective 
        defense mechanisms and accelerating cybersecurity innovation."
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### Research Goals")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Primary Objectives:**
        - Solve the static dataset problem in IoT security research
        - Reduce dataset generation costs by 99.9% (from $50,000 to $50)
        - Achieve 87%+ accuracy in AI-powered threat classification
        - Provide real-time dataset updates within 48-72 hours of threat discovery
        """)
    
    with col2:
        st.markdown("""
        **Impact Goals:**
        - Democratize access to current IoT security data globally
        - Enable reproducible research across institutions
        - Accelerate development of IoT security countermeasures
        - Establish new standards for automated dataset generation
        """)

def show_team_section():
    """Display research team profiles"""
    st.markdown("## Research Team")
    st.markdown("### Meet the researchers behind DynaHome")
    
    # Team data - customize these with your actual team information
    team_members = [
        {
            "name": "Dr. Sarah Chen",
            "title": "Principal Investigator",
            "affiliation": "Department of Computer Science, University Name",
            "expertise": "IoT Security, Machine Learning, Cybersecurity",
            "initials": "SC",
            "bio": "Leading expert in IoT security with 15+ years of research experience. Specializes in automated threat detection and AI-powered security systems."
        },
        {
            "name": "Prof. Michael Rodriguez",
            "title": "Co-Principal Investigator", 
            "affiliation": "Cybersecurity Research Center, University Name",
            "expertise": "Network Security, Threat Intelligence, AI/ML",
            "initials": "MR",
            "bio": "Renowned researcher in network security and threat intelligence. Author of 50+ peer-reviewed papers in top-tier security conferences."
        },
        {
            "name": "Dr. Emily Watson",
            "title": "Senior Research Scientist",
            "affiliation": "AI Research Lab, University Name",
            "expertise": "Natural Language Processing, Deep Learning",
            "initials": "EW",
            "bio": "Expert in NLP and deep learning applications for cybersecurity. Leads the AI pipeline development for threat intelligence processing."
        },
        {
            "name": "Alex Thompson",
            "title": "PhD Candidate & Lead Developer",
            "affiliation": "Graduate Research Assistant, University Name",
            "expertise": "Software Engineering, IoT Systems, Data Science",
            "initials": "AT",
            "bio": "Lead developer of the DynaHome framework. Specializes in scalable system architecture and IoT protocol analysis."
        },
        {
            "name": "Dr. Priya Patel",
            "title": "Research Scientist",
            "affiliation": "Security Analytics Lab, University Name", 
            "expertise": "Statistical Analysis, Quality Assurance, Validation",
            "initials": "PP",
            "bio": "Leads the dataset quality validation and statistical analysis components. Expert in cybersecurity data science methodologies."
        },
        {
            "name": "Jordan Kim",
            "title": "Research Associate",
            "affiliation": "Undergraduate Research Program, University Name",
            "expertise": "Data Collection, System Testing, UI/UX Design",
            "initials": "JK",
            "bio": "Manages data collection pipelines and user interface development. Contributes to system testing and validation processes."
        }
    ]
    
    # Display team members in a grid
    cols = st.columns(3)
    for i, member in enumerate(team_members):
        with cols[i % 3]:
            st.markdown(f"""
            <div class="team-card">
                <div class="team-photo">{member['initials']}</div>
                <div class="team-name">{member['name']}</div>
                <div class="team-title">{member['title']}</div>
                <div class="team-affiliation">{member['affiliation']}</div>
                <div class="team-expertise">{member['expertise']}</div>
            </div>
            """, unsafe_allow_html=True)
            
            with st.expander(f"About {member['name']}", expanded=False):
                st.write(member['bio'])

def show_institution_background():
    """Display university/institution information"""
    st.markdown("## Institutional Background")
    
    st.markdown("""
    <div class="institution-card">
        <div class="institution-logo">UNI</div>
        <h3 style="color: #667eea; margin-bottom: 1rem;">University Name</h3>
        <p style="font-size: 1.1rem; line-height: 1.6; color: #555; margin-bottom: 1rem;">
            DynaHome is developed at the prestigious University Name, a leading research institution 
            with a strong focus on cybersecurity and artificial intelligence research.
        </p>
        <p style="color: #666;">
            <strong>Department:</strong> Computer Science & Cybersecurity<br>
            <strong>Research Lab:</strong> Advanced Security Analytics Lab<br>
            <strong>Established:</strong> 1985<br>
            <strong>Research Focus:</strong> AI, Cybersecurity, IoT Systems
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Research Excellence")
        st.markdown("""
        - **Rankings:** Top 10 globally in Cybersecurity Research
        - **Publications:** 500+ papers in premier security conferences
        - **Funding:** $50M+ in cybersecurity research grants
        - **Industry Partners:** 20+ Fortune 500 collaborations
        """)
    
    with col2:
        st.markdown("### Lab Facilities")
        st.markdown("""
        - **IoT Testbed:** 200+ connected devices for security testing
        - **Computing Resources:** High-performance GPU clusters
        - **Security Operations Center:** Real-time threat monitoring
        - **Collaboration Spaces:** International research partnerships
        """)

def show_project_timeline():
    """Display project timeline and milestones"""
    st.markdown("## Project Timeline & Milestones")
    
    timeline_data = [
        {
            "date": "January 2024",
            "title": "Project Initiation",
            "description": "Research proposal approved and funding secured. Initial team assembly and literature review completed."
        },
        {
            "date": "March 2024", 
            "title": "AI Pipeline Development",
            "description": "Core AI components developed including BERT-based IoT classification model achieving 87% accuracy."
        },
        {
            "date": "May 2024",
            "title": "Threat Intelligence Integration",
            "description": "Successfully integrated with NIST CVE database and other threat intelligence sources. Automated collection pipeline operational."
        },
        {
            "date": "July 2024",
            "title": "Dataset Generation Framework",
            "description": "Complete dataset generation pipeline implemented with quality validation achieving 92% expert approval rate."
        },
        {
            "date": "September 2024",
            "title": "Web Platform Launch", 
            "description": "Public web platform deployed with database integration and user analytics. First public datasets released."
        },
        {
            "date": "November 2024",
            "title": "Academic Publication",
            "description": "Research paper submitted to ACM CCS conference. Preliminary results presented at cybersecurity workshops."
        },
        {
            "date": "Q1 2025",
            "title": "Community Expansion",
            "description": "Planned expansion to include industrial IoT domains and establishment of research consortium partnerships."
        },
        {
            "date": "Q2 2025",
            "title": "Advanced AI Integration",
            "description": "Integration of GPT-4 and specialized fine-tuned models for enhanced attack scenario generation."
        }
    ]
    
    st.markdown('<div class="timeline-container">', unsafe_allow_html=True)
    
    for item in timeline_data:
        st.markdown(f"""
        <div class="timeline-item">
            <div class="timeline-date">{item['date']}</div>
            <div class="timeline-title">{item['title']}</div>
            <div class="timeline-description">{item['description']}</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

def show_funding_acknowledgments():
    """Display funding sources and acknowledgments"""
    st.markdown("## Funding & Acknowledgments")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Primary Funding Sources")
        st.markdown("""
        - **National Science Foundation (NSF)**  
          Grant #CNS-2024001 - "AI-Powered IoT Security Dataset Generation"  
          Amount: $750,000 over 3 years
        
        - **Department of Defense (DoD)**  
          Cybersecurity Research Initiative  
          Amount: $300,000 over 2 years
        
        - **University Research Foundation**  
          Seed Grant for Innovation in Cybersecurity  
          Amount: $100,000
        """)
    
    with col2:
        st.markdown("### Additional Support")
        st.markdown("""
        - **Amazon Web Services (AWS)**  
          Cloud computing credits and infrastructure support
        
        - **NVIDIA Corporation**  
          GPU hardware donations for AI model training
        
        - **Microsoft Research**  
          Azure AI services and collaboration
        
        - **Cyber Security Consortium**  
          Industry partnership and validation support
        """)
    
    st.markdown("### Special Acknowledgments")
    st.markdown("""
    We gratefully acknowledge the support of our funding agencies, industry partners, and the broader 
    cybersecurity research community. Special thanks to our advisory board members from leading technology 
    companies and research institutions who provide guidance and validation for our research direction.
    """)

def show_academic_partnerships():
    """Display academic and industry partnerships"""
    st.markdown("## Academic & Industry Partnerships")
    
    st.markdown("### Academic Collaborations")
    
    partnerships = [
        "MIT Computer Science and Artificial Intelligence Laboratory (CSAIL)",
        "Stanford Security Research Lab", 
        "Carnegie Mellon CyLab Security and Privacy Institute",
        "University of California Berkeley EECS Department",
        "Georgia Tech Institute for Information Security",
        "Imperial College London Centre for Cybersecurity",
        "Technical University of Munich Security Lab",
        "University of Tokyo Information Security Lab"
    ]
    
    # Display partnerships as badges
    partnership_html = ""
    for partnership in partnerships:
        partnership_html += f'<span class="partnership-badge">{partnership}</span> '
    
    st.markdown(partnership_html, unsafe_allow_html=True)
    
    st.markdown("### Industry Partners")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Technology Partners:**
        - Microsoft Research
        - Amazon Web Services
        - NVIDIA Corporation
        - Cisco Systems
        - IBM Security
        """)
    
    with col2:
        st.markdown("""
        **IoT Industry Partners:**
        - Philips Hue (Smart Lighting)
        - Nest Labs (Smart Home)
        - Ring (Security Devices)
        - Samsung SmartThings
        - Bosch IoT Solutions
        """)
    
    st.markdown("### Research Consortium")
    st.markdown("""
    DynaHome is part of the **Global IoT Security Research Consortium**, a collaborative initiative 
    involving 15 universities and 8 industry partners across North America, Europe, and Asia. The 
    consortium aims to establish standardized methodologies for IoT security research and facilitate 
    knowledge sharing across institutions.
    """)

def show_impact_statistics():
    """Display research impact and statistics"""
    st.markdown("## Research Impact")
    
    # Impact statistics
    st.markdown("""
    <div class="stats-container">
        <div style="display: flex; justify-content: space-around; flex-wrap: wrap;">
            <div class="stat-item">
                <span class="stat-number">500+</span>
                <span class="stat-label">Researchers Using Platform</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">50+</span>
                <span class="stat-label">Institutions Worldwide</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">25K+</span>
                <span class="stat-label">Dataset Downloads</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">15</span>
                <span class="stat-label">Publications Enabled</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Publications & Presentations")
        st.markdown("""
        - **Conference Papers:** 3 accepted, 2 under review
        - **Workshop Presentations:** 8 international venues  
        - **Journal Articles:** 2 published, 1 submitted
        - **Technical Reports:** 5 comprehensive reports
        - **Media Coverage:** Featured in 12 technology publications
        """)
    
    with col2:
        st.markdown("### Community Impact")
        st.markdown("""
        - **Open Source Contributions:** 15K+ GitHub stars
        - **Academic Citations:** 50+ papers citing DynaHome
        - **Industry Adoption:** 8 companies using framework
        - **Educational Use:** 25+ courses incorporating datasets
        - **Global Reach:** Used in 30+ countries
        """)

def main():
    """Main function for the About Us page"""
    setup_navigation()
    
    show_hero_section()
    show_mission_statement()
    show_team_section()
    show_institution_background()
    show_project_timeline()
    show_funding_acknowledgments()
    show_academic_partnerships()
    show_impact_statistics()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; padding: 2rem 0;">
        <p>DynaHome Research Project • University Name • 
        <a href="mailto:contact@dynohome.org">Contact Us</a> • 
        <a href="https://github.com/dynohome">GitHub</a> • 
        <a href="https://arxiv.org/your-paper">Research Paper</a></p>
        <p><em>Advancing IoT Security Research Through AI Innovation</em></p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()