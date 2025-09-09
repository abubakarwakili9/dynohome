#!/usr/bin/env python3
"""
DynaHome Admin Interface Launcher
Secure administrative access only
"""

import sys
import os
import subprocess
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

def launch_admin_panel():
    """Launch the admin panel with security checks"""
    
    print("🔐 DynaHome Administration Panel")
    print("=" * 40)
    
    # Security environment checks
    if os.getenv('DYNOHOME_ENV') == 'production':
        print("⚠️  PRODUCTION ENVIRONMENT DETECTED")
        print("Ensure secure network access only")
    
    # Check if admin credentials are set
    admin_user = os.getenv('DYNOHOME_ADMIN_USER')
    admin_hash = os.getenv('DYNOHOME_ADMIN_PASS_HASH')
    
    if not admin_user or not admin_hash:
        print("⚠️  Using default credentials")
        print("Change DYNOHOME_ADMIN_USER and DYNOHOME_ADMIN_PASS_HASH environment variables")
    
    print("🚀 Launching admin interface...")
    print("🔗 Admin URL: http://localhost:8502")
    print("🔒 Authentication required")
    
    try:
        # Launch on different port for security
        cmd = [
            "streamlit", "run",
            str(project_root / "web_app" / "admin_panel.py"),
            "--server.port=8502",  # Different port
            "--server.address=127.0.0.1",  # Localhost only
            "--server.headless=true"
        ]
        
        subprocess.run(cmd)
        
    except KeyboardInterrupt:
        print("\n👋 Admin panel shutdown")
    except Exception as e:
        print(f"❌ Failed to launch admin panel: {e}")

if __name__ == "__main__":
    launch_admin_panel()