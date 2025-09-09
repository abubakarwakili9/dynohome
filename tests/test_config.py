# test_config.py
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_configuration():
    print("Testing Configuration System...")
    print("=" * 40)
    
    try:
        # Test 1: Import config module
        from config import DynaHomeConfig, get_config
        print("✅ Config module imported successfully")
        
        # Test 2: Create config instance
        config = DynaHomeConfig(environment="development")
        print("✅ Config instance created")
        
        # Test 3: Test configuration values
        print(f"✅ API URL: {config.api.cve_api_url}")
        print(f"✅ Web port: {config.webapp.port}")
        print(f"✅ Debug mode: {config.webapp.enable_debug}")
        print(f"✅ Data directory: {config.data.data_directory}")
        
        # Test 4: Test config summary
        summary = config.get_configuration_summary()
        print("✅ Configuration summary generated")
        
        # Test 5: Test global config function
        global_config = get_config()
        print("✅ Global config function works")
        
        print("\n🎉 Configuration system working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

if __name__ == "__main__":
    test_configuration()