# test_integration.py
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_config():
    try:
        from config import get_config
        config = get_config()
        print("✅ Config system working")
        return True
    except Exception as e:
        print(f"❌ Config system error: {e}")
        return False

def test_logging():
    try:
        from logging_config import setup_logging
        logger_system = setup_logging()
        print("✅ Logging system working")
        return True
    except Exception as e:
        print(f"❌ Logging system error: {e}")
        return False

def test_database():
    try:
        from database import DynaHomeDatabase
        db = DynaHomeDatabase(":memory:")
        print("✅ Database system working")
        return True
    except Exception as e:
        print(f"❌ Database system error: {e}")
        return False

def test_core_modules():
    try:
        from threat_collector import ThreatCollector
        from ai_classifier import IoTThreatClassifier
        print("✅ Core modules working")
        return True
    except Exception as e:
        print(f"❌ Core modules error: {e}")
        return False

if __name__ == "__main__":
    print("Testing DynaHome Integration...")
    print("=" * 40)
    
    tests = [test_config, test_logging, test_database, test_core_modules]
    passed = sum(test() for test in tests)
    
    print("=" * 40)
    print(f"Tests passed: {passed}/{len(tests)}")
    
    if passed == len(tests):
        print("🎉 All systems integrated successfully!")
    else:
        print("⚠️  Some systems need attention")