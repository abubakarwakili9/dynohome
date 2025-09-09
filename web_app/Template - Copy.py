# test_logging.py
import sys
from pathlib import Path
import time

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_logging():
    print("Testing Logging System...")
    print("=" * 40)
    
    try:
        # Test 1: Import logging module
        from logging_config import setup_logging, get_logger
        print("✅ Logging module imported successfully")
        
        # Test 2: Setup logging system
        logger_system = setup_logging()
        print("✅ Logging system initialized")
        
        # Test 3: Get a logger
        logger = get_logger('test.module')
        print("✅ Logger instance created")
        
        # Test 4: Test different log types
        logger_system.log_user_action("test_action", {"test": "data"})
        print("✅ User action logged")
        
        logger_system.log_threat_processing(10, 3, 15.5, 1)
        print("✅ Threat processing logged")
        
        logger_system.log_error("test_error", "This is a test error", {"context": "testing"})
        print("✅ Error logged")
        
        logger_system.log_performance_metric("test_operation", 2.5, True)
        print("✅ Performance metric logged")
        
        # Test 5: Get metrics summary
        metrics = logger_system.get_metrics_summary()
        print("✅ Metrics summary generated")
        print(f"   - Total operations: {metrics['recent_performance']['operations_last_hour']}")
        
        # Test 6: Check log files created
        log_dir = Path("data/logs")
        if log_dir.exists():
            log_files = list(log_dir.glob("*.log"))
            print(f"✅ Log files created: {len(log_files)} files")
            for log_file in log_files[:3]:  # Show first 3
                print(f"   - {log_file.name}")
        
        print("\n🎉 Logging system working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Logging test failed: {e}")
        import traceback
        print(traceback.format_exc())
        return False

if __name__ == "__main__":
    test_logging()