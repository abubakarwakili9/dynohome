# test_database.py
import sys
from pathlib import Path
import json
import tempfile
import os

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_database():
    print("Testing Database System...")
    print("=" * 40)
    
    try:
        # Test 1: Import database module
        from database import DynaHomeDatabase
        print("✅ Database module imported successfully")
        
        # Test 2: Create database instance (use temporary file for testing)
        test_db_path = "test_database.db"
        db = DynaHomeDatabase(test_db_path)
        print("✅ Database instance created")
        
        # Test 3: Test dataset save
        test_dataset = {
            'id': 'test_dataset_001',
            'title': 'Test Smart Home Dataset',
            'version': 'v1.0.0',
            'description': 'Test dataset for validation',
            'file_size_mb': 5.2,
            'quality_score': 0.85,
            'samples': {'total': 1000, 'attack': 200}
        }
        
        db.save_dataset_metadata(test_dataset)
        print("✅ Dataset metadata saved")
        
        # Test 4: Test download tracking
        db.track_download('test_dataset_001', 'CSV')
        db.track_download('test_dataset_001', 'JSON')
        print("✅ Downloads tracked")
        
        # Test 5: Test statistics
        stats = db.get_dataset_stats()
        print("✅ Statistics retrieved")
        print(f"   - Total datasets: {stats['total_datasets']}")
        print(f"   - Total downloads: {stats['total_downloads']}")
        print(f"   - Average quality: {stats['average_quality']}")
        
        # Test 6: Verify database file exists
        if Path(test_db_path).exists():
            print("✅ Database file created successfully")
            file_size = Path(test_db_path).stat().st_size
            print(f"   - File size: {file_size} bytes")
        
        # Test 7: Test another dataset
        test_dataset_2 = {
            'id': 'test_dataset_002',
            'title': 'Test IoT Protocol Dataset',
            'version': 'v1.1.0',
            'description': 'Test protocol dataset',
            'file_size_mb': 3.8,
            'quality_score': 0.92,
            'samples': {'total': 800, 'attack': 150}
        }
        
        db.save_dataset_metadata(test_dataset_2)
        print("✅ Second dataset saved")
        
        # Get updated stats
        updated_stats = db.get_dataset_stats()
        print(f"✅ Updated stats - Total datasets: {updated_stats['total_datasets']}")
        
        print("\n🎉 Database system working correctly!")
        
        # Cleanup test database
        try:
            os.remove(test_db_path)
            print("✅ Test database cleaned up")
        except:
            print("⚠️ Could not remove test database (normal on some systems)")
            
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        import traceback
        print(traceback.format_exc())
        return False

if __name__ == "__main__":
    test_database()