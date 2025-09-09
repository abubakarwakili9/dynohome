# database.py - Updated for better compatibility
import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

class DynaHomeDatabase:
    def __init__(self, db_path: str = "data/dynohome.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            # Create table with all columns needed
            conn.execute('''
                CREATE TABLE IF NOT EXISTS datasets (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    file_path TEXT,
                    file_size_mb REAL,
                    quality_score REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    download_count INTEGER DEFAULT 0
                )
            ''')
            
            # Check and add missing columns safely
            self._ensure_columns(conn)
            
            # Enhanced downloads tracking
            conn.execute('''
                CREATE TABLE IF NOT EXISTS downloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dataset_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_info TEXT,
                    format_type TEXT,
                    file_size_bytes INTEGER,
                    FOREIGN KEY (dataset_id) REFERENCES datasets (id)
                )
            ''')
            
            # Create indexes for better performance
            conn.execute('CREATE INDEX IF NOT EXISTS idx_datasets_title ON datasets(title)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_downloads_dataset_id ON downloads(dataset_id)')
    
    def _ensure_columns(self, conn):
        """Safely add missing columns to existing table"""
        # Get current columns
        cursor = conn.execute("PRAGMA table_info(datasets)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        
        # Define all columns we need
        required_columns = {
            'base_name': 'TEXT',
            'version': 'TEXT DEFAULT "v1.0"',
            'samples_total': 'INTEGER DEFAULT 0',
            'samples_attack': 'INTEGER DEFAULT 0', 
            'samples_normal': 'INTEGER DEFAULT 0',
            'status': 'TEXT DEFAULT "active"',
            'is_latest': 'BOOLEAN DEFAULT TRUE',
            'threat_count': 'INTEGER DEFAULT 0',
            'metadata': 'TEXT'
        }
        
        # Add missing columns
        for column_name, column_type in required_columns.items():
            if column_name not in existing_columns:
                try:
                    conn.execute(f'ALTER TABLE datasets ADD COLUMN {column_name} {column_type}')
                except sqlite3.OperationalError:
                    # Column might already exist or other error - continue
                    pass
        
        # Set base_name for existing records that don't have it
        try:
            conn.execute('''
                UPDATE datasets 
                SET base_name = CASE 
                    WHEN base_name IS NULL OR base_name = '' 
                    THEN SUBSTR(id, 1, CASE 
                        WHEN INSTR(id, '_') > 0 THEN INSTR(id, '_') - 1 
                        ELSE LENGTH(id) 
                    END)
                    ELSE base_name 
                END
                WHERE base_name IS NULL OR base_name = ''
            ''')
        except sqlite3.OperationalError:
            pass
    
    def save_dataset_metadata(self, dataset: Dict):
        """Flexible save method that works with any schema"""
        with sqlite3.connect(self.db_path) as conn:
            # Extract basic info
            dataset_id = dataset.get('id', f"dataset_{int(datetime.now().timestamp())}")
            title = dataset.get('title', 'Untitled Dataset')
            description = dataset.get('description', '')
            file_path = dataset.get('file_path', '')
            file_size_mb = dataset.get('file_size_mb', 0)
            quality_score = dataset.get('quality_score', 0)
            
            # Handle samples data
            samples = dataset.get('samples', {})
            if isinstance(samples, dict):
                samples_total = samples.get('total', 0)
                samples_attack = samples.get('attack', 0)
                samples_normal = samples.get('normal', 0)
            else:
                samples_total = 0
                samples_attack = 0
                samples_normal = 0
            
            # Get current columns to determine which ones to insert
            cursor = conn.execute("PRAGMA table_info(datasets)")
            existing_columns = {row[1] for row in cursor.fetchall()}
            
            # Build dynamic insert statement
            columns = ['id', 'title', 'description', 'file_path', 'file_size_mb', 'quality_score']
            values = [dataset_id, title, description, file_path, file_size_mb, quality_score]
            
            # Add optional columns if they exist
            if 'base_name' in existing_columns:
                columns.append('base_name')
                base_name = dataset_id.split('_')[0] if '_' in dataset_id else dataset_id
                values.append(base_name)
            
            if 'version' in existing_columns:
                columns.append('version')
                values.append(dataset.get('version', 'v1.0'))
            
            if 'samples_total' in existing_columns:
                columns.extend(['samples_total', 'samples_attack', 'samples_normal'])
                values.extend([samples_total, samples_attack, samples_normal])
            
            if 'status' in existing_columns:
                columns.append('status')
                values.append('active')
            
            if 'is_latest' in existing_columns:
                columns.append('is_latest')
                values.append(True)
            
            if 'threat_count' in existing_columns:
                columns.append('threat_count')
                values.append(dataset.get('threat_count', 0))
            
            if 'metadata' in existing_columns:
                columns.append('metadata')
                values.append(json.dumps(dataset))
            
            # Execute insert
            placeholders = ','.join(['?' for _ in columns])
            query = f"INSERT OR REPLACE INTO datasets ({','.join(columns)}) VALUES ({placeholders})"
            
            conn.execute(query, values)
            
            return dataset_id
    
    def save_dataset_with_versioning(self, dataset_info):
        """Save dataset with versioning - fallback to simple save if versioning not supported"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check if versioning columns exist
                cursor = conn.execute("PRAGMA table_info(datasets)")
                existing_columns = {row[1] for row in cursor.fetchall()}
                
                if 'base_name' not in existing_columns or 'version' not in existing_columns:
                    # Fall back to simple save
                    dataset_info['id'] = f"{dataset_info['base_name']}_{int(datetime.now().timestamp())}"
                    return self.save_dataset_metadata(dataset_info), "v1.0"
                
                # Full versioning logic
                base_name = dataset_info['base_name']
                
                # Check for existing versions
                cursor = conn.execute('''
                    SELECT version FROM datasets 
                    WHERE base_name = ? AND is_latest = TRUE
                    ORDER BY created_at DESC LIMIT 1
                ''', (base_name,))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Increment version
                    current_version = existing[0]
                    try:
                        if '.' in current_version:
                            major, minor = map(int, current_version.replace('v', '').split('.'))
                            new_version = f"v{major}.{minor + 1}"
                        else:
                            new_version = "v1.1"
                    except ValueError:
                        new_version = "v1.1"
                    
                    # Mark old version as not latest
                    conn.execute('''
                        UPDATE datasets SET is_latest = FALSE 
                        WHERE base_name = ? AND is_latest = TRUE
                    ''', (base_name,))
                else:
                    new_version = "v1.0"
                
                # Create new dataset with version
                dataset_info['version'] = new_version
                dataset_info['id'] = f"{base_name}_{new_version.replace('.', '_')}"
                
                dataset_id = self.save_dataset_metadata(dataset_info)
                return dataset_id, new_version
                
        except Exception as e:
            # Fallback to simple save
            dataset_info['id'] = f"{dataset_info['base_name']}_{int(datetime.now().timestamp())}"
            return self.save_dataset_metadata(dataset_info), "v1.0"
    
    def get_public_datasets(self, include_all_versions=False):
        """Get datasets with flexible column handling"""
        with sqlite3.connect(self.db_path) as conn:
            # Check what columns exist
            cursor = conn.execute("PRAGMA table_info(datasets)")
            existing_columns = {row[1] for row in cursor.fetchall()}
            
            # Build query based on available columns
            base_columns = ['id', 'title', 'description', 'file_path', 'file_size_mb', 'quality_score', 'created_at', 'download_count']
            
            # Filter to only existing columns
            available_columns = [col for col in base_columns if col in existing_columns]
            
            # Add optional columns
            optional_columns = ['base_name', 'version', 'samples_total', 'samples_attack', 'samples_normal', 'status', 'is_latest', 'threat_count', 'updated_at', 'metadata']
            for col in optional_columns:
                if col in existing_columns:
                    available_columns.append(col)
            
            query = f"SELECT {','.join(available_columns)} FROM datasets"
            
            # Add filters if possible
            if 'status' in existing_columns:
                if include_all_versions:
                    query += " WHERE status = 'active' ORDER BY created_at DESC"
                else:
                    if 'is_latest' in existing_columns:
                        query += " WHERE status = 'active' AND is_latest = TRUE ORDER BY created_at DESC"
                    else:
                        query += " WHERE status = 'active' ORDER BY created_at DESC"
            else:
                query += " ORDER BY created_at DESC"
            
            cursor = conn.execute(query)
            datasets = []
            
            for row in cursor.fetchall():
                dataset = {}
                for i, col_name in enumerate(available_columns):
                    if i < len(row):
                        dataset[col_name] = row[i]
                
                # Set defaults for missing columns
                dataset.setdefault('base_name', dataset.get('id', 'unknown').split('_')[0])
                dataset.setdefault('version', 'v1.0')
                dataset.setdefault('samples_total', 0)
                dataset.setdefault('samples_attack', 0)
                dataset.setdefault('samples_normal', 0)
                dataset.setdefault('status', 'active')
                dataset.setdefault('is_latest', True)
                dataset.setdefault('threat_count', 0)
                dataset.setdefault('download_count', 0)
                
                datasets.append(dataset)
            
            return datasets
    
    def get_dataset_by_id(self, dataset_id: str) -> Optional[Dict]:
        """Get a specific dataset by ID with flexible column handling"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            # Get column names
            column_names = [description[0] for description in cursor.description]
            
            # Build dataset dict
            dataset = {}
            for i, value in enumerate(row):
                if i < len(column_names):
                    dataset[column_names[i]] = value
            
            return dataset
    
    def track_download(self, dataset_id: str, format_type: str, user_info: str = None, file_size_bytes: int = None):
        """Track download with error handling"""
        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute('''
                    INSERT INTO downloads (dataset_id, format_type, user_info, file_size_bytes)
                    VALUES (?, ?, ?, ?)
                ''', (dataset_id, format_type, user_info, file_size_bytes))
                
                conn.execute('''
                    UPDATE datasets SET download_count = download_count + 1 
                    WHERE id = ?
                ''', (dataset_id,))
            except sqlite3.Error:
                # If downloads table doesn't exist or other error, continue silently
                pass
    
    def get_dataset_stats(self) -> Dict:
        """Get dataset statistics with error handling"""
        with sqlite3.connect(self.db_path) as conn:
            try:
                # Check available columns
                cursor = conn.execute("PRAGMA table_info(datasets)")
                existing_columns = {row[1] for row in cursor.fetchall()}
                
                # Build stats query based on available columns
                stats_columns = []
                if 'quality_score' in existing_columns:
                    stats_columns.append('AVG(quality_score) as avg_quality')
                if 'samples_total' in existing_columns:
                    stats_columns.append('SUM(samples_total) as total_samples')
                if 'samples_attack' in existing_columns:
                    stats_columns.append('SUM(samples_attack) as total_attack_samples')
                if 'file_size_mb' in existing_columns:
                    stats_columns.append('SUM(file_size_mb) as total_size_mb')
                if 'download_count' in existing_columns:
                    stats_columns.append('SUM(download_count) as total_downloads')
                
                base_query = "SELECT COUNT(*) as total_datasets"
                if stats_columns:
                    base_query += ", " + ", ".join(stats_columns)
                base_query += " FROM datasets"
                
                if 'status' in existing_columns:
                    base_query += " WHERE status = 'active'"
                
                cursor = conn.execute(base_query)
                row = cursor.fetchone()
                
                stats = {
                    'total_datasets': row[0] if row else 0,
                    'average_quality': 0,
                    'total_samples': 0,
                    'total_attack_samples': 0,
                    'total_size_mb': 0,
                    'total_downloads': 0
                }
                
                if row and len(row) > 1:
                    col_index = 1
                    if 'quality_score' in existing_columns:
                        stats['average_quality'] = round(row[col_index] or 0, 3)
                        col_index += 1
                    if 'samples_total' in existing_columns:
                        stats['total_samples'] = row[col_index] or 0
                        col_index += 1
                    if 'samples_attack' in existing_columns:
                        stats['total_attack_samples'] = row[col_index] or 0
                        col_index += 1
                    if 'file_size_mb' in existing_columns:
                        stats['total_size_mb'] = round(row[col_index] or 0, 2)
                        col_index += 1
                    if 'download_count' in existing_columns:
                        stats['total_downloads'] = row[col_index] or 0
                
                return stats
                
            except sqlite3.Error as e:
                return {
                    'total_datasets': 0,
                    'error': str(e)
                }
    
    def search_datasets(self, query: str, limit: int = 10) -> List[Dict]:
        """Search datasets with flexible column handling"""
        try:
            datasets = self.get_public_datasets()
            # Simple search in memory
            results = []
            query_lower = query.lower()
            
            for dataset in datasets:
                title = str(dataset.get('title', '')).lower()
                description = str(dataset.get('description', '')).lower()
                
                if query_lower in title or query_lower in description:
                    results.append(dataset)
                    if len(results) >= limit:
                        break
            
            return results
        except:
            return []