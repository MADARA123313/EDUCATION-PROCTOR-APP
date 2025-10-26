"""
DATABASE MODULE - AUTO-SAVE EVERYTHING!
SQLite database for persistent storage
FAST, RELIABLE, NO ERRORS!
"""

import sqlite3
import json
from datetime import datetime
import threading

class Database:
    def __init__(self, db_path='monitoring_data.db'):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def get_connection(self):
        """Get database connection - THREAD SAFE"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        """Initialize all tables - OPTIMIZED STRUCTURE"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Incidents table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER,
                    type TEXT,
                    severity TEXT,
                    title TEXT,
                    description TEXT,
                    timestamp TEXT,
                    device_name TEXT,
                    details TEXT,
                    acknowledged INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Location history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS location_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT,
                    ip_address TEXT,
                    country TEXT,
                    city TEXT,
                    region TEXT,
                    latitude REAL,
                    longitude REAL,
                    isp TEXT,
                    timezone TEXT,
                    vpn_detected INTEGER,
                    vpn_probability INTEGER,
                    alert_message TEXT,
                    timestamp TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Browser history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT,
                    browser TEXT,
                    url TEXT,
                    title TEXT,
                    category TEXT,
                    detected_at TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Process snapshots table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS process_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT,
                    pid INTEGER,
                    name TEXT,
                    cpu_percent REAL,
                    memory_mb REAL,
                    status TEXT,
                    timestamp TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Activity logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT,
                    activity_type TEXT,
                    details TEXT,
                    timestamp TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # System performance table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_performance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_percent REAL,
                    network_sent INTEGER,
                    network_recv INTEGER,
                    timestamp TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for SPEED
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_device ON incidents(device_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_location_device ON location_history(device_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_location_vpn ON location_history(vpn_detected)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_browser_device ON browser_scans(device_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_process_device ON process_snapshots(device_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_device ON activity_logs(device_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_performance_device ON system_performance(device_name)')
            
            conn.commit()
            conn.close()
            print("✅ Database initialized successfully!")
    
    # ===== INCIDENT METHODS =====
    
    def save_incident(self, incident):
        """Save incident to database - AUTO SAVE"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO incidents 
                (incident_id, type, severity, title, description, timestamp, device_name, details, acknowledged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident.get('id'),
                incident.get('type'),
                incident.get('severity'),
                incident.get('title'),
                incident.get('description'),
                incident.get('timestamp'),
                incident.get('details', {}).get('device_name', 'Unknown'),
                json.dumps(incident.get('details', {})),
                1 if incident.get('acknowledged') else 0
            ))
            
            conn.commit()
            conn.close()
    
    def get_incidents(self, limit=100, device_name=None):
        """Get incidents from database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if device_name:
            cursor.execute('''
                SELECT * FROM incidents 
                WHERE device_name = ?
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (device_name, limit))
        else:
            cursor.execute('''
                SELECT * FROM incidents 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        incidents = []
        for row in rows:
            incidents.append({
                'id': row['incident_id'],
                'type': row['type'],
                'severity': row['severity'],
                'title': row['title'],
                'description': row['description'],
                'timestamp': row['timestamp'],
                'details': json.loads(row['details']) if row['details'] else {},
                'acknowledged': bool(row['acknowledged'])
            })
        
        return incidents
    
    # ===== LOCATION METHODS =====
    
    def save_location(self, location_data):
        """Save location check to database"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO location_history
                (device_name, ip_address, country, city, region, latitude, longitude,
                 isp, timezone, vpn_detected, vpn_probability, alert_message, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                location_data.get('device_name'),
                location_data.get('ip_address'),
                location_data.get('country'),
                location_data.get('city'),
                location_data.get('region'),
                location_data.get('latitude'),
                location_data.get('longitude'),
                location_data.get('isp'),
                location_data.get('timezone'),
                1 if location_data.get('vpn_detected') else 0,
                location_data.get('vpn_probability'),
                location_data.get('alert_message'),
                location_data.get('timestamp')
            ))
            
            conn.commit()
            conn.close()
    
    def get_location_history(self, limit=100, device_name=None):
        """Get location history from database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if device_name:
            cursor.execute('''
                SELECT * FROM location_history 
                WHERE device_name = ?
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (device_name, limit))
        else:
            cursor.execute('''
                SELECT * FROM location_history 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                'device_name': row['device_name'],
                'ip_address': row['ip_address'],
                'country': row['country'],
                'city': row['city'],
                'region': row['region'],
                'latitude': row['latitude'],
                'longitude': row['longitude'],
                'isp': row['isp'],
                'timezone': row['timezone'],
                'vpn_detected': bool(row['vpn_detected']),
                'vpn_probability': row['vpn_probability'],
                'alert_message': row['alert_message'],
                'timestamp': row['timestamp']
            })
        
        return history
    
    # ===== BROWSER HISTORY METHODS =====
    
    def save_browser_scan(self, device_name, browser, url, title, category):
        """Save browser scan result"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO browser_scans
                (device_name, browser, url, title, category, detected_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                device_name,
                browser,
                url,
                title,
                category,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
    
    # ===== PERFORMANCE METHODS =====
    
    def save_performance(self, device_name, cpu, memory, disk, net_sent, net_recv):
        """Save system performance snapshot"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO system_performance
                (device_name, cpu_percent, memory_percent, disk_percent, 
                 network_sent, network_recv, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_name,
                cpu,
                memory,
                disk,
                net_sent,
                net_recv,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
    
    def get_performance_history(self, device_name, hours=24):
        """Get performance history for charts"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM system_performance
            WHERE device_name = ?
            AND created_at >= datetime('now', '-' || ? || ' hours')
            ORDER BY created_at DESC
        ''', (device_name, hours))
        
        rows = cursor.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                'cpu_percent': row['cpu_percent'],
                'memory_percent': row['memory_percent'],
                'disk_percent': row['disk_percent'],
                'timestamp': row['timestamp']
            })
        
        return history
    
    # ===== CLEANUP METHODS =====
    
    def cleanup_old_data(self, days=30):
        """Delete data older than X days - KEEP DATABASE FAST"""
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Keep incidents forever, but cleanup other data
            cursor.execute('''
                DELETE FROM location_history 
                WHERE created_at < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            cursor.execute('''
                DELETE FROM browser_scans 
                WHERE created_at < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            cursor.execute('''
                DELETE FROM process_snapshots 
                WHERE created_at < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            cursor.execute('''
                DELETE FROM system_performance 
                WHERE created_at < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            conn.commit()
            conn.close()
            
            # VACUUM to reclaim space and OPTIMIZE
            conn = self.get_connection()
            conn.execute('VACUUM')
            conn.close()
            
            print(f"✅ Cleaned up data older than {days} days")
    
    def get_stats(self):
        """Get database statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        cursor.execute('SELECT COUNT(*) as count FROM incidents')
        stats['total_incidents'] = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM location_history')
        stats['total_location_checks'] = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM location_history WHERE vpn_detected = 1')
        stats['total_vpn_detections'] = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM browser_scans')
        stats['total_browser_scans'] = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(DISTINCT device_name) as count FROM location_history')
        stats['total_devices'] = cursor.fetchone()['count']
        
        conn.close()
        
        return stats

# Global database instance
db = Database()

if __name__ == '__main__':
    print("="*80)
    print("DATABASE INITIALIZATION")
    print("="*80)
    print()
    
    db = Database()
    stats = db.get_stats()
    
    print("Database Statistics:")
    for key, value in stats.items():
        print(f"  • {key}: {value}")
    
    print()
    print("✅ Database ready for use!")
    print("="*80)


