import sqlite3
import os
import time
from datetime import date, datetime

DB_PATH = os.path.expanduser("~/airtel-wifi-manager/data/wifi_manager.db")

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Devices table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        ip TEXT,
        hostname TEXT,
        custom_name TEXT,
        is_blocked INTEGER DEFAULT 0,
        total_down_mb REAL DEFAULT 0.0,
        total_up_mb REAL DEFAULT 0.0,
        today_down_mb REAL DEFAULT 0.0,
        today_up_mb REAL DEFAULT 0.0,
        today_date TEXT,
        first_seen REAL,
        last_seen REAL,
        rate_limit_down INTEGER DEFAULT 0,
        rate_limit_up INTEGER DEFAULT 0,
        rate_limit_enabled INTEGER DEFAULT 0,
        notes TEXT DEFAULT ''
    )
    """)
    
    # Settings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)

    # Traffic history table for charts / logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac TEXT,
        timestamp REAL,
        down_mb REAL,
        up_mb REAL
    )
    """)

    # Domain / Search queries table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS domain_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        time_str TEXT,
        ip TEXT,
        mac TEXT,
        device_name TEXT,
        domain TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_queries_ts ON domain_queries(timestamp DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_queries_ip ON domain_queries(ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_queries_mac ON domain_queries(mac)")

    # Tethering / Hotspot alerts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tethering_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        time_str TEXT,
        ip TEXT,
        mac TEXT,
        device_name TEXT,
        ttl INTEGER,
        action TEXT DEFAULT 'Blocked (Dropped)'
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tether_ts ON tethering_alerts(timestamp DESC)")
    
    # Default settings
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('router_ip', '192.168.3.1')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_refresh_sec', '3')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('anti_tethering_enabled', '1')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('dns_logging_enabled', '1')")
    
    conn.commit()
    conn.close()

def get_setting(key, default=""):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key, value):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()

def get_all_devices():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_device(mac):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE mac = ?", (mac.upper(),))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def update_device_usage(mac, ip, hostname, down_delta_mb, up_delta_mb, is_blocked=0):
    mac = mac.upper()
    now = time.time()
    today_str = date.today().isoformat()
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
    existing = c.fetchone()
    
    if existing:
        today_date = existing["today_date"]
        # Reset today counters if day rolled over
        if today_date != today_str:
            new_today_down = down_delta_mb
            new_today_up = up_delta_mb
        else:
            new_today_down = existing["today_down_mb"] + down_delta_mb
            new_today_up = existing["today_up_mb"] + up_delta_mb
            
        new_total_down = existing["total_down_mb"] + down_delta_mb
        new_total_up = existing["total_up_mb"] + up_delta_mb
        
        c.execute("""
        UPDATE devices SET
            ip = COALESCE(NULLIF(?, ''), ip),
            hostname = COALESCE(NULLIF(?, ''), hostname),
            total_down_mb = ?,
            total_up_mb = ?,
            today_down_mb = ?,
            today_up_mb = ?,
            today_date = ?,
            last_seen = ?,
            is_blocked = ?
        WHERE mac = ?
        """, (ip, hostname, new_total_down, new_total_up, new_today_down, new_today_up, today_str, now, is_blocked, mac))
    else:
        c.execute("""
        INSERT INTO devices (
            mac, ip, hostname, custom_name, is_blocked,
            total_down_mb, total_up_mb, today_down_mb, today_up_mb, today_date,
            first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            mac, ip, hostname, '', is_blocked,
            down_delta_mb, up_delta_mb, down_delta_mb, up_delta_mb, today_str,
            now, now
        ))
        
    conn.commit()
    conn.close()

def set_device_name(mac, custom_name):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE devices SET custom_name = ? WHERE mac = ?", (custom_name.strip(), mac.upper()))
    conn.commit()
    conn.close()

def set_device_notes(mac, notes):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE devices SET notes = ? WHERE mac = ?", (notes, mac.upper()))
    conn.commit()
    conn.close()

def reset_device_usage(mac):
    today_str = date.today().isoformat()
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    UPDATE devices SET 
        total_down_mb = 0.0,
        total_up_mb = 0.0,
        today_down_mb = 0.0,
        today_up_mb = 0.0,
        today_date = ?
    WHERE mac = ?
    """, (today_str, mac.upper()))
    conn.commit()
    conn.close()

def reset_all_usage():
    today_str = date.today().isoformat()
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    UPDATE devices SET 
        total_down_mb = 0.0,
        total_up_mb = 0.0,
        today_down_mb = 0.0,
        today_up_mb = 0.0,
        today_date = ?
    """, (today_str,))
    conn.commit()
    conn.close()

def log_domain_query(ip, mac, device_name, domain):
    now = time.time()
    time_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO domain_queries (timestamp, time_str, ip, mac, device_name, domain)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (now, time_str, ip or '', (mac or '').upper(), device_name or '', domain.lower().strip()))
    conn.commit()
    conn.close()

def get_domain_queries(limit=100, search=None, mac_or_ip=None):
    conn = get_db()
    c = conn.cursor()
    query = "SELECT * FROM domain_queries WHERE 1=1"
    params = []
    
    if mac_or_ip:
        query += " AND (mac = ? OR ip = ?)"
        params.extend([mac_or_ip.upper(), mac_or_ip])
        
    if search:
        query += " AND (domain LIKE ? OR device_name LIKE ? OR ip LIKE ?)"
        term = f"%{search.strip()}%"
        params.extend([term, term, term])
        
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(min(int(limit), 1000))
    
    c.execute(query, params)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def clear_domain_queries(days=None):
    conn = get_db()
    c = conn.cursor()
    if days is not None and days > 0:
        cutoff = time.time() - (days * 86400)
        c.execute("DELETE FROM domain_queries WHERE timestamp < ?", (cutoff,))
    else:
        c.execute("DELETE FROM domain_queries")
    conn.commit()
    conn.close()

def log_tethering_alert(ip, mac, device_name, ttl, action="Blocked (Dropped)"):
    now = time.time()
    time_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    c = conn.cursor()
    # Throttle alerts from same IP within 15 seconds to avoid flooding
    c.execute("SELECT timestamp FROM tethering_alerts WHERE ip = ? ORDER BY timestamp DESC LIMIT 1", (ip,))
    last = c.fetchone()
    if last and (now - last["timestamp"]) < 15:
        conn.close()
        return
        
    c.execute("""
    INSERT INTO tethering_alerts (timestamp, time_str, ip, mac, device_name, ttl, action)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (now, time_str, ip or '', (mac or '').upper(), device_name or '', ttl, action))
    conn.commit()
    conn.close()

def get_tethering_alerts(limit=50):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM tethering_alerts ORDER BY timestamp DESC LIMIT ?", (min(int(limit), 200),))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def clear_tethering_alerts():
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM tethering_alerts")
    conn.commit()
    conn.close()
