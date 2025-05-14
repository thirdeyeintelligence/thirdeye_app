import sqlite3

conn = sqlite3.connect('thirdeye.db')
c = conn.cursor()

# Users table with theme column
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT,
    is_admin INTEGER DEFAULT 0,
    theme TEXT DEFAULT 'dark'
)
''')

# API keys per user and vendor
c.execute('''
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    vendor TEXT,
    api_key TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

# Search history table
c.execute('''
CREATE TABLE IF NOT EXISTS search_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    indicator TEXT,
    type TEXT,
    timestamp TEXT,
    verdict TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

# Ransomware tracker table
c.execute('''
CREATE TABLE IF NOT EXISTS ransomware_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_name TEXT,
    target_org TEXT,
    sector TEXT,
    status TEXT,
    date TEXT,
    tags TEXT,
    created_by TEXT
)
''')

print("✅ Database tables created/validated.")
conn.commit()
conn.close()
