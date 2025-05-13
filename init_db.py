# init_db.py

import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('thirdeye.db')
c = conn.cursor()

# Create users table
c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)''')

# Create API keys table
c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    vendor TEXT,
    api_key TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)''')

# Create search history table
c.execute('''CREATE TABLE IF NOT EXISTS search_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    indicator TEXT,
    type TEXT,
    timestamp TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)''')

# Create ransomware incidents table
c.execute('''CREATE TABLE IF NOT EXISTS ransomware_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_name TEXT,
    target_org TEXT,
    sector TEXT,
    status TEXT,
    date TEXT,
    tags TEXT
)''')

# Insert default admin user if not exists
c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
          ('admin', generate_password_hash('admin')))

conn.commit()
conn.close()
