import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('thirdeye.db')
cursor = conn.cursor()

# Hash the password 'admin'
hashed_pw = generate_password_hash('admin')

# Check if admin user already exists
cursor.execute("SELECT * FROM users WHERE username = 'admin'")
exists = cursor.fetchone()

if not exists:
    cursor.execute('''
        INSERT INTO users (username, password, email, is_admin, theme)
        VALUES (?, ?, ?, ?, ?)
    ''', ('admin', hashed_pw, 'admin@localhost', 1, 'dark'))
    conn.commit()
    print("✅ Admin user 'admin' created.")
else:
    print("ℹ️ Admin user already exists.")

conn.close()
