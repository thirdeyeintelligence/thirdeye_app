from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import random
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from utils import detect_indicator_type
from collections import defaultdict, Counter

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change for production
DATABASE = 'thirdeye.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Fun facts mapped by indicator type
FUN_FACTS = {
    'IP Address': ["This IP has traveled more than you this year!"],
    'URL': ["Some URLs like to masquerade as cats."],
    'Domain': ["Domains are the birthplaces of phishing empires."],
    'MD5 Hash': ["Hashes never lie... but they can be misunderstood."],
    'SHA1 Hash': ["Hashes never lie... but they can be misunderstood."],
    'SHA256 Hash': ["Hashes never lie... but they can be misunderstood."],
    'CVE': ["This CVE might just ruin someone's weekend."],
    'Unknown': ["Some indicators prefer to stay mysterious."]
}

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (request.form['username'],)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], request.form['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    history = conn.execute('SELECT indicator, type, timestamp FROM search_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10',
                           (session['user_id'],)).fetchall()
    conn.close()

    if request.method == 'POST':
        indicator = request.form['indicator']
        itype = detect_indicator_type(indicator)
        fun_fact = random.choice(FUN_FACTS.get(itype, ["Interesting indicator!"]))

        conn = get_db_connection()
        conn.execute('INSERT INTO search_history (user_id, indicator, type, timestamp) VALUES (?, ?, ?, ?)',
                     (session['user_id'], indicator, itype, datetime.now().isoformat()))
        conn.commit()
        conn.close()

        result = {
            'indicator': indicator,
            'indicator_type': itype,
            'fun_fact': fun_fact,
            'vendors': ['VirusTotal', 'URLScan', 'ThreatQ'],  # Mock data
            'splunk_query': f'index=threatintel "{indicator}"',
            'sentinel_query': f'SecurityEvent | where EventData contains "{indicator}"'
        }
        return render_template('result.html', result=result)

    return render_template('dashboard.html', history=history)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    if request.method == 'POST':
        conn.execute('INSERT INTO api_keys (user_id, vendor, api_key) VALUES (?, ?, ?)',
                     (session['user_id'], request.form['vendor'], request.form['api_key']))
        conn.commit()
    apis = conn.execute('SELECT vendor, api_key FROM api_keys WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('profile.html', apis=apis)

@app.route('/ransomware-tracker', methods=['GET', 'POST'])
def ransomware_tracker():
    conn = get_db_connection()
    if request.method == 'POST':
        conn.execute('''
            INSERT INTO ransomware_incidents
            (group_name, target_org, sector, status, date, tags)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            request.form['group_name'],
            request.form['target_org'],
            request.form['sector'],
            request.form['status'],
            request.form['date'],
            request.form['tags']
        ))
        conn.commit()

    rows = conn.execute('SELECT * FROM ransomware_incidents').fetchall()
    conn.close()

    data_by_year = defaultdict(list)
    group_counts = Counter()
    sector_counts = Counter()

    for row in rows:
        year = datetime.strptime(row['date'], "%Y-%m-%d").year
        data_by_year[year].append(row)
        group_counts[row['group_name']] += 1
        sector_counts[row['sector']] += 1

    return render_template('ransomware_tracker.html',
                           data_by_year=dict(data_by_year),
                           top_groups=group_counts.most_common(10),
                           top_sectors=sector_counts.most_common(10))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Needed for Render to auto-discover this app
if __name__ != '__main__':
    application = app

# Local run only
if __name__ == '__main__':
    app.run(debug=True)
