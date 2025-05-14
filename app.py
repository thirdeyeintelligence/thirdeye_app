from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import random
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from utils import detect_indicator_type
from api_clients import call_virustotal_detailed, call_abusech, call_opencti, call_anyrun

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'thirdeye.db'

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

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def calculate_verdict(vendor_hits):
    score = sum(vendor_hits.values())
    if score >= 3:
        return "☠️ Definitely Malicious"
    elif score == 2:
        return "⚠️ Suspicious Activity"
    elif score == 1:
        return "🧐 Possibly Harmless"
    return "✅ Likely Safe"

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (request.form['username'],)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], request.form['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            session['theme'] = user['theme'] if 'theme' in user.keys() else 'dark'
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    history = conn.execute('''
        SELECT sh.indicator, sh.type, MAX(sh.timestamp) as timestamp, u.username, sh.verdict
        FROM search_history sh
        JOIN users u ON sh.user_id = u.id
        GROUP BY sh.indicator, sh.type
        ORDER BY timestamp DESC LIMIT 20
    ''').fetchall()
    stats = conn.execute('SELECT verdict, COUNT(*) as count FROM search_history GROUP BY verdict').fetchall()
    type_counts = conn.execute('SELECT type, COUNT(*) as count FROM search_history GROUP BY type').fetchall()
    trend_data = conn.execute('SELECT DATE(timestamp) as day, COUNT(*) as count FROM search_history GROUP BY day ORDER BY day ASC').fetchall()
    conn.close()

    if request.method == 'POST':
        return redirect(url_for('view_result', indicator=request.form['indicator']))

    return render_template('dashboard.html', history=history, stats=stats, trend_data=trend_data, type_counts=type_counts)

@app.route('/result/<indicator>')
def view_result(indicator):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    itype = detect_indicator_type(indicator)
    fun_fact = random.choice(FUN_FACTS.get(itype, ["Interesting indicator!"]))

    # Fetch API keys
    conn = get_db_connection()
    key_rows = conn.execute('SELECT vendor, api_key FROM api_keys WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    key_map = {row['vendor']: row['api_key'] for row in key_rows}

    # Vendor integrations
    vt_data = call_virustotal_detailed(indicator, key_map.get('VirusTotal'))
    abuse_data = call_abusech(indicator, key_map.get('AbuseCH'))
    opencti_data = call_opencti(indicator, key_map.get('OpenCTI'))
    anyrun_data = call_anyrun(indicator, key_map.get('AnyRun'))

    # Detection score
    vendor_hits = {
        'VirusTotal': vt_data['malicious_count'] if vt_data else 0,
        'AbuseCH': abuse_data['score'] if abuse_data else 0,
        'OpenCTI': opencti_data['score'] if opencti_data else 0,
        'AnyRun': anyrun_data['score'] if anyrun_data else 0
    }

    verdict = calculate_verdict(vendor_hits)

    # Insert into search_history
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO search_history (user_id, indicator, type, timestamp, verdict)
        VALUES (?, ?, ?, ?, ?)
    ''', (session['user_id'], indicator, itype, datetime.now().isoformat(), verdict))
    conn.commit()
    conn.close()

    # Queries and result formatting
    queries = {
        'Sentinel': f"SecurityEvent | where EventID == 4688 and CommandLine has '{indicator}'",
        'Splunk': f"index=main sourcetype=processes CommandLine=*{indicator}*",
        'CrowdStrike': f"event_platform=Win CommandLine=*{indicator}*",
        'SentinelOne': f"events where indicator contains '{indicator}'"
    }

    result = {
        'indicator': indicator,
        'indicator_type': itype,
        'fun_fact': fun_fact,
        'queries': queries,
        'vt': vt_data,
        'verdict': verdict,
        'vendor_chart': vendor_hits
    }

    return render_template('result.html', result=result)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    api_keys = conn.execute('SELECT * FROM api_keys WHERE user_id = ?', (session['user_id'],)).fetchall()

    if request.method == 'POST':
        if request.form.get('action') == 'add_user' and session.get('is_admin'):
            uname = request.form.get('new_username')
            upass = generate_password_hash(request.form.get('new_password'))
            email = request.form.get('new_email')
            is_admin = 1 if request.form.get('role') == 'admin' else 0
            conn.execute('INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)',
                         (uname, upass, email, is_admin))
        elif request.form.get('action') == 'delete_user' and session.get('is_admin'):
            uid = request.form.get('user_id')
            if int(uid) != session['user_id']:
                conn.execute('DELETE FROM users WHERE id = ?', (uid,))
        else:
            new_password = request.form.get('new_password')
            email = request.form.get('email')
            theme = request.form.get('theme')
            if new_password:
                hashed_pw = generate_password_hash(new_password)
                conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_pw, session['user_id']))
            if email:
                conn.execute('UPDATE users SET email = ? WHERE id = ?', (email, session['user_id']))
            if theme:
                conn.execute('UPDATE users SET theme = ? WHERE id = ?', (theme, session['user_id']))
                session['theme'] = theme

            for vendor in ['VirusTotal', 'URLScan', 'OpenCTI', 'AnyRun', 'AbuseCH']:
                key = request.form.get(vendor)
                if key:
                    existing = conn.execute('SELECT * FROM api_keys WHERE user_id = ? AND vendor = ?', (session['user_id'], vendor)).fetchone()
                    if existing:
                        conn.execute('UPDATE api_keys SET api_key = ? WHERE id = ?', (key, existing['id']))
                    else:
                        conn.execute('INSERT INTO api_keys (user_id, vendor, api_key) VALUES (?, ?, ?)', (session['user_id'], vendor, key))
        conn.commit()

    all_users = []
    if session.get('is_admin'):
        all_users = conn.execute('SELECT id, username, email, is_admin FROM users').fetchall()

    conn.close()
    return render_template('profile.html', user=user, api_keys=api_keys, all_users=all_users)

@app.route('/ransomware', methods=['GET', 'POST'])
def ransomware():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        group = request.form.get('group_name')
        target = request.form.get('target_org')
        sector = request.form.get('sector')
        status = request.form.get('status')
        date = request.form.get('date')
        tags = request.form.get('tags')

        conn = get_db_connection()
        conn.execute('''
            INSERT INTO ransomware_incidents (group_name, target_org, sector, status, date, tags, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (group, target, sector, status, date, tags, session.get('username')))
        conn.commit()
        conn.close()

        return redirect(url_for('ransomware'))

    return render_template('ransomware_tracker.html')

@app.route('/api/ransomware')
def ransomware_api():
    conn = get_db_connection()
    data = conn.execute('SELECT * FROM ransomware_incidents').fetchall()
    conn.close()
    from collections import defaultdict
    out = {'by_year': defaultdict(list), 'group_counts': {}, 'sector_counts': {}}
    for row in data:
        year = row['date'].split('-')[0]
        out['by_year'][year].append(dict(row))
        out['group_counts'][row['group_name']] = out['group_counts'].get(row['group_name'], 0) + 1
        out['sector_counts'][row['sector']] = out['sector_counts'].get(row['sector'], 0) + 1
    return jsonify(out)

@app.route('/ransomware/delete', methods=['POST'])
def delete_ransomware():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    incident_id = request.form.get('incident_id')
    conn = get_db_connection()
    conn.execute('DELETE FROM ransomware_incidents WHERE id = ?', (incident_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('ransomware'))

@app.route('/test_api', methods=['POST'])
def test_api():
    data = request.get_json()
    vendor = data.get('vendor')
    api_key = data.get('api_key')

    if vendor == 'VirusTotal':
        headers = {"x-apikey": api_key}
        test = requests.get('https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f', headers=headers)
        if test.status_code == 200:
            return jsonify({'status': 'success'})
        return jsonify({'status': 'fail', 'message': f'Status {test.status_code}'})

    # Add similar logic for other vendors here

    return jsonify({'status': 'fail', 'message': 'Unsupported vendor'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
