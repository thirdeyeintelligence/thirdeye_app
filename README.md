# 🔍 ThirdEye Intelligence - SOC Analyst Web Application

A complete Flask-based threat intelligence web application for SOC analysts to:
- Investigate IPs, hashes, domains, CVEs
- Retrieve multi-vendor intelligence (VirusTotal, etc.)
- Generate SIEM hunting queries (Sentinel, Splunk, etc.)
- Track ransomware attacks across industries and time
- Manage user access with admin functionality
- Choose between Dark/Light theme

---

## 🚀 Features

- 🔐 Login/authentication with admin/user roles
- 🧪 Hash lookup with vendor scoring + fun verdicts
- 📜 Threat hunting queries with copy-to-clipboard
- 📈 Visual dashboards for vendor detection and trends
- 🛡️ Ransomware incident tracking (group, org, sector)
- 👤 API key management per vendor
- 🎨 Theme toggle (dark/light) stored in profile
- 📊 Historical search logs with drill-down capability

---

## 📁 Project Structure

thirdeye/
├── app.py
├── init_db.py
├── api_clients.py
├── utils.py
├── thirdeye.db
├── static/
│ └── logo.png
├── templates/
│ ├── login.html
│ ├── dashboard.html
│ ├── result.html
│ ├── profile.html
│ └── ransomware_tracker.html

pip3 install -r requirements.txt

python3 init_db.py
python3 app.py
