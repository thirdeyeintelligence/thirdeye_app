# ThirdEye Intelligence Web App (SOC + Ransomware Tracker)

This is a Flask-based web application for SOC analysts. It includes indicator analysis and a ransomware tracking feature for incidents in Australia.

---

## ✅ Features

- User Login (admin / admin)
- Indicator Analysis: IPs, URLs, Domains, Hashes, CVEs
- Fun Facts per Indicator Type
- Vendor API Key Management
- Historical Search Log
- Splunk & Sentinel Query Generator
- Ransomware Tracker:
  - Incident Submission
  - Yearly Tabs
  - Tagging with Colored Labels
  - Live Search (no button!)
  - Top 10 Group & Sector Charts

---

## 🔧 Setup Instructions

```bash
# Install required packages
pip3 install -r requirements.txt

# Initialize the database
python3 init_db.py

# Run the Flask app
python3 app.py

thirdeye_app/
├── app.py
├── utils.py
├── init_db.py
├── requirements.txt
├── README.md
├── templates/
│   ├── login.html
│   ├── dashboard.html
│   ├── result.html
│   ├── profile.html
│   └── ransomware_tracker.html
└── static/
    └── logo.png
