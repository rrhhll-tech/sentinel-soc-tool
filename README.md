# ⬡ SENTINEL — SOC L1 Analyst Tool

A complete Security Operations Center Level 1 tool built with Python and Flask.

## Features
- 🔴 Real-time alert analysis and severity classification
- 🌐 Live IP reputation checking via AbuseIPDB
- 📊 Incident history dashboard with analytics charts
- 🔐 Secure analyst login and registration system
- ⚠️ False positive flagging with reason documentation
- 📤 Escalation system for L2 handover
- 🔍 Search and filter incidents
- 📄 PDF report export
- 🗄️ SQLite database for incident storage

## Tech Stack
- Python 3
- Flask
- SQLAlchemy
- AbuseIPDB API
- Chart.js
- ReportLab

## Setup
1. Clone the repository
2. Install dependencies: pip install flask flask-sqlalchemy werkzeug requests reportlab
3. Add your AbuseIPDB API key in app.py
4. Run: python app.py
5. Open: http://127.0.0.1:5000

## Built By
SOC L1 Analyst in Training