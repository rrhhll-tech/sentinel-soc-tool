from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus import Paragraph
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
import requests
import anthropic
import re
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sentinel.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "sentinel-secret-key-2026"
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
db = SQLAlchemy(app)

os.makedirs("uploads", exist_ok=True)

GROQ_KEY = "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"

class Analyst(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100))
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))
    created_at = db.Column(db.String(100))

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(100))
    alert = db.Column(db.String(500))
    severity = db.Column(db.String(50))
    analysis = db.Column(db.String(200))
    ip = db.Column(db.String(50))
    country = db.Column(db.String(10))
    isp = db.Column(db.String(200))
    score = db.Column(db.Integer)
    verdict = db.Column(db.String(200))
    analyst = db.Column(db.String(50))
    false_positive = db.Column(db.Boolean, default=False)
    fp_reason = db.Column(db.String(300))
    escalated = db.Column(db.Boolean, default=False)
    escalation_notes = db.Column(db.String(500))
    escalation_priority = db.Column(db.String(20))
    escalated_at = db.Column(db.String(100))
    source = db.Column(db.String(50), default="manual")
    mitre_id = db.Column(db.String(50))
    mitre_name = db.Column(db.String(200))

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "analyst" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

MITRE_MAPPING = {
    "brute force": ("T1110", "Brute Force"),
    "failed login": ("T1110", "Brute Force"),
    "multiple failed": ("T1110", "Brute Force"),
    "malware": ("T1204", "User Execution"),
    "ransomware": ("T1486", "Data Encrypted for Impact"),
    "powershell": ("T1059.001", "PowerShell"),
    "encoded command": ("T1027", "Obfuscated Files or Information"),
    "large file transfer": ("T1041", "Exfiltration Over C2 Channel"),
    "new location": ("T1078", "Valid Accounts"),
    "suspicious login": ("T1078", "Valid Accounts"),
    "port scan": ("T1046", "Network Service Discovery"),
    "sql injection": ("T1190", "Exploit Public-Facing Application"),
    "phishing": ("T1566", "Phishing"),
}

def get_mitre(alert):
    alert_lower = alert.lower()
    for keyword, (tid, tname) in MITRE_MAPPING.items():
        if keyword in alert_lower:
            return tid, tname
    return None, None

def analyze_alert(alert):
    alert_lower = alert.lower()
    if "multiple failed login" in alert_lower or ("failed login" in alert_lower and "multiple" in alert_lower):
        return "HIGH RISK", "Possible brute force attack"
    elif "malware detected" in alert_lower or "malware" in alert_lower:
        return "HIGH RISK", "Malware activity detected"
    elif "ip flagged as malicious" in alert_lower:
        return "HIGH RISK", "Known malicious IP"
    elif "ransomware" in alert_lower:
        return "CRITICAL", "Ransomware detected — isolate host NOW"
    elif "powershell" in alert_lower and ("encoded" in alert_lower or "bypass" in alert_lower):
        return "HIGH RISK", "Suspicious PowerShell execution"
    elif "login from new location" in alert_lower or "new location" in alert_lower:
        return "MEDIUM RISK", "Suspicious login — verify with user"
    elif "large file transfer" in alert_lower or "exfiltration" in alert_lower:
        return "MEDIUM RISK", "Possible data exfiltration"
    elif "login successful" in alert_lower or "accepted password" in alert_lower:
        return "LOW RISK", "Normal activity"
    elif "failed password" in alert_lower or "authentication failure" in alert_lower:
        return "MEDIUM RISK", "Failed authentication attempt"
    elif "port scan" in alert_lower or "nmap" in alert_lower:
        return "HIGH RISK", "Port scanning detected"
    elif "sql injection" in alert_lower or "sqlmap" in alert_lower:
        return "CRITICAL", "SQL Injection attempt detected"
    elif "phishing" in alert_lower:
        return "HIGH RISK", "Phishing attempt detected"
    else:
        return "UNKNOWN", "Manual review needed"

def extract_ip(alert):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(pattern, alert)
    if match:
        return match.group()
    return None

def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()["data"]
        score = data["abuseConfidenceScore"]
        if score >= 80:
            verdict = "HIGHLY MALICIOUS — Block immediately"
        elif score >= 40:
            verdict = "SUSPICIOUS — Monitor closely"
        elif score >= 10:
            verdict = "LOW RISK — Keep an eye on it"
        else:
            verdict = "CLEAN — No threat detected"
        return {
            "ip": data["ipAddress"],
            "country": data["countryCode"],
            "isp": data["isp"],
            "score": score,
            "reports": data["totalReports"],
            "verdict": verdict
        }
    except:
        return None

def save_incident(alert, severity, analysis, ip_data, analyst_username, source="manual"):
    mitre_id, mitre_name = get_mitre(alert)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    incident = Incident(
        timestamp=timestamp,
        alert=alert,
        severity=severity,
        analysis=analysis,
        ip=ip_data["ip"] if ip_data else None,
        country=ip_data["country"] if ip_data else None,
        isp=ip_data["isp"] if ip_data else None,
        score=ip_data["score"] if ip_data else None,
        verdict=ip_data["verdict"] if ip_data else None,
        analyst=analyst_username,
        false_positive=False,
        escalated=False,
        source=source,
        mitre_id=mitre_id,
        mitre_name=mitre_name
    )
    db.session.add(incident)
    db.session.commit()
    return incident

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    if request.method == "POST":
        fullname = request.form.get("fullname")
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        if password != confirm:
            error = "Passwords do not match"
        elif Analyst.query.filter_by(username=username).first():
            error = "Analyst ID already taken — choose another"
        else:
            hashed = generate_password_hash(password)
            analyst = Analyst(
                fullname=fullname,
                username=username,
                password=hashed,
                created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            db.session.add(analyst)
            db.session.commit()
            success = "Account created! You can now login."
    return render_template("register.html", error=error, success=success)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        analyst = Analyst.query.filter_by(username=username).first()
        if analyst and check_password_hash(analyst.password, password):
            session["analyst"] = username
            session["fullname"] = analyst.fullname
            return redirect(url_for("index"))
        else:
            error = "Invalid analyst ID or access code"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    result = None
    if request.method == "POST":
        alert = request.form.get("alert")
        severity, analysis = analyze_alert(alert)
        ip = extract_ip(alert)
        ip_data = check_ip(ip) if ip else None
        incident = save_incident(alert, severity, analysis, ip_data, session["analyst"])
        result = {
            "alert": alert,
            "severity": severity,
            "analysis": analysis,
            "ip_data": ip_data,
            "timestamp": incident.timestamp,
            "mitre_id": incident.mitre_id,
            "mitre_name": incident.mitre_name,
        }
    return render_template("index.html", result=result,
                           analyst=session["analyst"],
                           fullname=session["fullname"])

@app.route("/upload_log", methods=["GET", "POST"])
@login_required
def upload_log():
    results = None
    filename = None
    if request.method == "POST":
        file = request.files.get("logfile")
        if file and file.filename:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            results = []
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                severity, analysis = analyze_alert(line)
                if severity != "UNKNOWN":
                    ip = extract_ip(line)
                    ip_data = check_ip(ip) if ip else None
                    incident = save_incident(line, severity, analysis, ip_data,
                                          session["analyst"], source="log_upload")
                    results.append({
                        "line": line[:100],
                        "severity": severity,
                        "analysis": analysis,
                        "ip": ip,
                        "mitre_id": incident.mitre_id,
                        "mitre_name": incident.mitre_name,
                    })
    return render_template("upload_log.html", results=results,
                           filename=filename,
                           analyst=session["analyst"],
                           fullname=session["fullname"])

@app.route("/history")
@login_required
def history():
    search = request.args.get("search", "")
    severity_filter = request.args.get("severity", "")
    status_filter = request.args.get("status", "")
    source_filter = request.args.get("source", "")
    query = Incident.query
    if search:
        query = query.filter(
            Incident.alert.contains(search) |
            Incident.ip.contains(search) |
            Incident.analyst.contains(search)
        )
    if severity_filter:
        query = query.filter(Incident.severity == severity_filter)
    if status_filter == "escalated":
        query = query.filter(Incident.escalated == True)
    elif status_filter == "fp":
        query = query.filter(Incident.false_positive == True)
    elif status_filter == "open":
        query = query.filter(Incident.escalated == False, Incident.false_positive == False)
    if source_filter:
        query = query.filter(Incident.source == source_filter)
    incidents = query.order_by(Incident.id.desc()).all()
    return render_template("history.html",
                           incidents=incidents,
                           analyst=session["analyst"],
                           fullname=session["fullname"],
                           search=search,
                           severity_filter=severity_filter,
                           status_filter=status_filter,
                           source_filter=source_filter)

@app.route("/escalated")
@login_required
def escalated():
    incidents = Incident.query.filter_by(escalated=True).order_by(Incident.id.desc()).all()
    return render_template("escalated.html", incidents=incidents,
                           analyst=session["analyst"],
                           fullname=session["fullname"])

@app.route("/flag_fp/<int:incident_id>", methods=["GET", "POST"])
@login_required
def flag_fp(incident_id):
    incident = Incident.query.get(incident_id)
    reason = request.form.get("reason", "No reason provided")
    if incident:
        incident.false_positive = True
        incident.fp_reason = reason
        db.session.commit()
    return redirect(url_for("history"))

@app.route("/unflag_fp/<int:incident_id>")
@login_required
def unflag_fp(incident_id):
    incident = Incident.query.get(incident_id)
    if incident:
        incident.false_positive = False
        incident.fp_reason = None
        db.session.commit()
    return redirect(url_for("history"))

@app.route("/escalate/<int:incident_id>", methods=["GET", "POST"])
@login_required
def escalate(incident_id):
    incident = Incident.query.get(incident_id)
    notes = request.form.get("notes", "No notes provided")
    priority = request.form.get("priority", "HIGH")
    if incident:
        incident.escalated = True
        incident.escalation_notes = notes
        incident.escalation_priority = priority
        incident.escalated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.session.commit()
    return redirect(url_for("history"))

@app.route("/deescalate/<int:incident_id>")
@login_required
def deescalate(incident_id):
    incident = Incident.query.get(incident_id)
    if incident:
        incident.escalated = False
        incident.escalation_notes = None
        incident.escalation_priority = None
        incident.escalated_at = None
        db.session.commit()
    return redirect(url_for("history"))

@app.route("/export_pdf/<int:incident_id>")
@login_required
def export_pdf(incident_id):
    incident = Incident.query.get(incident_id)
    if not incident:
        return redirect(url_for("history"))
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                           rightMargin=72, leftMargin=72,
                           topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    story = []
    title_style = ParagraphStyle('title', parent=styles['Heading1'],
        fontSize=18, textColor=colors.HexColor('#003366'),
        spaceAfter=6, alignment=TA_CENTER)
    subtitle_style = ParagraphStyle('subtitle', parent=styles['Normal'],
        fontSize=10, textColor=colors.grey, spaceAfter=20, alignment=TA_CENTER)
    section_style = ParagraphStyle('section', parent=styles['Heading2'],
        fontSize=11, textColor=colors.HexColor('#003366'),
        spaceBefore=16, spaceAfter=8)
    normal_style = ParagraphStyle('normal', parent=styles['Normal'],
        fontSize=10, spaceAfter=6, leading=16)
    story.append(Paragraph("SENTINEL SOC L1", title_style))
    story.append(Paragraph("INCIDENT REPORT", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("ALERT DETAILS", section_style))
    alert_data = [
        ["Field", "Value"],
        ["Incident ID", str(incident.id)],
        ["Timestamp", incident.timestamp or "N/A"],
        ["Alert", incident.alert or "N/A"],
        ["Severity", incident.severity or "N/A"],
        ["Analysis", incident.analysis or "N/A"],
        ["Analyst", incident.analyst or "N/A"],
        ["Source", incident.source or "manual"],
        ["MITRE ID", incident.mitre_id or "N/A"],
        ["MITRE Technique", incident.mitre_name or "N/A"],
    ]
    table_style = TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#003366')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('BACKGROUND', (0,1), (0,-1), colors.HexColor('#f0f4f8')),
        ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,1), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9f9f9')]),
        ('PADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ])
    t = Table(alert_data, colWidths=[2*inch, 4*inch])
    t.setStyle(table_style)
    story.append(t)
    if incident.ip:
        story.append(Paragraph("IP INTELLIGENCE", section_style))
        ip_data = [
            ["Field", "Value"],
            ["IP Address", incident.ip or "N/A"],
            ["Country", incident.country or "N/A"],
            ["ISP", incident.isp or "N/A"],
            ["Abuse Score", f"{incident.score}%" if incident.score is not None else "N/A"],
            ["Verdict", incident.verdict or "N/A"],
        ]
        t2 = Table(ip_data, colWidths=[2*inch, 4*inch])
        t2.setStyle(table_style)
        story.append(t2)
    story.append(Paragraph("INCIDENT STATUS", section_style))
    status_data = [
        ["Field", "Value"],
        ["False Positive", "YES" if incident.false_positive else "NO"],
        ["FP Reason", incident.fp_reason or "N/A"],
        ["Escalated", "YES" if incident.escalated else "NO"],
        ["Priority", incident.escalation_priority or "N/A"],
        ["Escalation Notes", incident.escalation_notes or "N/A"],
    ]
    t3 = Table(status_data, colWidths=[2*inch, 4*inch])
    t3.setStyle(table_style)
    story.append(t3)
    story.append(Paragraph("RECOMMENDED ACTIONS", section_style))
    if incident.severity == "CRITICAL":
        actions = ["1. ISOLATE affected host immediately", "2. Block IP at firewall",
                   "3. Escalate to L2 and L3 NOW", "4. Notify security manager",
                   "5. Preserve logs and memory dump"]
    elif incident.severity == "HIGH RISK":
        actions = ["1. Block suspicious IP at firewall", "2. Investigate affected user account",
                   "3. Escalate to L2 analyst", "4. Check for lateral movement",
                   "5. Document all findings"]
    elif incident.severity == "MEDIUM RISK":
        actions = ["1. Verify with affected user", "2. Monitor account for 24 hours",
                   "3. Check login history", "4. Document findings"]
    else:
        actions = ["1. Monitor and log", "2. No immediate action required",
                   "3. Review if pattern continues"]
    for action in actions:
        story.append(Paragraph(action, normal_style))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("— END OF REPORT —", subtitle_style))
    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                    download_name=f"incident_{incident.id}_report.pdf",
                    mimetype="application/pdf")

@app.route("/mitre")
@login_required
def mitre():
    incidents = Incident.query.filter(Incident.mitre_id != None).all()
    mitre_stats = {}
    for inc in incidents:
        if inc.mitre_id:
            if inc.mitre_id not in mitre_stats:
                mitre_stats[inc.mitre_id] = {
                    "id": inc.mitre_id,
                    "name": inc.mitre_name,
                    "count": 0,
                    "severities": []
                }
            mitre_stats[inc.mitre_id]["count"] += 1
            mitre_stats[inc.mitre_id]["severities"].append(inc.severity)
    return render_template("mitre.html",
                           mitre_stats=mitre_stats,
                           analyst=session["analyst"],
                           fullname=session["fullname"])
@app.route("/ai_assistant", methods=["GET", "POST"])
@login_required
def ai_assistant():
    response = None
    question = None
    if request.method == "POST":
        question = request.form.get("question")
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_KEY)
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": """You are SENTINEL AI, an expert SOC L1 analyst assistant. 
                        You help security analysts investigate incidents, understand threats, 
                        and take the right actions. Give clear, concise, professional answers.
                        Always structure your response with:
                        1. Threat Assessment
                        2. Recommended Actions
                        3. MITRE ATT&CK Technique if applicable"""
                    },
                    {
                        "role": "user",
                        "content": question
                    }
                ],
                model="llama-3.3-70b-versatile",
            )
            response = chat_completion.choices[0].message.content
        except Exception as e:
            response = f"AI Error: {str(e)}"
    return render_template("ai_assistant.html",
                           response=response,
                           question=question,
                           analyst=session["analyst"],
                           fullname=session["fullname"])
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)