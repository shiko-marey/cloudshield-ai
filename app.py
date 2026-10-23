from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cloudshield_secret_key_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cloudshield.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# 1. Users Table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email_or_phone = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# 2. Scan History Table
class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain = db.Column(db.String(200), nullable=False)
    status_code = db.Column(db.String(50), nullable=False)
    ssl_status = db.Column(db.String(100), nullable=False)
    security_score = db.Column(db.Integer, nullable=False)
    headers_score = db.Column(db.String(50), default="N/A")
    risk_level = db.Column(db.String(50), default="Low")
    ai_recommendations = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# Helper function to generate ready-to-use configuration snippets
def generate_remediation_configs(missing_headers):
    nginx_rules = []
    apache_rules = []
    
    header_map = {
        'Strict-Transport-Security': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        'Content-Security-Policy': 'add_header Content-Security-Policy "default-src \'self\';" always;',
        'X-Frame-Options': 'add_header X-Frame-Options "SAMEORIGIN" always;',
        'X-Content-Type-Options': 'add_header X-Content-Type-Options "nosniff" always;',
        'Referrer-Policy': 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
    }
    
    apache_map = {
        'Strict-Transport-Security': 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
        'Content-Security-Policy': 'Header always set Content-Security-Policy "default-src \'self\'"',
        'X-Frame-Options': 'Header always set X-Frame-Options "SAMEORIGIN"',
        'X-Content-Type-Options': 'Header always set X-Content-Type-Options "nosniff"',
        'Referrer-Policy': 'Header always set Referrer-Policy "strict-origin-when-cross-origin"'
    }

    for header in missing_headers:
        if header in header_map:
            nginx_rules.append(header_map[header])
            apache_rules.append(apache_map[header])

    return {
        'nginx': "\n".join(nginx_rules) if nginx_rules else "# All key security headers are present!",
        'apache': "\n".join(apache_rules) if apache_rules else "# All key security headers are present!"
    }

# Helper function to perform advanced security scan
def perform_security_scan(target_url):
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
        
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path
    
    status_code = "Unknown"
    ssl_status = "Not Secure / No SSL"
    score = 40
    
    security_headers = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options'
    ]
    missing_headers = []
    
    # HTTP Status & Security Headers Check
    try:
        response = requests.get(target_url, timeout=5, allow_redirects=True)
        status_code = str(response.status_code)
        if response.status_code == 200:
            score += 20
        
        headers = response.headers
        present_headers = 0
        for header in security_headers:
            if header in headers:
                present_headers += 1
            else:
                missing_headers.append(header)
                
        headers_score_text = f"{present_headers}/{len(security_headers)} Passed"
        score += (present_headers * 5)
        
    except Exception:
        status_code = "Connection Failed"
        headers_score_text = "0/4 Passed"
        score -= 20
        # لو فشل الاتصال، نعتبر كل هيدرز الأمان مفقودة لتوليد أكواد الحلول فوراً
        missing_headers = security_headers.copy()

    # SSL Certificate Check
    if target_url.startswith('https://'):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        ssl_status = "Valid SSL Certificate"
                        score += 20
        except Exception:
            ssl_status = "Invalid or Expired SSL"
            score -= 10

    if score > 100: score = 100
    if score < 0: score = 0

    if score >= 80:
        risk_level = "Safe"
        ai_recommendations = "System exhibits a strong security posture with active SSL and vital security headers enabled. Recommended: Keep SSL auto-renew active and perform periodic vulnerability assessments."
    elif score >= 50:
        risk_level = "Medium Risk"
        ai_recommendations = f"Moderate security risks detected. Missing critical headers: {', '.join(missing_headers) if missing_headers else 'None'}. Implement HSTS and Content Security Policies to protect against XSS and clickjacking."
    else:
        risk_level = "High Risk"
        ai_recommendations = "Critical Security Warning! The target lacks secure transport or proper server headers. High risk of MITM attacks or phishing/malicious activity. Immediate remediation required."

    remediation_configs = generate_remediation_configs(missing_headers)

    return {
        "domain": domain,
        "status_code": status_code,
        "ssl_status": ssl_status,
        "headers_score": headers_score_text,
        "risk_level": risk_level,
        "score": score,
        "ai_recommendations": ai_recommendations,
        "remediation": remediation_configs
    }

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    scan_result = None
    if request.method == 'POST':
        target_url = request.form['target_url']
        scan_data = perform_security_scan(target_url)
        
        new_scan = ScanHistory(
            user_id=session['user_id'],
            domain=scan_data['domain'],
            status_code=scan_data['status_code'],
            ssl_status=scan_data['ssl_status'],
            security_score=scan_data['score'],
            headers_score=scan_data['headers_score'],
            risk_level=scan_data['risk_level'],
            ai_recommendations=scan_data['ai_recommendations']
        )
        db.session.add(new_scan)
        db.session.commit()
        
        scan_data['id'] = new_scan.id
        scan_result = scan_data
        
        session['latest_remediation'] = scan_data['remediation']
        session['latest_domain'] = scan_data['domain']

    history = ScanHistory.query.filter_by(user_id=session['user_id']).order_by(ScanHistory.timestamp.desc()).all()
    
    total_scans = len(history)
    safe_scans = sum(1 for scan in history if scan.security_score >= 80)
    risk_scans = total_scans - safe_scans

    stats = {
        "total": total_scans,
        "safe": safe_scans,
        "risk": risk_scans
    }

    return render_template('index.html', scan_result=scan_result, stats=stats)

@app.route('/history')
def history_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    history = ScanHistory.query.filter_by(user_id=session['user_id']).order_by(ScanHistory.timestamp.desc()).all()
    return render_template('history.html', history=history)

@app.route('/remediation')
def remediation_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    remediation = session.get('latest_remediation', None)
    domain = session.get('latest_domain', 'No scan performed yet')
    
    return render_template('remediation.html', remediation=remediation, domain=domain)

@app.route('/export_pdf/<int:scan_id>')
def export_pdf(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=session['user_id']).first_or_404()
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#0e7490'), spaceAfter=12)
    heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#1e293b'), spaceAfter=10)
    normal_style = styles['Normal']
    
    story.append(Paragraph("🛡️ CloudShield AI - Security Audit Report", title_style))
    story.append(Paragraph(f"<b>Generated on:</b> {scan.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}", normal_style))
    story.append(Spacer(1, 15))
    
    data = [
        [Paragraph("<b>Metric</b>", normal_style), Paragraph("<b>Value</b>", normal_style)],
        ["Target Domain", scan.domain],
        ["HTTP Status Code", scan.status_code],
        ["SSL Status", scan.ssl_status],
        ["Security Headers", scan.headers_score],
        ["Overall Score", f"{scan.security_score} / 100"],
        ["Risk Assessment", scan.risk_level]
    ]
    
    t = Table(data, colWidths=[200, 300])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#f1f5f9')),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.HexColor('#0f172a')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("🤖 AI Security Analysis & Recommendations", heading_style))
    story.append(Paragraph(scan.ai_recommendations or "No details available.", normal_style))
    
    doc.build(story)
    
    buffer.seek(0)
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=CloudShield_Report_{scan.domain}.pdf'
    return response

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email_or_phone = request.form['email_or_phone']
        password = request.form['password']
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email_or_phone=email_or_phone, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Email or Phone is already in use!', 'danger')
            
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_phone = request.form['email_or_phone']
        password = request.form['password']
        
        user = User.query.filter_by(email_or_phone=email_or_phone).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials, please check your input.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
    app = app  
if __name__ == '__main__':
    app.run(debug=True)