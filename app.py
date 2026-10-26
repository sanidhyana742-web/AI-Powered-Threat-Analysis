import os
import logging
import csv
import io
import platform
import time
import shutil
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from dotenv import load_dotenv
from google import genai
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, bcrypt, User
from ml_engine import load_dataset, compute_analytics, get_xai_explanation, generate_synthetic_attacks
from security_engine import TECHNIQUE_MAP, create_executive_briefing, map_incident

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ncirip-phd-super-secret-key-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ncirip_users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Gemini API setup. The legacy variable is accepted so the existing .env keeps working.
gemini_api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("OPENAI_API_KEY")
gemini_client = genai.Client(api_key=gemini_api_key) if gemini_api_key else None
logger = logging.getLogger(__name__)
admin_activity = []
app_started_at = time.time()

def record_admin_activity(action):
    admin_activity.insert(0, {
        'action': action,
        'actor': current_user.username,
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
    })
    del admin_activity[20:]

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

    admin_username = os.getenv('ADMIN_USERNAME')
    admin_email = os.getenv('ADMIN_EMAIL')
    admin_password = os.getenv('ADMIN_PASSWORD')
    if admin_username and admin_email and admin_password:
        admin = User.query.filter_by(username=admin_username).first()
        if not admin:
            admin = User(username=admin_username, email=admin_email, role='Admin')
            db.session.add(admin)
        admin.email = admin_email
        admin.role = 'Admin'
        admin.set_password(admin_password)
        db.session.commit()

# --- AUTHENTICATION ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = 'Analyst'

        if not email:
            flash('Email address is required.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email address is already registered.', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html', page_title="Register Analyst")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password credentials.', 'danger')

    return render_template('login.html', page_title="Platform Login")

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.role == 'Admin':
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username, role='Admin').first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid administrator credentials.', 'danger')
    return render_template(
        'admin_login.html',
        page_title="Administrator Login",
        admin_configured=bool(os.getenv('ADMIN_USERNAME') and os.getenv('ADMIN_EMAIL') and os.getenv('ADMIN_PASSWORD')),
    )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):
        if current_user.role != 'Admin':
            return render_template('forbidden.html', page_title="Access Restricted"), 403
        return view(*args, **kwargs)
    return wrapped_view

@app.route('/admin')
@admin_required
def admin_dashboard():
    dataset = load_dataset()
    users = User.query.order_by(User.id.desc()).all()
    return render_template(
        'admin_dashboard.html',
        page_title='Administrator Console',
        users=users,
        activity=admin_activity,
        stats={
            'users': len(users),
            'admins': sum(user.role == 'Admin' for user in users),
            'records': len(dataset),
            'active': int(dataset['threat_active'].sum()) if not dataset.empty else 0,
            'critical': int((dataset['severity'] == 'CRITICAL').sum()) if not dataset.empty else 0,
        },
    )

@app.post('/admin/users/<int:user_id>/role')
@admin_required
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role', 'Analyst')
    if new_role not in {'Admin', 'Analyst', 'Operator', 'Policy Maker'}:
        flash('Unsupported role selection.', 'danger')
    elif user.id == current_user.id and new_role != 'Admin':
        flash('You cannot remove your own administrator access.', 'danger')
    else:
        user.role = new_role
        db.session.commit()
        record_admin_activity(f'Changed {user.username} role to {new_role}')
    return redirect(url_for('admin_dashboard'))

@app.post('/admin/users/<int:user_id>/delete')
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own administrator account.', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        record_admin_activity(f'Removed account {user.username}')
        flash(f'Account {user.username} was removed.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.post('/admin/users/<int:user_id>/password')
@admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    password = request.form.get('password', '')
    if len(password) < 8:
        flash('Password must contain at least 8 characters.', 'danger')
    else:
        user.set_password(password)
        db.session.commit()
        record_admin_activity(f'Reset password for {user.username}')
        flash(f'Password updated for {user.username}.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.get('/admin/users/export')
@admin_required
def export_users():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'username', 'email', 'role'])
    for user in User.query.order_by(User.id).all():
        writer.writerow([user.id, user.username, user.email, user.role])
    record_admin_activity('Exported user directory')
    return Response(output.getvalue(), mimetype='text/csv', headers={
        'Content-Disposition': 'attachment; filename=ncirip-user-directory.csv',
    })

@app.get('/admin/api/health')
@admin_required
def admin_health():
    dataset = load_dataset()
    users = User.query.count()
    active = int(dataset['threat_active'].sum()) if not dataset.empty else 0
    critical = int((dataset['severity'] == 'CRITICAL').sum()) if not dataset.empty else 0
    disk = shutil.disk_usage(os.path.dirname(os.path.abspath(__file__)))
    return jsonify({
        'database': 'online',
        'dataset': 'online' if not dataset.empty else 'unavailable',
        'ai_gateway': 'configured' if gemini_client else 'not configured',
        'records': len(dataset),
        'users': users,
        'active_signals': active,
        'critical_findings': critical,
        'uptime_seconds': int(time.time() - app_started_at),
        'disk_free_gb': round(disk.free / (1024 ** 3), 1),
        'platform': platform.system(),
        'checked_at': datetime.now(timezone.utc).strftime('%H:%M:%S UTC'),
    })

@app.route('/admin/telemetry')
@admin_required
def admin_telemetry():
    return render_template('admin_telemetry.html', page_title='Real-Time System Telemetry')

@app.get('/admin/api/telemetry')
@admin_required
def admin_telemetry_api():
    dataset = load_dataset()
    health = admin_health().get_json()
    return jsonify({
        'health': health,
        'components': [
            {'name': 'Database', 'status': health['database'], 'detail': f"{health['users']} identities"},
            {'name': 'Threat dataset', 'status': health['dataset'], 'detail': f"{health['records']:,} records"},
            {'name': 'AI gateway', 'status': health['ai_gateway'], 'detail': 'Gemini integration'},
            {'name': 'Telemetry stream', 'status': 'online', 'detail': f"{health['active_signals']:,} active signals"},
        ],
        'severity': {
            'critical': health['critical_findings'],
            'high': int((dataset['severity'] == 'HIGH').sum()) if not dataset.empty else 0,
            'medium': int((dataset['severity'] == 'MEDIUM').sum()) if not dataset.empty else 0,
            'low': int((dataset['severity'] == 'LOW').sum()) if not dataset.empty else 0,
        },
        'activity': admin_activity[:10],
    })

# --- WEB APPLICATION ROUTES ---

@app.route('/')
@login_required
def dashboard():
    stats = compute_analytics()
    return render_template('dashboard.html', page_title="Executive Dashboard", stats=stats)

@app.route('/threat-analytics')
@login_required
def threat_analytics():
    xai_data = get_xai_explanation()
    return render_template('threat_analytics.html', page_title="AI & XAI Threat Analytics", xai=xai_data)

@app.route('/gan-generator')
@login_required
def gan_generator():
    sectors = sorted(load_dataset()["sector"].dropna().unique().tolist())
    return render_template('gan_generator.html', page_title="GAN Attack Generator", sectors=sectors)

@app.route('/api/gan/generate', methods=['POST'])
@login_required
def gan_generate():
    payload = request.get_json() or {}
    try:
        result = generate_synthetic_attacks(
            count=payload.get('count', 8),
            sector=payload.get('sector', 'All sectors'),
            intensity=payload.get('intensity', 'Balanced'),
            seed=payload.get('seed'),
        )
        return jsonify(result)
    except (TypeError, ValueError):
        return jsonify({"error": "Use a valid sample count and optional numeric seed."}), 400

@app.route('/api/predict', methods=['POST'])
def api_predict():
    data = request.get_json() or {}
    cvss = float(data.get('cvss', 5.0))
    criticality = float(data.get('criticality', 5.0))
    
    # Calculation logic or ML model predict
    score = min(99.9, round((cvss * 7.0) + (criticality * 3.0), 1))
    severity = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM"

    return jsonify({
        "status": "success",
        "severity": severity,
        "confidence": score
    })
@app.route('/attack-graph')
@login_required
def attack_graph():
    return render_template('attack_graph.html', page_title="Attack Path Graph Engine")

@app.route('/api/graph-data')
@login_required
def graph_data():
    dataset = load_dataset()
    records = dataset.head(12).to_dict(orient='records') if not dataset.empty else []
    nodes = [{"id": "sector", "label": "Critical Infrastructure", "group": "sector"}]
    edges = []
    for index, record in enumerate(records, start=1):
        cve_id = str(record.get('cve_id', f'Incident {index}'))
        technique = str(record.get('mitre_technique', 'T1190'))
        nodes.extend([
            {"id": f"cve-{index}", "label": f"{cve_id}\nCVSS {record.get('cvss_score', 'N/A')}", "group": "cve"},
            {"id": f"technique-{index}", "label": f"{technique}\n{TECHNIQUE_MAP.get(technique, ('ATT&CK Technique', ''))[0]}", "group": "technique"},
        ])
        edges.extend([
            {"from": "sector", "to": f"cve-{index}", "label": str(record.get('attack_type', 'OBSERVED')).upper()},
            {"from": f"cve-{index}", "to": f"technique-{index}", "label": "MAPS TO"},
        ])
    return jsonify({"nodes": nodes, "edges": edges})

@app.route('/api/incident/analyze', methods=['POST'])
@login_required
def analyze_incident():
    payload = request.get_json() or {}
    incident = str(payload.get('incident', '')).strip()
    if not incident:
        return jsonify({"error": "Describe an incident before analysis."}), 400
    analysis = map_incident(incident, load_dataset())
    if gemini_client:
        try:
            prompt = f"You are ThreatGPT. Return a concise incident brief with exactly these headings: ASSESSMENT, RISK LEVEL, KEY FINDINGS, RECOMMENDED ACTIONS. Use plain text, no Markdown. Ground it in this mapping JSON: {analysis}. Incident: {incident}"
            response = gemini_client.models.generate_content(model=os.getenv("GEMINI_MODEL", "gemini-3.6-flash"), contents=prompt)
            analysis["copilot_brief"] = response.text or "No copilot brief returned."
        except Exception as error:
            logger.error("ThreatGPT incident analysis failed: %s: %s", type(error).__name__, error)
            analysis["copilot_brief"] = "ThreatGPT is unavailable; deterministic ATT&CK mapping is still available below."
    else:
        analysis["copilot_brief"] = "ThreatGPT is not configured; deterministic ATT&CK mapping is still available below."
    return jsonify(analysis)

@app.route('/api/reports/executive-briefing')
@login_required
def executive_briefing():
    analysis = map_incident("Current critical infrastructure risk posture", load_dataset())
    pdf = create_executive_briefing(compute_analytics(), analysis)
    return send_file(pdf, mimetype='application/pdf', as_attachment=True, download_name='ncirip-executive-briefing.pdf')

@app.route('/sector-risk')
@login_required
def sector_risk():
    df = load_dataset()
    records = df.head(50).to_dict(orient='records') if not df.empty else []
    return render_template('sector_risk.html', page_title="Sector Vulnerability Matrix", records=records)

# --- DYNAMIC CHATBOT API ENDPOINT ---

@app.route('/api/chatbot', methods=['POST'])
@login_required
def chatbot_response():
    user_msg = request.json.get('message', '')
    stats = compute_analytics()
    
    system_prompt = f"""
    You are CyberSentinel AI, an assistant for National Critical Infrastructure Protection.
    System Real-Time Context:
    - Tracked Dataset Records: {stats.get('total_records', 10000)}
    - Critical Incidents: {stats.get('critical_count', 1400)}
    - Average Risk Score: {stats.get('avg_risk', 68.5)}
    - Primary Sectors: Power, Transportation, Healthcare, Financial, Telecommunications.
    Answer as a concise cybersecurity analyst brief. Always use this exact structure:
    ASSESSMENT
    [one or two sentences answering the user]

    RISK LEVEL
    [LOW, MEDIUM, HIGH, or CRITICAL, with a short reason]

    KEY FINDINGS
    - [specific finding]
    - [specific finding]

    RECOMMENDED ACTIONS
    1. [highest-priority action]
    2. [next action]
    3. [next action]

    Use plain text only. Do not use Markdown bold, tables, code fences, greetings, or asterisks.
    Reference CVEs, MITRE ATT&CK techniques, and XAI factors when relevant. Keep responses under 180 words.
    """
    
    try:
        if gemini_client is None:
            raise RuntimeError("GEMINI_API_KEY is not configured")

        response = gemini_client.models.generate_content(
            model=os.getenv("GEMINI_MODEL", "gemini-3.6-flash"),
            contents=f"{system_prompt}\n\nUser query: {user_msg}",
        )
        reply = response.text or "No response was returned."
    except Exception as error:
        logger.error("Sentinel AI request failed: %s: %s", type(error).__name__, error)
        if type(error).__name__ in ("ClientError", "AuthenticationError"):
            reply = "Sentinel AI is unavailable: the Gemini API key was rejected or has no access. Check GEMINI_API_KEY in .env, then restart Flask."
        else:
            reply = "Sentinel AI is temporarily unavailable. Check the Flask terminal for the API error and try again."

    return jsonify({"response": reply})

if __name__ == '__main__':
    app.run(debug=True, port=5000)