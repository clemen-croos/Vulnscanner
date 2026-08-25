import os
import sys
import logging
import json
import uuid
import hashlib
import secrets
import threading
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt as pyjwt
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

APP_BUILD_ID = '2026-08-22-runtime-engine-2.3'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Store a stable secret in the environment for deployed instances.
_env_secret = os.environ.get('SECRET_KEY', '')
if len(_env_secret) < 64:
    # Keep local development tokens valid across server restarts.
    _key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
    if os.path.exists(_key_file):
        with open(_key_file, 'r') as _f:
            _env_secret = _f.read().strip()
        logger.info("SECRET_KEY loaded from .secret_key file.")
    else:
        _env_secret = secrets.token_hex(64)
        with open(_key_file, 'w') as _f:
            _f.write(_env_secret)
        logger.warning("SECRET_KEY generated and saved to .secret_key. "
                       "Set SECRET_KEY env var in production instead.")
app.config['SECRET_KEY'] = _env_secret
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///vulnscanner.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['REPORTS_FOLDER'] = os.path.join(os.path.dirname(__file__), 'reports')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

# Request rate limits
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["2000 per day", "300 per hour"],
    storage_uri="memory://",
)

# Browser origins allowed to call the API
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
CORS(app, resources={r"/api/*": {
    "origins": ALLOWED_ORIGINS,
    "methods": ["GET", "POST", "DELETE", "OPTIONS"],
    "allow_headers": ["Authorization", "Content-Type"],
}})
db = SQLAlchemy(app)


# Models

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {'id': self.id, 'username': self.username,
                'email': self.email, 'role': self.role}


class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_uuid = db.Column(db.String(36), unique=True, default=lambda: uuid.uuid4().hex)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    apk_name = db.Column(db.String(255), nullable=False)
    apk_path = db.Column(db.String(512))
    apk_size = db.Column(db.Integer)
    package_name = db.Column(db.String(255))
    version_name = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    progress = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Integer, default=0)
    total_findings = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    scan_options = db.Column(db.Text)
    error_message = db.Column(db.Text)
    static_status = db.Column(db.String(20), default='not_requested')
    static_progress = db.Column(db.Integer, default=0)
    static_risk_score = db.Column(db.Integer, default=0)
    static_total_findings = db.Column(db.Integer, default=0)
    static_critical_count = db.Column(db.Integer, default=0)
    static_high_count = db.Column(db.Integer, default=0)
    static_medium_count = db.Column(db.Integer, default=0)
    static_low_count = db.Column(db.Integer, default=0)
    static_error = db.Column(db.Text)
    dynamic_status = db.Column(db.String(20), default='not_requested')
    dynamic_progress = db.Column(db.Integer, default=0)
    dynamic_risk_score = db.Column(db.Integer, default=0)
    dynamic_total_findings = db.Column(db.Integer, default=0)
    dynamic_critical_count = db.Column(db.Integer, default=0)
    dynamic_high_count = db.Column(db.Integer, default=0)
    dynamic_medium_count = db.Column(db.Integer, default=0)
    dynamic_low_count = db.Column(db.Integer, default=0)
    dynamic_error = db.Column(db.Text)
    dynamic_metadata = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='scan', lazy=True, cascade='all, delete-orphan')

    def to_dict(self, include_vulns=False):
        d = {
            'id': self.id, 'scan_uuid': self.scan_uuid,
            'apk_name': self.apk_name, 'apk_size': self.apk_size,
            'package_name': self.package_name, 'version_name': self.version_name,
            'status': self.status, 'progress': self.progress,
            'risk_score': self.risk_score, 'total_findings': self.total_findings,
            'critical_count': self.critical_count, 'high_count': self.high_count,
            'medium_count': self.medium_count, 'low_count': self.low_count,
            'error_message': self.error_message,
            'scan_options': json.loads(self.scan_options) if self.scan_options else {},
            'analyses': {
                'static': self.analysis_summary('static'),
                'dynamic': self.analysis_summary('dynamic'),
            },
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }
        if include_vulns:
            d['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        return d

    def analysis_summary(self, analysis_type):
        prefix = 'dynamic' if analysis_type == 'dynamic' else 'static'
        return {
            'type': prefix,
            'status': getattr(self, f'{prefix}_status') or 'not_requested',
            'progress': getattr(self, f'{prefix}_progress') or 0,
            'risk_score': getattr(self, f'{prefix}_risk_score') or 0,
            'total_findings': getattr(self, f'{prefix}_total_findings') or 0,
            'critical_count': getattr(self, f'{prefix}_critical_count') or 0,
            'high_count': getattr(self, f'{prefix}_high_count') or 0,
            'medium_count': getattr(self, f'{prefix}_medium_count') or 0,
            'low_count': getattr(self, f'{prefix}_low_count') or 0,
            'error': getattr(self, f'{prefix}_error'),
            'metadata': json.loads(self.dynamic_metadata) if prefix == 'dynamic' and self.dynamic_metadata else {},
        }


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    analysis_type = db.Column(db.String(20), nullable=False, default='static', index=True)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(100))
    cvss_score = db.Column(db.Float)
    description = db.Column(db.Text)
    location = db.Column(db.String(512))
    evidence = db.Column(db.Text)
    remediation = db.Column(db.Text)
    poc_command = db.Column(db.Text)
    is_false_positive = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.String(20), default='high')
    cwe_id = db.Column(db.String(20))
    owasp_category = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'scan_id': self.scan_id, 'analysis_type': self.analysis_type,
            'title': self.title, 'severity': self.severity,
            'category': self.category, 'cvss_score': self.cvss_score,
            'description': self.description, 'location': self.location,
            'evidence': self.evidence, 'remediation': self.remediation,
            'poc_command': self.poc_command, 'references': [],
            'is_false_positive': self.is_false_positive,
            'confidence': self.confidence, 'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255))
    report_type = db.Column(db.String(50))
    format = db.Column(db.String(10))
    file_path = db.Column(db.String(512))
    file_size = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'scan_id': self.scan_id,
            'title': self.title, 'report_type': self.report_type,
            'format': self.format, 'file_size': self.file_size,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'apk_name': self.scan.apk_name if self.scan else None,
            'risk_score': self.scan.risk_score if self.scan else None
        }


def ensure_schema():
    """Apply additive compatibility migrations for existing development DBs."""
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    scan_columns = {column['name'] for column in inspector.get_columns('scans')}
    additions = {
        'static_status': "VARCHAR(20) DEFAULT 'not_requested'",
        'static_progress': 'INTEGER DEFAULT 0', 'static_risk_score': 'INTEGER DEFAULT 0',
        'static_total_findings': 'INTEGER DEFAULT 0', 'static_critical_count': 'INTEGER DEFAULT 0',
        'static_high_count': 'INTEGER DEFAULT 0', 'static_medium_count': 'INTEGER DEFAULT 0',
        'static_low_count': 'INTEGER DEFAULT 0', 'static_error': 'TEXT',
        'dynamic_status': "VARCHAR(20) DEFAULT 'not_requested'",
        'dynamic_progress': 'INTEGER DEFAULT 0', 'dynamic_risk_score': 'INTEGER DEFAULT 0',
        'dynamic_total_findings': 'INTEGER DEFAULT 0', 'dynamic_critical_count': 'INTEGER DEFAULT 0',
        'dynamic_high_count': 'INTEGER DEFAULT 0', 'dynamic_medium_count': 'INTEGER DEFAULT 0',
        'dynamic_low_count': 'INTEGER DEFAULT 0', 'dynamic_error': 'TEXT', 'dynamic_metadata': 'TEXT',
    }
    for name, sql_type in additions.items():
        if name not in scan_columns:
            db.session.execute(text(f'ALTER TABLE scans ADD COLUMN {name} {sql_type}'))

    vuln_columns = {column['name'] for column in inspector.get_columns('vulnerabilities')}
    if 'analysis_type' not in vuln_columns:
        db.session.execute(text(
            "ALTER TABLE vulnerabilities ADD COLUMN analysis_type VARCHAR(20) DEFAULT 'static'"
        ))

    # Treat legacy findings and completed scans as static results.
    db.session.execute(text(
        "UPDATE vulnerabilities SET analysis_type='static' "
        "WHERE analysis_type IS NULL OR analysis_type=''"
    ))
    db.session.execute(text("""
        UPDATE scans SET
          static_status=CASE WHEN status='completed' THEN 'completed' ELSE COALESCE(static_status,'not_requested') END,
          static_progress=CASE WHEN status='completed' THEN 100 ELSE COALESCE(static_progress,0) END,
          static_risk_score=CASE WHEN status='completed' THEN risk_score ELSE COALESCE(static_risk_score,0) END,
          static_total_findings=CASE WHEN status='completed' THEN total_findings ELSE COALESCE(static_total_findings,0) END,
          static_critical_count=CASE WHEN status='completed' THEN critical_count ELSE COALESCE(static_critical_count,0) END,
          static_high_count=CASE WHEN status='completed' THEN high_count ELSE COALESCE(static_high_count,0) END,
          static_medium_count=CASE WHEN status='completed' THEN medium_count ELSE COALESCE(static_medium_count,0) END,
          static_low_count=CASE WHEN status='completed' THEN low_count ELSE COALESCE(static_low_count,0) END,
          dynamic_status=COALESCE(dynamic_status,'not_requested')
    """))
    db.session.commit()


# Authentication helpers

def make_token(user_id, username, role):
    payload = {
        'sub': str(user_id),
        'username': username,
        'role': role,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=24)  # 24-hour expiry
    }
    token = pyjwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    # PyJWT 1.x returns bytes; later releases return text.
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing token'}), 401
        token = auth.split(' ', 1)[1].strip()
        try:
            payload = pyjwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms=['HS256']
            )
        except pyjwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except Exception as e:
            # Authentication must never accept an unverified token.
            return jsonify({'error': f'Invalid token: {str(e)}'}), 401
        request.current_user_id = int(payload['sub'])
        request.current_role = payload.get('role', 'user')
        return f(*args, **kwargs)
    return decorated

# Authentication routes

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'app': 'VulnScanner',
        'build_id': APP_BUILD_ID,
        'dynamic_device': os.environ.get('DYNAMIC_ANALYSIS_DEVICE') or 'not configured',
    })


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json() or {}
    if not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400
    email = str(data.get('email')).strip().lower()
    user = User.query.filter(db.func.lower(User.email) == email).first()
    if not user or not check_password_hash(user.password_hash, data.get('password', '')):
        return jsonify({'error': 'Invalid email or password'}), 401
    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 403
    token = make_token(user.id, user.username, user.role)
    return jsonify({'access_token': token, 'user': user.to_dict()})


@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    data = request.get_json() or {}
    required = ('username', 'email', 'password')
    if any(not isinstance(data.get(field), str) or not data[field].strip()
           for field in required):
        return jsonify({'error': 'Username, email, and password required'}), 400
    if len(data['password']) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    email = data['email'].strip().lower()
    if User.query.filter(db.func.lower(User.email) == email).first():
        return jsonify({'error': 'Email already registered'}), 409
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already taken'}), 409
    user = User(
        username=data['username'].strip(),
        email=email,
        password_hash=generate_password_hash(data['password'])
    )
    db.session.add(user)
    db.session.commit()
    token = make_token(user.id, user.username, user.role)
    return jsonify({'access_token': token, 'user': user.to_dict()}), 201


@app.route('/api/auth/refresh', methods=['POST'])
@require_auth
def refresh_token():
    """
    Called by the frontend when it receives a 401.
    Returns a fresh 24-hour token using the existing valid token.
    Frontend should: on any 401, POST here first, update stored token, retry original request.
    """
    user = User.query.get(request.current_user_id)
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or disabled'}), 401
    token = make_token(user.id, user.username, user.role)
    return jsonify({'access_token': token})


@app.route('/api/auth/me')
@require_auth
def me():
    user = User.query.get(request.current_user_id)
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or disabled'}), 401
    return jsonify({'user': user.to_dict()})


# Dashboard

@app.route('/api/dashboard/stats')
@require_auth
def dashboard_stats():
    uid = request.current_user_id
    scans = Scan.query.filter_by(user_id=uid, status='completed').all()
    all_scans = Scan.query.filter_by(user_id=uid).order_by(Scan.created_at.desc()).all()

    critical = sum(s.critical_count for s in scans)
    high = sum(s.high_count for s in scans)
    medium = sum(s.medium_count for s in scans)
    low = sum(s.low_count for s in scans)
    avg_risk = int(sum(s.risk_score for s in scans) / len(scans)) if scans else 0

    from sqlalchemy import func
    cat_counts = db.session.query(
        Vulnerability.category, func.count(Vulnerability.id)
    ).join(Scan).filter(Scan.user_id == uid).group_by(Vulnerability.category).all()

    trend = [{
        'date': s.created_at.strftime('%b %d') if s.created_at else '',
        'risk_score': s.risk_score,
        'total_findings': s.total_findings,
        'name': s.apk_name
    } for s in reversed(all_scans[:7])]

    return jsonify({
        'total_scans': len(all_scans),
        'completed_scans': len(scans),
        'overall_risk_score': avg_risk,
        'severity_breakdown': {'critical': critical, 'high': high, 'medium': medium, 'low': low},
        'recent_scans': [s.to_dict() for s in all_scans[:5]],
        'category_breakdown': [{'category': c[0], 'count': c[1]} for c in cat_counts if c[0]],
        'trend_data': trend
    })


# Scans

@app.route('/api/scans')
@require_auth
def list_scans():
    uid = request.current_user_id
    status = request.args.get('status')
    q = Scan.query.filter_by(user_id=uid)
    if status:
        q = q.filter_by(status=status)
    scans = q.order_by(Scan.created_at.desc()).limit(50).all()
    return jsonify({'scans': [s.to_dict() for s in scans], 'total': len(scans), 'pages': 1, 'current_page': 1})


@app.route('/api/scans/<int:scan_id>')
@require_auth
def get_scan(scan_id):
    uid = request.current_user_id
    scan = Scan.query.filter_by(id=scan_id, user_id=uid).first_or_404()
    include_vulns = request.args.get('include_vulns', 'false').lower() == 'true'
    return jsonify({'scan': scan.to_dict(include_vulns=include_vulns)})


@app.route('/api/scans/<int:scan_id>/status')
@require_auth
@limiter.limit("600 per hour")
def scan_status(scan_id):
    uid = request.current_user_id
    scan = Scan.query.filter_by(id=scan_id, user_id=uid).first_or_404()
    return jsonify({
        'status': scan.status, 'progress': scan.progress,
        'error': scan.error_message,
        'error_message': scan.error_message,
        'analyses': {
            'static': scan.analysis_summary('static'),
            'dynamic': scan.analysis_summary('dynamic'),
        }
    })


@app.route('/api/scans/<int:scan_id>/results/<analysis_type>')
@require_auth
def scan_results(scan_id, analysis_type):
    if analysis_type not in ('static', 'dynamic'):
        return jsonify({'error': 'analysis_type must be static or dynamic'}), 400
    scan = Scan.query.filter_by(id=scan_id, user_id=request.current_user_id).first_or_404()
    vulns = Vulnerability.query.filter_by(
        scan_id=scan.id, analysis_type=analysis_type, is_false_positive=False
    ).order_by(Vulnerability.id.asc()).all()
    return jsonify({
        'scan': scan.to_dict(),
        'analysis': scan.analysis_summary(analysis_type),
        'vulnerabilities': [v.to_dict() for v in vulns],
    })


@app.route('/api/scans/upload', methods=['POST'])
@require_auth
@limiter.limit("10 per hour")
def upload_apk():
    uid = request.current_user_id

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.lower().endswith('.apk'):
        return jsonify({'error': 'Only .apk files allowed'}), 400

    options = {'static': True, 'dynamic': False, 'ai_filter': True}
    try:
        raw = request.form.get('options')
        if raw:
            supplied = json.loads(raw)
            if not isinstance(supplied, dict):
                raise ValueError('options must be an object')
            options.update(supplied)
    except (TypeError, ValueError, json.JSONDecodeError):
        return jsonify({'error': 'Invalid scan options'}), 400

    options['static'] = options.get('static') is True
    options['dynamic'] = options.get('dynamic') is True
    options['ai_filter'] = options.get('ai_filter') is not False
    if not options['static'] and not options['dynamic']:
        return jsonify({'error': 'Enable at least one analysis: static or dynamic'}), 400

    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    MAX_BYTES = 100 * 1024 * 1024
    MIN_BYTES = 1_000
    if file_size > MAX_BYTES:
        return jsonify({'error': 'File too large. Maximum size is 100 MB.'}), 413
    if file_size < MIN_BYTES:
        return jsonify({'error': 'File too small to be a valid APK.'}), 400

    scan_uuid = uuid.uuid4().hex
    from werkzeug.utils import secure_filename
    filename = secure_filename(file.filename) or f'upload_{scan_uuid}.apk'
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], scan_uuid)
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)

    scan = Scan(
        scan_uuid=scan_uuid, user_id=uid,
        apk_name=filename, apk_path=filepath,
        apk_size=file_size, status='pending', progress=0,
        static_status='pending' if options['static'] else 'not_requested',
        dynamic_status='pending' if options['dynamic'] else 'not_requested',
        scan_options=json.dumps(options)
    )
    db.session.add(scan)
    db.session.commit()

    t = threading.Thread(target=_run_scan, args=(scan.id, filepath, options))
    t.daemon = True
    t.start()

    return jsonify({'message': 'Scan started', 'scan_id': scan.id, 'scan_uuid': scan_uuid}), 201


@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
@require_auth
def delete_scan(scan_id):
    uid = request.current_user_id
    scan = Scan.query.filter_by(id=scan_id, user_id=uid).first_or_404()
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'message': 'Deleted'})


def _run_scan(scan_id, apk_path, options):
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return
        try:
            scan.status = 'running'
            scan.progress = 5
            db.session.commit()

            from modules.static_analyzer import StaticAnalyzer
            analyzer = StaticAnalyzer(apk_path)
            apk_info = analyzer.parse_apk()
            scan.package_name = apk_info.get('package_name', 'Unknown')
            scan.version_name = apk_info.get('version_name', '1.0')
            db.session.commit()

            from modules.risk_scorer import RiskScorer
            scorer = RiskScorer()
            all_findings = []

            def save_findings(analysis_type, findings):
                for f in findings:
                    db.session.add(Vulnerability(
                        scan_id=scan.id, analysis_type=analysis_type,
                        title=f.get('title', 'Unknown'), severity=f.get('severity', 'medium'),
                        category=f.get('category', 'General'), cvss_score=f.get('cvss_score'),
                        description=f.get('description', ''), location=f.get('location', ''),
                        evidence=f.get('evidence', ''), remediation=f.get('remediation', ''),
                        poc_command=f.get('poc_command'), confidence=f.get('confidence', 'medium'),
                        cwe_id=f.get('cwe_id'), owasp_category=f.get('owasp_category')
                    ))
                prefix = analysis_type
                setattr(scan, f'{prefix}_risk_score', scorer.calculate_risk_score(findings))
                setattr(scan, f'{prefix}_total_findings', len(findings))
                for severity in ('critical', 'high', 'medium', 'low'):
                    setattr(scan, f'{prefix}_{severity}_count',
                            sum(1 for finding in findings if finding.get('severity') == severity))
                all_findings.extend(findings)

            if options.get('static'):
                scan.static_status = 'running'
                scan.static_progress = 10
                scan.progress = 10
                db.session.commit()
                try:
                    static_findings = analyzer.run_all_checks()
                    scan.static_progress = 75
                    scan.progress = 40 if options.get('dynamic') else 75
                    db.session.commit()
                    if options.get('ai_filter') and static_findings:
                        from modules.ai_filter import AIFilter
                        static_findings = AIFilter().filter_findings(static_findings)
                    save_findings('static', static_findings)
                    scan.static_progress = 100
                    scan.static_status = 'completed'
                    scan.progress = 50 if options.get('dynamic') else 95
                    db.session.commit()
                except Exception as static_error:
                    logger.exception("Static analysis failed for scan %s", scan.id)
                    scan.static_status = 'failed'
                    scan.static_error = str(static_error)[:2000]
                    scan.static_progress = 100
                    if not options.get('dynamic'):
                        raise
                    scan.progress = 50
                    db.session.commit()

            if options.get('dynamic'):
                scan.dynamic_status = 'running'
                scan.dynamic_progress = 5
                scan.progress = 52 if options.get('static') else 10
                db.session.commit()
                try:
                    from modules.dynamic_analyzer import DynamicAnalyzer

                    def dynamic_progress(percent, stage):
                        current = Scan.query.get(scan_id)
                        if not current:
                            return
                        current.dynamic_progress = percent
                        current.progress = (50 + percent // 2) if options.get('static') else percent
                        current.dynamic_metadata = json.dumps({'current_stage': stage})
                        db.session.commit()

                    dynamic_result = DynamicAnalyzer(
                        apk_path, scan.package_name, progress_callback=dynamic_progress,
                        scan_profile=options.get('scan_type', 'quick')
                    ).run()
                    dynamic_findings = dynamic_result.findings
                    save_findings('dynamic', dynamic_findings)
                    scan.dynamic_metadata = json.dumps(dynamic_result.metadata)
                    scan.dynamic_progress = 100
                    scan.dynamic_status = 'completed'
                    scan.progress = 95
                    db.session.commit()
                except Exception as dynamic_error:
                    logger.exception("Dynamic analysis failed for scan %s", scan.id)
                    scan.dynamic_status = 'failed'
                    scan.dynamic_error = str(dynamic_error)[:2000]
                    scan.dynamic_progress = 100
                    scan.progress = 95
                    db.session.commit()

            # Preserve aggregate fields for the dashboard and existing clients.
            scan.risk_score = scorer.calculate_risk_score(all_findings)
            scan.total_findings = len(all_findings)
            for severity in ('critical', 'high', 'medium', 'low'):
                setattr(scan, f'{severity}_count',
                        sum(1 for finding in all_findings if finding.get('severity') == severity))
            requested = [scan.static_status] if options.get('static') else []
            requested += [scan.dynamic_status] if options.get('dynamic') else []
            scan.status = 'completed' if any(s == 'completed' for s in requested) else 'failed'
            scan.progress = 100
            scan.completed_at = datetime.utcnow()
            if scan.status == 'failed':
                errors = [e for e in (scan.static_error, scan.dynamic_error) if e]
                scan.error_message = ' | '.join(errors)[:2000]
            db.session.commit()
        except Exception as e:
            logger.exception("Scan error for %s", scan_id)
            scan.status = 'failed'
            scan.error_message = str(e)
            if options.get('static') and scan.static_status in ('pending', 'running'):
                scan.static_status = 'failed'
                scan.static_error = str(e)[:2000]
            if options.get('dynamic') and scan.dynamic_status in ('pending', 'running'):
                scan.dynamic_status = 'failed'
                scan.dynamic_error = str(e)[:2000]
            scan.progress = 100
            db.session.commit()


# Vulnerabilities

@app.route('/api/vulnerabilities')
@require_auth
def list_vulns():
    uid = request.current_user_id
    severity = request.args.get('severity')
    category = request.args.get('category')
    search = request.args.get('search', '')
    analysis_type = request.args.get('analysis_type')

    q = Vulnerability.query.join(Scan).filter(
        Scan.user_id == uid, Vulnerability.is_false_positive == False
    )
    if severity:
        q = q.filter(Vulnerability.severity == severity)
    if category:
        q = q.filter(Vulnerability.category == category)
    if search:
        q = q.filter(Vulnerability.title.ilike(f'%{search}%'))
    if analysis_type in ('static', 'dynamic'):
        q = q.filter(Vulnerability.analysis_type == analysis_type)

    vulns = q.all()
    return jsonify({'vulnerabilities': [v.to_dict() for v in vulns], 'total': len(vulns), 'pages': 1})


@app.route('/api/vulnerabilities/categories')
@require_auth
def vuln_categories():
    uid = request.current_user_id
    from sqlalchemy import func
    cats = db.session.query(Vulnerability.category).join(Scan).filter(
        Scan.user_id == uid
    ).distinct().all()
    return jsonify({'categories': [c[0] for c in cats if c[0]]})


@app.route('/api/vulnerabilities/<int:vid>')
@require_auth
def get_vuln(vid):
    uid = request.current_user_id
    v = Vulnerability.query.join(Scan).filter(
        Vulnerability.id == vid, Scan.user_id == uid
    ).first_or_404()
    return jsonify({'vulnerability': v.to_dict()})


@app.route('/api/vulnerabilities/<int:vid>/mark-false-positive', methods=['POST'])
@require_auth
def mark_fp(vid):
    uid = request.current_user_id
    v = Vulnerability.query.join(Scan).filter(
        Vulnerability.id == vid, Scan.user_id == uid
    ).first_or_404()
    v.is_false_positive = not v.is_false_positive
    db.session.commit()
    return jsonify({'is_false_positive': v.is_false_positive})


# Reports

@app.route('/api/reports')
@require_auth
def list_reports():
    uid = request.current_user_id
    reports = Report.query.filter_by(user_id=uid).order_by(Report.created_at.desc()).all()
    return jsonify({'reports': [r.to_dict() for r in reports], 'total': len(reports), 'pages': 1})


@app.route('/api/reports/generate', methods=['POST'])
@require_auth
def generate_report():
    uid = request.current_user_id
    data = request.get_json() or {}
    scan_id = data.get('scan_id')
    fmt = data.get('format', 'html')
    report_type = data.get('report_type', 'full')
    analysis_type = data.get('analysis_type')
    if analysis_type not in (None, 'static', 'dynamic'):
        return jsonify({'error': 'analysis_type must be static or dynamic'}), 400

    scan = Scan.query.filter_by(id=scan_id, user_id=uid).first_or_404()
    vuln_query = Vulnerability.query.filter_by(scan_id=scan_id, is_false_positive=False)
    if analysis_type:
        vuln_query = vuln_query.filter_by(analysis_type=analysis_type)
    vulns = vuln_query.all()

    from modules.report_generator import ReportGenerator
    gen = ReportGenerator(app.config['REPORTS_FOLDER'])
    report_data = {
        'scan': scan.to_dict(),
        'vulnerabilities': [v.to_dict() for v in vulns],
        'report_type': report_type,
        'analysis_type': analysis_type or 'combined'
    }
    file_path, file_size = gen.generate(report_data, fmt)

    r = Report(
        scan_id=scan_id, user_id=uid,
        title=f"{(analysis_type or 'Combined').title()} {report_type.title()} Report - {scan.apk_name}",
        report_type=report_type, format=fmt,
        file_path=file_path, file_size=file_size
    )
    db.session.add(r)
    db.session.commit()
    return jsonify({'message': 'Generated', 'report': r.to_dict(),
                    'download_url': f'/api/reports/{r.id}/download'}), 201


@app.route('/api/reports/<int:rid>/download')
@require_auth
def download_report(rid):
    from flask import send_file
    uid = request.current_user_id
    r = Report.query.filter_by(id=rid, user_id=uid).first_or_404()
    if not r.file_path or not os.path.exists(r.file_path):
        return jsonify({'error': 'File not found'}), 404
    mime = {'pdf': 'application/pdf', 'html': 'text/html', 'json': 'application/json'}
    return send_file(r.file_path, mimetype=mime.get(r.format, 'application/octet-stream'),
                     as_attachment=True, download_name=f'report_{rid}.{r.format}')


@app.route('/api/reports/<int:rid>', methods=['DELETE'])
@require_auth
def delete_report(rid):
    uid = request.current_user_id
    r = Report.query.filter_by(id=rid, user_id=uid).first_or_404()
    if r.file_path and os.path.exists(r.file_path):
        os.remove(r.file_path)
    db.session.delete(r)
    db.session.commit()
    return jsonify({'message': 'Deleted'})


# Development data and startup

def seed():
    if User.query.first():
        return
    logger.info("Seeding demo data...")
    user = User(
        username='admin', email='admin@vulnscanner.io',
        password_hash=generate_password_hash('admin123'), role='admin'
    )
    db.session.add(user)
    db.session.flush()

    demo_apps = [
        {
            'name': 'BankingApp.apk', 'package': 'com.demo.banking',
            'version': '2.1.0', 'risk_score': 78,
            'vulns': [
                {'title': 'Hardcoded API Key', 'severity': 'critical', 'category': 'Secrets', 'cvss': 9.8,
                 'description': 'The application contains a hardcoded AWS API key in source code.',
                 'location': 'MainActivity.java:42',
                 'evidence': 'private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";',
                 'remediation': 'Remove hardcoded key. Use Android Keystore or fetch from secure backend.',
                 'poc': 'adb shell am start -n com.demo.banking/.MainActivity'},
                {'title': 'Weak Encryption (MD5)', 'severity': 'high', 'category': 'Cryptography', 'cvss': 7.5,
                 'description': 'MD5 is used for password hashing, which is cryptographically broken.',
                 'location': 'CryptoUtils.java:87', 'evidence': 'MessageDigest.getInstance("MD5")',
                 'remediation': 'Replace MD5 with SHA-256 or bcrypt.', 'poc': None},
                {'title': 'Exported Activity Without Permission', 'severity': 'high', 'category': 'Components', 'cvss': 7.2,
                 'description': 'An activity is exported without requiring any permissions.',
                 'location': 'AndroidManifest.xml',
                 'evidence': '<activity android:name=".AdminActivity" android:exported="true"/>',
                 'remediation': 'Add android:permission or set exported=false.',
                 'poc': 'adb shell am start -n com.demo.banking/.AdminActivity'},
                {'title': 'Insecure WebView Settings', 'severity': 'high', 'category': 'WebView', 'cvss': 6.8,
                 'description': 'JavaScript is enabled in WebView with file access allowed.',
                 'location': 'WebActivity.java:21',
                 'evidence': 'webView.getSettings().setJavaScriptEnabled(true);',
                 'remediation': 'Disable JavaScript unless necessary.', 'poc': None},
                {'title': 'Debug Mode Enabled', 'severity': 'medium', 'category': 'Manifest', 'cvss': 5.3,
                 'description': 'The application has debuggable=true in production.',
                 'location': 'AndroidManifest.xml', 'evidence': 'android:debuggable="true"',
                 'remediation': 'Set debuggable to false before release.',
                 'poc': 'adb shell run-as com.demo.banking cat databases/users.db'},
                {'title': 'Cleartext Traffic Allowed', 'severity': 'high', 'category': 'Network', 'cvss': 7.4,
                 'description': 'App permits cleartext HTTP traffic.',
                 'location': 'network_security_config.xml',
                 'evidence': '<base-config cleartextTrafficPermitted="true">',
                 'remediation': 'Set cleartextTrafficPermitted to false.', 'poc': None},
                {'title': 'AWS Secret Key Exposed', 'severity': 'critical', 'category': 'Secrets', 'cvss': 9.1,
                 'description': 'AWS secret access key found hardcoded.',
                 'location': 'BuildConfig.java:196',
                 'evidence': 'AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
                 'remediation': 'Revoke exposed key. Use secrets manager.', 'poc': None},
                {'title': 'SQL Injection Risk', 'severity': 'high', 'category': 'Injection', 'cvss': 8.1,
                 'description': 'Raw SQL query constructed with user input.',
                 'location': 'DatabaseHelper.java:34',
                 'evidence': 'db.execSQL("SELECT * FROM users WHERE id=" + userId);',
                 'remediation': 'Use parameterized queries.', 'poc': None},
            ]
        },
        {
            'name': 'HealthApp.apk', 'package': 'com.demo.health',
            'version': '1.5.4', 'risk_score': 42,
            'vulns': [
                {'title': 'Insecure Data Storage', 'severity': 'medium', 'category': 'Storage', 'cvss': 5.5,
                 'description': 'Sensitive health data stored in SharedPreferences without encryption.',
                 'location': 'UserPrefs.java:55',
                 'evidence': 'prefs.putString("patient_data", sensitiveData);',
                 'remediation': 'Use EncryptedSharedPreferences.', 'poc': None},
                {'title': 'Backup Enabled', 'severity': 'medium', 'category': 'Manifest', 'cvss': 4.3,
                 'description': 'App allows full backup which could expose sensitive data.',
                 'location': 'AndroidManifest.xml', 'evidence': 'android:allowBackup="true"',
                 'remediation': 'Set allowBackup to false.', 'poc': None},
                {'title': 'Privacy Leak: Email Address', 'severity': 'low', 'category': 'Privacy', 'cvss': 3.1,
                 'description': 'User email address logged to logcat.',
                 'location': 'LoginActivity.java:78',
                 'evidence': 'Log.d("AUTH", "User email: " + email);',
                 'remediation': 'Remove PII from logs.', 'poc': None},
            ]
        },
        {
            'name': 'GameApp.apk', 'package': 'com.demo.game',
            'version': '3.0.1', 'risk_score': 31,
            'vulns': [
                {'title': 'SSL Certificate Not Validated', 'severity': 'high', 'category': 'Network', 'cvss': 7.4,
                 'description': 'Custom TrustManager accepts all SSL certificates.',
                 'location': 'NetworkHelper.java:45',
                 'evidence': 'public void checkServerTrusted(X509Certificate[] certs, String authType) {}',
                 'remediation': 'Use proper certificate validation.', 'poc': None},
                {'title': 'Unprotected Content Provider', 'severity': 'medium', 'category': 'Components', 'cvss': 5.8,
                 'description': 'Content provider exported without permissions.',
                 'location': 'AndroidManifest.xml',
                 'evidence': '<provider android:name=".GameDataProvider" android:exported="true"/>',
                 'remediation': 'Add read/write permissions.',
                 'poc': 'adb shell content query --uri content://com.demo.game.provider/scores'},
            ]
        }
    ]

    for i, app_data in enumerate(demo_apps):
        scan = Scan(
            user_id=user.id, apk_name=app_data['name'],
            package_name=app_data['package'], version_name=app_data['version'],
            status='completed', risk_score=app_data['risk_score'],
            static_status='completed', static_progress=100,
            static_risk_score=app_data['risk_score'],
            static_total_findings=len(app_data['vulns']),
            total_findings=len(app_data['vulns']),
            critical_count=sum(1 for v in app_data['vulns'] if v['severity'] == 'critical'),
            high_count=sum(1 for v in app_data['vulns'] if v['severity'] == 'high'),
            medium_count=sum(1 for v in app_data['vulns'] if v['severity'] == 'medium'),
            low_count=sum(1 for v in app_data['vulns'] if v['severity'] == 'low'),
            static_critical_count=sum(1 for v in app_data['vulns'] if v['severity'] == 'critical'),
            static_high_count=sum(1 for v in app_data['vulns'] if v['severity'] == 'high'),
            static_medium_count=sum(1 for v in app_data['vulns'] if v['severity'] == 'medium'),
            static_low_count=sum(1 for v in app_data['vulns'] if v['severity'] == 'low'),
            created_at=datetime.utcnow() - timedelta(days=i * 3),
            completed_at=datetime.utcnow() - timedelta(days=i * 3 - 1)
        )
        db.session.add(scan)
        db.session.flush()
        for v in app_data['vulns']:
            db.session.add(Vulnerability(
                scan_id=scan.id, analysis_type='static', title=v['title'], severity=v['severity'],
                category=v['category'], cvss_score=v['cvss'],
                description=v['description'], location=v['location'],
                evidence=v['evidence'], remediation=v['remediation'],
                poc_command=v['poc']
            ))
    db.session.commit()
    logger.info("Demo data seeded.")


_schema_ready = False
_schema_lock = threading.Lock()


@app.before_request
def initialize_database_once():
    """Initialize/migrate the database for Flask CLI, WSGI, and local runs."""
    global _schema_ready
    if _schema_ready:
        return
    with _schema_lock:
        if not _schema_ready:
            db.create_all()
            ensure_schema()
            seed()
            _schema_ready = True


if __name__ == '__main__':
    with app.app_context():
        initialize_database_once()
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
