"""
VulnScanner Database Models
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    api_key = db.Column(db.String(64), unique=True)

    scans = db.relationship('Scan', backref='user', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    scan_uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: __import__('uuid').uuid4().hex)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    apk_name = db.Column(db.String(255), nullable=False)
    apk_path = db.Column(db.String(512))
    apk_size = db.Column(db.Integer)
    apk_hash_md5 = db.Column(db.String(32))
    apk_hash_sha256 = db.Column(db.String(64))
    package_name = db.Column(db.String(255))
    version_name = db.Column(db.String(50))
    version_code = db.Column(db.String(20))
    min_sdk = db.Column(db.Integer)
    target_sdk = db.Column(db.Integer)
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    progress = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Integer, default=0)
    total_findings = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    scan_options = db.Column(db.Text)  # JSON string
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='scan', lazy=True, cascade='all, delete-orphan')

    def to_dict(self, include_vulns=False):
        data = {
            'id': self.id,
            'scan_uuid': self.scan_uuid,
            'apk_name': self.apk_name,
            'apk_size': self.apk_size,
            'apk_hash_md5': self.apk_hash_md5,
            'package_name': self.package_name,
            'version_name': self.version_name,
            'version_code': self.version_code,
            'min_sdk': self.min_sdk,
            'target_sdk': self.target_sdk,
            'status': self.status,
            'progress': self.progress,
            'risk_score': self.risk_score,
            'total_findings': self.total_findings,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }
        if include_vulns:
            data['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        return data


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low
    category = db.Column(db.String(100))
    cvss_score = db.Column(db.Float)
    description = db.Column(db.Text)
    location = db.Column(db.String(512))
    evidence = db.Column(db.Text)
    remediation = db.Column(db.Text)
    poc_command = db.Column(db.Text)
    references = db.Column(db.Text)  # JSON array
    is_false_positive = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.String(20), default='medium')  # high, medium, low
    cwe_id = db.Column(db.String(20))
    owasp_category = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        import json
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'title': self.title,
            'severity': self.severity,
            'category': self.category,
            'cvss_score': self.cvss_score,
            'description': self.description,
            'location': self.location,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'poc_command': self.poc_command,
            'references': json.loads(self.references) if self.references else [],
            'is_false_positive': self.is_false_positive,
            'confidence': self.confidence,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255))
    report_type = db.Column(db.String(50))  # full, executive, compliance
    format = db.Column(db.String(10))  # pdf, html, json
    file_path = db.Column(db.String(512))
    file_size = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'title': self.title,
            'report_type': self.report_type,
            'format': self.format,
            'file_size': self.file_size,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'apk_name': self.scan.apk_name if self.scan else None,
            'risk_score': self.scan.risk_score if self.scan else None
        }
