"""
VulnScanner Enterprise - Scans Routes
=======================================
Updated scan orchestrator using the enterprise analysis engine.
Replace backend/routes/scans.py with this file.
"""

import os
import json
import uuid
import hashlib
import threading
import time
from flask import Blueprint, request, jsonify, current_app
from app import limiter
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from database import db, Scan, Vulnerability, User
from datetime import datetime

scans_bp = Blueprint('scans', __name__)

ALLOWED_EXTENSIONS = {'apk'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def compute_hashes(filepath):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


@scans_bp.route('', methods=['GET'])
@jwt_required()
def list_scans():
    user_id = get_jwt_identity()

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    status = request.args.get('status')

    query = Scan.query.filter_by(user_id=user_id)
    if status:
        query = query.filter_by(status=status)

    pagination = query.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'scans': [s.to_dict() for s in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@scans_bp.route('/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_scan(scan_id):
    user_id = get_jwt_identity()

    scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first_or_404()
    include_vulns = request.args.get('include_vulns', 'false').lower() == 'true'
    return jsonify({'scan': scan.to_dict(include_vulns=include_vulns)})


@scans_bp.route('/upload', methods=['POST'])
@jwt_required()
@limiter.limit("10 per hour")
def upload_apk():
    user_id = get_jwt_identity()

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.lower().endswith('.apk'):
        return jsonify({'error': 'Invalid file type. Only .apk files are allowed'}), 400

    options = {'static': True, 'dynamic': False, 'ai_filter': True}
    try:
        raw = request.form.get('options')
        if raw:
            options.update(json.loads(raw))
    except Exception:
        pass

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
    filename = secure_filename(file.filename) or f'upload_{scan_uuid}.apk'
    upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], scan_uuid)
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)

    try:
        md5_hash, sha256_hash = compute_hashes(filepath)
    except Exception:
        md5_hash, sha256_hash = 'unknown', 'unknown'

    scan = Scan(
        scan_uuid=scan_uuid,
        user_id=user_id,
        apk_name=filename,
        apk_path=filepath,
        apk_size=file_size,
        apk_hash_md5=md5_hash,
        apk_hash_sha256=sha256_hash,
        status='pending',
        progress=0,
        scan_options=json.dumps(options)
    )
    db.session.add(scan)
    db.session.commit()

    app = current_app._get_current_object()
    t = threading.Thread(
        target=_run_enterprise_scan,
        args=(app, scan.id, filepath, options),
        daemon=True
    )
    t.start()

    return jsonify({
        'message': 'APK uploaded successfully. Enterprise scan started.',
        'scan_id': scan.id,
        'scan_uuid': scan_uuid
    }), 201


def _update_scan_progress(app, scan_id, progress, status=None):
    """Thread-safe progress update"""
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if scan:
            scan.progress = progress
            if status:
                scan.status = status
            db.session.commit()


def _run_enterprise_scan(app, scan_id, apk_path, options):
    """
    Enterprise scan orchestrator using the full analysis engine.
    Runs all analysis modules in sequence with real-time progress updates.
    """
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        try:
            scan.status = 'running'
            scan.progress = 5
            db.session.commit()

            from modules.static_analyzer import VulnScannerEngine
            engine = VulnScannerEngine(apk_path)

            def on_progress(pct, msg=''):
                try:
                    s = Scan.query.get(scan_id)
                    if s:
                        s.progress = pct
                        db.session.commit()
                except Exception:
                    pass

            on_progress(8, 'Validating APK structure...')
            from modules.static_analyzer import APKValidator
            validator = APKValidator()
            validation = validator.validate(apk_path)

            if not validation['valid']:
                scan.status = 'failed'
                scan.error_message = 'APK validation failed: ' + '; '.join(validation['errors'])
                scan.progress = 0
                db.session.commit()
                return

            on_progress(12, 'Computing file hashes...')
            hashes = validator.compute_hashes(apk_path)
            scan.apk_hash_md5 = hashes['md5']
            scan.apk_hash_sha256 = hashes['sha256']
            db.session.commit()

            on_progress(18, 'Parsing APK metadata...')
            apk_info = engine.parse_apk()
            scan.package_name = apk_info.get('package_name', 'Unknown')
            scan.version_name = apk_info.get('version_name', '1.0')
            scan.version_code = str(apk_info.get('version_code', '1'))
            if apk_info.get('min_sdk'):
                scan.min_sdk = int(apk_info['min_sdk']) if str(apk_info['min_sdk']).isdigit() else None
            if apk_info.get('target_sdk'):
                scan.target_sdk = int(apk_info['target_sdk']) if str(apk_info['target_sdk']).isdigit() else None
            db.session.commit()

            on_progress(25, 'Extracting APK content...')
            manifest_content, code_content = engine.extract_content()

            on_progress(35, 'Analyzing AndroidManifest.xml...')
            from modules.static_analyzer import ManifestAnalyzer
            manifest_analyzer = ManifestAnalyzer()
            manifest_findings = manifest_analyzer.analyze(
                manifest_content, scan.package_name or ''
            )

            on_progress(50, 'Scanning DEX bytecode for vulnerabilities...')
            from modules.static_analyzer import CodeAnalyzer
            code_analyzer = CodeAnalyzer()
            code_findings = code_analyzer.analyze(
                code_content, scan.package_name or ''
            )

            on_progress(62, 'Analyzing signing certificate...')
            from modules.static_analyzer import CertificateAnalyzer
            cert_analyzer = CertificateAnalyzer()
            cert_findings = cert_analyzer.analyze(apk_path)

            on_progress(70, 'Scanning native libraries...')
            from modules.static_analyzer import NativeLibAnalyzer
            native_analyzer = NativeLibAnalyzer()
            native_findings = native_analyzer.analyze(apk_path)

            on_progress(78, 'Analyzing obfuscation...')
            from modules.static_analyzer import ObfuscationAnalyzer
            obf_analyzer = ObfuscationAnalyzer()
            obf_result = obf_analyzer.analyze(code_content, apk_path)
            obf_findings = obf_result['findings']

            all_findings = (
                manifest_findings +
                code_findings +
                cert_findings +
                native_findings +
                obf_findings
            )

            # Filter likely false positives when requested.
            on_progress(85, 'Running AI false-positive filter...')
            if options.get('ai_filter', True) and all_findings:
                from modules.ai_filter import AIFilter
                ai_filter = AIFilter()
                all_findings = ai_filter.filter_findings(all_findings)

            on_progress(90, 'Deduplicating findings...')
            seen_titles = set()
            unique_findings = []
            for f in all_findings:
                title = f.get('title', '')
                if title not in seen_titles:
                    seen_titles.add(title)
                    unique_findings.append(f)
            all_findings = unique_findings

            on_progress(93, 'Calculating risk score...')
            from modules.risk_scorer import RiskScorer
            risk_scorer = RiskScorer()
            risk_score = risk_scorer.calculate_risk_score(all_findings)

            on_progress(96, 'Saving results...')
            for f in all_findings:
                vuln = Vulnerability(
                    scan_id=scan.id,
                    title=f.get('title', 'Unknown Finding'),
                    severity=f.get('severity', 'medium'),
                    category=f.get('category', 'General'),
                    cvss_score=f.get('cvss_score'),
                    description=f.get('description', ''),
                    location=f.get('location', ''),
                    evidence=f.get('evidence', ''),
                    remediation=f.get('remediation', ''),
                    poc_command=f.get('poc_command'),
                    confidence=f.get('confidence', 'medium'),
                    cwe_id=f.get('cwe_id'),
                    owasp_category=f.get('owasp_category')
                )
                db.session.add(vuln)

            scan.risk_score = risk_score
            scan.total_findings = len(all_findings)
            scan.critical_count = sum(1 for f in all_findings if f.get('severity') == 'critical')
            scan.high_count = sum(1 for f in all_findings if f.get('severity') == 'high')
            scan.medium_count = sum(1 for f in all_findings if f.get('severity') == 'medium')
            scan.low_count = sum(1 for f in all_findings if f.get('severity') == 'low')
            scan.status = 'completed'
            scan.progress = 100
            scan.completed_at = datetime.utcnow()

            import json as _json
            scan.scan_options = _json.dumps({
                **options,
                'apk_info': apk_info,
                'hashes': hashes,
                'validation_warnings': validation.get('warnings', []),
                'obfuscation_score': obf_result.get('obfuscation_score', 0),
                'protection_level': obf_result.get('protection_level', 'None'),
            })
            db.session.commit()

        except Exception as e:
            import traceback
            error_msg = str(e)
            tb = traceback.format_exc()
            print(f"[SCAN ERROR] scan_id={scan_id}: {error_msg}\n{tb}")

            try:
                s = Scan.query.get(scan_id)
                if s:
                    s.status = 'failed'
                    s.error_message = f'Scan error: {error_msg[:500]}'
                    s.progress = 0
                    db.session.commit()
            except Exception:
                pass


@scans_bp.route('/<int:scan_id>/status', methods=['GET'])
@jwt_required()
def scan_status(scan_id):
    user_id = get_jwt_identity()

    scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first_or_404()
    return jsonify({
        'status': scan.status,
        'progress': scan.progress,
        'error': scan.error_message
    })


@scans_bp.route('/<int:scan_id>', methods=['DELETE'])
@jwt_required()
def delete_scan(scan_id):
    user_id = get_jwt_identity()

    scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first_or_404()

    if scan.apk_path and os.path.exists(scan.apk_path):
        try:
            import shutil
            upload_dir = os.path.dirname(scan.apk_path)
            shutil.rmtree(upload_dir, ignore_errors=True)
        except Exception:
            pass

    db.session.delete(scan)
    db.session.commit()
    return jsonify({'message': 'Scan deleted successfully'})
