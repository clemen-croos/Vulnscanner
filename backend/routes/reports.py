"""Reports Routes"""

import os
import json
from flask import Blueprint, request, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import db, Report, Scan, Vulnerability
from modules.report_generator import ReportGenerator

reports_bp = Blueprint('reports', __name__)


@reports_bp.route('', methods=['GET'])
@jwt_required()
def list_reports():
    user_id = get_jwt_identity()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    pagination = Report.query.filter_by(user_id=user_id).order_by(
        Report.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'reports': [r.to_dict() for r in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages
    })


@reports_bp.route('/generate', methods=['POST'])
@jwt_required()
def generate_report():
    user_id = get_jwt_identity()
    data = request.get_json()

    scan_id = data.get('scan_id')
    report_type = data.get('report_type', 'full')  # full, executive, compliance
    fmt = data.get('format', 'html')  # html, pdf, json

    if not scan_id:
        return jsonify({'error': 'scan_id is required'}), 400

    scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first_or_404()
    vulnerabilities = Vulnerability.query.filter_by(
        scan_id=scan_id, is_false_positive=False
    ).all()

    generator = ReportGenerator(current_app.config['REPORTS_FOLDER'])
    report_data = {
        'scan': scan.to_dict(),
        'vulnerabilities': [v.to_dict() for v in vulnerabilities],
        'report_type': report_type
    }

    try:
        file_path, file_size = generator.generate(report_data, fmt)

        report = Report(
            scan_id=scan_id,
            user_id=user_id,
            title=f"{report_type.title()} Report - {scan.apk_name}",
            report_type=report_type,
            format=fmt,
            file_path=file_path,
            file_size=file_size
        )
        db.session.add(report)
        db.session.commit()

        return jsonify({
            'message': 'Report generated successfully',
            'report': report.to_dict(),
            'download_url': f'/api/reports/{report.id}/download'
        }), 201

    except Exception as e:
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500


@reports_bp.route('/<int:report_id>/download', methods=['GET'])
@jwt_required()
def download_report(report_id):
    user_id = get_jwt_identity()
    report = Report.query.filter_by(id=report_id, user_id=user_id).first_or_404()

    if not report.file_path or not os.path.exists(report.file_path):
        return jsonify({'error': 'Report file not found'}), 404

    mime_types = {'pdf': 'application/pdf', 'html': 'text/html', 'json': 'application/json'}
    return send_file(
        report.file_path,
        mimetype=mime_types.get(report.format, 'application/octet-stream'),
        as_attachment=True,
        download_name=f"vulnscanner_report_{report.id}.{report.format}"
    )


@reports_bp.route('/<int:report_id>', methods=['DELETE'])
@jwt_required()
def delete_report(report_id):
    user_id = get_jwt_identity()
    report = Report.query.filter_by(id=report_id, user_id=user_id).first_or_404()
    if report.file_path and os.path.exists(report.file_path):
        os.remove(report.file_path)
    db.session.delete(report)
    db.session.commit()
    return jsonify({'message': 'Report deleted'})
