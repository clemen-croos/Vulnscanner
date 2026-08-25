"""Vulnerabilities Routes"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import db, Vulnerability, Scan

vulns_bp = Blueprint('vulnerabilities', __name__)


@vulns_bp.route('', methods=['GET'])
@jwt_required()
def list_vulnerabilities():
    user_id = get_jwt_identity()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    severity = request.args.get('severity')
    category = request.args.get('category')
    scan_id = request.args.get('scan_id', type=int)
    search = request.args.get('search', '')

    # Join with scans to filter by user
    query = Vulnerability.query.join(Scan).filter(
        Scan.user_id == user_id,
        Vulnerability.is_false_positive == False
    )

    if scan_id:
        query = query.filter(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if category:
        query = query.filter(Vulnerability.category == category)
    if search:
        query = query.filter(Vulnerability.title.ilike(f'%{search}%'))

    pagination = query.order_by(
        db.case(
            (Vulnerability.severity == 'critical', 1),
            (Vulnerability.severity == 'high', 2),
            (Vulnerability.severity == 'medium', 3),
            (Vulnerability.severity == 'low', 4),
            else_=5
        )
    ).paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'vulnerabilities': [v.to_dict() for v in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@vulns_bp.route('/<int:vuln_id>', methods=['GET'])
@jwt_required()
def get_vulnerability(vuln_id):
    user_id = get_jwt_identity()
    vuln = Vulnerability.query.join(Scan).filter(
        Vulnerability.id == vuln_id,
        Scan.user_id == user_id
    ).first_or_404()
    return jsonify({'vulnerability': vuln.to_dict()})


@vulns_bp.route('/<int:vuln_id>/mark-false-positive', methods=['POST'])
@jwt_required()
def mark_false_positive(vuln_id):
    user_id = get_jwt_identity()
    vuln = Vulnerability.query.join(Scan).filter(
        Vulnerability.id == vuln_id,
        Scan.user_id == user_id
    ).first_or_404()
    vuln.is_false_positive = not vuln.is_false_positive
    db.session.commit()
    return jsonify({
        'message': 'Updated',
        'is_false_positive': vuln.is_false_positive
    })


@vulns_bp.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    user_id = get_jwt_identity()
    categories = db.session.query(Vulnerability.category).join(Scan).filter(
        Scan.user_id == user_id
    ).distinct().all()
    return jsonify({'categories': [c[0] for c in categories if c[0]]})
