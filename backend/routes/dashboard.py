"""Dashboard Routes"""

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import db, Scan, Vulnerability
from sqlalchemy import func
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    user_id = get_jwt_identity()

    total_scans = Scan.query.filter_by(user_id=user_id).count()
    completed_scans = Scan.query.filter_by(user_id=user_id, status='completed').count()

    # Vulnerability counts across all scans
    vuln_stats = db.session.query(
        func.sum(Scan.critical_count),
        func.sum(Scan.high_count),
        func.sum(Scan.medium_count),
        func.sum(Scan.low_count),
        func.avg(Scan.risk_score)
    ).filter_by(user_id=user_id, status='completed').first()

    # Recent scans
    recent_scans = Scan.query.filter_by(user_id=user_id).order_by(
        Scan.created_at.desc()
    ).limit(5).all()

    # Category breakdown
    category_counts = db.session.query(
        Vulnerability.category, func.count(Vulnerability.id)
    ).join(Scan).filter(
        Scan.user_id == user_id,
        Vulnerability.is_false_positive == False
    ).group_by(Vulnerability.category).all()

    # Trend data (last 7 scans)
    trend_scans = Scan.query.filter_by(
        user_id=user_id, status='completed'
    ).order_by(Scan.created_at.desc()).limit(7).all()

    trend_data = [{
        'date': s.created_at.strftime('%b %d') if s.created_at else '',
        'risk_score': s.risk_score,
        'total_findings': s.total_findings,
        'name': s.apk_name
    } for s in reversed(trend_scans)]

    return jsonify({
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'overall_risk_score': int(vuln_stats[4] or 0),
        'severity_breakdown': {
            'critical': int(vuln_stats[0] or 0),
            'high': int(vuln_stats[1] or 0),
            'medium': int(vuln_stats[2] or 0),
            'low': int(vuln_stats[3] or 0)
        },
        'recent_scans': [s.to_dict() for s in recent_scans],
        'category_breakdown': [{'category': c[0], 'count': c[1]} for c in category_counts if c[0]],
        'trend_data': trend_data
    })
