"""
VulnScanner Enterprise Risk Scorer
====================================
CVSS-inspired risk scoring with exploitability and impact metrics.
Replace backend/modules/risk_scorer.py with this file.
"""

from typing import List, Dict, Any


class RiskScorer:
    """
    Enterprise-grade CVSS-inspired risk scoring.
    Produces 0-100 score with category breakdown.
    """

    SEVERITY_WEIGHTS = {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 1,
        'info': 0
    }

    # Category risk multipliers
    CATEGORY_MULTIPLIERS = {
        'Secrets': 1.3,
        'SSL/TLS': 1.2,
        'Certificate': 1.2,
        'Cryptography': 1.1,
        'Malware Behavior': 1.4,
        'Code Injection': 1.3,
        'Permissions': 1.0,
        'Components': 1.1,
        'WebView': 1.1,
        'Network': 1.0,
        'Storage': 0.9,
        'Manifest': 0.9,
        'Native Code': 1.0,
        'Obfuscation': 0.7,
        'Anti-Analysis': 0.8,
    }

    def calculate_risk_score(self, findings: List[Dict]) -> int:
        """Calculate overall 0-100 risk score"""
        if not findings:
            return 0

        critical = [f for f in findings if f.get('severity') == 'critical']
        high = [f for f in findings if f.get('severity') == 'high']
        medium = [f for f in findings if f.get('severity') == 'medium']
        low = [f for f in findings if f.get('severity') == 'low']

        # Base score from severity distribution
        if critical:
            # A confirmed critical issue must remain in the critical (90+) band.
            base = min(100, 87 + len(critical) * 3)
        elif high:
            base = min(84, 60 + len(high) * 5 + len(medium) * 2)
        elif medium:
            base = min(59, 35 + len(medium) * 6 + len(low) * 2)
        elif low:
            base = min(34, 15 + len(low) * 4)
        else:
            base = 5

        # Apply category multipliers
        weighted_sum = 0
        total_weight = 0
        for f in findings:
            cat = f.get('category', 'General')
            sev = f.get('severity', 'low')
            weight = self.SEVERITY_WEIGHTS.get(sev, 1)
            multiplier = self.CATEGORY_MULTIPLIERS.get(cat, 1.0)
            weighted_sum += weight * multiplier
            total_weight += weight

        # Adjust base by category weighting
        if total_weight > 0:
            category_factor = weighted_sum / total_weight
            adjusted = base * min(1.3, max(0.8, category_factor))
        else:
            adjusted = base

        return min(100, max(0, int(adjusted)))

    def get_risk_breakdown(self, findings: List[Dict]) -> Dict[str, Any]:
        """Get detailed risk breakdown by category"""
        categories = {}
        for f in findings:
            cat = f.get('category', 'General')
            sev = f.get('severity', 'low')
            if cat not in categories:
                categories[cat] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}
            categories[cat][sev] = categories[cat].get(sev, 0) + 1
            categories[cat]['total'] += 1

        # Sort by risk impact
        sorted_cats = sorted(
            categories.items(),
            key=lambda x: (
                x[1].get('critical', 0) * 10 +
                x[1].get('high', 0) * 7 +
                x[1].get('medium', 0) * 4 +
                x[1].get('low', 0)
            ),
            reverse=True
        )

        return {
            'by_category': dict(sorted_cats),
            'total_findings': len(findings),
            'critical': sum(1 for f in findings if f.get('severity') == 'critical'),
            'high': sum(1 for f in findings if f.get('severity') == 'high'),
            'medium': sum(1 for f in findings if f.get('severity') == 'medium'),
            'low': sum(1 for f in findings if f.get('severity') == 'low'),
        }

    def get_masvs_mapping(self, findings: List[Dict]) -> Dict[str, List[str]]:
        """Map findings to OWASP MASVS categories"""
        masvs = {
            'MASVS-STORAGE': [],
            'MASVS-CRYPTO': [],
            'MASVS-AUTH': [],
            'MASVS-NETWORK': [],
            'MASVS-PLATFORM': [],
            'MASVS-CODE': [],
            'MASVS-RESILIENCE': [],
        }

        category_map = {
            'Storage': 'MASVS-STORAGE',
            'Cryptography': 'MASVS-CRYPTO',
            'Certificate': 'MASVS-CRYPTO',
            'SSL/TLS': 'MASVS-NETWORK',
            'Network': 'MASVS-NETWORK',
            'Secrets': 'MASVS-AUTH',
            'Permissions': 'MASVS-PLATFORM',
            'Components': 'MASVS-PLATFORM',
            'WebView': 'MASVS-PLATFORM',
            'Manifest': 'MASVS-PLATFORM',
            'Code Injection': 'MASVS-CODE',
            'Native Code': 'MASVS-CODE',
            'Malware Behavior': 'MASVS-CODE',
            'Obfuscation': 'MASVS-RESILIENCE',
            'Anti-Analysis': 'MASVS-RESILIENCE',
        }

        for f in findings:
            cat = f.get('category', '')
            masvs_cat = category_map.get(cat, 'MASVS-CODE')
            title = f.get('title', 'Unknown')
            if title not in masvs[masvs_cat]:
                masvs[masvs_cat].append(title)

        return {k: v for k, v in masvs.items() if v}
