"""
VulnScanner Enterprise AI/NLP Filter
=====================================
Advanced false positive reduction using multi-tier classification.
Replace backend/modules/ai_filter.py with this file.
"""

import re
import math
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# False-positive allowlists

FALSE_POSITIVE_STRINGS = {
    'example', 'sample', 'test', 'demo', 'placeholder', 'dummy',
    'your_key_here', 'insert_key', 'replace_with', 'your_api_key',
    'xxx', '000000', 'aaaaaa', 'abcdef', '123456', '111111',
    'changeme', 'todo', 'fixme', 'mock', 'fake', 'stub',
    'undefined', 'null', 'none', 'empty', 'default',
    'my_api_key', 'api_key_here', 'enter_key', 'put_key',
    'xxxxxxxxxxxxxxxx', 'aaaaaaaaaaaaaaaa', '1234567890123456',
}

# Common non-secret values
SAFE_PATTERNS = [
    r'^[a-f0-9]{32}$',          # MD5 hash (legitimate)
    r'^\d{10,13}$',              # Timestamps
    r'^[01]+$',                  # Binary strings
    r'^(.)\1{7,}$',              # Repeated chars
    r'(?i)^test[_\-]?\w+$',     # Test values
    r'(?i)^example[_\-]?\w+$',  # Example values
    r'(?i)^sample[_\-]?\w+$',   # Sample values
    r'(?i)^dummy[_\-]?\w+$',    # Dummy values
]

# High-confidence secret formats
HIGH_CONFIDENCE_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',                           # AWS Access Key
    r'AIza[0-9A-Za-z\-_]{35}',                    # Google API Key
    r'-----BEGIN.*PRIVATE KEY-----',               # Private Key
    r'ghp_[0-9a-zA-Z]{36}',                       # GitHub Token
    r'sk-[a-zA-Z0-9]{48}',                        # OpenAI Key
    r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+',  # JWT Token
    r'(?i)jdbc:[a-z]+://[^\s"\']{10,}',           # DB Connection
]

# Category-specific severity overrides
SEVERITY_CONTEXT_RULES = {
    'Secrets': {
        'keywords_upgrade': ['production', 'prod', 'live', 'release', 'master'],
        'keywords_downgrade': ['test', 'dev', 'debug', 'example', 'sample'],
    },
    'SSL/TLS': {
        'keywords_upgrade': ['banking', 'payment', 'auth', 'login', 'credential'],
        'keywords_downgrade': ['test', 'debug', 'development'],
    }
}


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


class AIFilter:
    """
    Multi-tier AI/NLP filter for vulnerability findings.
    Tier 1: Rule-based fast filtering
    Tier 2: Entropy analysis
    Tier 3: Context-aware scoring
    Tier 4: Optional ML classifier
    """

    def __init__(self):
        self.ml_available = self._try_load_ml()

    def _try_load_ml(self) -> bool:
        try:
            from sklearn.ensemble import RandomForestClassifier
            import numpy as np
            return True
        except ImportError:
            return False

    def filter_findings(self, findings: List[Dict]) -> List[Dict]:
        """Main filter pipeline"""
        if not findings:
            return findings

        filtered = []
        stats = {'total': len(findings), 'removed': 0, 'confidence_boosted': 0}

        for finding in findings:
            result = self._evaluate(finding)
            if result is not None:
                filtered.append(result)
            else:
                stats['removed'] += 1

        logger.info(
            f"AI Filter: {stats['total']} → {len(filtered)} findings "
            f"({stats['removed']} filtered as false positives)"
        )
        return filtered

    def _evaluate(self, finding: Dict) -> Dict | None:
        """Evaluate a single finding through all tiers"""
        category = finding.get('category', '').lower()
        severity = finding.get('severity', 'low')
        evidence = finding.get('evidence', '')
        title = finding.get('title', '')

        # Secret findings still need placeholder/entropy checks even when the
        # pattern matcher initially labels them critical.
        if severity == 'critical' and category != 'secrets':
            finding['ai_confidence'] = 0.95
            finding['confidence'] = 'high'
            return finding

        if category == 'ssl/tls' and severity in ('critical', 'high'):
            finding['ai_confidence'] = 0.92
            finding['confidence'] = 'high'
            return finding

        if category == 'secrets':
            result = self._filter_secret(finding, evidence, title)
            if result is None:
                return None
            finding = result

        evidence_lower = evidence.lower()

        if any(fp in evidence_lower for fp in FALSE_POSITIVE_STRINGS):
            has_real = any(re.search(p, evidence) for p in HIGH_CONFIDENCE_PATTERNS)
            if not has_real:
                logger.debug(f'Filtered FP (allowlist): {title}')
                return None

        confidence_score = self._compute_confidence(finding)
        finding['ai_confidence'] = round(confidence_score, 3)

        if confidence_score < 0.25 and severity not in ('critical', 'high'):
            return None

        if confidence_score >= 0.75:
            finding['confidence'] = 'high'
        elif confidence_score >= 0.45:
            finding['confidence'] = 'medium'
        else:
            finding['confidence'] = 'low'

        return finding

    def _filter_secret(self, finding: Dict, evidence: str, title: str) -> Dict | None:
        """Secret-specific filtering with entropy analysis"""

        value = ''

        quoted = re.search(r'["\']([A-Za-z0-9\-_/+.@]{8,})["\']', evidence)
        if quoted:
            value = quoted.group(1)
        else:
            assigned = re.search(r'[=:]\s*([A-Za-z0-9\-_/+.@]{8,})', evidence)
            if assigned:
                value = assigned.group(1)
            else:
                value = evidence[:50]

        if not value:
            return finding

        for safe_pat in SAFE_PATTERNS:
            if re.match(safe_pat, value):
                return None

        if value.lower() in FALSE_POSITIVE_STRINGS:
            return None

        entropy = shannon_entropy(value)

        for hc_pattern in HIGH_CONFIDENCE_PATTERNS:
            if re.search(hc_pattern, evidence):
                finding['confidence'] = 'high'
                finding['ai_confidence'] = 0.97
                return finding

        if entropy < 2.0:
            return None
        elif entropy < 3.0:
            context = evidence.lower()
            has_context = any(kw in context for kw in [
                'key', 'token', 'secret', 'password', 'auth', 'credential',
                'api', 'access', 'private', 'encrypt', 'bearer', 'oauth'
            ])
            if not has_context:
                return None
            finding['confidence'] = 'low'
        elif entropy < 4.0:
            finding['confidence'] = 'medium'
        else:
            finding['confidence'] = 'high'

        if value and len(set(value)) < 5:
            return None

        return finding

    def _compute_confidence(self, finding: Dict) -> float:
        """Compute 0.0-1.0 confidence score"""
        score = 0.50

        evidence = finding.get('evidence', '')
        location = finding.get('location', '')
        category = finding.get('category', '')
        severity = finding.get('severity', 'low')
        title = finding.get('title', '')

        if len(evidence) > 30:
            score += 0.08
        if len(evidence) > 80:
            score += 0.07

        if any(ext in location for ext in ['.java', '.kt', '.smali']):
            score += 0.10
        if ':' in location:
            score += 0.08
        if 'AndroidManifest' in location:
            score += 0.10

        cvss = finding.get('cvss_score', 0) or 0
        if severity == 'critical' and cvss >= 9.0:
            score += 0.12
        elif severity == 'high' and cvss >= 7.0:
            score += 0.10
        elif severity == 'medium' and 4.0 <= cvss < 7.0:
            score += 0.08
        elif severity == 'low' and cvss < 4.0:
            score += 0.05

        if finding.get('cwe_id') and finding['cwe_id'] != 'CWE-200':
            score += 0.05

        if finding.get('owasp_category'):
            score += 0.05

        engine_confidence = finding.get('confidence', 'medium')
        if engine_confidence == 'high':
            score += 0.10
        elif engine_confidence == 'low':
            score -= 0.10

        for hc_pattern in HIGH_CONFIDENCE_PATTERNS:
            if re.search(hc_pattern, evidence):
                score += 0.20
                break

        return max(0.0, min(1.0, score))
