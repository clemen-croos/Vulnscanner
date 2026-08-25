"""
VulnScanner Enterprise Report Generator
=========================================
Generates professional PDF/HTML/JSON security reports.
Replace backend/modules/report_generator.py with this file.
"""

import os
import json
import uuid
from datetime import datetime
from typing import Dict, Tuple, List


SEVERITY_COLORS = {
    'critical': '#ef4444',
    'high': '#f97316',
    'medium': '#eab308',
    'low': '#22c55e',
    'info': '#3b82f6',
}

SEVERITY_BG = {
    'critical': 'rgba(239,68,68,0.12)',
    'high': 'rgba(249,115,22,0.12)',
    'medium': 'rgba(234,179,8,0.12)',
    'low': 'rgba(34,197,94,0.12)',
    'info': 'rgba(59,130,246,0.12)',
}


def _risk_color(score: int) -> str:
    if score >= 80: return '#ef4444'
    if score >= 60: return '#f97316'
    if score >= 40: return '#eab308'
    if score >= 20: return '#3b82f6'
    return '#22c55e'


def _risk_label(score: int) -> str:
    if score >= 80: return 'CRITICAL RISK'
    if score >= 60: return 'HIGH RISK'
    if score >= 40: return 'MEDIUM RISK'
    if score >= 20: return 'LOW RISK'
    return 'MINIMAL RISK'


def _get_owasp_top10_coverage(findings: List[Dict]) -> Dict[str, int]:
    counts = {
        'M1: Improper Credential Usage': 0,
        'M2: Insecure Data Storage': 0,
        'M3: Insecure Communication': 0,
        'M4: Insufficient Input/Output Validation': 0,
        'M5: Improper Cryptography Usage': 0,
        'M6: Insecure Authorization': 0,
        'M7: Insufficient Binary Protections': 0,
        'M8: Security Misconfiguration': 0,
        'M9: Insecure Data Storage': 0,
        'M10: Insufficient Cryptography': 0,
    }
    for f in findings:
        owasp = f.get('owasp_category', '')
        for key in counts:
            if owasp and key.split(':')[0] in owasp:
                counts[key] += 1
    return {k: v for k, v in counts.items() if v > 0}


HTML_REPORT = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScanner Security Report — {apk_name}</title>
<style>
:root {{
  --bg: #080c16; --bg2: #0d1220; --card: #111827;
  --border: #1e2d4a; --text: #e2e8f0; --muted: #6b7280;
  --purple: #7c3aed;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; }}
.page {{ max-width:1100px; margin:0 auto; padding:0 24px 60px; }}

/* Header */
.report-header {{ background:linear-gradient(135deg,#0d1220,#080c16); border-bottom:2px solid var(--purple); padding:40px 32px; margin-bottom:32px; }}
.report-header-inner {{ display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:20px; }}
.logo-area h1 {{ font-size:2rem; color:var(--purple); font-weight:900; }}
.logo-area p {{ color:var(--muted); font-size:0.9rem; margin-top:4px; }}
.report-meta {{ text-align:right; }}
.report-meta p {{ font-size:0.85rem; color:var(--muted); }}
.report-meta strong {{ color:var(--text); }}

/* Risk score banner */
.risk-banner {{ border-radius:16px; padding:28px 32px; margin-bottom:32px; display:flex; align-items:center; gap:32px; border:1px solid; }}
.risk-circle {{ width:100px; height:100px; border-radius:50%; display:flex; flex-direction:column; align-items:center; justify-content:center; border:4px solid; flex-shrink:0; }}
.risk-circle .score {{ font-size:2.4rem; font-weight:900; line-height:1; }}
.risk-circle .label {{ font-size:0.65rem; color:var(--muted); margin-top:2px; }}
.risk-details h2 {{ font-size:1.4rem; font-weight:800; }}
.risk-details p {{ color:var(--muted); font-size:0.9rem; margin-top:4px; }}
.risk-details .meta-row {{ display:flex; gap:24px; margin-top:12px; flex-wrap:wrap; }}
.risk-details .meta-item {{ font-size:0.85rem; }}
.risk-details .meta-item span {{ color:var(--muted); }}

/* Summary cards */
.summary-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:32px; }}
.summary-card {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; text-align:center; }}
.summary-card .count {{ font-size:2.8rem; font-weight:900; line-height:1; }}
.summary-card .cat {{ font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-top:6px; font-weight:700; }}

/* APK info */
.section {{ margin-bottom:36px; }}
.section-title {{ font-size:1.1rem; font-weight:700; color:#94a3b8; border-left:3px solid var(--purple); padding-left:12px; margin-bottom:16px; }}
.info-grid {{ display:grid; grid-template-columns:repeat(2,1fr); gap:12px; }}
.info-item {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px 16px; }}
.info-item .info-label {{ font-size:0.72rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:4px; }}
.info-item .info-value {{ font-size:0.9rem; color:var(--text); font-weight:600; font-family:monospace; word-break:break-all; }}

/* OWASP coverage */
.owasp-grid {{ display:grid; grid-template-columns:repeat(2,1fr); gap:8px; }}
.owasp-item {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:10px 14px; display:flex; justify-content:space-between; align-items:center; }}
.owasp-name {{ font-size:0.82rem; color:#94a3b8; }}
.owasp-count {{ font-size:0.9rem; font-weight:800; color:var(--purple); }}

/* Vulnerability cards */
.vuln-section-header {{ display:flex; align-items:center; gap:10px; margin:24px 0 14px; }}
.vuln-sev-label {{ font-size:0.9rem; font-weight:800; text-transform:uppercase; }}
.vuln-count-badge {{ background:rgba(255,255,255,0.08); border-radius:20px; padding:2px 10px; font-size:0.8rem; color:var(--muted); }}

.vuln-card {{ background:var(--card); border:1px solid var(--border); border-radius:12px; margin-bottom:14px; overflow:hidden; }}
.vuln-card-header {{ padding:14px 18px; display:flex; align-items:center; gap:12px; background:rgba(255,255,255,0.02); border-bottom:1px solid var(--border); }}
.sev-badge {{ padding:3px 10px; border-radius:20px; font-size:0.7rem; font-weight:800; text-transform:uppercase; letter-spacing:0.05em; border:1px solid; }}
.vuln-title {{ font-size:0.95rem; font-weight:700; flex:1; }}
.cvss-tag {{ font-size:0.75rem; font-family:monospace; padding:2px 8px; background:rgba(255,255,255,0.05); border-radius:6px; color:var(--muted); }}

.vuln-card-body {{ padding:18px; }}
.field-label {{ font-size:0.7rem; text-transform:uppercase; letter-spacing:0.06em; color:var(--purple); font-weight:700; margin-bottom:5px; margin-top:14px; }}
.field-label:first-child {{ margin-top:0; }}
.field-text {{ font-size:0.88rem; color:#94a3b8; line-height:1.6; }}
.code-block {{ background:#040810; border:1px solid var(--border); border-radius:6px; padding:11px 14px; font-family:'Courier New',monospace; font-size:0.8rem; color:#7dd3fc; margin-top:5px; overflow-x:auto; white-space:pre-wrap; word-break:break-all; }}
.tag-row {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:5px; }}
.tag {{ font-size:0.72rem; padding:2px 8px; border-radius:6px; font-weight:600; }}

/* Footer */
.report-footer {{ text-align:center; padding:32px; color:var(--muted); font-size:0.82rem; border-top:1px solid var(--border); margin-top:48px; }}

@media print {{
  body {{ background:white; color:black; }}
  .report-header {{ background:white; border-bottom:2px solid #7c3aed; }}
  .vuln-card {{ border:1px solid #ccc; page-break-inside:avoid; }}
  .summary-card {{ border:1px solid #ccc; }}
}}
</style>
</head>
<body>
<div class="report-header">
  <div class="report-header-inner">
    <div class="logo-area">
      <h1>🛡 VulnScanner</h1>
      <p>Enterprise Android Security Analysis Report</p>
    </div>
    <div class="report-meta">
      <p>Report Type: <strong>{report_type}</strong></p>
      <p>Generated: <strong>{generated_at}</strong></p>
      <p>Report ID: <strong>{report_id}</strong></p>
    </div>
  </div>
</div>

<div class="page">

  <!-- Risk Banner -->
  <div class="risk-banner" style="background:{risk_bg};border-color:{risk_border};">
    <div class="risk-circle" style="border-color:{risk_color};color:{risk_color};background:{risk_circle_bg};">
      <span class="score">{risk_score}</span>
      <span class="label">/100</span>
    </div>
    <div class="risk-details">
      <h2 style="color:{risk_color};">{risk_label}</h2>
      <p>{apk_name}</p>
      <div class="meta-row">
        <div class="meta-item"><span>Package:</span> {package_name}</div>
        <div class="meta-item"><span>Version:</span> {version_name}</div>
        {min_sdk_row}
        <div class="meta-item"><span>Total Findings:</span> <strong style="color:{risk_color}">{total_findings}</strong></div>
      </div>
    </div>
  </div>

  <!-- Severity Summary -->
  <div class="summary-grid">
    <div class="summary-card" style="border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.06);">
      <div class="count" style="color:#ef4444;">{critical_count}</div>
      <div class="cat" style="color:#ef4444;">Critical</div>
    </div>
    <div class="summary-card" style="border-color:rgba(249,115,22,0.3);background:rgba(249,115,22,0.06);">
      <div class="count" style="color:#f97316;">{high_count}</div>
      <div class="cat" style="color:#f97316;">High</div>
    </div>
    <div class="summary-card" style="border-color:rgba(234,179,8,0.3);background:rgba(234,179,8,0.06);">
      <div class="count" style="color:#eab308;">{medium_count}</div>
      <div class="cat" style="color:#eab308;">Medium</div>
    </div>
    <div class="summary-card" style="border-color:rgba(34,197,94,0.3);background:rgba(34,197,94,0.06);">
      <div class="count" style="color:#22c55e;">{low_count}</div>
      <div class="cat" style="color:#22c55e;">Low</div>
    </div>
  </div>

  <!-- APK Metadata -->
  <div class="section">
    <div class="section-title">📱 APK Metadata</div>
    <div class="info-grid">
      {apk_info_rows}
    </div>
  </div>

  <!-- OWASP Coverage -->
  {owasp_section}

  <!-- Executive Summary -->
  <div class="section">
    <div class="section-title">📋 Executive Summary</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;">
      <p class="field-text">{executive_summary}</p>
    </div>
  </div>

  <!-- Vulnerability Findings -->
  <div class="section">
    <div class="section-title">🔍 Vulnerability Findings</div>
    {vulnerability_sections}
  </div>

</div>

<div class="report-footer">
  VulnScanner Enterprise v1.0 &nbsp;·&nbsp; Group M &nbsp;·&nbsp; NIT3003 Capstone Project &nbsp;·&nbsp; Victoria University<br>
  Generated: {generated_at} &nbsp;·&nbsp; Report ID: {report_id}
</div>
</body>
</html>'''


class ReportGenerator:
    def __init__(self, reports_folder: str):
        self.reports_folder = reports_folder
        os.makedirs(reports_folder, exist_ok=True)

    def generate(self, data: Dict, fmt: str) -> Tuple[str, int]:
        if fmt == 'json':
            return self._generate_json(data)
        elif fmt == 'pdf':
            return self._generate_pdf(data)
        else:
            return self._generate_html(data)

    def _generate_html(self, data: Dict) -> Tuple[str, int]:
        scan = data['scan']
        vulns = data['vulnerabilities']
        report_type = data.get('report_type', 'full').title()

        # Sort by severity
        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        vulns_sorted = sorted(vulns, key=lambda v: order.get(v.get('severity', 'low'), 4))

        risk_score = scan.get('risk_score', 0)
        rc = _risk_color(risk_score)
        rl = _risk_label(risk_score)

        # APK info rows
        apk_info = scan.get('apk_info') or scan
        info_items = [
            ('Package Name', apk_info.get('package_name') or scan.get('package_name', 'Unknown')),
            ('Version', apk_info.get('version_name') or scan.get('version_name', 'Unknown')),
            ('Min SDK', str(apk_info.get('min_sdk') or scan.get('min_sdk', 'Unknown'))),
            ('Target SDK', str(apk_info.get('target_sdk') or scan.get('target_sdk', 'Unknown'))),
            ('MD5', apk_info.get('md5') or scan.get('apk_hash_md5', 'N/A')),
            ('SHA-1', apk_info.get('sha1', 'N/A')),
            ('SHA-256', apk_info.get('sha256') or scan.get('apk_hash_sha256', 'N/A')),
            ('File Size', f"{((scan.get('apk_size') or 0) / 1024 / 1024):.2f} MB" if scan.get('apk_size') else 'N/A'),
        ]
        apk_info_rows = ''.join(
            f'<div class="info-item"><div class="info-label">{lbl}</div><div class="info-value">{val}</div></div>'
            for lbl, val in info_items if val and val != 'None'
        )

        # Min SDK row
        min_sdk = apk_info.get('min_sdk') or scan.get('min_sdk')
        min_sdk_row = f'<div class="meta-item"><span>Min SDK:</span> {min_sdk}</div>' if min_sdk else ''

        # OWASP coverage
        owasp_coverage = _get_owasp_top10_coverage(vulns)
        if owasp_coverage:
            owasp_items = ''.join(
                f'<div class="owasp-item"><span class="owasp-name">{name}</span><span class="owasp-count">{cnt} finding{"s" if cnt > 1 else ""}</span></div>'
                for name, cnt in owasp_coverage.items()
            )
            owasp_section = f'''<div class="section">
              <div class="section-title">📊 OWASP Mobile Top 10 Coverage</div>
              <div class="owasp-grid">{owasp_items}</div>
            </div>'''
        else:
            owasp_section = ''

        # Executive summary
        critical_count = scan.get('critical_count', 0)
        high_count = scan.get('high_count', 0)
        medium_count = scan.get('medium_count', 0)
        low_count = scan.get('low_count', 0)
        total = len(vulns)

        if risk_score >= 80:
            risk_desc = 'CRITICAL security risk. Immediate remediation required before any deployment.'
        elif risk_score >= 60:
            risk_desc = 'HIGH security risk. Significant vulnerabilities require urgent attention.'
        elif risk_score >= 40:
            risk_desc = 'MEDIUM security risk. Several issues should be addressed before production.'
        elif risk_score >= 20:
            risk_desc = 'LOW security risk. Minor issues detected that should be addressed.'
        else:
            risk_desc = 'MINIMAL security risk. No significant vulnerabilities detected.'

        exec_summary = (
            f'Analysis of <strong>{scan.get("apk_name", "the APK")}</strong> identified '
            f'<strong>{total} security findings</strong>: '
            f'{critical_count} Critical, {high_count} High, {medium_count} Medium, {low_count} Low. '
            f'The overall risk score is <strong>{risk_score}/100</strong> — {risk_desc} '
            f'Priority remediation should focus on {", ".join(set(v.get("category","") for v in vulns_sorted[:3] if v.get("category"))) or "the identified issues"}.'
        )

        # Vulnerability sections grouped by severity
        vuln_html = ''
        for sev in ['critical', 'high', 'medium', 'low']:
            sev_vulns = [v for v in vulns_sorted if v.get('severity') == sev]
            if not sev_vulns:
                continue
            color = SEVERITY_COLORS[sev]
            vuln_html += f'''
            <div class="vuln-section-header">
              <div class="sev-badge" style="color:{color};background:{SEVERITY_BG[sev]};border-color:{color}40;">{sev.upper()}</div>
              <span class="vuln-count-badge">{len(sev_vulns)} finding{"s" if len(sev_vulns) > 1 else ""}</span>
            </div>'''

            for v in sev_vulns:
                cvss = v.get('cvss_score')
                cvss_tag = f'<span class="cvss-tag">CVSS {cvss}</span>' if cvss else ''
                cwe = v.get('cwe_id', '')
                owasp = v.get('owasp_category', '')
                evidence = v.get('evidence', '')
                remediation = v.get('remediation', '')
                poc = v.get('poc_command', '')

                evidence_html = f'<div class="field-label">Evidence</div><div class="code-block">{_esc(evidence)}</div>' if evidence else ''
                poc_html = f'<div class="field-label">Proof of Concept</div><div class="code-block">{_esc(poc)}</div><div style="margin-top:6px;font-size:0.75rem;color:#eab308;padding:6px 10px;background:rgba(234,179,8,0.07);border-radius:6px;">⚠️ Only execute in authorized test environments</div>' if poc else ''
                tags = ''
                if cwe:
                    tags += f'<span class="tag" style="background:rgba(59,130,246,0.1);color:#3b82f6;">{cwe}</span>'
                if owasp:
                    tags += f'<span class="tag" style="background:rgba(124,58,237,0.1);color:#a78bfa;">{owasp}</span>'
                tags_html = f'<div class="field-label">References</div><div class="tag-row">{tags}</div>' if tags else ''

                vuln_html += f'''
                <div class="vuln-card">
                  <div class="vuln-card-header">
                    <div class="sev-badge" style="color:{color};background:{SEVERITY_BG[sev]};border-color:{color}40;">{sev.upper()}</div>
                    <div class="vuln-title">{_esc(v.get("title","Unknown"))}</div>
                    {cvss_tag}
                  </div>
                  <div class="vuln-card-body">
                    <div class="field-label">Description</div>
                    <div class="field-text">{_esc(v.get("description",""))}</div>
                    <div class="field-label">Location</div>
                    <div class="code-block">{_esc(v.get("location","N/A"))}</div>
                    {evidence_html}
                    <div class="field-label">Remediation</div>
                    <div class="field-text">{_esc(remediation)}</div>
                    {poc_html}
                    {tags_html}
                  </div>
                </div>'''

        apk_name = scan.get('apk_name', 'Unknown APK')
        report_id = uuid.uuid4().hex[:12].upper()
        generated_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

        html = HTML_REPORT.format(
            apk_name=apk_name,
            report_type=report_type,
            generated_at=generated_at,
            report_id=report_id,
            risk_score=risk_score,
            risk_color=rc,
            risk_label=rl,
            risk_bg=f'rgba({",".join(str(int(rc.lstrip("#")[i:i+2],16)) for i in (0,2,4))},0.06)',
            risk_border=f'rgba({",".join(str(int(rc.lstrip("#")[i:i+2],16)) for i in (0,2,4))},0.25)',
            risk_circle_bg=f'rgba({",".join(str(int(rc.lstrip("#")[i:i+2],16)) for i in (0,2,4))},0.1)',
            package_name=scan.get('package_name', 'Unknown'),
            version_name=scan.get('version_name', 'Unknown'),
            min_sdk_row=min_sdk_row,
            total_findings=len(vulns),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            apk_info_rows=apk_info_rows,
            owasp_section=owasp_section,
            executive_summary=exec_summary,
            vulnerability_sections=vuln_html,
        )

        filename = f"vulnscanner_report_{uuid.uuid4().hex[:8]}.html"
        filepath = os.path.join(self.reports_folder, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        return filepath, len(html.encode('utf-8'))

    def _generate_pdf(self, data: Dict) -> Tuple[str, int]:
        html_path, _ = self._generate_html(data)
        pdf_path = html_path.replace('.html', '.pdf')
        try:
            import weasyprint
            weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
            os.remove(html_path)
            return pdf_path, os.path.getsize(pdf_path)
        except Exception:
            try:
                from reportlab.pdfgen import canvas
                from reportlab.lib.pagesizes import A4
                from reportlab.lib import colors as rl_colors
                scan = data['scan']
                vulns = data['vulnerabilities']
                c = canvas.Canvas(pdf_path, pagesize=A4)
                w, h = A4
                # Header
                c.setFillColorRGB(0.49, 0.23, 0.93)
                c.setFont("Helvetica-Bold", 22)
                c.drawString(40, h - 60, "VulnScanner Security Report")
                c.setFillColorRGB(0.88, 0.91, 0.94)
                c.setFont("Helvetica", 11)
                c.drawString(40, h - 85, f"App: {scan.get('apk_name', 'Unknown')}")
                c.drawString(40, h - 100, f"Package: {scan.get('package_name', 'Unknown')}   Version: {scan.get('version_name', '?')}")
                c.drawString(40, h - 115, f"Risk Score: {scan.get('risk_score', 0)}/100   Total: {len(vulns)} findings")
                c.drawString(40, h - 130, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
                # Severity boxes
                sev_data = [
                    ('Critical', scan.get('critical_count', 0), (0.94, 0.27, 0.27)),
                    ('High', scan.get('high_count', 0), (0.98, 0.45, 0.09)),
                    ('Medium', scan.get('medium_count', 0), (0.92, 0.70, 0.03)),
                    ('Low', scan.get('low_count', 0), (0.13, 0.77, 0.37)),
                ]
                x = 40
                for label, cnt, col in sev_data:
                    c.setFillColorRGB(*col)
                    c.roundRect(x, h - 175, 110, 35, 5, fill=1, stroke=0)
                    c.setFillColorRGB(1, 1, 1)
                    c.setFont("Helvetica-Bold", 18)
                    c.drawCentredString(x + 55, h - 156, str(cnt))
                    c.setFont("Helvetica", 9)
                    c.drawCentredString(x + 55, h - 168, label)
                    x += 125

                # Vulnerabilities
                y = h - 210
                order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                sorted_vulns = sorted(vulns, key=lambda v: order.get(v.get('severity', 'low'), 4))
                sev_colors_rgb = {
                    'critical': (0.94, 0.27, 0.27), 'high': (0.98, 0.45, 0.09),
                    'medium': (0.92, 0.70, 0.03), 'low': (0.13, 0.77, 0.37),
                }
                for v in sorted_vulns[:30]:
                    if y < 100:
                        c.showPage()
                        y = h - 50
                    sev = v.get('severity', 'low')
                    col = sev_colors_rgb.get(sev, (0.5, 0.5, 0.5))
                    c.setFillColorRGB(*col)
                    c.roundRect(40, y - 4, 60, 14, 3, fill=1, stroke=0)
                    c.setFillColorRGB(1, 1, 1)
                    c.setFont("Helvetica-Bold", 7)
                    c.drawCentredString(70, y + 4, sev.upper())
                    c.setFillColorRGB(0.88, 0.91, 0.94)
                    c.setFont("Helvetica-Bold", 10)
                    title = v.get('title', 'Unknown')[:70]
                    c.drawString(108, y + 4, title)
                    y -= 16
                    desc = v.get('description', '')[:120]
                    if desc:
                        c.setFont("Helvetica", 8)
                        c.setFillColorRGB(0.53, 0.60, 0.67)
                        c.drawString(108, y + 2, desc)
                        y -= 14
                    c.setFillColorRGB(0.12, 0.18, 0.29)
                    c.rect(40, y, 515, 0.5, fill=1, stroke=0)
                    y -= 10

                c.save()
                return pdf_path, os.path.getsize(pdf_path)
            except Exception as e:
                # Fallback to HTML
                return html_path, os.path.getsize(html_path)

    def _generate_json(self, data: Dict) -> Tuple[str, int]:
        scan = data['scan']
        vulns = data['vulnerabilities']
        report = {
            'report_version': '2.0',
            'generator': 'VulnScanner Enterprise v1.0',
            'generated_at': datetime.utcnow().isoformat(),
            'report_type': data.get('report_type', 'full'),
            'app_info': {
                'apk_name': scan.get('apk_name'),
                'package_name': scan.get('package_name'),
                'version_name': scan.get('version_name'),
                'min_sdk': scan.get('min_sdk'),
                'target_sdk': scan.get('target_sdk'),
                'hashes': {
                    'md5': scan.get('apk_hash_md5'),
                    'sha256': scan.get('apk_hash_sha256'),
                }
            },
            'risk_summary': {
                'overall_score': scan.get('risk_score', 0),
                'total_findings': len(vulns),
                'critical': scan.get('critical_count', 0),
                'high': scan.get('high_count', 0),
                'medium': scan.get('medium_count', 0),
                'low': scan.get('low_count', 0),
            },
            'owasp_coverage': _get_owasp_top10_coverage(vulns),
            'vulnerabilities': vulns,
        }
        content = json.dumps(report, indent=2, default=str)
        filename = f"vulnscanner_report_{uuid.uuid4().hex[:8]}.json"
        filepath = os.path.join(self.reports_folder, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        return filepath, len(content.encode('utf-8'))


def _esc(text: str) -> str:
    """HTML escape"""
    if not text:
        return ''
    return (str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;'))
