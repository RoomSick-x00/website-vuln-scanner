from flask import Flask, render_template, request, make_response, jsonify
import os
import sys
import hashlib
import dns.resolver

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, "static"),
    template_folder=os.path.join(BASE_DIR, "templates")
)
sys.path.append(os.path.abspath(os.path.join(BASE_DIR, "..", "cli")))
import commands_cli as commands


def extract_domain(target: str) -> str:
    """Match backend app.scan_utils.extract_domain for consistent verification."""
    from urllib.parse import urlparse

    parsed = urlparse(target if "://" in target else f"https://{target}")
    return (parsed.netloc or target).lower().removeprefix("www.")


def generate_verify_token(domain):
    return "vuln-verify-" + hashlib.sha256(domain.encode()).hexdigest()[:16]


def target_display(target):
    if not target:
        return "target"
    return extract_domain(target)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status/<scan_id>")
def api_status(scan_id):
    data = commands.get_status(scan_id)
    return data


@app.route("/submit", methods=["POST"])
def submit_scan():
    url = request.form["url"]
    scan_mode = request.form.get("scan_mode", "quick")

    if scan_mode == "custom":
        selected = request.form.getlist("modules")
        if not selected:
            return "Please select at least one module."
        scan_type = "custom"
        modules = selected
        needs_verify = "xss" in selected
    elif scan_mode == "full":
        scan_type = "full"
        modules = None
        needs_verify = True
    else:
        scan_type = "quick"
        modules = None
        needs_verify = False

    domain = extract_domain(url)
    txt_host = f"_vuln-verify.{domain}"

    if needs_verify:
        token = generate_verify_token(domain)
        return render_template(
            "verify.html",
            domain=domain,
            txt_host=txt_host,
            token=token,
            url=url,
            scan_type=scan_type,
            modules=modules or [],
        )

    result = commands.submit_scan_with_type(url, scan_type, modules=modules)
    if "error" in result:
        return result["error"]
    if "id" not in result:
        return f"Backend response: {result}"

    return render_template(
        "status.html",
        scan_id=result["id"],
        target=url,
        target_display=target_display(url),
    )


@app.route("/api/verify-domain")
def api_verify_domain():
    domain = request.args.get("domain")
    token = request.args.get("token")
    if not domain or not token:
        return jsonify({"verified": False, "error": "Missing params"})
    domain = extract_domain(domain)
    txt_host = f"_vuln-verify.{domain}"
    try:
        answers = dns.resolver.resolve(txt_host, "TXT")
        for r in answers:
            for s in r.strings:
                if token.encode() in s or token in s.decode(errors="ignore"):
                    return jsonify({"verified": True})
        return jsonify({"verified": False, "error": "TXT record not found"})
    except Exception as e:
        return jsonify({"verified": False, "error": str(e)})


@app.route("/start-scan", methods=["POST"])
def start_scan():
    url = request.form["url"]
    scan_type = request.form.get("scan_type", "quick")
    modules = request.form.getlist("modules")
    if not modules and "," in scan_type:
        modules = [m.strip() for m in scan_type.split(",")]
        scan_type = "custom"
    result = commands.submit_scan_with_type(
        url, scan_type, modules=modules if modules else None
    )
    if "error" in result:
        return result["error"]
    if "id" not in result:
        return f"Backend response: {result}"
    return render_template(
        "status.html",
        scan_id=result["id"],
        target=url,
        target_display=target_display(url),
    )


@app.route("/status/<scan_id>")
def status(scan_id):
    response = commands.check_status(scan_id)
    target = response.get("target", "")
    return render_template(
        "status.html",
        scan_id=scan_id,
        status=response["status"],
        target=target,
        target_display=target_display(target),
    )


MODULE_LABELS = {
    "tls": "TLS/SSL",
    "http_headers": "HTTP Headers",
    "dns": "DNS",
    "xss": "XSS",
}


MODULE_ORDER = ["tls", "http_headers", "dns", "xss"]

DEFAULT_REMEDIATION = {
    "dns": (
        "Investigate your DNS resolver configuration and try the scan again. "
        "These errors suggest a DNS lookup timeout or resolver-level failure."
    ),
    "tls": "Review the TLS finding and update your certificate, protocol, or cipher configuration as needed.",
    "http_headers": "Review the affected HTTP response header and add or tighten the recommended security policy.",
    "xss": "Validate and encode untrusted input before reflecting it in responses.",
}


def _label_modules(modules):
    return [MODULE_LABELS.get(m, m) for m in modules]


def _compute_risk(findings):
    """Return (grade, label, vuln_count) from non-info findings."""
    sev_weights = {"critical": 40, "high": 25, "medium": 12, "low": 5}
    vulns = [f for f in findings if f.get("severity", "").lower() != "info"]
    score = sum(sev_weights.get(f.get("severity", "").lower(), 0) for f in vulns)

    if not vulns:
        return "A", "Clean", 0
    if score >= 80:
        return "F", "Critical risk", len(vulns)
    if score >= 50:
        return "D", "High risk", len(vulns)
    if score >= 25:
        return "C", "Moderate risk", len(vulns)
    if score >= 10:
        return "B", "Low risk", len(vulns)
    return "B+", "Minor issues", len(vulns)


def _severity_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = finding.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _ensure_remediation(finding):
    if finding.get("severity", "").lower() == "info" or finding.get("remediation"):
        return
    module = finding.get("module_name") or finding.get("task_type") or "unknown"
    finding["remediation"] = DEFAULT_REMEDIATION.get(
        module,
        "Investigate this finding and validate the affected configuration before rescanning.",
    )


def _module_tab_stats(grouped):
    """Per-module counts for tab badges (excludes info)."""
    stats = {}
    for module, items in grouped.items():
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in items:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
        stats[module] = counts
    return stats


def _severity_summary_text(counts):
    parts = []
    labels = (("high", "High"), ("medium", "Medium"), ("low", "Low"))
    for key, label in labels:
        count = counts.get(key, 0)
        if count:
            parts.append(f"{count} {label}")
    return ", ".join(parts)


def _sort_grouped_findings(grouped):
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for items in grouped.values():
        items.sort(key=lambda f: sev_order.get(f.get("severity", "info").lower(), 5))


def _priority_groups(priority_actions):
    groups = []
    lookup = {}
    for item in priority_actions:
        module = item.get("module_name") or item.get("task_type") or "unknown"
        if module not in lookup:
            lookup[module] = {"module": module, "items": []}
            groups.append(lookup[module])
        lookup[module]["items"].append(item)
    return groups


def _prepare_findings_for_display(findings, grouped):
    """Attach stable DOM ids and return the highest-priority non-info findings."""
    sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    module_lookup = {}
    for module, items in grouped.items():
        for finding in items:
            module_lookup[(finding.get("issue"), finding.get("evidence"))] = module

    for idx, finding in enumerate(findings, 1):
        finding["_issue_id"] = f"finding-{idx}"
        if not finding.get("module_name") and not finding.get("task_type"):
            module = module_lookup.get((finding.get("issue"), finding.get("evidence")))
            if module:
                finding["module_name"] = module
        _ensure_remediation(finding)

    issue_lookup = {
        (
            f.get("module_name") or f.get("task_type") or "unknown",
            f.get("issue"),
            f.get("evidence"),
        ): f.get("_issue_id")
        for f in findings
    }
    fallback_idx = len(findings) + 1
    for module, items in grouped.items():
        for finding in items:
            key = (module, finding.get("issue"), finding.get("evidence"))
            finding["_issue_id"] = issue_lookup.get(key, finding.get("_issue_id"))
            if not finding.get("_issue_id"):
                finding["_issue_id"] = f"finding-{fallback_idx}"
                fallback_idx += 1
            _ensure_remediation(finding)

    actionable = [
        f for f in findings
        if f.get("severity", "").lower() in sev_weights
    ]
    actionable.sort(
        key=lambda f: (
            sev_weights.get(f.get("severity", "").lower(), 0),
            -findings.index(f),
        ),
        reverse=True,
    )
    return actionable[:3]


@app.route("/results/<scan_id>")
def results(scan_id):
    data = commands.get_results(scan_id)
    if "error" in data:
        return data["error"]

    findings = data.get("results", data.get("findings", []))
    grouped = data.get("grouped", {})
    ran_modules = data.get("ran_modules", [])
    skipped_modules = data.get("skipped_modules", [])
    target = data.get("target", "")
    _sort_grouped_findings(grouped)

    active_modules = [m for m in MODULE_ORDER if m in grouped]
    domain_display = extract_domain(target) if target else "Unknown"
    risk_grade, risk_label, vuln_count = _compute_risk(findings)
    severity_counts = _severity_counts(findings)
    tab_stats = _module_tab_stats(grouped)
    tab_summary = {
        module: _severity_summary_text(counts)
        for module, counts in tab_stats.items()
    }
    priority_actions = _prepare_findings_for_display(findings, grouped)
    priority_groups = _priority_groups(priority_actions)

    return render_template(
        "results.html",
        scan_id=scan_id,
        target=target,
        domain_display=domain_display,
        grouped=grouped,
        results=findings,
        ran_modules=ran_modules,
        skipped_modules=skipped_modules,
        ran_modules_display=_label_modules(ran_modules),
        skipped_modules_display=_label_modules(skipped_modules),
        active_modules=active_modules,
        module_labels=MODULE_LABELS,
        module_order=MODULE_ORDER,
        risk_grade=risk_grade,
        risk_label=risk_label,
        vuln_count=vuln_count,
        severity_counts=severity_counts,
        tab_stats=tab_stats,
        tab_summary=tab_summary,
        priority_actions=priority_actions,
        priority_groups=priority_groups,
    )


@app.route("/report/<scan_id>")
def download_report(scan_id):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from datetime import datetime
    import io

    data = commands.get_results(scan_id)
    findings = data.get("results", data.get("findings", []))
    target = data.get("target", "Unknown")

    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    findings = sorted(findings, key=lambda f: sev_order.get(f.get('severity', 'info').lower(), 5))

    PAGE_W, PAGE_H = A4
    DARK       = colors.HexColor('#0f172a')
    ACCENT     = colors.HexColor('#6366f1')
    WHITE      = colors.white
    LIGHT_GRAY = colors.HexColor('#f8fafc')
    MID_GRAY   = colors.HexColor('#64748b')
    TEXT_DARK  = colors.HexColor('#1e293b')

    SEV_COLOR = {
        'critical': colors.HexColor('#ef4444'),
        'high':     colors.HexColor('#f97316'),
        'medium':   colors.HexColor('#eab308'),
        'low':      colors.HexColor('#3b82f6'),
        'info':     colors.HexColor('#6b7280'),
    }
    SEV_BG = {
        'critical': colors.HexColor('#fef2f2'),
        'high':     colors.HexColor('#fff7ed'),
        'medium':   colors.HexColor('#fefce8'),
        'low':      colors.HexColor('#eff6ff'),
        'info':     colors.HexColor('#f9fafb'),
    }

    buffer = io.BytesIO()

    def draw_header(c, doc):
        c.setFillColor(DARK)
        c.rect(0, PAGE_H - 80, PAGE_W, 80, fill=1, stroke=0)
        c.setFillColor(ACCENT)
        c.rect(0, PAGE_H - 84, PAGE_W, 4, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 20)
        c.drawString(2*cm, PAGE_H - 48, "Vulnerability Scan Report")
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.HexColor('#94a3b8'))
        c.drawString(2*cm, PAGE_H - 65, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        c.setFillColor(MID_GRAY)
        c.setFont("Helvetica", 8)
        c.drawRightString(PAGE_W - 2*cm, 1.2*cm, f"Page {doc.page}")
        c.setFillColor(ACCENT)
        c.rect(0, 0.9*cm, PAGE_W, 2, fill=1, stroke=0)

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=3.5*cm, bottomMargin=2.5*cm
    )
    styles = getSampleStyleSheet()
    wrap = ParagraphStyle('wrap', fontSize=9, leading=13, textColor=TEXT_DARK, wordWrap='CJK')
    remediation_style = ParagraphStyle('remed', fontSize=9, leading=13, textColor=colors.HexColor('#1e40af'), wordWrap='CJK')

    story = []

    meta_data = [
        [Paragraph('<b>Target</b>', wrap), Paragraph(target, wrap)],
        [Paragraph('<b>Total Issues</b>', wrap), Paragraph(str(len(findings)), wrap)],
        [Paragraph('<b>Report Date</b>', wrap), Paragraph(datetime.utcnow().strftime('%B %d, %Y'), wrap)],
    ]
    meta_table = Table(meta_data, colWidths=[4*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#e0e7ff')),
        ('BACKGROUND', (1,0), (1,-1), LIGHT_GRAY),
        ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('PADDING',    (0,0), (-1,-1), 8),
        ('BOX',        (0,0), (-1,-1), 0.5, colors.HexColor('#c7d2fe')),
        ('GRID',       (0,0), (-1,-1), 0.3, colors.HexColor('#e0e7ff')),
        ('VALIGN',     (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.6*cm))

    counts = {}
    for sev in ['critical','high','medium','low','info']:
        counts[sev] = sum(1 for f in findings if f.get('severity','').lower() == sev)

    sum_data = [[
        Paragraph(f'<b>CRITICAL</b>\n{counts["critical"]}', ParagraphStyle('s', fontSize=9, textColor=SEV_COLOR['critical'], alignment=1)),
        Paragraph(f'<b>HIGH</b>\n{counts["high"]}',         ParagraphStyle('s', fontSize=9, textColor=SEV_COLOR['high'],     alignment=1)),
        Paragraph(f'<b>MEDIUM</b>\n{counts["medium"]}',     ParagraphStyle('s', fontSize=9, textColor=SEV_COLOR['medium'],   alignment=1)),
        Paragraph(f'<b>LOW</b>\n{counts["low"]}',           ParagraphStyle('s', fontSize=9, textColor=SEV_COLOR['low'],      alignment=1)),
        Paragraph(f'<b>INFO</b>\n{counts["info"]}',         ParagraphStyle('s', fontSize=9, textColor=SEV_COLOR['info'],     alignment=1)),
    ]]
    sum_table = Table(sum_data, colWidths=[3.4*cm]*5)
    sum_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor('#fef2f2')),
        ('BACKGROUND', (1,0), (1,0), colors.HexColor('#fff7ed')),
        ('BACKGROUND', (2,0), (2,0), colors.HexColor('#fefce8')),
        ('BACKGROUND', (3,0), (3,0), colors.HexColor('#eff6ff')),
        ('BACKGROUND', (4,0), (4,0), colors.HexColor('#f9fafb')),
        ('BOX',        (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('GRID',       (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING',    (0,0), (-1,-1), 10),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 0.8*cm))

    heading_style = ParagraphStyle('h2', fontSize=13, fontName='Helvetica-Bold', textColor=DARK, spaceAfter=8)
    story.append(Paragraph("Findings", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12))

    for i, f in enumerate(findings, 1):
        sev = f.get('severity', 'info').lower()
        sev_color = SEV_COLOR.get(sev, colors.grey)
        sev_bg    = SEV_BG.get(sev, LIGHT_GRAY)

        issue_style = ParagraphStyle('issue', fontSize=11, fontName='Helvetica-Bold', textColor=TEXT_DARK)
        header_data = [[
            Paragraph(f'<b>{i}. {f.get("issue","N/A")}</b>', issue_style),
            Paragraph(f'<b>{sev.upper()}</b>', ParagraphStyle('sev', fontSize=9, fontName='Helvetica-Bold', textColor=sev_color, alignment=2)),
        ]]
        header_table = Table(header_data, colWidths=[13*cm, 4*cm])
        header_table.setStyle(TableStyle([
            ('BACKGROUND',   (0,0), (-1,-1), sev_bg),
            ('LEFTPADDING',  (0,0), (0,0),   10),
            ('RIGHTPADDING', (1,0), (1,0),   10),
            ('TOPPADDING',   (0,0), (-1,-1), 8),
            ('BOTTOMPADDING',(0,0), (-1,-1), 8),
            ('LINEBELOW',    (0,0), (-1,0),  1, sev_color),
        ]))
        story.append(header_table)

        body_data = [
            [Paragraph('<b>Evidence</b>', wrap),    Paragraph(f.get('evidence','N/A'), wrap)],
            [Paragraph('<b>Remediation</b>', wrap), Paragraph(f.get('remediation','N/A'), remediation_style)],
        ]
        body_table = Table(body_data, colWidths=[3.5*cm, 13.5*cm])
        body_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f1f5f9')),
            ('BACKGROUND', (1,0), (1,-1), WHITE),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE',   (0,0), (-1,-1), 9),
            ('PADDING',    (0,0), (-1,-1), 8),
            ('BOX',        (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('GRID',       (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
            ('VALIGN',     (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(body_table)
        story.append(Spacer(1, 0.35*cm))

    doc.build(story, onFirstPage=draw_header, onLaterPages=draw_header)
    buffer.seek(0)
    response = make_response(buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{scan_id[:8]}.pdf'
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
