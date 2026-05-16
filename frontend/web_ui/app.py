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


def generate_verify_token(domain):
    return "vuln-verify-" + hashlib.sha256(domain.encode()).hexdigest()[:16]


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

    # Custom mode — build scan_type from checkboxes
    if scan_mode == "custom":
        selected = request.form.getlist("modules")
        if not selected:
            return "Please select at least one module."
        scan_type = ",".join(selected)
        needs_verify = "xss" in selected
    elif scan_mode == "full":
        scan_type = "full"
        needs_verify = True
    else:
        scan_type = "quick"
        needs_verify = False

    # Extract domain from URL
    from urllib.parse import urlparse
    domain = urlparse(url).netloc or url

    if needs_verify:
        token = generate_verify_token(domain)
        return render_template(
            "verify.html",
            domain=domain,
            token=token,
            url=url,
            scan_type=scan_type
        )

    # No verification needed — submit directly
    result = commands.submit_scan_with_type(url, scan_type)
    if "error" in result:
        return result["error"]
    if "id" not in result:
        return f"Backend response: {result}"

    return render_template("status.html", scan_id=result["id"], target=url)


@app.route("/api/verify-domain")
def api_verify_domain():
    domain = request.args.get("domain")
    token = request.args.get("token")
    if not domain or not token:
        return jsonify({"verified": False, "error": "Missing params"})
    try:
        answers = dns.resolver.resolve(domain, "TXT")
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
    scan_type = request.form["scan_type"]
    result = commands.submit_scan_with_type(url, scan_type)
    if "error" in result:
        return result["error"]
    if "id" not in result:
        return f"Backend response: {result}"
    return render_template("status.html", scan_id=result["id"], target=url)


@app.route("/status/<scan_id>")
def status(scan_id):
    response = commands.check_status(scan_id)
    return render_template("status.html", scan_id=scan_id, status=response["status"])


@app.route("/results/<scan_id>")
def results(scan_id):
    data = commands.get_results(scan_id)
    findings = data.get("findings", [])

    # Group by module_name
    from collections import defaultdict
    grouped = defaultdict(list)
    for f in findings:
        grouped[f.get("module_name", "unknown")].append(f)

    all_modules = ["http_headers", "tls", "dns", "xss"]
    ran_modules = list(grouped.keys())
    skipped_modules = [m for m in all_modules if m not in ran_modules]

    return render_template(
        "results.html",
        scan_id=scan_id,
        grouped=dict(grouped),
        results=findings,
        ran_modules=ran_modules,
        skipped_modules=skipped_modules
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
    findings = data.get("findings", [])
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