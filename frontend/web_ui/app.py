from flask import Flask, render_template, request, make_response
import os
import sys
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, "static"),
    template_folder=os.path.join(BASE_DIR, "templates")
)
sys.path.append(os.path.abspath(os.path.join(BASE_DIR, "..", "cli")))
import commands_cli as commands

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
    result = commands.submit_scan(url)
    if "error" in result:
        return result["error"]
    if "id" not in result:
        return f"Backend response: {result}"
    scan_id = result["id"]
    return render_template("status.html", scan_id=scan_id)

@app.route("/status/<scan_id>")
def status(scan_id):
    response = commands.check_status(scan_id)
    return render_template("status.html", scan_id=scan_id, status=response["status"])

@app.route("/results/<scan_id>")
def results(scan_id):
    data = commands.get_results(scan_id)
    return render_template(
        "results.html",
        scan_id=scan_id,
        results=data.get("findings", [])
    )

@app.route("/report/<scan_id>")
def download_report(scan_id):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    import io

    data = commands.get_results(scan_id)
    findings = data.get("findings", [])
    target = data.get("target", "Unknown")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle('title', fontSize=22, fontName='Helvetica-Bold', spaceAfter=6, textColor=colors.HexColor('#4f46e5'))
    story.append(Paragraph("Vulnerability Scan Report", title_style))
    story.append(Paragraph(f"Target: {target}", styles['Normal']))
    story.append(Paragraph(f"Scan ID: {scan_id}", styles['Normal']))
    story.append(Paragraph(f"Total Issues: {len(findings)}", styles['Normal']))
    story.append(Spacer(1, 0.5*cm))

    severity_colors = {
        'high':   colors.HexColor('#f87171'),
        'medium': colors.HexColor('#fbbf24'),
        'low':    colors.HexColor('#60a5fa'),
        'info':   colors.HexColor('#9ca3af'),
    }

    for i, f in enumerate(findings, 1):
        sev = f.get('severity', 'info').lower()
        sev_color = severity_colors.get(sev, colors.grey)

        story.append(Paragraph(f"{i}. {f.get('issue', 'N/A')}", ParagraphStyle('issue', fontSize=13, fontName='Helvetica-Bold', spaceAfter=4)))

        table_data = [
            ['Severity',    f.get('severity', '').upper()],
            ['Evidence',    f.get('evidence', 'N/A')],
            ['Remediation', f.get('remediation', 'N/A')],
            ['Penalty',     f"-{f.get('score_penalty', 0)} pts"],
        ]
        t = Table(table_data, colWidths=[4*cm, 13*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#1e1b4b')),
            ('TEXTCOLOR',  (0,0), (0,-1), colors.white),
            ('TEXTCOLOR',  (1,1), (1,-1), colors.HexColor('#374151')),
            ('TEXTCOLOR',  (1,0), (1,0),  sev_color),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE',   (0,0), (-1,-1), 10),
            ('ROWBACKGROUNDS', (1,0), (1,-1), [colors.HexColor('#f9fafb'), colors.white]),
            ('BOX',        (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
            ('GRID',       (0,0), (-1,-1), 0.3, colors.HexColor('#e5e7eb')),
            ('VALIGN',     (0,0), (-1,-1), 'TOP'),
            ('PADDING',    (0,0), (-1,-1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.4*cm))

    doc.build(story)
    buffer.seek(0)
    response = make_response(buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{scan_id[:8]}.pdf'
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)