from fastapi import APIRouter
from fastapi.responses import FileResponse

from tasks.pdf_reports.generate_report import create_pdf

router = APIRouter()


@router.get("/download-report")
def download_report():

    scan_data = {
        "url": "https://example.com",

        "date": "13 May 2026",

        "vulnerabilities": [

            {
                "name": "SQL Injection",
                "severity": "High",
                "description": "User input not sanitized.",
                "solution": "Use parameterized queries."
            },

            {
                "name": "Cross Site Scripting",
                "severity": "Medium",
                "description": "Scripts can be injected.",
                "solution": "Validate user inputs."
            }
        ]
    }

    pdf_file = create_pdf(scan_data)

    return FileResponse(
        path=pdf_file,
        media_type="application/pdf",
        filename="scan_report.pdf"
    )