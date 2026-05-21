# Web UI

This folder contains the Flask web interface. It provides scan submission,
domain verification, animated status polling, result exploration, and PDF report
download.

## Files

- `app.py` creates the Flask app, applies response security headers, proxies
  scan actions to the backend through `frontend/cli/commands_cli.py`, renders
  pages, verifies DNS TXT records, computes display risk summaries, and builds
  PDF reports.
- `templates/` contains the Jinja HTML templates.
- `static/` contains CSS and other static browser assets.

## Routes

- `/` renders the scan form.
- `/submit` handles scan form submissions and decides whether verification is
  required.
- `/api/verify-domain` checks the DNS TXT verification record from the browser
  flow.
- `/start-scan` submits a verified full/custom scan to the backend.
- `/status/<scan_id>` renders the polling screen.
- `/api/status/<scan_id>` returns backend scan status to browser JavaScript.
- `/results/<scan_id>` renders findings, severity filters, module tabs, and
  priority actions.
- `/report/<scan_id>` generates a PDF report with ReportLab.
- `/logout` returns `Clear-Site-Data` for scanner/header validation demos.

## Logic

The web UI does not run scanners. It collects user intent, handles UX-specific
verification flow, then calls the backend API. The results page computes display
grade and severity summaries from backend findings, while the backend remains
the source of truth for scan status and stored findings.
