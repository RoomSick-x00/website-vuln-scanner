# Frontend

This folder contains both user-facing clients: a command-line interface and a
Flask web UI. Both talk to the FastAPI backend over HTTP instead of directly
touching the database.

## Folders

- `cli/` contains Python helper functions and the `argparse` command entry
  point.
- `web_ui/` contains the Flask app, Jinja templates, and static CSS.

## Files

- `requirements.txt` lists frontend-specific Python dependencies used by the
  Flask UI and report generation.

## Workflow

1. The user submits a URL from the CLI or web form.
2. The frontend sends the request to `BACKEND_URL` using the backend `/scans/`
   API.
3. For Quick scans, the user is sent to the status/polling flow immediately.
4. For Full scans or custom scans containing XSS, the web UI shows the DNS TXT
   verification screen first.
5. The status page polls the backend until the scan is complete.
6. The results page reads grouped findings and renders risk summary, per-module
   tabs, priority fixes, and PDF download.

## Logic

The frontend is deliberately a client layer. Scan mode selection, verification
screens, progress animation, risk scoring, and report rendering live here, but
scanner execution and persistent scan state remain in the backend/workers.
