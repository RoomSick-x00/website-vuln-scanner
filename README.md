# Website Vulnerability Scanning System

## Overview

A cloud-deployable, asynchronous website vulnerability scanning system.
It scans a target URL for common security issues, stores scan metadata and
findings in PostgreSQL, and exposes reports through a FastAPI backend, CLI, and
Flask web UI.

## Tech Stack

- Backend: Python + FastAPI
- Async task queue: Celery + Redis
- Workers / scanner modules: Python
- Database: PostgreSQL
- Frontend: Flask web UI + CLI
- Deployment: Docker Compose locally; Railway service notes under `deployment/`

## Repo Structure

- `backend/` -> FastAPI app, DB models, schemas, migrations, scan routes
- `tasks/` -> Celery app and scan task enqueueing
- `workers/` -> scanner modules and result persistence processor
- `frontend/cli/` -> command-line client helpers
- `frontend/web_ui/` -> Flask UI, templates, static CSS
- `deployment/` -> Dockerfiles and `docker-compose.yml`
- `docs/` -> architecture, DFD, and workflow notes
- `test_processor.py` and `workers/scanner_modules/test_*.py` -> manual scanner smoke scripts

## What The Scanner Checks

Current active scan modules:

- `tls` - TLS/SSL certificate, protocol, cipher, and forward secrecy checks
- `http_headers` - security header checks such as CSP, HSTS, X-Frame-Options, and related response headers
- `dns` - DNS security/configuration checks such as SPF, DMARC, DNSSEC, CAA, and MX-related signals
- `xss` - reflected XSS probing for authorized targets

Scan modes:

- `quick` -> TLS + HTTP Headers + DNS
- `full` -> TLS + HTTP Headers + DNS + XSS
- `custom` -> selected modules from the UI/CLI

## How The Workflow Works

1. The web UI or CLI submits a scan request to the FastAPI backend.
2. The backend creates a `scans` row in PostgreSQL.
3. Celery enqueues one task per scanner module.
4. Workers run scanner modules in parallel.
5. Each worker appends findings to the same scan row and records its module in `completed_modules`.
6. The scan is marked `COMPLETED` only after all expected modules finish.
7. Results are available through the API, web results page, CLI, and PDF report route.

Stored scan fields include:

- scan ID
- target URL
- scan mode/type
- status
- timestamps
- findings
- completed modules
- domain verification token
- domain verification status

## API Endpoints

Main backend routes:

- `GET /health`
- `POST /scans/` - create a scan
- `GET /scans/` - list scans
- `GET /scans/{scan_id}` - get scan status/results
- `GET /scans/{scan_id}/verification-token` - get TXT verification details
- `POST /scans/{scan_id}/verify` - verify domain ownership
- `PATCH /scans/{scan_id}/status` - update scan status manually

## How To Run Locally Without Docker (PowerShell)

### 1. Start Redis

```powershell
wsl
redis-server
```

### 2. Start the backend server

```powershell
cd "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\backend"
$env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/scanner_db"
$env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner"
uvicorn app.main:app --reload
```

Backend runs at:

```text
http://localhost:8000
```

### 3. Start the Celery worker

```powershell
cd "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner"
$env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner;C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\backend"
$env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/scanner_db"
celery -A tasks.celery_app worker --loglevel=info --pool=solo
```

`--pool=solo` is recommended on Windows.

### 4. Start the Flask web UI

```powershell
cd "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\frontend\web_ui"
$env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner"
$env:BACKEND_URL = "http://localhost:8000"
python app.py
```

Web UI runs at:

```text
http://localhost:5000
```

## CLI Usage

Run from the repo root with `BACKEND_URL` pointing at the FastAPI backend:

```powershell
$env:BACKEND_URL = "http://localhost:8000"
python -m frontend.cli.main submit --url https://example.com
python -m frontend.cli.main status --id <scan_id>
python -m frontend.cli.main results --id <scan_id>
```

## Database Notes

The backend uses SQLAlchemy and PostgreSQL. On backend startup,
`backend/app/main.py` runs:

```py
Base.metadata.create_all(bind=engine)
run_migrations()
```

Current lightweight migrations add:

- `scan_mode`
- `verification_token`
- `verified`
- `completed_modules`

The database URL defaults to:

```text
postgresql://postgres:postgres@localhost:5432/scanner_db
```

Override it with:

```powershell
$env:DATABASE_URL = "postgresql://user:password@host:5432/dbname"
```

## Domain Verification

Full scans and XSS scans require domain ownership verification in the UI flow.
The verification record is a TXT record:

```text
Type: TXT
Name/Host: _vuln-verify.<domain>
Value: vuln-verify-<stable-token>
```

The token is deterministic for a domain, so returning later with the same
domain will produce the same TXT value. DNS propagation can take up to 15
minutes.

Backend behavior:

1. Create scan with `status=QUEUED`, `verified=False`, and token stored.
2. Do not enqueue Full/XSS modules yet.
3. User verifies DNS, or submits after the TXT record already exists.
4. Backend sets `verified=True`.
5. Backend enqueues the scan.

The web UI calls `/api/verify-domain` before submitting Full/XSS scans, and the
backend re-checks the same TXT record before queueing those scan modules.

## Verification Demo States

For screenshots, append one of these query params to the verify page URL:

- `?verify_state=checking` keeps the button in the checking state.
- `?verify_state=failed` shows the failed state.
- Omit the param to use real TXT verification.

## Results And Reports

The web UI shows:

- paced loading state with elapsed time
- scan progress by module
- grade and severity breakdown
- "Fix These First" priority section
- grouped results by module
- per-finding evidence and remediation
- PDF report download

The backend stores findings in PostgreSQL in the scan row's `findings` JSON
field. This means copy that says "we do not store scan results" should not be
used.

## Smoke Checks

Useful local checks:

```powershell
python -m compileall backend tasks workers frontend
```

```powershell
$env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\backend;C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner"
python -c "from workers.processor import run_scan; from frontend.cli import formatter; print('imports ok')"
```

Template JS parse check:

```powershell
node -e "const fs=require('fs'),vm=require('vm'); for (const f of ['frontend/web_ui/templates/status.html','frontend/web_ui/templates/results.html','frontend/web_ui/templates/index.html','frontend/web_ui/templates/verify.html']) { const s=fs.readFileSync(f,'utf8'); const scripts=[...s.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]); for (const [i,code] of scripts.entries()) new vm.Script(code,{filename:f+':script'+i}); console.log(f,'ok'); }"
```

Note: the current scanner `test_*.py` files are manual smoke scripts rather
than pytest-style collected tests.

## Pre-Ship Checklist

- Add a durable `/verify/<scan_id>` resume flow if users should return later.
- Run one Quick Scan end to end.
- Run one Full/XSS scan after real DNS verification.
- Confirm PostgreSQL stores scan rows, findings, `completed_modules`, and verification fields.
- Confirm Redis and Celery worker are running before testing async scans.
