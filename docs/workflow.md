# Project Workflow

This document explains how the website vulnerability scanner works from a user
submitting a URL through task execution, persistence, status polling, and final
reporting.

## High-Level Flow

1. A user submits a target URL from the Flask web UI or CLI.
2. The frontend sends the scan request to the FastAPI backend.
3. The backend creates a scan row in PostgreSQL.
4. The backend decides which scanner modules should run.
5. If the scan includes XSS, domain ownership must be verified first.
6. The backend queues one Celery task per selected scanner module.
7. Celery sends tasks through Redis to worker processes.
8. Workers run scanner modules and append findings to the scan row.
9. The scan is marked complete only after all expected modules finish.
10. The UI/CLI/API reads the stored results and displays the report.

```text
User
  -> Flask Web UI or CLI
  -> FastAPI Backend
  -> PostgreSQL scan row
  -> Celery enqueue
  -> Redis broker
  -> Worker process
  -> Scanner module
  -> PostgreSQL findings
  -> Results page / CLI / API / PDF report
```

## Main Components

### Flask Web UI

Location: `frontend/web_ui/`

The web UI is the browser-facing client. It handles:

- scan form rendering;
- Quick, Full, and Custom scan selection;
- DNS verification screen for Full/XSS scans;
- animated status page;
- results page with severity summary and module tabs;
- PDF report generation.

The UI does not run scanners directly. It calls the backend API through helper
functions in `frontend/cli/commands_cli.py`.

### CLI

Location: `frontend/cli/`

The CLI is a lightweight command-line client. It submits scans, checks status,
and prints result summaries by calling the same backend endpoints used by the
web UI.

### FastAPI Backend

Location: `backend/app/`

The backend is the system of record. It owns:

- scan creation;
- scan status;
- scan mode resolution;
- domain verification state;
- database persistence;
- API responses;
- task queue handoff.

The main router is `backend/app/routers/scan.py`.

### Celery Task Layer

Location: `tasks/`

The task layer expands a scan into scanner jobs. For every selected module,
`tasks/scan_tasks.py` calls `workers.processor.run_scan.delay(...)`, creating a
separate Celery task.

### Redis

Redis acts as the Celery broker and result backend. It carries task messages
from the backend to workers.

### Worker Processor

Location: `workers/processor.py`

The worker processor receives Celery tasks, runs scanner modules, retries
failures, enriches findings, and writes results back to PostgreSQL.

### Scanner Modules

Location: `workers/scanner_modules/`

Current active modules:

- `tls`: TLS/SSL certificate, protocol, cipher, chain, and forward secrecy
  checks.
- `http_headers`: security header checks, HSTS/CSP checks, and dangerous header
  detection.
- `dns`: SPF, DMARC, DNSSEC, CAA, MX, domain existence, and managed platform
  checks.
- `xss`: reflected XSS probes for authorized targets.

## Scan Modes

### Quick Scan

Quick scan runs passive checks:

```text
tls + http_headers + dns
```

This mode does not require domain verification because it does not submit test
payloads to forms or URL parameters.

### Full Scan

Full scan runs every active scanner:

```text
tls + http_headers + dns + xss
```

Because XSS probing is active/intrusive, Full Scan requires domain ownership
verification before scanner tasks are queued.

### Custom Scan

Custom scan runs only the modules selected by the user. If the selected modules
include `xss`, the same domain verification flow is required.

## Web UI Workflow

### 1. User Opens The Home Page

Route:

```text
GET /
```

Template:

```text
frontend/web_ui/templates/index.html
```

The user enters a URL and chooses:

- Quick Scan;
- Full Scan;
- Custom Scan with selected modules.

Client-side JavaScript normalizes URLs, validates basic URL shape, updates the
submit button text, and inserts hidden module inputs for custom scans.

### 2. User Submits The Form

Route:

```text
POST /submit
```

Implementation:

```text
frontend/web_ui/app.py
```

The Flask app reads:

- `url`;
- `scan_mode`;
- selected `modules`, if custom mode is used.

Then it decides whether the request needs verification:

- Quick Scan: no verification.
- Full Scan: verification required.
- Custom Scan: verification required only if `xss` is selected.

### 3A. Quick Scan Starts Immediately

For Quick Scan, Flask calls:

```py
commands.submit_scan_with_type(url, "quick")
```

That helper posts to the backend:

```text
POST /scans/
```

If the backend returns a scan ID, Flask renders:

```text
frontend/web_ui/templates/status.html
```

### 3B. Full/XSS Scan Shows Verification First

For Full Scan or Custom Scan with XSS, Flask renders:

```text
frontend/web_ui/templates/verify.html
```

The verification page shows a DNS TXT record:

```text
Type: TXT
Name/Host: _vuln-verify.<domain>
Value: vuln-verify-<stable-token>
```

The token is deterministic. It is generated from the domain with SHA-256 and a
stable prefix, so the same domain gets the same token later.

### 4. Web UI Checks DNS Verification

Browser JavaScript calls:

```text
GET /api/verify-domain?domain=<domain>&token=<token>
```

Flask checks DNS TXT records with `dnspython`.

If the TXT record is found, the page submits a hidden form to:

```text
POST /start-scan
```

Then Flask sends the scan request to the backend and renders the status page.

## Backend Scan Creation Workflow

Backend route:

```text
POST /scans/
```

Implementation:

```text
backend/app/routers/scan.py
```

### 1. Resolve Effective Scan Mode

The backend supports both current and legacy request fields:

- current: `scan_mode`;
- legacy: `scan_type`.

If neither is provided, the backend defaults to:

```text
quick
```

### 2. Resolve Scanner Modules

Module resolution is handled by:

```text
backend/app/scan_utils.py
```

Rules:

- `quick` resolves to `tls`, `http_headers`, `dns`;
- `full` resolves to `tls`, `http_headers`, `dns`, `xss`;
- custom module lists are filtered to known module names;
- an empty valid module list returns HTTP 422.

### 3. Create The Database Row

The backend creates a `Scan` row with:

- UUID scan ID;
- target URL;
- scan mode;
- legacy scan type when needed;
- `QUEUED` status;
- empty `completed_modules`;
- verification token and verification state.

The database model is:

```text
backend/app/models/scan.py
```

### 4. Decide Whether To Queue Tasks

If the module set does not include XSS, the scan is verified automatically and
tasks are queued immediately.

If the module set includes XSS, the backend checks whether the required TXT
record already exists. If it exists, tasks are queued. If it does not exist, the
scan stays `QUEUED` and `verified=False` until verification succeeds.

## Backend Verification Workflow

Backend verification endpoints:

```text
GET /scans/{scan_id}/verification-token
POST /scans/{scan_id}/verify
```

The token endpoint returns:

- scan ID;
- domain;
- verification token;
- TXT host;
- TXT value.

The verify endpoint:

1. Loads the scan row.
2. Recreates or reads the verification token.
3. Looks for the TXT value at `_vuln-verify.<domain>`.
4. Sets `verified=True` if found.
5. Queues the scan if it is still `QUEUED`.

## Task Queue Workflow

Function:

```text
tasks/scan_tasks.py -> enqueue_scan(...)
```

The backend calls `enqueue_scan(...)` with:

- `scan_id`;
- target URL;
- scan mode;
- selected scanner modules.

The task layer loops through each module and queues:

```py
run_scan.delay(
    scan_id=scan_id,
    task_type=task_type,
    target_url=target_url,
    scan_mode=effective_mode,
    allowed_modules=modules,
)
```

This creates independent tasks, so modules can run in parallel when the Celery
worker configuration allows it.

## Worker Execution Workflow

Celery task:

```text
workers.processor.run_scan
```

### 1. Validate The Module

The worker checks whether `task_type` is expected for the scan mode and allowed
module list. If a task is not allowed, it returns a skipped result and does not
scan.

### 2. Mark The Scan Running

The worker locks the scan row with SQLAlchemy and sets:

- `status = RUNNING`;
- `started_at`, if it has not already been set.

### 3. Run The Scanner

The worker looks up the scanner in `SCANNER_REGISTRY`:

```text
tls -> TLSScanner
http_headers -> HTTPHeadersScanner
xss -> XSSScanner
dns -> DNSScanner
```

It calls:

```py
scanner.safe_scan(target_url, timeout=30)
```

`safe_scan()` wraps scanner errors and converts unexpected exceptions into a
finding. This prevents one scanner bug from crashing the entire worker process.

### 4. Enrich Findings

Raw scanner findings are extended with:

- `scan_id`;
- `task_type`.

The standard finding fields are:

- `module_name`;
- `issue`;
- `evidence`;
- `severity`;
- `score_penalty`;
- `remediation`.

### 5. Persist Findings

The worker locks the scan row again and:

- appends new findings to `scan.findings`;
- appends the module name to `scan.completed_modules`;
- compares completed modules with expected modules.

If all expected modules are complete:

```text
status = COMPLETED
finished_at = current time
```

Otherwise:

```text
status = RUNNING
```

### 6. Retry And Failure Behavior

`run_scan` is configured with:

```text
max_retries=3
```

If scanner execution raises an exception outside `safe_scan()`, Celery retries
with an increasing countdown. If all retries fail, the processor marks the scan
`FAILED` and appends a system finding explaining the failure.

## Status Polling Workflow

Web route:

```text
GET /status/<scan_id>
```

Template:

```text
frontend/web_ui/templates/status.html
```

Browser JavaScript polls:

```text
GET /api/status/<scan_id>
```

Flask forwards that to the backend scan detail endpoint:

```text
GET /scans/{scan_id}
```

The status page handles:

- `QUEUED`: show waiting state;
- `RUNNING`: animate progress and continue polling;
- `COMPLETED`: redirect to `/results/<scan_id>`;
- `FAILED`: show failure state.

The progress bar is paced for user experience. The real source of truth is
always the backend scan status.

## Results Workflow

Web route:

```text
GET /results/<scan_id>
```

Flask reads backend scan details and prepares display data:

- raw findings;
- grouped findings;
- modules run;
- skipped modules;
- severity counts;
- risk grade;
- priority actions;
- tab summaries.

Template:

```text
frontend/web_ui/templates/results.html
```

The results page shows:

- target domain;
- overall risk grade;
- severity count pills;
- scanner summary;
- links to run skipped modules;
- "Fix These First" section;
- per-module finding tabs;
- evidence and remediation for each finding;
- copy buttons for fixes;
- PDF report download.

## PDF Report Workflow

Web route:

```text
GET /report/<scan_id>
```

The Flask app:

1. Fetches backend results.
2. Sorts findings by severity.
3. Uses ReportLab to build an A4 PDF.
4. Includes target metadata, severity summary, evidence, and remediation.
5. Returns the PDF as a download response.

## CLI Workflow

CLI entry point:

```text
python -m frontend.cli.main
```

Commands:

```powershell
python -m frontend.cli.main submit --url https://example.com
python -m frontend.cli.main status --id <scan_id>
python -m frontend.cli.main results --id <scan_id>
```

The CLI uses `BACKEND_URL`, defaulting to:

```text
http://localhost:8000
```

The CLI flow is simpler than the web flow. It submits Quick scans by default
and prints scan ID, status, target, and grouped finding counts.

## Data Lifecycle

### Scan Row Created

Initial state:

```text
status = QUEUED
findings = []
completed_modules = []
```

### Worker Starts

First worker task updates:

```text
status = RUNNING
started_at = now
```

### Modules Finish

Each module appends:

```text
findings += module findings
completed_modules += module name
```

### Scan Finishes

When all expected modules are complete:

```text
status = COMPLETED
finished_at = now
```

### Scan Fails

If worker retries are exhausted or findings cannot be persisted:

```text
status = FAILED
finished_at = now
findings += system failure finding
```

## Local Development Workflow

Run the services in separate terminals.

### 1. Start Redis

```powershell
wsl
redis-server
```

### 2. Start PostgreSQL

Use a local PostgreSQL server with a database matching `DATABASE_URL`.

Default local URL:

```text
postgresql://postgres:postgres@localhost:5432/scanner_db
```

### 3. Start Backend

```powershell
cd "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\backend"
$env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/scanner_db"
$env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner"
uvicorn app.main:app --reload
```

Backend URL:

```text
http://localhost:8000
```

### 4. Start Celery Worker

```powershell
cd "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner"
$env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner;C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\backend"
$env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/scanner_db"
celery -A tasks.celery_app worker --loglevel=info --pool=solo
```

On Windows, `--pool=solo` avoids multiprocessing issues.

### 5. Start Web UI

```powershell
cd "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\frontend\web_ui"
$env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner"
$env:BACKEND_URL = "http://localhost:8000"
python app.py
```

Frontend URL:

```text
http://localhost:5000
```

### 6. Run A Quick End-To-End Check

1. Open `http://localhost:5000`.
2. Enter a URL such as `https://example.com`.
3. Choose Quick Scan.
4. Wait for the status page to redirect.
5. Confirm the results page shows TLS, HTTP header, and DNS findings.

## Docker Compose Workflow

Docker Compose file:

```text
deployment/docker-compose.yml
```

Services:

- `db`: PostgreSQL;
- `redis`: Redis broker;
- `backend`: FastAPI API;
- `worker`: Celery worker;
- `frontend`: Flask web UI.

The containerized flow is the same as local development, but service hostnames
are internal Docker network names:

- backend connects to PostgreSQL at `db`;
- backend and worker connect to Redis at `redis`;
- frontend calls backend at `http://backend:8000`.

## Railway Deployment Workflow

Railway deployment uses separate services from the same GitHub repository:

- PostgreSQL database service;
- Redis database service;
- backend web service;
- Celery worker service;
- frontend web service.

Each service receives its own environment variables. The worker is private and
does not need a public domain. The backend and frontend are public web services.

## Security And Permission Workflow

The scanner separates passive and intrusive checks:

- TLS, HTTP header, and DNS checks are passive.
- XSS probing is intrusive because it sends test payloads through URL
  parameters and forms.

Any scan containing XSS requires domain ownership verification. The verification
token is placed in DNS, which proves the user controls the domain or can ask the
domain owner to authorize the scan.

## Troubleshooting Workflow

### Scan Stays Queued

Check:

- Redis is running.
- Celery worker is running.
- Backend and worker use the same Redis URL.
- For Full/XSS scans, `verified=True` or the DNS TXT record exists.

### Scan Starts But Never Completes

Check:

- worker logs for scanner exceptions;
- database connectivity from the worker;
- whether `completed_modules` is updating;
- whether the expected module list matches the queued module list.

### DNS Verification Fails

Check:

- TXT host is exactly `_vuln-verify.<domain>`;
- TXT value matches the shown token;
- DNS propagation has completed;
- the record was added to the root domain if scanning `www.<domain>`;
- local/network DNS resolver can see the TXT record.

### Results Page Has No Findings

Check:

- scan status is `COMPLETED`;
- `findings` JSON in PostgreSQL is not empty;
- worker logs show each module completed;
- the backend `GET /scans/{scan_id}` response includes `results` and `grouped`.

## Important Implementation Notes

- The backend stores scan findings in PostgreSQL. Results are not transient.
- `scan_type` is a legacy field; `scan_mode` is the preferred field.
- Custom scans may store selected modules in legacy `scan_type` as a
  comma-separated value.
- Workers use row locking while updating scan rows to reduce race conditions
  between parallel module tasks.
- The UI progress animation is not the scan engine. It only visualizes polling
  while the backend and workers do the real work.
