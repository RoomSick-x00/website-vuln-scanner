# System Architecture

This document explains how the website vulnerability scanner is built. It is
written for someone who may be new to backend systems, queues, workers, and web
security scanners.

## What This Project Does

The project scans a website URL for common security problems and shows the
results in a web UI, CLI, API response, and PDF report.

The scanner currently checks:

- TLS/SSL setup, such as certificates, supported TLS versions, and ciphers.
- HTTP security headers, such as CSP, HSTS, X-Frame-Options, and related
  browser protection headers.
- DNS configuration, such as SPF, DMARC, DNSSEC, CAA, and MX records.
- Reflected XSS, but only after domain ownership verification.

The important design choice is that scanning is asynchronous. That means the
user does not wait for the backend HTTP request to perform all scanner work.
Instead, the backend creates a scan record, queues scanner jobs, and workers run
those jobs in the background.

## Architecture At A Glance

```text
Browser
  |
  v
Flask Web UI --------------+
                           |
CLI -----------------------+--> FastAPI Backend ---> PostgreSQL
                                 |
                                 v
                              Celery
                                 |
                                 v
                               Redis
                                 |
                                 v
                            Celery Worker
                                 |
                                 v
                         Scanner Modules
                                 |
                                 v
                            Target Website
```

The result path goes back through PostgreSQL:

```text
Scanner Modules
  -> Worker Processor
  -> PostgreSQL scan row
  -> FastAPI Backend
  -> Flask Web UI / CLI / API response / PDF
```

## Why The System Is Split Into Services

The project has multiple parts because each part has a clear job:

- The frontend talks to users.
- The backend stores scan state and exposes APIs.
- Redis passes background jobs from the backend to workers.
- Celery workers run slow network scans outside normal HTTP requests.
- PostgreSQL stores scan metadata and findings.
- Scanner modules contain the actual security-checking logic.

This separation keeps the app easier to reason about. If scans are slow, the
web API can still respond quickly because the slow work is handled by workers.

## Component 1: Flask Web UI

Location:

```text
frontend/web_ui/
```

The Flask web UI is what the user sees in the browser.

It contains:

- `app.py`: Flask routes, backend API calls, DNS verification, results
  preparation, and PDF report generation.
- `templates/`: HTML pages rendered by Flask.
- `static/css/style.css`: styling for the web pages.

Important routes:

- `/`: scan form.
- `/submit`: handles the scan form.
- `/api/verify-domain`: checks a DNS TXT record for XSS/full scans.
- `/start-scan`: submits a verified scan to the backend.
- `/status/<scan_id>`: animated status page.
- `/api/status/<scan_id>`: JSON status endpoint used by browser JavaScript.
- `/results/<scan_id>`: full results page.
- `/report/<scan_id>`: PDF download route.

The web UI does not run scanner modules. It sends requests to the backend.

## Component 2: CLI Frontend

Location:

```text
frontend/cli/
```

The CLI is a terminal-based client. It is useful for testing and automation.

It contains:

- `main.py`: command parser.
- `commands_cli.py`: HTTP calls to the backend API.
- `formatter.py`: terminal output formatting.
- `api.py`: older/simple API wrapper.

Example commands:

```powershell
python -m frontend.cli.main submit --url https://example.com
python -m frontend.cli.main status --id <scan_id>
python -m frontend.cli.main results --id <scan_id>
```

The CLI and web UI are both clients. They do not own scan state.

## Component 3: FastAPI Backend

Location:

```text
backend/app/
```

The backend is the main API and the system of record. "System of record" means
this is the part of the project that creates and stores the official scan
state.

It contains:

- `main.py`: app startup, security headers, router registration, table creation,
  and migrations.
- `database.py`: SQLAlchemy database connection and session management.
- `models/scan.py`: database model for a scan.
- `schemas/scan.py`: request and response shapes.
- `routers/scan.py`: scan API endpoints.
- `scan_utils.py`: scan mode, module, domain, token, and grouping helpers.
- `migrate.py`: lightweight startup migrations.

Main endpoints:

- `GET /health`
- `POST /scans/`
- `GET /scans/`
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/verification-token`
- `POST /scans/{scan_id}/verify`
- `PATCH /scans/{scan_id}/status`

The backend decides what scanner modules should run, creates database records,
and queues Celery tasks. It does not directly perform scanning inside the HTTP
request.

## Component 4: PostgreSQL Database

PostgreSQL stores scan records. The main table is:

```text
scans
```

The model is defined in:

```text
backend/app/models/scan.py
```

Each scan row contains:

- `id`: scan UUID.
- `target`: target URL.
- `scan_mode`: `quick`, `full`, or `custom`.
- `scan_type`: legacy alias and custom module storage.
- `status`: `QUEUED`, `RUNNING`, `COMPLETED`, or `FAILED`.
- `created_at`: when the scan row was created.
- `started_at`: when a worker first started running it.
- `finished_at`: when it completed or failed.
- `findings`: JSON list of scanner findings.
- `completed_modules`: JSON list of finished modules.
- `verification_token`: TXT verification token for XSS/full scans.
- `verified`: whether domain ownership has been confirmed.

The database is shared by the backend and workers. The backend creates scan
rows. Workers update those rows with findings.

## Component 5: Celery

Celery is the task queue framework.

Location:

```text
tasks/
```

Important files:

- `celery_app.py`: creates and configures the Celery app.
- `scan_tasks.py`: creates one Celery task per scanner module.
- `queue_config.py`: reserved for future queue configuration.

Celery lets the project say, "Run this scan module later in a worker process."
That is useful because network scanning can be slow, unreliable, or parallel.

## Component 6: Redis

Redis is used as the Celery broker and result backend.

In simple terms:

- The backend puts task messages into Redis.
- Workers listen to Redis.
- Workers take tasks from Redis and execute them.

Redis does not store the final scan report. PostgreSQL stores the scan report.

## Component 7: Worker Processor

Location:

```text
workers/processor.py
```

The worker processor is the code Celery runs for each scanner task.

It does these things:

1. Receives `scan_id`, `task_type`, `target_url`, scan mode, and allowed
   modules.
2. Checks whether the requested module is valid for the scan.
3. Marks the scan `RUNNING`.
4. Runs the correct scanner module.
5. Adds `scan_id` and `task_type` to each finding.
6. Appends findings to the database row.
7. Adds the module name to `completed_modules`.
8. Marks the scan `COMPLETED` if all expected modules are done.
9. Marks the scan `FAILED` if retries are exhausted or persistence fails.

The worker processor is the bridge between queue messages and scanner logic.

## Component 8: Scanner Modules

Location:

```text
workers/scanner_modules/
```

Scanner modules contain the actual security checks.

Active scanners:

- `tls.py`
- `https_headers.py`
- `dns.py`
- `xss.py`

Shared base class:

```text
base.py
```

Every active scanner returns a list of findings. A finding is a dictionary with
fields like:

- `module_name`
- `issue`
- `evidence`
- `severity`
- `score_penalty`
- `remediation`

The scanner modules do not write to the database directly. They only return
findings. The worker processor handles persistence.

## Scan Mode Architecture

Scan modes are defined in helper code so the frontend, backend, and workers can
agree on which modules should run.

Current module groups:

```text
quick = tls + http_headers + dns
full  = tls + http_headers + dns + xss
custom = user-selected modules
```

Important files:

- `backend/app/scan_utils.py`
- `tasks/scan_tasks.py`
- `workers/processor.py`

The backend is the main authority for resolving requested modules before tasks
are queued.

## Domain Verification Architecture

XSS scanning sends test payloads to the target site. Because this is more
intrusive than passive checks, the project requires proof that the user controls
the domain.

Verification works with a DNS TXT record:

```text
Type: TXT
Name/Host: _vuln-verify.<domain>
Value: vuln-verify-<stable-token>
```

The token is generated from the domain. This means the same domain gets the
same token in future sessions.

Verification exists in two places:

- The Flask UI checks TXT records before submitting the final scan request.
- The backend also checks verification before queueing XSS/full scans.

The backend check is important because frontend checks alone cannot be trusted.

## Security Headers Architecture

Both the backend and frontend set security headers.

Backend:

```text
backend/app/main.py
```

Frontend:

```text
frontend/web_ui/app.py
```

Headers include:

- Content-Security-Policy
- Cross-Origin-Embedder-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy
- Strict-Transport-Security
- Cache-Control
- Permissions-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy

The frontend uses CSP nonces for inline scripts. A nonce is a per-request random
value that allows only approved inline scripts to run.

## Deployment Architecture

Deployment files live in:

```text
deployment/
```

Docker Compose runs these services:

- `db`: PostgreSQL.
- `redis`: Redis.
- `backend`: FastAPI.
- `worker`: Celery worker.
- `frontend`: Flask/Gunicorn web UI.

Railway deployment uses the same logical services, but each service is deployed
separately from the same repository.

## Why Not Run Scanners In The Backend Request?

A beginner might wonder why the backend does not simply scan the site inside
`POST /scans/`.

Reasons:

- Scanning can take 30 to 60 seconds or longer.
- Network requests can time out.
- Some modules can run independently.
- Users need status updates while work is running.
- A web server should avoid long blocking requests.
- Background workers can be scaled separately from the API.

The queue-based architecture makes the system more reliable and easier to
extend.

## How A New Scanner Fits Into The Architecture

To add a new scanner:

1. Create a new scanner class in `workers/scanner_modules/`.
2. Subclass `BaseScanner`.
3. Implement `scan(target, timeout)`.
4. Return findings using `self._finding(...)`.
5. Register the scanner in `workers/processor.py`.
6. Add the module name to allowed module lists in `backend/app/scan_utils.py`.
7. Update UI labels if users should be able to select it.
8. Add docs and a smoke script if useful.

The scanner should not directly call Celery, Redis, or PostgreSQL. It should
only scan and return findings.

## Important Architecture Rules

- The backend owns scan creation and API contracts.
- PostgreSQL owns durable scan state and findings.
- Redis only transports Celery task messages.
- Workers run scanner modules and persist results.
- Scanner modules return findings but do not manage database state.
- The frontend displays and submits data but does not decide final security
  authorization.
- XSS scans require domain verification.
- The UI progress bar is visual; backend status is authoritative.

## Beginner Glossary

- API: a set of HTTP endpoints that other parts of the app can call.
- Backend: server-side code that handles requests and business logic.
- Frontend: the user-facing interface.
- Database: durable storage for application data.
- Queue: a place where jobs wait to be processed.
- Worker: a background process that consumes queued jobs.
- Broker: the system Celery uses to pass messages; Redis is the broker here.
- Scanner module: a Python class that checks one category of security issues.
- Finding: one result from a scanner, such as a missing header or weak TLS
  setting.
- Severity: how important a finding is, such as `low`, `medium`, or `high`.
- Remediation: suggested fix for a finding.
- DNS TXT record: a DNS record that can store text, used here to prove domain
  control.
