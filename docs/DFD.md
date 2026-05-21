# Data Flow Diagram And Explanation

This document explains how data moves through the website vulnerability scanner.
It is written for beginners, so it explains what each data item is, where it
comes from, where it goes, and why it matters.

DFD means "Data Flow Diagram." A DFD focuses on data movement, not just code
files. It answers questions like:

- Who sends data into the system?
- Which process handles that data?
- Where is the data stored?
- Which external systems are contacted?
- Where are the trust boundaries?

## Level 0: Whole System View

At the highest level, the system takes a website URL from a user and returns a
security report.

```text
[User]
  |
  | target URL, scan mode
  v
[Website Vulnerability Scanner]
  |
  | security findings, report
  v
[User]
```

External systems used by the scanner:

- target website;
- DNS resolvers;
- PostgreSQL database;
- Redis;
- optional hosting platform such as Railway or Docker network.

## Level 1: Main Data Flow

```text
[User Browser / CLI]
  |
  | 1. Submit target URL and scan mode
  v
[Frontend Client]
  |
  | 2. POST /scans/
  v
[FastAPI Backend]
  |
  | 3. Create scan row
  v
[PostgreSQL]

[FastAPI Backend]
  |
  | 4. Queue scanner tasks
  v
[Redis / Celery Broker]
  |
  | 5. Deliver task messages
  v
[Celery Worker]
  |
  | 6. Run scanner modules
  v
[Target Website / DNS]

[Celery Worker]
  |
  | 7. Store findings
  v
[PostgreSQL]

[Frontend Client]
  |
  | 8. Poll status and request results
  v
[FastAPI Backend]
  |
  | 9. Read scan row and findings
  v
[PostgreSQL]

[FastAPI Backend]
  |
  | 10. Return report data
  v
[Frontend Client]
  |
  | 11. Render results or PDF
  v
[User]
```

## Main Data Stores

### PostgreSQL

PostgreSQL stores durable scan data.

Stored data includes:

- scan ID;
- target URL;
- scan mode;
- status;
- timestamps;
- findings JSON;
- completed modules;
- verification token;
- verification status.

PostgreSQL is the source of truth. If Redis restarts, the final scan records are
still in PostgreSQL.

### Redis

Redis stores Celery queue messages and task result metadata.

Redis data includes:

- task messages;
- task IDs;
- task routing information;
- short-lived Celery result backend data.

Redis is not the main report database. It helps move jobs from backend to
workers.

## External Entities

### User

The user provides:

- target URL;
- scan mode;
- selected modules for custom scans;
- DNS TXT verification record, when needed.

The user receives:

- scan ID;
- scan status;
- findings;
- remediation suggestions;
- PDF report.

### Target Website

The target website is the website being scanned.

Scanner modules may send:

- TLS handshake attempts;
- HTTP GET requests;
- HTTP form submissions for XSS probes;
- requests with modified query parameters.

The target website returns:

- TLS certificate data;
- response headers;
- HTML content;
- reflected payloads, if vulnerable;
- connection errors or timeouts.

### DNS Resolver

DNS resolvers are used for:

- SPF lookups;
- DMARC lookups;
- DNSSEC/DNSKEY lookups;
- CAA lookups;
- MX lookups;
- domain verification TXT lookup.

The scanner receives DNS answers or resolver errors.

## Data Flow 1: Quick Scan Submission

Quick Scan is the simplest flow.

Input from user:

```json
{
  "target": "https://example.com",
  "scan_mode": "quick"
}
```

Backend actions:

1. Validate the request with `ScanCreate`.
2. Resolve modules to:

```text
tls, http_headers, dns
```

3. Create a scan row in PostgreSQL.
4. Mark it `QUEUED`.
5. Queue three Celery tasks.

Data stored in PostgreSQL:

```text
id = generated UUID
target = https://example.com
scan_mode = quick
status = QUEUED
completed_modules = []
findings = []
verified = True
```

Data sent to Redis:

```text
run_scan(scan_id, "tls", target_url, "quick", allowed_modules)
run_scan(scan_id, "http_headers", target_url, "quick", allowed_modules)
run_scan(scan_id, "dns", target_url, "quick", allowed_modules)
```

## Data Flow 2: Full Scan Submission With Verification

Full Scan includes XSS, so it needs domain verification.

Input from user:

```json
{
  "target": "https://example.com",
  "scan_mode": "full"
}
```

The frontend first shows the user a TXT record:

```text
Type: TXT
Name/Host: _vuln-verify.example.com
Value: vuln-verify-<token>
```

The user adds this record in their DNS provider.

Verification request:

```text
GET /api/verify-domain?domain=example.com&token=vuln-verify-<token>
```

If DNS returns the expected TXT value, the web UI submits the scan.

Backend actions:

1. Resolve modules to:

```text
tls, http_headers, dns, xss
```

2. Generate or reuse the verification token.
3. Check DNS TXT record again.
4. Create scan row.
5. Queue all four modules only if verification passes.

Why check twice?

- The frontend check improves user experience.
- The backend check enforces the rule securely.

Frontend checks alone are not enough because a user could bypass browser code
and call the backend API directly.

## Data Flow 3: Custom Scan

Custom scan data includes a selected module list.

Example input:

```json
{
  "target": "https://example.com",
  "scan_mode": "custom",
  "modules": ["tls", "dns"]
}
```

The backend filters the list to known modules. Unknown module names are ignored.
If no valid module remains, the backend returns an error.

If the list includes `xss`, verification is required.

Data stored:

```text
scan_mode = custom
scan_type = comma-separated selected modules
```

`scan_type` is a legacy field. It is still used so older code paths can rebuild
the selected module list.

## Data Flow 4: Worker Task Execution

Each queued module becomes a worker task.

Input to worker:

```text
scan_id
task_type
target_url
scan_mode
allowed_modules
```

Worker reads:

- scan row from PostgreSQL;
- scanner registry from code;
- target website or DNS data.

Worker writes:

- updated scan status;
- findings;
- completed module list;
- finished timestamp if this was the last module.

The worker uses row locking while updating the scan. This matters because
several module tasks can finish around the same time.

## Data Flow 5: Scanner Finding Data

A scanner returns a list of finding dictionaries.

Example finding:

```json
{
  "module_name": "http_headers",
  "issue": "Content-Security-Policy header missing",
  "evidence": "Header not present in HTTP response",
  "severity": "high",
  "score_penalty": 25,
  "remediation": "Add a Content-Security-Policy header."
}
```

The worker adds:

```json
{
  "scan_id": "<scan uuid>",
  "task_type": "http_headers"
}
```

Then it appends the enriched finding to the scan row's `findings` JSON field.

## Data Flow 6: Status Polling

The status page asks for scan status repeatedly.

Browser request:

```text
GET /api/status/<scan_id>
```

Flask forwards to backend:

```text
GET /scans/{scan_id}
```

Backend reads from PostgreSQL and returns:

- scan ID;
- target;
- status;
- scan mode;
- completed modules;
- findings;
- grouped findings;
- ran/skipped modules;
- verified flag.

The browser uses the status field:

- `QUEUED`: show waiting state.
- `RUNNING`: continue progress animation.
- `COMPLETED`: redirect to results.
- `FAILED`: show failure.

## Data Flow 7: Results Page

The results page receives scan data from the backend and transforms it for
display.

Raw backend data:

- `results`: list of findings;
- `grouped`: findings grouped by module;
- `ran_modules`;
- `skipped_modules`;
- `target`.

Flask display calculations:

- severity counts;
- risk grade;
- risk label;
- priority actions;
- tab summaries;
- module labels;
- default remediation fallback.

Rendered output:

- risk score banner;
- severity filter buttons;
- module tabs;
- finding cards;
- fix/remediation text;
- copy buttons;
- PDF download link.

## Data Flow 8: PDF Report

PDF route:

```text
GET /report/<scan_id>
```

Input:

- scan ID in URL.

Process:

1. Flask requests backend results.
2. Findings are sorted by severity.
3. ReportLab creates a PDF in memory.
4. Flask returns the bytes as a download.

Output:

```text
Content-Type: application/pdf
Content-Disposition: attachment; filename=scan_report_<id>.pdf
```

The PDF is generated on request. It is not stored as a file by default.

## Trust Boundaries

A trust boundary is a place where data crosses from one security zone to
another. These are important because data should be validated or checked when it
crosses a boundary.

### Boundary 1: User To Frontend

Data:

- URL;
- scan mode;
- selected modules.

Risks:

- malformed URL;
- unsupported module names;
- accidental or unauthorized target.

Controls:

- frontend URL validation;
- backend schema validation;
- backend module filtering;
- XSS verification rule.

### Boundary 2: Frontend To Backend

Data:

- JSON scan request;
- scan ID in URLs;
- verification request.

Risks:

- direct API calls bypassing UI;
- invalid scan IDs;
- forged module selection;
- attempted XSS scan without permission.

Controls:

- backend validation;
- backend verification check;
- 404 for unknown scan IDs;
- known module allowlist.

### Boundary 3: Backend To Redis

Data:

- Celery task messages.

Risks:

- queue unavailable;
- wrong Redis URL;
- tasks not consumed.

Controls:

- shared environment configuration;
- worker startup checks;
- monitoring/logging.

### Boundary 4: Worker To Target Website

Data:

- HTTP requests;
- TLS handshakes;
- DNS lookups;
- XSS test payloads.

Risks:

- timeouts;
- target blocks requests;
- intrusive scan against unauthorized target;
- false positives or false negatives.

Controls:

- timeouts;
- `safe_scan()` wrapper;
- XSS verification;
- scanner-specific error findings.

### Boundary 5: Worker To PostgreSQL

Data:

- findings;
- status updates;
- completed module list.

Risks:

- race conditions between parallel modules;
- database connection failure;
- partial updates.

Controls:

- row locking with `with_for_update()`;
- transactions;
- retry/failure handling;
- system finding on failure.

### Boundary 6: Backend To Frontend Results

Data:

- findings and remediation text;
- target URL;
- scan status.

Risks:

- unsafe rendering;
- broken UI if fields are missing;
- confusing result state.

Controls:

- Jinja escaping;
- default values in schemas;
- default remediation fallback;
- grouped result shape.

## Sensitive Or Important Data

The project does not handle passwords or user accounts in its current form, but
some data is still important.

Important data:

- target URLs;
- scan findings;
- DNS verification tokens;
- scan IDs;
- timestamps;
- remediation text.

Why it matters:

- Findings may reveal weaknesses in a real site.
- Scan IDs can be used to retrieve results if endpoints are public.
- Verification tokens prove domain control for scanner authorization.

## Data Validation Points

Validation happens in several layers:

- Browser JavaScript validates the URL shape for usability.
- Flask reads form fields and decides whether verification UI is needed.
- FastAPI/Pydantic validates request structure.
- Backend helper logic filters scan modules to known values.
- Backend DNS verification checks XSS authorization.
- Scanner modules validate target parsing and handle network errors.
- UI display code handles missing fields with defaults.

The backend validation is the most important because it protects the API even
when someone does not use the browser UI.

## Error Data Flow

Errors can happen at many points.

### Backend Error

Example:

- no valid scanner modules selected.

Response:

```text
HTTP 422
```

### Scanner Error

Example:

- target cannot be reached;
- TLS handshake fails;
- DNS resolver times out.

Response:

- scanner returns a finding explaining the error;
- severity depends on the scanner and error type.

### Worker Failure

Example:

- scanner crashes unexpectedly outside normal handling;
- database persistence fails.

Response:

- Celery retries up to three times;
- if retries fail, scan becomes `FAILED`;
- system finding is appended.

## Data Flow By File

### `frontend/web_ui/app.py`

Receives form data, checks verification state, calls backend helper functions,
prepares result display data, and creates PDF reports.

### `frontend/cli/commands_cli.py`

Creates HTTP requests to the backend and returns JSON data to CLI formatting or
Flask routes.

### `backend/app/routers/scan.py`

Receives scan API requests, creates scan rows, handles verification, and queues
tasks.

### `backend/app/scan_utils.py`

Transforms scan mode data into module lists and groups findings by module.

### `tasks/scan_tasks.py`

Transforms one scan request into multiple Celery task messages.

### `workers/processor.py`

Transforms Celery task data into scanner execution and database updates.

### `workers/scanner_modules/*.py`

Transforms target website/DNS responses into normalized findings.

## Beginner Glossary

- Data flow: the path information takes through the system.
- External entity: something outside the main app, like the user or target
  website.
- Process: code that transforms data, such as the backend or worker.
- Data store: persistent or temporary storage, such as PostgreSQL or Redis.
- Trust boundary: a point where data moves between areas with different trust
  levels.
- Validation: checking that incoming data is allowed and shaped correctly.
- Finding: one scanner result.
- Remediation: advice for fixing a finding.
- Queue message: data telling a worker what background job to run.
