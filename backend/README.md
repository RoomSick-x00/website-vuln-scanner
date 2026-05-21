# Backend

This folder contains the FastAPI API and database layer for the website
vulnerability scanner. It is the system of record for scans: every submitted
scan is stored here, status changes are persisted here, and worker findings are
read from the same database rows when clients request results.

## Workflow

1. A client posts a target URL to `POST /scans/`.
2. The router validates the requested scan mode and module list.
3. A `Scan` row is created in PostgreSQL with `QUEUED` status.
4. If the scan includes XSS, the backend requires DNS TXT verification before
   queueing scanner work.
5. Verified scans are passed to `tasks.scan_tasks.enqueue_scan`, which creates
   Celery jobs for each selected scanner module.
6. Clients poll `GET /scans/{scan_id}` for status, completed modules, grouped
   findings, and verification state.

## Architecture

- `app/main.py` creates the FastAPI app, initializes tables/migrations, adds
  security headers, and mounts routers.
- `app/database.py` defines the SQLAlchemy engine, session factory, declarative
  base, and request-scoped DB dependency.
- `app/models/` contains SQLAlchemy database models.
- `app/schemas/` contains Pydantic request and response shapes.
- `app/routers/` contains API endpoints.
- `app/core/` contains shared constants/enums.
- `app/scan_utils.py` centralizes scan-mode, domain, verification-token, and
  grouping helpers used by the API.
- `app/migrate.py` contains lightweight startup migrations for columns added
  during development.
- `app/create_tables.py` is a manual helper script for table creation.

## Logic Notes

The backend deliberately keeps scanner execution out of request handlers. API
requests create or read state; actual network scanning happens in Celery worker
processes. This keeps the HTTP API responsive while scans run asynchronously.

The `scan_type` field is kept as a legacy alias for older clients, while
`scan_mode` is the current canonical field. Custom scans store the selected
module list as a comma-separated legacy `scan_type` value so older paths can
still reconstruct which modules were requested.
