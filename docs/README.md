# Project Documentation

This folder contains the main learning docs for the website vulnerability
scanner. These documents explain the project at a system level, so a reader can
understand how the frontend, backend, queue, workers, database, and scanner
modules work together.

If you are new to the project, start here after reading the root `README.md`.

## Recommended Reading Order

1. `architecture.md`

   Start here to understand the big picture: what each service does, why the
   project is split into frontend/backend/tasks/workers, and how the scanner
   modules fit into the system.

2. `workflow.md`

   Read this next to understand the actual step-by-step lifecycle of a scan:
   submission, verification, queueing, worker execution, polling, results, and
   PDF reporting.

3. `DFD.md`

   Read this when you want to understand the data movement in more detail:
   what data enters the system, where it is stored, which external systems are
   contacted, and where validation/trust boundaries exist.

## Document Guide

### `architecture.md`

Explains the structure of the whole application.

Use it when you want to know:

- what each major component is responsible for;
- why Celery and Redis are used;
- what PostgreSQL stores;
- how scanner modules are organized;
- how deployment is structured;
- how a new scanner would be added.

### `workflow.md`

Explains the end-to-end runtime behavior.

Use it when you want to know:

- what happens after a user clicks "Start Scan";
- how Quick, Full, and Custom scans differ;
- how DNS verification works for XSS scans;
- how worker tasks update scan status;
- how the results page and PDF report are built;
- how to run the full system locally.

### `DFD.md`

Explains the data-flow diagram and trust boundaries.

Use it when you want to know:

- which data moves between the user, frontend, backend, Redis, workers,
  PostgreSQL, DNS, and the target website;
- what gets stored permanently;
- what Redis is used for;
- where validation happens;
- where unauthorized or malformed data could enter;
- how errors flow through the system.

## How These Docs Relate To The Code

The docs in this folder explain the system-level view. For implementation
details inside a specific folder, read that folder's own `README.md`.

Useful code entry points:

- Backend API: `backend/app/`
- Scan routes: `backend/app/routers/scan.py`
- Database model: `backend/app/models/scan.py`
- Scan helpers: `backend/app/scan_utils.py`
- Celery setup: `tasks/celery_app.py`
- Task enqueueing: `tasks/scan_tasks.py`
- Worker orchestration: `workers/processor.py`
- Scanner modules: `workers/scanner_modules/`
- CLI client: `frontend/cli/`
- Flask web UI: `frontend/web_ui/`
- Deployment files: `deployment/`

## For Different Readers

### New Developer

Read:

1. root `README.md`
2. `docs/architecture.md`
3. `docs/workflow.md`
4. folder-level README files for the part you are editing

### Debugging A Scan

Read:

1. `docs/workflow.md`
2. `docs/DFD.md`
3. `workers/README.md`
4. `tasks/README.md`

Then check:

- backend logs;
- Celery worker logs;
- Redis connection;
- PostgreSQL scan row;
- `completed_modules`;
- `findings`.

### Explaining The Project In A Presentation

Read:

1. `docs/architecture.md`
2. the "High-Level Flow" section in `docs/workflow.md`
3. the "Level 0" and "Level 1" sections in `docs/DFD.md`

These sections give the cleanest explanation of the project without going too
deep into implementation details.

### Adding A New Scanner

Read:

1. `docs/architecture.md`
2. `workers/scanner_modules/README.md`
3. `workers/README.md`
4. `backend/app/README.md`

The scanner should return normalized findings. The worker processor should
remain responsible for persistence and scan status updates.

## Documentation Style

These docs are intentionally beginner-friendly. They avoid assuming that the
reader already knows Celery, Redis, SQLAlchemy, FastAPI, Flask, DNS
verification, or scanner terminology.

When updating docs:

- explain new terms the first time they appear;
- prefer concrete examples over vague descriptions;
- mention the relevant file paths;
- keep architecture, workflow, and data-flow topics in their matching files;
- update this index if a new major documentation file is added.
