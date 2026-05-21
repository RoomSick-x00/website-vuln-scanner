# Tasks

This folder contains Celery queue configuration and enqueueing logic. It bridges
the synchronous FastAPI request flow and the asynchronous worker execution flow.

## Files

- `celery_app.py` creates the Celery application, reads Redis connection
  settings, registers task modules, and configures JSON serialization.
- `scan_tasks.py` resolves a scan mode into scanner module names and queues one
  Celery task per module.
- `queue_config.py` is currently empty and reserved for future queue/routing
  settings.
- `__init__.py` marks this directory as a package.

## Workflow

1. `backend/app/routers/scan.py` calls `enqueue_scan(...)`.
2. `scan_tasks.py` expands `quick`, `full`, or custom module choices into a
   list like `["tls", "http_headers", "dns"]`.
3. For each module, it calls `workers.processor.run_scan.delay(...)`.
4. Celery sends those jobs through Redis to worker processes.
5. Workers run modules independently and persist results back into PostgreSQL.

## Logic

The queue layer is intentionally thin. It does not scan targets or update the
database directly; it only decides how many tasks are needed and sends enough
context for each worker task to know the scan ID, target URL, scan mode, and
allowed module set.
