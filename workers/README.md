# Workers

This folder contains the asynchronous scanner execution layer. Celery workers
import this package, run scanner modules, and write findings back into the
backend database.

## Files

- `processor.py` is the Celery task implementation and scanner orchestrator.
- `scanner_modules/` contains individual scanner implementations.
- `__init__.py` marks this directory as a package.

## Workflow

1. Celery receives a `workers.processor.run_scan` task.
2. `processor.py` checks whether the requested `task_type` is allowed for the
   scan.
3. The processor looks up the scanner instance in `SCANNER_REGISTRY`.
4. The scan row is marked `RUNNING` and `started_at` is set if needed.
5. The processor calls `scanner.safe_scan(target_url, timeout=30)`.
6. Findings are enriched with `scan_id` and `task_type`.
7. Findings are appended to the scan row and the module is added to
   `completed_modules`.
8. When all expected modules are complete, the scan is marked `COMPLETED`.

## Architecture

`processor.py` is the boundary between generic queue execution and specific
security checks. Individual scanners only return finding dictionaries; the
processor handles retries, status transitions, result enrichment, and database
persistence.

## Logic

Scanner failures are retried up to three times with exponential countdown. If a
module still cannot complete, the scan is marked `FAILED` and a system finding
is appended so the UI has a useful explanation instead of an empty result.
