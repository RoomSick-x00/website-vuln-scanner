# Backend Tasks Placeholder

This directory is currently empty and appears to be an older placeholder for
task-related code.

## Current Architecture

Active Celery configuration and scan enqueueing live in the top-level
`tasks/` package:

- `tasks/celery_app.py`
- `tasks/scan_tasks.py`
- `tasks/queue_config.py`

## Logic

Keep task code in the top-level `tasks/` package unless the project is later
restructured. The backend imports `tasks.scan_tasks.enqueue_scan` directly from
there.
