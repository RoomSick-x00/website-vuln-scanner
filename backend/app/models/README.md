# Backend Models

This folder contains SQLAlchemy ORM models. Models define the database tables
used by both the FastAPI backend and Celery workers.

## Files

- `scan.py` defines the `Scan` model mapped to the `scans` table.
- `__init__.py` marks this directory as a package.

## `Scan` Model

Each scan row stores:

- `id`: UUID string generated when a scan is submitted.
- `target`: submitted target URL.
- `scan_mode`: current mode such as `quick`, `full`, or `custom`.
- `scan_type`: legacy alias, also used to preserve custom module selections.
- `status`: lifecycle state from `ScanStatus`.
- `created_at`, `started_at`, `finished_at`: scan timestamps.
- `findings`: JSON list appended by workers as modules finish.
- `completed_modules`: JSON list used to decide when all expected modules are
  done.
- `verification_token` and `verified`: DNS ownership verification state for
  XSS/full scans.

## Logic

Workers lock and update the same scan row as each scanner module finishes.
Completion is derived from `completed_modules`: once the expected module set is
contained in that list, the worker marks the scan `COMPLETED`.
