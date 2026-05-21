# Backend Application Package

`backend/app` is the importable FastAPI application package. The package is
copied into the backend and worker containers so both API code and Celery tasks
can use the same database model and helper logic.

## Files

- `main.py` creates the FastAPI app, creates missing tables, runs lightweight
  migrations, applies global security headers, includes the scan router, and
  exposes `/health`.
- `database.py` reads `DATABASE_URL`, normalizes Railway-style `postgres://`
  URLs to SQLAlchemy's `postgresql://`, creates the engine/session factory, and
  provides `get_db()` for FastAPI dependency injection.
- `migrate.py` runs idempotent `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
  statements for fields that were added after the first scan model existed.
- `scan_utils.py` contains pure helper logic for supported modules, scan modes,
  deterministic verification tokens, target-domain extraction, and grouping
  findings by scanner module.
- `create_tables.py` is a direct script for creating tables from SQLAlchemy
  metadata. The API already calls `Base.metadata.create_all()` on startup.
- `__init__.py` marks this directory as a Python package.

## Request Flow

The API starts in `main.py`, then hands `/scans` requests to
`routers/scan.py`. The router uses `schemas/scan.py` to validate/shape data,
`models/scan.py` to persist it, `scan_utils.py` to decide which modules should
run, and `tasks.scan_tasks.enqueue_scan()` to send actual scanner work to
Celery.

## Design Logic

Database setup is intentionally simple for a small project: SQLAlchemy metadata
creates missing tables, and `migrate.py` applies safe additive migrations. For a
larger production system this folder would usually move to Alembic migrations.
