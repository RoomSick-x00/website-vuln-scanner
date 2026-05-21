# Backend Core

This folder holds shared primitives that are intentionally independent of API
routes and database models.

## Files

- `enums.py` defines `ScanStatus`, the lifecycle values used by the backend,
  worker processor, database rows, and API responses.
- `__init__.py` marks this directory as a package.

## Logic

`ScanStatus` is a string enum so FastAPI/Pydantic can serialize values cleanly
and SQLAlchemy can store the same readable values in the `scans.status` column:
`QUEUED`, `RUNNING`, `COMPLETED`, and `FAILED`.
