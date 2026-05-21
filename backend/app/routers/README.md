# Backend Routers

This folder contains FastAPI route modules. Route files are the boundary between
HTTP clients and the internal scan/task/database logic.

## Files

- `scan.py` exposes the `/scans` API.
- `__init__.py` marks this directory as a package.

## `scan.py` Workflow

- `POST /scans/` creates a scan, resolves modules, stores verification state,
  and queues Celery tasks when allowed.
- `GET /scans/` lists scan rows.
- `GET /scans/{scan_id}` returns detail results, including grouped findings,
  modules run, skipped modules, completed modules, and verification state.
- `GET /scans/{scan_id}/verification-token` returns the TXT record details for
  proving domain ownership.
- `POST /scans/{scan_id}/verify` checks DNS TXT records and queues the scan if
  verification succeeds.
- `PATCH /scans/{scan_id}/status` manually updates lifecycle status.

## Logic

Quick scans are queued immediately. Any module set containing `xss` requires a
deterministic TXT token at `_vuln-verify.<domain>`. This protects the active XSS
probe from being run against domains the user does not control.
