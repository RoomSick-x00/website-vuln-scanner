# Backend Schemas

This folder contains Pydantic models for request validation and response
serialization.

## Files

- `scan.py` defines all scan-related request and response schemas.
- `__init__.py` marks this directory as a package.

## Schema Roles

- `ScanCreate` accepts new scan submissions. It supports current `scan_mode`,
  optional `modules`, and legacy `scan_type`.
- `ScanResponse` is the compact scan row response returned by create/list
  operations.
- `ScanDetailResponse` is the richer result shape used by UI/CLI status and
  results views.
- `VerificationTokenResponse` returns the DNS TXT record a user must add.
- `VerifyDomainResponse` reports whether domain ownership verification passed.

## Logic

Schemas keep HTTP payloads stable even if the SQLAlchemy model changes. They
also normalize defaults such as empty `findings` and `completed_modules` lists,
which avoids `None` handling in clients.
