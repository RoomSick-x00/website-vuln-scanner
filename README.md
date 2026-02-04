# Website Vulnerability Scanning System

## Overview
A cloud-deployable, asynchronous website vulnerability scanning system.
Scans a target URL for multiple vulnerabilities, stores results in PostgreSQL, 
and exposes structured reports via API or CLI/Web UI.

## Tech Stack
- Backend: Python + FastAPI
- Async Task Queue: Celery + Redis
- Workers / Scanner modules: Python
- Database: PostgreSQL
- Frontend: CLI + minimal web UI (optional)
- Deployment: Docker Compose, optional cloud deployment

## Repo Structure
- `backend/` → FastAPI + DB models
- `tasks/` → Celery task queue configuration
- `workers/` → Scanner modules + findings processor
- `frontend/` → CLI / web interface
- `deployment/` → Dockerfiles + docker-compose
- `docs/` → Architecture, DFD, workflow diagrams
- `tests/` → Unit + integration tests 
