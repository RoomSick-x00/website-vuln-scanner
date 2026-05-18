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


## How to run using without Docker(on powershell)?
# Starting redis server.
wsl
redis-server

# Starting backend server(uvicorn)
cd "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\backend"
$env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/scanner_db"
$env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner"
uvicorn app.main:app --reload

# Starting Celery 
cd "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner"
$env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner;C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\backend"
$env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/scanner_db"
celery -A tasks.celery_app worker --loglevel=info --pool=solo

# Starting Frontend server:
cd "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\frontend\web_ui"
$env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner"
$env:BACKEND_URL = "http://localhost:8000"
python app.py

## Temporary verify bypass

Domain verification is currently forced to succeed for UI testing in
`frontend/web_ui/templates/verify.html` inside `verifyDomain()`.

To disable the bypass before shipping, remove:

```js
const verificationResult = { success: true };
```

Then uncomment the real `/api/verify-domain` fetch block directly below it.

For screenshots, append one of these query params to the verify page URL:

- `?verify_state=checking` keeps the button in the checking state.
- `?verify_state=failed` shows the failed state.
- Omit the param to use the temporary success bypass.
