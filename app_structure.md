website-vuln-scanner/
│
├─ backend/                     # Member 1
│   ├─ app/
│   │   └─ __init__.py
│   ├─ models/
│   │   └─ __init__.py
│   ├─ main.py                  # FastAPI entry point
│   └─ requirements.txt         # Backend dependencies
│
├─ tasks/                       # Member 2
│   ├─ celery_app.py             # Celery config
│   └─ queue_config.py           # Redis + queue settings
│
├─ workers/                     # Member 3
│   ├─ scanner_modules/
│   │   └─ __init__.py
│   └─ processor.py              # Findings processor / normalizer
│
├─ frontend/                     # Member 4
│   ├─ cli/
│   │   └─ cli.py                # CLI for scan submission
│   └─ web_ui/
│       └─ index.html            # Minimal web UI for scan submission
│
├─ deployment/
│   ├─ Dockerfile.backend
│   ├─ Dockerfile.worker
│   ├─ Dockerfile.frontend
│   └─ docker-compose.yml
│
├─ docs/
│   ├─ architecture.md
│   ├─ DFD.md
│   └─ workflow.md
│
├─ tests/
│   ├─ test_backend.py
│   ├─ test_workers.py
│   └─ test_integration.py
│
└─ README.md
