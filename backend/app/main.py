from fastapi import FastAPI

from backend.app.routers import scan
from backend.app.routers import report

app = FastAPI(title="Vulnerability Scanner API")

app.include_router(scan.router)
app.include_router(report.router)


@app.get("/health")
def health():
    return {"status": "ok"}