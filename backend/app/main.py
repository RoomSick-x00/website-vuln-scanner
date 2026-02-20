from fastapi import FastAPI
from backend.app.routers import scan

app = FastAPI(title="Vulnerability Scanner API")

app.include_router(scan.router)
