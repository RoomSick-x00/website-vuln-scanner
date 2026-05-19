from fastapi import FastAPI
from app.routers import scan
from app.database import Base, engine
from app.models.scan import Scan
from app.migrate import run_migrations

Base.metadata.create_all(bind=engine)
run_migrations()

app = FastAPI(title="Vulnerability Scanner API")

app.include_router(scan.router)


@app.get("/health")
def health():
    return {"status": "ok"}