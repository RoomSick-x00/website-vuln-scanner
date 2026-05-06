from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.routers import scan

app = FastAPI(title="Vulnerability Scanner API")

app.include_router(scan.router)


@app.get("/health")
def health():
    return {"status": "ok"}

    from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)