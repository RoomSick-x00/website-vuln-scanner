from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from app.routers import scan
from app.database import Base, engine
from app.models.scan import Scan
from app.migrate import run_migrations

Base.metadata.create_all(bind=engine)
run_migrations()

app = FastAPI(title="Vulnerability Scanner API")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'"
        )
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Origin-Agent-Cluster"] = "?1"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers.pop("Server", None)
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.include_router(scan.router)


@app.get("/health")
def health():
    return {"status": "ok"}
