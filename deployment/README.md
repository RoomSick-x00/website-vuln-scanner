# Railway Deployment

Deploy this project as separate Railway services from the same GitHub repo.
Do not deploy `deployment/docker-compose.yml` directly.

## Services

Create these Railway services:

- PostgreSQL database
- Redis database
- Backend web service
- Celery worker service
- Frontend web service

## Backend Service

Use this Dockerfile path:

```text
deployment/DockerFile.backend
```

Required variables:

```text
DATABASE_URL=<Railway Postgres DATABASE_URL>
REDIS_URL=<Railway Redis REDIS_URL>
```

Expose the backend publicly. The container listens on Railway's `PORT`.

## Worker Service

Use this Dockerfile path:

```text
deployment/Dockerfile.worker
```

Required variables:

```text
DATABASE_URL=<Railway Postgres DATABASE_URL>
REDIS_URL=<Railway Redis REDIS_URL>
CELERY_BROKER_URL=<Railway Redis REDIS_URL>
CELERY_RESULT_BACKEND=<Railway Redis REDIS_URL>
```

The worker is a private/background service and does not need a public domain.

## Frontend Service

Use this Dockerfile path:

```text
deployment/Dockerfile.frontend
```

Required variables:

```text
BACKEND_URL=https://<your-backend-service>.up.railway.app
FLASK_DEBUG=false
```

Expose the frontend publicly. The container listens on Railway's `PORT`.

## Notes

- Keep `.env` out of Git. Use Railway variables instead.
- Add the Redis and Postgres variables to both backend and worker.
- Full/XSS scans require the domain TXT verification record before tasks are queued.

## Security Hardening

The frontend and backend set these application headers in code:

```text
Content-Security-Policy
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cache-Control: no-store
Permissions-Policy: camera=(), microphone=(), geolocation=()
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-Permitted-Cross-Domain-Policies: none
Origin-Agent-Cluster: ?1
Referrer-Policy: no-referrer
```

`Clear-Site-Data: "*"` is intentionally only returned from the frontend `/logout` endpoint. Do not set it globally, because it clears browser storage on every response.

Some findings must be handled at the hosting or DNS layer:

- TLS forward secrecy: Railway terminates public HTTPS before traffic reaches the container. Use Railway's managed TLS, or put Cloudflare/nginx in front and prefer TLS 1.3 plus ECDHE suites for TLS 1.2.
- Server header: the backend starts Uvicorn with `--no-server-header`. If Railway or another proxy still adds `Server`, hide or genericise it at that proxy. For nginx use `server_tokens off;`.
- SPF: add a TXT record on the root domain, for example `v=spf1 include:_spf.google.com -all` if Google Workspace sends your mail. Replace the include with your actual mail provider.
- DMARC: add TXT `_dmarc` with a policy such as `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com`. Move to `p=reject` after monitoring legitimate mail.
- DNSSEC: enable DNSSEC at your DNS provider, then add the DS record at your registrar if they are separate services.
- CAA: add a CAA record limiting certificate issuance, for example `0 issue "letsencrypt.org"` if Let's Encrypt is your only CA.
