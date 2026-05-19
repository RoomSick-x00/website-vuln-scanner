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
