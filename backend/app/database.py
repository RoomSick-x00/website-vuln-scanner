import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# DATABASE_URL is set via environment variable.
# Local: set $env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/scanner_db" in terminal
# Docker: set via docker-compose.yml e.g. DATABASE_URL=postgresql://postgres:aarsh@db:5432/scanner_db
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/scanner_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()