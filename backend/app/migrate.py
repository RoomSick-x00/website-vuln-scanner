from sqlalchemy import text
from app.database import engine


def run_migrations():
    statements = [
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_mode VARCHAR DEFAULT 'quick'",
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS verification_token VARCHAR",
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE",
        "UPDATE scans SET scan_mode = COALESCE(scan_type, 'quick') WHERE scan_mode IS NULL",
    ]
    with engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))
