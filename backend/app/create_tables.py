from backend.app.database import engine, Base

# Import models so SQLAlchemy can detect them
from backend.app.models.scan import Scan

print("Creating tables...")

Base.metadata.create_all(bind=engine)

print("Tables created successfully!")

from backend.app.database import engine, Base
from backend.app.models.scan import Scan

# Create all tables
Base.metadata.create_all(bind=engine)

print("Tables created successfully")