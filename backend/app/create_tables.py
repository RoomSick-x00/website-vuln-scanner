from app.database import Base, engine
from app.models.scan import Scan

print("Creating tables...")

Base.metadata.create_all(bind=engine)

print("Tables created successfully!")

from backend.app.database import engine, Base
from backend.app.models.scan import Scan

# Create all tables
Base.metadata.create_all(bind=engine)

print("Tables created successfully")