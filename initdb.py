# initdb.py
from models import Base
from database import engine

# Create tables in the database
Base.metadata.create_all(bind=engine)

print("Database tables created successfully!")