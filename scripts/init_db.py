"""
Run this once to manually create tables:
    python scripts/init_db.py
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database.connection import engine
from app.database.models import Base
from app.utils.logger import setup_logging, get_logger

setup_logging()
logger = get_logger("init_db")


def init():
    logger.info("Creating all database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("All tables created successfully.")
    
    # Print table names for confirmation
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    logger.info("Tables in database", tables=tables)


if __name__ == "__main__":
    init()
