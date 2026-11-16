from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import settings

_url = settings.DATABASE_URL
_kwargs = {"connect_args": {"check_same_thread": False}} if _url.startswith("sqlite") else {"pool_pre_ping": True}
engine = create_engine(_url, **_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session and closes it afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
