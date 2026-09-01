# wiperx/web/db.py
"""
Database Layer
---------------
SQLAlchemy engine/session setup for the (optional) persistent backend.

Zero-config behavior is unchanged: with no DATABASE_URL set, the app runs
exactly as before, entirely in-memory (see web/models.py's fallback path).
Set DATABASE_URL to opt into persistence:

    DATABASE_URL=sqlite:////absolute/path/to/wiperx.db      (file-based, no server)
    DATABASE_URL=postgresql+psycopg2://user:pass@host/dbname (production)

init_db() creates tables if missing (Base.metadata.create_all - fine for
this scope; a real deployment tracking schema changes over time should
move to Alembic migrations instead of relying on create_all).
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger(__name__)

Base = declarative_base()

_engine = None
_SessionLocal: Optional[sessionmaker] = None


def is_db_enabled() -> bool:
    """True once init_db() has successfully set up a session factory."""
    return _SessionLocal is not None


def init_db(database_url: Optional[str] = None):
    """
    Initialize the DB engine/session factory and create tables if absent.

    Args:
        database_url : Override for DATABASE_URL (mainly for tests). If
                        neither this nor the env var is set, the function
                        is a no-op and is_db_enabled() stays False - the
                        app falls back to the in-memory stores.

    Returns:
        The SQLAlchemy Engine, or None if no database_url was configured.
    """
    global _engine, _SessionLocal

    url = database_url or os.environ.get("DATABASE_URL")
    if not url:
        logger.info("[db] DATABASE_URL not set - using in-memory stores")
        return None

    # web.db_models must be imported before create_all so its tables are
    # registered on Base.metadata.
    from web import db_models  # noqa: F401

    engine = create_engine(url, pool_pre_ping=True, future=True)
    Base.metadata.create_all(engine)

    _engine = engine
    _SessionLocal = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    logger.info("[db] initialized against %s", _safe_url(url))
    return engine


def reset_db_state_for_tests() -> None:
    """Undo init_db() - used only by the test suite between cases."""
    global _engine, _SessionLocal
    _engine = None
    _SessionLocal = None


def get_session():
    """
    Open a new Session. Caller is responsible for closing it (use as a
    context manager: `with get_session() as session: ...`).

    Raises:
        RuntimeError : if init_db() was never called / no DATABASE_URL.
    """
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized - call init_db() or set DATABASE_URL")
    return _SessionLocal()


def _safe_url(url: str) -> str:
    """Redact a password from a DB URL before logging it."""
    if "://" not in url or "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    creds, host = rest.split("@", 1)
    user = creds.split(":", 1)[0]
    return f"{scheme}://{user}:***@{host}"
