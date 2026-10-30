import os
import socket
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
    AsyncEngine
)
from core.config import settings
from core.logger import setup_logger
from db.models import Base

logger = setup_logger("db.session")

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def is_postgres_port_open(host: str, port: int, timeout: float = 0.2) -> bool:
    """Non-blocking probe to verify if PostgreSQL port is active."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def get_database_url() -> str:
    """
    Selects database connection string.
    Connects to PostgreSQL if available, otherwise falls back smoothly to SQLite async.
    """
    postgres_available = is_postgres_port_open(settings.postgres_host, settings.postgres_port, timeout=0.15)
    
    if postgres_available:
        logger.info(f"Connected to PostgreSQL database at {settings.postgres_host}:{settings.postgres_port}")
        return settings.database_url
    else:
        sqlite_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "securathon_audit.db")
        logger.info(f"PostgreSQL port inactive. Using async SQLite fallback at: {sqlite_path}")
        return f"sqlite+aiosqlite:///{sqlite_path}"


async def init_db() -> AsyncEngine:
    """
    Initializes the async database engine, creates tables, and sets up sessionmaker.
    """
    global _engine, _session_factory

    if _engine is not None:
        return _engine

    db_url = get_database_url()
    
    # Engine configuration
    is_sqlite = db_url.startswith("sqlite")
    connect_args = {"check_same_thread": False} if is_sqlite else {}

    _engine = create_async_engine(
        db_url,
        echo=False,
        future=True,
        connect_args=connect_args
    )

    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )

    # Automatically create tables if they do not exist
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Forensic database tables verified / initialized successfully.")

    return _engine


async def close_db():
    """Disposes database connection pool."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Closed forensic database connection pool.")


@asynccontextmanager
async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Provides an asynchronous transactional database session scope."""
    global _session_factory
    if _session_factory is None:
        await init_db()

    assert _session_factory is not None
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

