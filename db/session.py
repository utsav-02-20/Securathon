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
    - If DATABASE_URL is set, uses it directly (falls back to SQLite if PostgreSQL fails).
    - If DB_TYPE is 'postgres', connects to PostgreSQL if port is active.
    - Otherwise defaults cleanly to fast zero-config async SQLite.
    """
    sqlite_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "securathon_audit.db")
    default_sqlite_url = f"sqlite+aiosqlite:///{sqlite_path}"

    # 1. Explicit DATABASE_URL in .env
    if settings.database_url:
        db_url = settings.database_url
        if db_url.startswith("sqlite"):
            logger.info("Using configured SQLite database from DATABASE_URL.")
            return db_url
        elif db_url.startswith("postgres"):
            if is_postgres_port_open(settings.postgres_host, settings.postgres_port, timeout=0.15):
                logger.info(f"Connecting to PostgreSQL database: {settings.postgres_host}:{settings.postgres_port}")
                return db_url
            else:
                logger.warning(f"PostgreSQL port inactive. Falling back to SQLite at: {sqlite_path}")
                return default_sqlite_url
        return db_url

    # 2. Check DB_TYPE setting
    if settings.db_type.lower() in ("postgres", "postgresql"):
        if is_postgres_port_open(settings.postgres_host, settings.postgres_port, timeout=0.15):
            url = f"postgresql+asyncpg://{settings.postgres_user}:{settings.postgres_password}@{settings.postgres_host}:{settings.postgres_port}/{settings.postgres_db}"
            logger.info(f"Connected to PostgreSQL database at {settings.postgres_host}:{settings.postgres_port}")
            return url
        else:
            logger.warning(f"PostgreSQL requested but port inactive. Falling back to SQLite at: {sqlite_path}")
            return default_sqlite_url

    # 3. Default to zero-config SQLite
    logger.info(f"Using zero-config async SQLite database: {sqlite_path}")
    return default_sqlite_url



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

    try:
        engine = create_async_engine(
            db_url,
            echo=False,
            future=True,
            connect_args=connect_args
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        _engine = engine
        _session_factory = async_sessionmaker(
            bind=_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        logger.info("Forensic database tables verified / initialized successfully.")
        return _engine
    except Exception as e:
        if not is_sqlite:
            logger.warning(f"PostgreSQL connection failed ({e}). Falling back to SQLite...")
            sqlite_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "securathon_audit.db")
            sqlite_url = f"sqlite+aiosqlite:///{sqlite_path}"
            _engine = create_async_engine(
                sqlite_url,
                echo=False,
                future=True,
                connect_args={"check_same_thread": False}
            )
            _session_factory = async_sessionmaker(
                bind=_engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            async with _engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Forensic database tables initialized on SQLite fallback.")
            return _engine
        raise

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

