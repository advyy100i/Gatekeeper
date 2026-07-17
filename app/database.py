"""
Database configuration and connection management.
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Database URL. Defaults to local SQLite; set DATABASE_URL to a Postgres DSN in
# production (managed platforms provide one — see render.yaml / DEPLOYMENT.md).
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./gaas_gateway.db")

# Managed platforms (Render/Railway/Heroku) hand out "postgres://" URLs. Route
# them to the installed psycopg v3 driver via the "postgresql+psycopg://" scheme
# (plain "postgresql://" would select psycopg2, which we don't install).
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

_is_sqlite = DATABASE_URL.startswith("sqlite")

# SQLite needs check_same_thread=False for FastAPI's threadpool; Postgres wants
# pool_pre_ping so dropped managed-DB connections are recycled transparently.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    pool_pre_ping=not _is_sqlite,
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db():
    """
    Dependency function to get database session.
    Yields a database session and ensures it's closed after use.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Initialize the database by creating all tables.
    """
    # Import all models to ensure they're registered with Base.metadata
    # Import at function level to avoid circular imports
    from app.models import Gateway, Route, User, Service, UsageLog, ApiKey, RequestHash, MerkleRoot, AnomalyScoreLog
    from sqlalchemy import inspect, text
    
    Base.metadata.create_all(bind=engine)

    # Legacy in-place column migrations below use SQLite-specific DDL and only
    # matter for pre-existing local SQLite files. On a fresh Postgres database
    # create_all() already produced every column, so skip them entirely.
    if not _is_sqlite:
        return

    # Check if api_key_revealed column exists in users table, add it if missing
    inspector = inspect(engine)
    if 'users' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('users')]
        if 'api_key_revealed' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN api_key_revealed BOOLEAN DEFAULT 0"))
                conn.commit()
    
    # ApiKey table is created automatically by Base.metadata.create_all
    # Existing User.api_key entries will continue to work via backward compatibility in get_current_user
    
    # Check if new rate limit override columns exist in api_keys table, add them if missing
    if 'api_keys' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('api_keys')]
        if 'rate_limit_requests' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE api_keys ADD COLUMN rate_limit_requests INTEGER"))
                conn.commit()
        if 'rate_limit_window_seconds' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE api_keys ADD COLUMN rate_limit_window_seconds INTEGER"))
                conn.commit()
        # Check if new billing columns exist in api_keys table, add them if missing
        if 'price_per_request' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE api_keys ADD COLUMN price_per_request REAL DEFAULT 0.001"))
                conn.commit()
        if 'total_cost' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE api_keys ADD COLUMN total_cost REAL DEFAULT 0.0"))
                conn.commit()

    # Check if watermarking_enabled column exists in services table, add it if missing
    if 'services' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('services')]
        if 'watermarking_enabled' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE services ADD COLUMN watermarking_enabled BOOLEAN DEFAULT 0"))
                conn.commit()
    # Check if blockchain anchoring columns exist in merkle_roots table, add them if missing
    if 'merkle_roots' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('merkle_roots')]
        if 'is_anchored' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE merkle_roots ADD COLUMN is_anchored BOOLEAN DEFAULT 0"))
                conn.commit()
        if 'tx_hash' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE merkle_roots ADD COLUMN tx_hash TEXT"))
                conn.commit()
        if 'block_number' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE merkle_roots ADD COLUMN block_number INTEGER"))
                conn.commit()
        if 'anchored_at' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE merkle_roots ADD COLUMN anchored_at TIMESTAMP"))
                conn.commit()
