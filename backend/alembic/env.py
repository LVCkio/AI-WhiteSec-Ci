"""Alembic environment — wired to the app's SQLAlchemy models.

DATABASE_URL is read from the environment variable (or .env via pydantic-settings)
so that the same env.py works in Docker, local dev, and CI without modification.

Usage:
    # Generate a new revision from current models:
    alembic revision --autogenerate -m "add column x"

    # Apply all pending migrations:
    alembic upgrade head

    # Roll back one step:
    alembic downgrade -1
"""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# ---------------------------------------------------------------------------
# Make sure the backend package is importable when running alembic from the
# backend/ directory (its parent is the project root).
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent.parent  # backend/
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from app.database import Base  # noqa: E402  (after sys.path fix)
import app.models  # noqa: F401, E402  (registers models on Base.metadata)

# Alembic Config object provided by the CLI.
config = context.config

# Set up Python logging from alembic.ini.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Point autogenerate at all registered models.
target_metadata = Base.metadata

# ---------------------------------------------------------------------------
# Override sqlalchemy.url from the environment so .env takes precedence over
# the placeholder in alembic.ini.
# ---------------------------------------------------------------------------
_db_url = os.getenv("DATABASE_URL", "")
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)


# ---------------------------------------------------------------------------
# Migration runners
# ---------------------------------------------------------------------------

def run_migrations_offline() -> None:
    """Emit SQL to stdout without a live database connection."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
