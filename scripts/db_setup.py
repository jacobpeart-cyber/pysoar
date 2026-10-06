#!/usr/bin/env python
"""Database setup and migration script for PySOAR.

Usage:
    python scripts/db_setup.py                # Run migrations only
    python scripts/db_setup.py --drop         # Drop all tables (be careful!)
"""

import asyncio
import sys
from pathlib import Path
from argparse import ArgumentParser

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.runtime.migration import MigrationContext
from src.core.config import settings
from src.models.base import Base


def get_alembic_config() -> Config:
    """Create Alembic configuration."""
    alembic_cfg = Config(str(project_root / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", settings.database_url)
    return alembic_cfg


async def create_database() -> None:
    """Create database if it doesn't exist."""
    print("Checking database connectivity...")
    try:
        engine = create_async_engine(settings.database_url, echo=False)
        async with engine.begin() as conn:
            await conn.execute(sa.text("SELECT 1"))
        await engine.dispose()
        print("✓ Database connection successful")
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        raise


async def run_migrations_async() -> None:
    """Run Alembic migrations using async engine."""
    print("\nRunning migrations...")

    engine = create_async_engine(settings.database_url, echo=False)

    async with engine.begin() as connection:
        # Create migration context
        def do_run_migrations(connection):
            ctx = MigrationContext.configure(connection)
            cfg = get_alembic_config()
            script = ScriptDirectory.from_config(cfg)

            def process_revision_directives(context, revision, directives):
                if getattr(context.config.cmd_opts, 'autogenerate', False):
                    script = directives[0]
                    if script.upgrade_ops.is_empty():
                        directives[:] = []
                        return

            ctx.configure(
                connection=connection,
                target_metadata=Base.metadata,
                process_revision_directives=process_revision_directives,
            )

            with ctx.begin_transaction():
                ctx.run_migrations()

        await connection.run_sync(do_run_migrations)

    await engine.dispose()
    print("✓ Migrations completed successfully")


def run_migrations() -> None:
    """Run Alembic migrations synchronously."""
    print("\nRunning migrations...")
    try:
        alembic_cfg = get_alembic_config()
        command_args = type('obj', (object,), {
            'autogenerate': False,
            'message': None,
            'sql': False,
            'tag': None,
            'rev_range': None,
        })()
        alembic_cfg.cmd_opts = command_args

        from alembic.command import upgrade
        upgrade(alembic_cfg, "head")
        print("✓ Migrations completed successfully")
    except Exception as e:
        print(f"✗ Migration failed: {e}")
        raise


async def drop_all_tables() -> None:
    """Drop all tables from database."""
    print("\nDropping all tables...")

    engine = create_async_engine(settings.database_url, echo=False)

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)

    await engine.dispose()
    print("✓ All tables dropped successfully")


def main() -> None:
    """Main entry point."""
    parser = ArgumentParser(description="PySOAR Database Setup")
    parser.add_argument(
        "--drop",
        action="store_true",
        help="Drop all tables from database (DANGEROUS!)"
    )

    args = parser.parse_args()

    try:
        # Check database connectivity
        asyncio.run(create_database())

        # Drop tables if requested
        if args.drop:
            confirm = input("\n⚠️  WARNING: This will delete ALL data! Type 'yes' to confirm: ")
            if confirm.lower() == "yes":
                asyncio.run(drop_all_tables())
            else:
                print("Cancelled.")
                return

        # Run migrations
        run_migrations()

        print("\n✓ Database setup completed successfully!")
        print("\nNext steps:")
        print("  1. Configure your environment variables in .env")
        print("  2. Start the application: uvicorn src.main:app --reload")
        print("  3. Access API docs at http://localhost:8000/docs")

    except Exception as e:
        print(f"\n✗ Setup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
