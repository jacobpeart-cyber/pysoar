#!/usr/bin/env python
"""Database setup and migration script for PySOAR.

Usage:
    python scripts/db_setup.py                # Run migrations only
    python scripts/db_setup.py --seed         # Run migrations and seed demo data
    python scripts/db_setup.py --drop         # Drop all tables (be careful!)
"""

import asyncio
import sys
from pathlib import Path
from argparse import ArgumentParser
from datetime import datetime, timezone
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.runtime.migration import MigrationContext
from alembic.operations import Operations
from src.core.config import settings
from src.models.base import Base
from src.models.user import User, UserRole
from src.models.organization import Organization, OrganizationMember
from src.models.alert import Alert


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


async def seed_demo_data() -> None:
    """Seed demo data into the database."""
    print("\nSeeding demo data...")

    engine = create_async_engine(settings.database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        try:
            # Create default organization
            org = Organization(
                id=str(uuid4()),
                name="Default Organization",
                description="Default organization for PySOAR",
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(org)
            await session.flush()

            # Create admin user
            admin_user = User(
                id=str(uuid4()),
                email=settings.first_admin_email,
                hashed_password=settings.first_admin_password,  # In production, this should be hashed
                full_name="Admin User",
                role=UserRole.ADMIN.value,
                is_active=True,
                is_superuser=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(admin_user)
            await session.flush()

            # Add admin to organization
            org_member = OrganizationMember(
                id=str(uuid4()),
                organization_id=org.id,
                user_id=admin_user.id,
                role="admin",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(org_member)

            # Create sample analyst user
            analyst_user = User(
                id=str(uuid4()),
                email="analyst@pysoar.local",
                hashed_password="changeme123",
                full_name="Security Analyst",
                role=UserRole.ANALYST.value,
                is_active=True,
                is_superuser=False,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(analyst_user)
            await session.flush()

            # Add analyst to organization
            analyst_member = OrganizationMember(
                id=str(uuid4()),
                organization_id=org.id,
                user_id=analyst_user.id,
                role="analyst",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(analyst_member)

            # Create sample viewer user
            viewer_user = User(
                id=str(uuid4()),
                email="viewer@pysoar.local",
                hashed_password="changeme123",
                full_name="SOC Viewer",
                role=UserRole.VIEWER.value,
                is_active=True,
                is_superuser=False,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(viewer_user)
            await session.flush()

            # Add viewer to organization
            viewer_member = OrganizationMember(
                id=str(uuid4()),
                organization_id=org.id,
                user_id=viewer_user.id,
                role="viewer",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(viewer_member)

            # Create sample alerts
            for i in range(3):
                alert = Alert(
                    id=str(uuid4()),
                    title=f"Sample Alert {i+1}",
                    description=f"This is a sample alert for testing purposes {i+1}",
                    severity="medium" if i == 0 else "low" if i == 1 else "high",
                    status="open",
                    source="sample",
                    assigned_to=analyst_user.id if i == 0 else None,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                session.add(alert)

            await session.commit()
            print("✓ Demo data seeded successfully")
            print(f"  - Organization: Default Organization")
            print(f"  - Admin User: {settings.first_admin_email}")
            print(f"  - Analyst User: analyst@pysoar.local")
            print(f"  - Viewer User: viewer@pysoar.local")
            print(f"  - Sample Alerts: 3")
        except Exception as e:
            await session.rollback()
            print(f"✗ Failed to seed demo data: {e}")
            raise

    await engine.dispose()


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
        "--seed",
        action="store_true",
        help="Seed demo data after running migrations"
    )
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

        # Seed demo data if requested
        if args.seed:
            asyncio.run(seed_demo_data())

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
