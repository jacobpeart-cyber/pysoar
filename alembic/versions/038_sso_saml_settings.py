"""SAML 2.0 single sign-on: ``sso_configurations.saml_settings``.

Idempotent like 027-037: the column is added only when the table exists and
lacks it (databases whose tables came from ``init_db``'s ``create_all`` may
already have it).

``saml_settings`` (JSON, nullable) holds what a SAML configuration needs beyond
the shared columns (``issuer`` = IdP entity id, ``discovery_url`` = IdP metadata
URL, ``client_id`` = our SP entity id): the IdP single sign-on URL, the IdP
signing certificates (PEM), the NameID format, ``want_response_signed`` and the
allowed clock skew. OIDC rows leave it NULL.

Downgrade drops the column.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "038"
down_revision: Union[str, None] = "037"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "sso_configurations"
COLUMN = "saml_settings"


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    existing = _columns(op.get_bind(), TABLE)
    if existing is not None and COLUMN not in existing:
        with op.batch_alter_table(TABLE) as batch:
            batch.add_column(sa.Column(COLUMN, sa.JSON(), nullable=True))


def downgrade() -> None:
    existing = _columns(op.get_bind(), TABLE)
    if existing is not None and COLUMN in existing:
        with op.batch_alter_table(TABLE) as batch:
            batch.drop_column(COLUMN)
