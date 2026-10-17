"""Identity package: SSO configuration, SCIM tokens, custom roles, user identity columns.

Idempotent like 027-036: every step runs only when the table exists and lacks
what it adds (databases whose tables came from ``init_db``'s ``create_all``
may already have them).

1. New tables ``sso_configurations`` (one identity provider per organisation),
   ``scim_tokens`` (hashed provisioning tokens) and ``roles`` (custom roles:
   a default tier plus per-area overrides).
2. ``users`` gains ``custom_role_id`` (FK roles, SET NULL), ``external_id``
   (SCIM externalId), ``identity_source`` (local / oidc / scim, default local)
   and ``sso_subject`` (the OIDC ``sub`` bound at first login), with a unique
   constraint on ``(organization_id, sso_subject)`` and an index on
   ``(organization_id, external_id)``.

Downgrade drops the user columns and the three tables.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "037"
down_revision: Union[str, None] = "036"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

USERS = "users"
USER_SSO_UNIQUE = "uq_users_org_sso_subject"
USER_EXTERNAL_INDEX = "ix_users_org_external_id"
USER_ROLE_INDEX = "ix_users_custom_role_id"
USER_COLUMNS: list[tuple[str, sa.types.TypeEngine, dict]] = [
    ("custom_role_id", sa.String(36), {"nullable": True}),
    ("external_id", sa.String(255), {"nullable": True}),
    ("identity_source", sa.String(20), {"nullable": False, "server_default": "local"}),
    ("sso_subject", sa.String(255), {"nullable": True}),
]


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def _names(bind: sa.engine.Connection, table: str) -> set[str]:
    inspector = sa.inspect(bind)
    names = {ix["name"] for ix in inspector.get_indexes(table) if ix.get("name")}
    names |= {uc["name"] for uc in inspector.get_unique_constraints(table) if uc.get("name")}
    return names


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    bind = op.get_bind()

    if _columns(bind, "roles") is None:
        op.create_table(
            "roles",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("name", sa.String(100), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("default_tier", sa.String(10), nullable=False, server_default="read"),
            sa.Column("area_tiers", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("created_by", sa.String(36), nullable=True),
            *_timestamps(),
            sa.UniqueConstraint("organization_id", "name", name="uq_roles_org_name"),
        )
        op.create_index("ix_roles_organization_id", "roles", ["organization_id"])

    if _columns(bind, "sso_configurations") is None:
        op.create_table(
            "sso_configurations",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("protocol", sa.String(10), nullable=False, server_default="oidc"),
            sa.Column("display_name", sa.String(100), nullable=True),
            sa.Column("issuer", sa.String(500), nullable=False),
            sa.Column("client_id", sa.String(255), nullable=False),
            sa.Column("client_secret", sa.String(2048), nullable=True),
            sa.Column("scopes", sa.String(255), nullable=False, server_default="openid email profile"),
            sa.Column("discovery_url", sa.String(500), nullable=True),
            sa.Column("email_claim", sa.String(100), nullable=False, server_default="email"),
            sa.Column("name_claim", sa.String(100), nullable=False, server_default="name"),
            sa.Column("groups_claim", sa.String(100), nullable=True),
            sa.Column("group_role_map", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("jit_provisioning", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("default_role", sa.String(50), nullable=False, server_default="viewer"),
            sa.Column("allowed_email_domains", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("require_email_verified", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("trust_idp_mfa", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_test_status", sa.String(20), nullable=True),
            sa.Column("last_test_detail", sa.Text(), nullable=True),
            sa.Column("updated_by", sa.String(36), nullable=True),
            *_timestamps(),
            sa.UniqueConstraint("organization_id", name="uq_sso_configurations_organization_id"),
        )
        op.create_index("ix_sso_configurations_organization_id", "sso_configurations", ["organization_id"])

    if _columns(bind, "scim_tokens") is None:
        op.create_table(
            "scim_tokens",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("name", sa.String(100), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False),
            sa.Column("token_prefix", sa.String(12), nullable=False),
            sa.Column("created_by", sa.String(36), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_by", sa.String(36), nullable=True),
            *_timestamps(),
            sa.UniqueConstraint("token_hash", name="uq_scim_tokens_token_hash"),
        )
        op.create_index("ix_scim_tokens_organization_id", "scim_tokens", ["organization_id"])
        op.create_index("ix_scim_tokens_token_hash", "scim_tokens", ["token_hash"])

    existing = _columns(bind, USERS)
    if existing is not None:
        missing = [(name, type_, kw) for name, type_, kw in USER_COLUMNS if name not in existing]
        names = _names(bind, USERS)
        with op.batch_alter_table(USERS) as batch:
            for name, type_, kw in missing:
                batch.add_column(sa.Column(name, type_, **kw))
            if "custom_role_id" in [m[0] for m in missing]:
                batch.create_foreign_key("fk_users_custom_role_id_roles", "roles", ["custom_role_id"], ["id"], ondelete="SET NULL")
            if USER_SSO_UNIQUE not in names:
                batch.create_unique_constraint(USER_SSO_UNIQUE, ["organization_id", "sso_subject"])
        names = _names(bind, USERS)
        if USER_EXTERNAL_INDEX not in names:
            op.create_index(USER_EXTERNAL_INDEX, USERS, ["organization_id", "external_id"])
        if USER_ROLE_INDEX not in names:
            op.create_index(USER_ROLE_INDEX, USERS, ["custom_role_id"])


def downgrade() -> None:
    bind = op.get_bind()
    existing = _columns(bind, USERS)
    if existing is not None:
        names = _names(bind, USERS)
        # The FK is named by upgrade() below, but a users table built by the
        # models' create_all (init_db, or alembic's empty-database bootstrap in
        # env.py) carries the dialect's default name; drop whichever exists.
        role_fks = [
            fk["name"] for fk in sa.inspect(bind).get_foreign_keys(USERS)
            if fk.get("constrained_columns") == ["custom_role_id"] and fk.get("name")
        ]
        for index in (USER_ROLE_INDEX, USER_EXTERNAL_INDEX):
            if index in names:
                op.drop_index(index, table_name=USERS)
        with op.batch_alter_table(USERS) as batch:
            if USER_SSO_UNIQUE in names:
                batch.drop_constraint(USER_SSO_UNIQUE, type_="unique")
            for fk_name in role_fks:
                batch.drop_constraint(fk_name, type_="foreignkey")
            for name, _type, _kw in USER_COLUMNS:
                if name in existing:
                    batch.drop_column(name)
    for table in ("scim_tokens", "sso_configurations", "roles"):
        if _columns(bind, table) is not None:
            op.drop_table(table)
