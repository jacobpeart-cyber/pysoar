"""PySOAR Agent Platform — endpoint_agents, agent_commands, agent_results, agent_heartbeats.

Revision ID: 012
Revises: 011
Create Date: 2026-04-11

Introduces the unified endpoint agent platform that carries Breach &
Attack Simulation execution, Live Response / incident containment, and
Purple Team exercises. See ``src/agents/capabilities.py`` for the
capability/action enforcement model and ``src/agents/service.py`` for
the hash-chained audit trail.
"""

from alembic import op
import sqlalchemy as sa


revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "endpoint_agents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("os_type", sa.String(32), nullable=True),
        sa.Column("os_version", sa.String(128), nullable=True),
        sa.Column("agent_version", sa.String(32), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=True),
        sa.Column("enrollment_token_hash", sa.String(128), nullable=True),
        sa.Column("enrollment_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_command_hash", sa.String(64), nullable=True),
        sa.Column(
            "enrolled_by",
            sa.String(36),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id"),
            nullable=True,
        ),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("extra_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_endpoint_agents_hostname", "endpoint_agents", ["hostname"])
    op.create_index("ix_endpoint_agents_status", "endpoint_agents", ["status"])
    op.create_index("ix_endpoint_agents_token_hash", "endpoint_agents", ["token_hash"])
    op.create_index("ix_endpoint_agents_organization_id", "endpoint_agents", ["organization_id"])

    op.create_table(
        "agent_commands",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("endpoint_agents.id"), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("command_hash", sa.String(64), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=True),
        sa.Column("chain_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("simulation_id", sa.String(36), nullable=True),
        sa.Column("incident_id", sa.String(36), nullable=True),
        sa.Column("approval_required", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("approved_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approval_reason", sa.Text(), nullable=True),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("issued_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_agent_commands_agent_id", "agent_commands", ["agent_id"])
    op.create_index("ix_agent_commands_action", "agent_commands", ["action"])
    op.create_index("ix_agent_commands_status", "agent_commands", ["status"])
    op.create_index("ix_agent_commands_command_hash", "agent_commands", ["command_hash"])
    op.create_index("ix_agent_commands_agent_status", "agent_commands", ["agent_id", "status"])
    op.create_index("ix_agent_commands_simulation_id", "agent_commands", ["simulation_id"])
    op.create_index("ix_agent_commands_incident_id", "agent_commands", ["incident_id"])

    op.create_table(
        "agent_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "command_id",
            sa.String(36),
            sa.ForeignKey("agent_commands.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("endpoint_agents.id"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("stdout", sa.Text(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("artifacts", sa.JSON(), nullable=False),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_agent_results_command_id", "agent_results", ["command_id"])
    op.create_index("ix_agent_results_agent_id", "agent_results", ["agent_id"])

    op.create_table(
        "agent_heartbeats",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("endpoint_agents.id"), nullable=False),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("telemetry", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_agent_heartbeats_agent_id", "agent_heartbeats", ["agent_id"])


def downgrade() -> None:
    op.drop_index("ix_agent_heartbeats_agent_id", table_name="agent_heartbeats")
    op.drop_table("agent_heartbeats")

    op.drop_index("ix_agent_results_agent_id", table_name="agent_results")
    op.drop_index("ix_agent_results_command_id", table_name="agent_results")
    op.drop_table("agent_results")

    op.drop_index("ix_agent_commands_incident_id", table_name="agent_commands")
    op.drop_index("ix_agent_commands_simulation_id", table_name="agent_commands")
    op.drop_index("ix_agent_commands_agent_status", table_name="agent_commands")
    op.drop_index("ix_agent_commands_command_hash", table_name="agent_commands")
    op.drop_index("ix_agent_commands_status", table_name="agent_commands")
    op.drop_index("ix_agent_commands_action", table_name="agent_commands")
    op.drop_index("ix_agent_commands_agent_id", table_name="agent_commands")
    op.drop_table("agent_commands")

    op.drop_index("ix_endpoint_agents_organization_id", table_name="endpoint_agents")
    op.drop_index("ix_endpoint_agents_token_hash", table_name="endpoint_agents")
    op.drop_index("ix_endpoint_agents_status", table_name="endpoint_agents")
    op.drop_index("ix_endpoint_agents_hostname", table_name="endpoint_agents")
    op.drop_table("endpoint_agents")
