"""Remaining module-specific tables.

Revision ID: 004
Revises: 003
Create Date: 2026-03-24 00:00:03.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create remaining module tables."""

    # ITDR tables
    op.create_table(
        'identity_threats',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('threat_type', sa.String(100), nullable=False),
        sa.Column('threat_description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'credential_monitors',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('monitor_name', sa.String(255), nullable=False),
        sa.Column('source', sa.String(100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'privileged_access_events',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('access_type', sa.String(100), nullable=False),
        sa.Column('resource', sa.String(255), nullable=False),
        sa.Column('event_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )

    op.create_table(
        'credential_exposures',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('credential_type', sa.String(100), nullable=False),
        sa.Column('exposed_value', sa.String(255), nullable=False),
        sa.Column('source', sa.String(100), nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'access_anomalies',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('anomaly_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )

    op.create_table(
        'identity_profiles',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('profile_data', sa.JSON(), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )

    # Vulnerability Management tables
    op.create_table(
        'vulnerability_instances',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_id', sa.String(36), nullable=True),
        sa.Column('vulnerability_id', sa.String(36), nullable=True),
        sa.Column('instance_status', sa.String(50), nullable=False),
        sa.Column('detected_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
    )

    op.create_table(
        'vulnerability_exceptions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('vulnerability_id', sa.String(36), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('exception_status', sa.String(50), nullable=False),
        sa.Column('expiration_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'scan_profiles',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('profile_name', sa.String(255), nullable=False),
        sa.Column('scan_type', sa.String(100), nullable=False),
        sa.Column('configuration', sa.JSON(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'patch_operations',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_id', sa.String(36), nullable=True),
        sa.Column('patch_name', sa.String(255), nullable=False),
        sa.Column('patch_status', sa.String(50), nullable=False),
        sa.Column('deployment_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
    )

    # Supply Chain tables
    op.create_table(
        'sboms',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('application_name', sa.String(255), nullable=False),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('sbom_format', sa.String(50), nullable=True),
        sa.Column('generated_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'sbom_components',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('sbom_id', sa.String(36), nullable=True),
        sa.Column('component_name', sa.String(255), nullable=False),
        sa.Column('component_version', sa.String(50), nullable=True),
        sa.Column('component_type', sa.String(100), nullable=False),
        sa.Column('license', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['sbom_id'], ['sboms.id']),
    )

    op.create_table(
        'software_components',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('component_name', sa.String(255), nullable=False),
        sa.Column('component_type', sa.String(100), nullable=False),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('vendor', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'supply_chain_risks',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('component_id', sa.String(36), nullable=True),
        sa.Column('risk_type', sa.String(100), nullable=False),
        sa.Column('risk_description', sa.Text(), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'vendor_assessments',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('vendor_name', sa.String(255), nullable=False),
        sa.Column('assessment_type', sa.String(100), nullable=False),
        sa.Column('assessment_result', sa.String(50), nullable=True),
        sa.Column('assessment_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # Dark Web tables
    op.create_table(
        'darkweb_monitors',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('monitor_name', sa.String(255), nullable=False),
        sa.Column('monitor_type', sa.String(100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'darkweb_findings',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('monitor_id', sa.String(36), nullable=True),
        sa.Column('finding_title', sa.String(255), nullable=False),
        sa.Column('finding_description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(50), nullable=True),
        sa.Column('discovered_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['monitor_id'], ['darkweb_monitors.id']),
    )

    op.create_table(
        'darkweb_credential_leaks',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('credential_type', sa.String(100), nullable=False),
        sa.Column('leaked_data', sa.String(255), nullable=False),
        sa.Column('source', sa.String(100), nullable=True),
        sa.Column('discovered_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'darkweb_brand_threats',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('brand_name', sa.String(255), nullable=False),
        sa.Column('threat_description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(50), nullable=True),
        sa.Column('discovered_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # Integration tables
    op.create_table(
        'integration_connectors',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('connector_name', sa.String(255), nullable=False),
        sa.Column('connector_type', sa.String(100), nullable=False),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'installed_integrations',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('connector_id', sa.String(36), nullable=True),
        sa.Column('instance_name', sa.String(255), nullable=False),
        sa.Column('configuration', sa.JSON(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['connector_id'], ['integration_connectors.id']),
    )

    op.create_table(
        'integration_actions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('connector_id', sa.String(36), nullable=True),
        sa.Column('action_name', sa.String(255), nullable=False),
        sa.Column('action_description', sa.Text(), nullable=True),
        sa.Column('action_type', sa.String(100), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['connector_id'], ['integration_connectors.id']),
    )

    op.create_table(
        'integration_executions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('action_id', sa.String(36), nullable=True),
        sa.Column('execution_status', sa.String(50), nullable=False),
        sa.Column('input_data', sa.JSON(), nullable=True),
        sa.Column('output_data', sa.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['action_id'], ['integration_actions.id']),
    )

    op.create_table(
        'webhook_endpoints',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('integration_id', sa.String(36), nullable=True),
        sa.Column('endpoint_url', sa.Text(), nullable=False),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['integration_id'], ['installed_integrations.id']),
    )

    # Agentic tables
    op.create_table(
        'soc_agents',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('agent_name', sa.String(255), nullable=False),
        sa.Column('agent_type', sa.String(100), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'investigations',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('agent_id', sa.String(36), nullable=True),
        sa.Column('investigation_title', sa.String(255), nullable=False),
        sa.Column('investigation_status', sa.String(50), nullable=False),
        sa.Column('findings', sa.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['agent_id'], ['soc_agents.id']),
    )

    op.create_table(
        'reasoning_steps',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('investigation_id', sa.String(36), nullable=True),
        sa.Column('step_number', sa.Integer(), nullable=False),
        sa.Column('reasoning', sa.Text(), nullable=False),
        sa.Column('conclusion', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id']),
    )

    op.create_table(
        'agent_actions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('agent_id', sa.String(36), nullable=True),
        sa.Column('action_name', sa.String(255), nullable=False),
        sa.Column('action_description', sa.Text(), nullable=True),
        sa.Column('action_result', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['agent_id'], ['soc_agents.id']),
    )

    op.create_table(
        'agent_memories',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('agent_id', sa.String(36), nullable=True),
        sa.Column('memory_type', sa.String(100), nullable=False),
        sa.Column('memory_content', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['agent_id'], ['soc_agents.id']),
    )


def downgrade() -> None:
    """Drop all remaining tables."""
    tables = [
        'agent_memories', 'agent_actions', 'reasoning_steps', 'investigations',
        'soc_agents', 'webhook_endpoints', 'integration_executions',
        'integration_actions', 'installed_integrations', 'integration_connectors',
        'darkweb_brand_threats', 'darkweb_credential_leaks', 'darkweb_findings',
        'darkweb_monitors', 'vendor_assessments', 'supply_chain_risks',
        'software_components', 'sbom_components', 'sboms', 'patch_operations',
        'scan_profiles', 'vulnerability_exceptions', 'vulnerability_instances',
        'identity_profiles', 'access_anomalies', 'credential_exposures',
        'privileged_access_events', 'credential_monitors', 'identity_threats'
    ]
    for table in tables:
        op.drop_table(table)
