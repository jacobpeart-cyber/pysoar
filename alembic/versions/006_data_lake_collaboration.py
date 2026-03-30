"""Data Lake and Collaboration tables.

Revision ID: 006
Revises: 005
Create Date: 2026-03-24 00:00:05.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create data lake and collaboration tables."""

    # Data Lake tables
    op.create_table(
        'data_sources',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('source_name', sa.String(255), nullable=False),
        sa.Column('source_type', sa.String(100), nullable=False),
        sa.Column('connection_config', sa.JSON(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'data_pipelines',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('source_id', sa.String(36), nullable=True),
        sa.Column('pipeline_name', sa.String(255), nullable=False),
        sa.Column('pipeline_config', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('last_run', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['source_id'], ['data_sources.id']),
    )

    op.create_table(
        'unified_data_models',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_name', sa.String(255), nullable=False),
        sa.Column('model_schema', sa.JSON(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'data_partitions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_id', sa.String(36), nullable=True),
        sa.Column('partition_key', sa.String(255), nullable=False),
        sa.Column('partition_value', sa.String(255), nullable=False),
        sa.Column('partition_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['model_id'], ['unified_data_models.id']),
    )

    op.create_table(
        'query_jobs',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_id', sa.String(36), nullable=True),
        sa.Column('query_string', sa.Text(), nullable=False),
        sa.Column('job_status', sa.String(50), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('result_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['model_id'], ['unified_data_models.id']),
    )

    # Collaboration tables
    op.create_table(
        'war_rooms',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('room_name', sa.String(255), nullable=False),
        sa.Column('incident_id', sa.String(36), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id']),
    )

    op.create_table(
        'war_room_messages',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('room_id', sa.String(36), nullable=True),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('message_content', sa.Text(), nullable=False),
        sa.Column('message_type', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['room_id'], ['war_rooms.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )

    op.create_table(
        'action_items',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('room_id', sa.String(36), nullable=True),
        sa.Column('assigned_to', sa.String(36), nullable=True),
        sa.Column('action_title', sa.String(255), nullable=False),
        sa.Column('action_description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('due_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['room_id'], ['war_rooms.id']),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id']),
    )

    op.create_table(
        'shared_artifacts',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('room_id', sa.String(36), nullable=True),
        sa.Column('artifact_name', sa.String(255), nullable=False),
        sa.Column('artifact_type', sa.String(100), nullable=False),
        sa.Column('artifact_url', sa.Text(), nullable=True),
        sa.Column('artifact_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['room_id'], ['war_rooms.id']),
    )

    op.create_table(
        'incident_timeline',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('room_id', sa.String(36), nullable=True),
        sa.Column('event_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('event_description', sa.Text(), nullable=False),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['room_id'], ['war_rooms.id']),
    )

    # Phishing Simulation tables
    op.create_table(
        'phishing_campaigns',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('campaign_name', sa.String(255), nullable=False),
        sa.Column('campaign_type', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'phishing_templates',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('template_name', sa.String(255), nullable=False),
        sa.Column('subject_line', sa.String(255), nullable=False),
        sa.Column('email_body', sa.Text(), nullable=False),
        sa.Column('phishing_url', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'target_groups',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('campaign_id', sa.String(36), nullable=True),
        sa.Column('group_name', sa.String(255), nullable=False),
        sa.Column('target_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['campaign_id'], ['phishing_campaigns.id']),
    )

    op.create_table(
        'campaign_events',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('campaign_id', sa.String(36), nullable=True),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('target_email', sa.String(255), nullable=False),
        sa.Column('event_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('event_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['campaign_id'], ['phishing_campaigns.id']),
    )

    op.create_table(
        'security_awareness_scores',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('campaign_id', sa.String(36), nullable=True),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('assessment_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['campaign_id'], ['phishing_campaigns.id']),
    )


def downgrade() -> None:
    """Drop all data lake and collaboration tables."""
    tables = [
        'security_awareness_scores', 'campaign_events', 'target_groups',
        'phishing_templates', 'phishing_campaigns', 'incident_timeline',
        'shared_artifacts', 'action_items', 'war_room_messages', 'war_rooms',
        'query_jobs', 'data_partitions', 'unified_data_models', 'data_pipelines',
        'data_sources'
    ]
    for table in tables:
        op.drop_table(table)
