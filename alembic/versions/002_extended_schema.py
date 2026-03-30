"""Extended schema for all module-specific tables.

Revision ID: 002
Revises: 001
Create Date: 2026-03-24 00:00:01.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all extended module tables."""

    # Hunting tables
    op.create_table(
        'hunt_hypotheses',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('hypothesis', sa.Text(), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'hunt_notebooks',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('hypothesis_id', sa.String(36), nullable=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['hypothesis_id'], ['hunt_hypotheses.id']),
    )

    op.create_table(
        'hunt_findings',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('hypothesis_id', sa.String(36), nullable=True),
        sa.Column('finding_description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['hypothesis_id'], ['hunt_hypotheses.id']),
    )

    op.create_table(
        'hunt_templates',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('template_data', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'hunt_sessions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('hypothesis_id', sa.String(36), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['hypothesis_id'], ['hunt_hypotheses.id']),
    )

    # Exposure tables
    op.create_table(
        'exposure_assets',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_name', sa.String(255), nullable=False),
        sa.Column('asset_type', sa.String(100), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('exposure_level', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'exposure_scans',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('scan_name', sa.String(255), nullable=False),
        sa.Column('scan_type', sa.String(100), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'attack_surfaces',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('asset_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('cve_id', sa.String(50), nullable=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'asset_vulnerabilities',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_id', sa.String(36), nullable=True),
        sa.Column('vulnerability_id', sa.String(36), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id']),
    )

    op.create_table(
        'remediation_tickets',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('vulnerability_id', sa.String(36), nullable=True),
        sa.Column('ticket_status', sa.String(50), nullable=False),
        sa.Column('due_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id']),
    )

    # AI/ML tables
    op.create_table(
        'ml_models',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_name', sa.String(255), nullable=False),
        sa.Column('model_type', sa.String(100), nullable=False),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'ai_analyses',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_id', sa.String(36), nullable=True),
        sa.Column('input_data', sa.JSON(), nullable=False),
        sa.Column('output_data', sa.JSON(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['model_id'], ['ml_models.id']),
    )

    op.create_table(
        'threat_predictions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_id', sa.String(36), nullable=True),
        sa.Column('threat_type', sa.String(100), nullable=False),
        sa.Column('probability', sa.Float(), nullable=True),
        sa.Column('predicted_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['model_id'], ['ml_models.id']),
    )

    op.create_table(
        'anomaly_detections',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_id', sa.String(36), nullable=True),
        sa.Column('anomaly_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['model_id'], ['ml_models.id']),
    )

    op.create_table(
        'nl_queries',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('query_text', sa.Text(), nullable=False),
        sa.Column('converted_query', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # UEBA tables
    op.create_table(
        'entity_profiles',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('entity_type', sa.String(50), nullable=False),
        sa.Column('entity_identifier', sa.String(255), nullable=False),
        sa.Column('profile_data', sa.JSON(), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'behavior_baselines',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('entity_id', sa.String(36), nullable=True),
        sa.Column('baseline_data', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['entity_id'], ['entity_profiles.id']),
    )

    op.create_table(
        'behavior_events',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('entity_id', sa.String(36), nullable=True),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('event_data', sa.JSON(), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['entity_id'], ['entity_profiles.id']),
    )

    op.create_table(
        'peer_groups',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('group_name', sa.String(255), nullable=False),
        sa.Column('members', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'ueba_risk_alerts',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('entity_id', sa.String(36), nullable=True),
        sa.Column('risk_type', sa.String(100), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['entity_id'], ['entity_profiles.id']),
    )

    # Simulation tables
    op.create_table(
        'attack_simulations',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('campaign_name', sa.String(255), nullable=False),
        sa.Column('campaign_type', sa.String(100), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'simulation_tests',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('campaign_id', sa.String(36), nullable=True),
        sa.Column('test_name', sa.String(255), nullable=False),
        sa.Column('test_type', sa.String(100), nullable=False),
        sa.Column('result_status', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['campaign_id'], ['attack_simulations.id']),
    )

    op.create_table(
        'attack_techniques',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('mitre_technique_id', sa.String(50), nullable=True),
        sa.Column('technique_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'adversary_profiles',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('profile_name', sa.String(255), nullable=False),
        sa.Column('techniques', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'security_posture_scores',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('campaign_id', sa.String(36), nullable=True),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('assessment_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['campaign_id'], ['attack_simulations.id']),
    )

    # Deception tables
    op.create_table(
        'decoys',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('decoy_name', sa.String(255), nullable=False),
        sa.Column('decoy_type', sa.String(100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'honey_tokens',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('token_value', sa.String(255), nullable=False),
        sa.Column('token_type', sa.String(100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'deception_campaigns',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('campaign_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'decoy_interactions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('decoy_id', sa.String(36), nullable=True),
        sa.Column('interaction_type', sa.String(100), nullable=False),
        sa.Column('interaction_data', sa.JSON(), nullable=True),
        sa.Column('source_ip', sa.String(45), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['decoy_id'], ['decoys.id']),
    )


def downgrade() -> None:
    """Drop all extended tables."""
    tables = [
        'decoy_interactions', 'deception_campaigns', 'honey_tokens', 'decoys',
        'security_posture_scores', 'adversary_profiles', 'attack_techniques',
        'simulation_tests', 'attack_simulations', 'ueba_risk_alerts', 'peer_groups',
        'behavior_events', 'behavior_baselines', 'entity_profiles', 'nl_queries',
        'anomaly_detections', 'threat_predictions', 'ai_analyses', 'ml_models',
        'remediation_tickets', 'asset_vulnerabilities', 'vulnerabilities',
        'attack_surfaces', 'exposure_scans', 'exposure_assets', 'hunt_sessions',
        'hunt_templates', 'hunt_findings', 'hunt_notebooks', 'hunt_hypotheses'
    ]
    for table in tables:
        op.drop_table(table)
