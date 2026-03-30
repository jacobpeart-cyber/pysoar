"""Final module-specific tables.

Revision ID: 005
Revises: 004
Create Date: 2026-03-24 00:00:04.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create final module tables."""

    # Playbook Builder tables
    op.create_table(
        'visual_playbooks',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('playbook_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('playbook_data', sa.JSON(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'playbook_nodes',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('playbook_id', sa.String(36), nullable=True),
        sa.Column('node_name', sa.String(255), nullable=False),
        sa.Column('node_type', sa.String(100), nullable=False),
        sa.Column('node_config', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['playbook_id'], ['visual_playbooks.id']),
    )

    op.create_table(
        'playbook_edges',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('playbook_id', sa.String(36), nullable=True),
        sa.Column('source_node_id', sa.String(36), nullable=False),
        sa.Column('target_node_id', sa.String(36), nullable=False),
        sa.Column('edge_condition', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['playbook_id'], ['visual_playbooks.id']),
    )

    op.create_table(
        'playbook_node_executions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('node_id', sa.String(36), nullable=True),
        sa.Column('execution_status', sa.String(50), nullable=False),
        sa.Column('input_data', sa.JSON(), nullable=True),
        sa.Column('output_data', sa.JSON(), nullable=True),
        sa.Column('execution_time', sa.Integer(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['node_id'], ['playbook_nodes.id']),
    )

    # DLP tables
    op.create_table(
        'dlp_policies',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('policy_name', sa.String(255), nullable=False),
        sa.Column('policy_description', sa.Text(), nullable=True),
        sa.Column('rules', sa.JSON(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'data_classifications',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('classification_level', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'dlp_incidents',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('policy_id', sa.String(36), nullable=True),
        sa.Column('incident_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('incident_status', sa.String(50), nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['policy_id'], ['dlp_policies.id']),
    )

    op.create_table(
        'dlp_violations',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('incident_id', sa.String(36), nullable=True),
        sa.Column('violation_type', sa.String(100), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('remediation_status', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['incident_id'], ['dlp_incidents.id']),
    )

    op.create_table(
        'sensitive_data_discoveries',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('data_type', sa.String(100), nullable=False),
        sa.Column('location', sa.String(255), nullable=False),
        sa.Column('discovery_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('classification', sa.String(100), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # Risk Quantification tables
    op.create_table(
        'risk_scenarios',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('scenario_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('probability', sa.Float(), nullable=True),
        sa.Column('impact', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'fair_analyses',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('scenario_id', sa.String(36), nullable=True),
        sa.Column('analysis_name', sa.String(255), nullable=False),
        sa.Column('analysis_results', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['scenario_id'], ['risk_scenarios.id']),
    )

    op.create_table(
        'risk_controls',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('scenario_id', sa.String(36), nullable=True),
        sa.Column('control_name', sa.String(255), nullable=False),
        sa.Column('control_type', sa.String(100), nullable=False),
        sa.Column('effectiveness', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['scenario_id'], ['risk_scenarios.id']),
    )

    op.create_table(
        'risk_registers',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('register_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('risk_data', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'business_impact_assessments',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('assessment_name', sa.String(255), nullable=False),
        sa.Column('business_function', sa.String(255), nullable=False),
        sa.Column('impact_analysis', sa.JSON(), nullable=False),
        sa.Column('assessment_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # OT/ICS tables
    op.create_table(
        'ot_assets',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_name', sa.String(255), nullable=False),
        sa.Column('asset_type', sa.String(100), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('network_segment', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'ot_zones',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('zone_name', sa.String(255), nullable=False),
        sa.Column('zone_description', sa.Text(), nullable=True),
        sa.Column('zone_type', sa.String(100), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'ot_alerts',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_id', sa.String(36), nullable=True),
        sa.Column('alert_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('alert_description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['ot_assets.id']),
    )

    op.create_table(
        'ot_incidents',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_id', sa.String(36), nullable=True),
        sa.Column('incident_type', sa.String(100), nullable=False),
        sa.Column('incident_description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['ot_assets.id']),
    )

    op.create_table(
        'ot_policy_rules',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('policy_name', sa.String(255), nullable=False),
        sa.Column('rule_description', sa.Text(), nullable=True),
        sa.Column('rule_content', sa.JSON(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # Container Security tables
    op.create_table(
        'kubernetes_clusters',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('cluster_name', sa.String(255), nullable=False),
        sa.Column('cluster_endpoint', sa.Text(), nullable=True),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'container_images',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('cluster_id', sa.String(36), nullable=True),
        sa.Column('image_name', sa.String(255), nullable=False),
        sa.Column('image_tag', sa.String(100), nullable=True),
        sa.Column('image_digest', sa.String(255), nullable=True),
        sa.Column('scan_status', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['cluster_id'], ['kubernetes_clusters.id']),
    )

    op.create_table(
        'image_vulnerabilities',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('image_id', sa.String(36), nullable=True),
        sa.Column('vulnerability_id', sa.String(50), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('fixed_in_version', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['image_id'], ['container_images.id']),
    )

    op.create_table(
        'k8s_security_findings',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('cluster_id', sa.String(36), nullable=True),
        sa.Column('finding_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['cluster_id'], ['kubernetes_clusters.id']),
    )

    op.create_table(
        'runtime_alerts',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('image_id', sa.String(36), nullable=True),
        sa.Column('alert_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('alert_details', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['image_id'], ['container_images.id']),
    )

    # Privacy tables
    op.create_table(
        'data_subject_requests',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('request_type', sa.String(100), nullable=False),
        sa.Column('requester_info', sa.JSON(), nullable=False),
        sa.Column('request_status', sa.String(50), nullable=False),
        sa.Column('requested_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('due_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'privacy_impact_assessments',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('pia_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('assessment_data', sa.JSON(), nullable=False),
        sa.Column('assessment_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'consent_records',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('individual_id', sa.String(255), nullable=False),
        sa.Column('consent_type', sa.String(100), nullable=False),
        sa.Column('consent_given', sa.Boolean(), nullable=False),
        sa.Column('consent_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('withdrawal_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'data_processing_records',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('processing_activity', sa.String(255), nullable=False),
        sa.Column('data_category', sa.String(100), nullable=False),
        sa.Column('processing_purpose', sa.Text(), nullable=False),
        sa.Column('legal_basis', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'privacy_incidents',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('incident_type', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('affected_individuals', sa.Integer(), nullable=True),
        sa.Column('incident_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # Threat Modeling tables
    op.create_table(
        'threat_models',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_name', sa.String(255), nullable=False),
        sa.Column('application_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('model_data', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'threat_model_components',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_id', sa.String(36), nullable=True),
        sa.Column('component_name', sa.String(255), nullable=False),
        sa.Column('component_type', sa.String(100), nullable=False),
        sa.Column('component_description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['model_id'], ['threat_models.id']),
    )

    op.create_table(
        'identified_threats',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_id', sa.String(36), nullable=True),
        sa.Column('threat_name', sa.String(255), nullable=False),
        sa.Column('threat_description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['model_id'], ['threat_models.id']),
    )

    op.create_table(
        'threat_mitigations',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('threat_id', sa.String(36), nullable=True),
        sa.Column('mitigation_name', sa.String(255), nullable=False),
        sa.Column('mitigation_description', sa.Text(), nullable=True),
        sa.Column('mitigation_status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['threat_id'], ['identified_threats.id']),
    )

    op.create_table(
        'attack_trees',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('model_id', sa.String(36), nullable=True),
        sa.Column('tree_name', sa.String(255), nullable=False),
        sa.Column('tree_data', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['model_id'], ['threat_models.id']),
    )

    # API Security tables
    op.create_table(
        'api_endpoint_inventory',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('endpoint_name', sa.String(255), nullable=False),
        sa.Column('endpoint_url', sa.Text(), nullable=False),
        sa.Column('http_method', sa.String(50), nullable=False),
        sa.Column('authentication_type', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'api_vulnerabilities',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('endpoint_id', sa.String(36), nullable=True),
        sa.Column('vulnerability_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['endpoint_id'], ['api_endpoint_inventory.id']),
    )

    op.create_table(
        'api_security_policies',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('policy_name', sa.String(255), nullable=False),
        sa.Column('policy_rules', sa.JSON(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'api_compliance_checks',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('endpoint_id', sa.String(36), nullable=True),
        sa.Column('check_type', sa.String(100), nullable=False),
        sa.Column('check_result', sa.String(50), nullable=True),
        sa.Column('check_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['endpoint_id'], ['api_endpoint_inventory.id']),
    )

    op.create_table(
        'api_anomaly_detection',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('endpoint_id', sa.String(36), nullable=True),
        sa.Column('anomaly_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('anomaly_data', sa.JSON(), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['endpoint_id'], ['api_endpoint_inventory.id']),
    )


def downgrade() -> None:
    """Drop all final tables."""
    tables = [
        'api_anomaly_detection', 'api_compliance_checks', 'api_security_policies',
        'api_vulnerabilities', 'api_endpoint_inventory', 'attack_trees',
        'threat_mitigations', 'identified_threats', 'threat_model_components',
        'threat_models', 'privacy_incidents', 'data_processing_records',
        'consent_records', 'privacy_impact_assessments', 'data_subject_requests',
        'runtime_alerts', 'k8s_security_findings', 'image_vulnerabilities',
        'container_images', 'kubernetes_clusters', 'ot_policy_rules', 'ot_incidents',
        'ot_alerts', 'ot_zones', 'ot_assets', 'business_impact_assessments',
        'risk_registers', 'risk_controls', 'fair_analyses', 'risk_scenarios',
        'sensitive_data_discoveries', 'dlp_violations', 'dlp_incidents',
        'data_classifications', 'dlp_policies', 'playbook_node_executions',
        'playbook_edges', 'playbook_nodes', 'visual_playbooks'
    ]
    for table in tables:
        op.drop_table(table)
