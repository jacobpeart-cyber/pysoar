"""Additional module-specific tables.

Revision ID: 003
Revises: 002
Create Date: 2026-03-24 00:00:02.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create additional module tables."""

    # Remediation tables
    op.create_table(
        'remediation_policies',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('policy_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'remediation_actions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('policy_id', sa.String(36), nullable=True),
        sa.Column('action_name', sa.String(255), nullable=False),
        sa.Column('action_type', sa.String(100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['policy_id'], ['remediation_policies.id']),
    )

    op.create_table(
        'remediation_playbooks',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('policy_id', sa.String(36), nullable=True),
        sa.Column('playbook_name', sa.String(255), nullable=False),
        sa.Column('playbook_steps', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['policy_id'], ['remediation_policies.id']),
    )

    op.create_table(
        'remediation_executions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('action_id', sa.String(36), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('result', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['action_id'], ['remediation_actions.id']),
    )

    op.create_table(
        'remediation_integrations',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('integration_name', sa.String(255), nullable=False),
        sa.Column('integration_type', sa.String(100), nullable=False),
        sa.Column('config', sa.JSON(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # Compliance tables
    op.create_table(
        'compliance_frameworks',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('framework_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('framework_version', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'compliance_controls',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('framework_id', sa.String(36), nullable=True),
        sa.Column('control_id', sa.String(50), nullable=False),
        sa.Column('control_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id']),
    )

    op.create_table(
        'poams',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('control_id', sa.String(36), nullable=True),
        sa.Column('finding_title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('target_completion_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['control_id'], ['compliance_controls.id']),
    )

    op.create_table(
        'compliance_evidence',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('control_id', sa.String(36), nullable=True),
        sa.Column('evidence_name', sa.String(255), nullable=False),
        sa.Column('evidence_data', sa.Text(), nullable=True),
        sa.Column('evidence_type', sa.String(100), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['control_id'], ['compliance_controls.id']),
    )

    op.create_table(
        'compliance_assessments',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('framework_id', sa.String(36), nullable=True),
        sa.Column('assessment_name', sa.String(255), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('assessment_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('results', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['framework_id'], ['compliance_frameworks.id']),
    )

    op.create_table(
        'cisa_directives',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('directive_name', sa.String(255), nullable=False),
        sa.Column('directive_number', sa.String(50), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('issued_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'cui_markings',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('marking_type', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('resource_id', sa.String(36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # Zero Trust tables
    op.create_table(
        'zero_trust_policies',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('policy_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('policy_rules', sa.JSON(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'device_trust_profiles',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('device_id', sa.String(255), nullable=False),
        sa.Column('device_name', sa.String(255), nullable=True),
        sa.Column('trust_score', sa.Float(), nullable=True),
        sa.Column('last_verified', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'access_decisions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('policy_id', sa.String(36), nullable=True),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('resource', sa.String(255), nullable=False),
        sa.Column('decision', sa.String(50), nullable=False),
        sa.Column('decision_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['policy_id'], ['zero_trust_policies.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )

    op.create_table(
        'micro_segments',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('segment_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('members', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'identity_verifications',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('verification_type', sa.String(100), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )

    # STIG tables
    op.create_table(
        'stig_benchmarks',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('benchmark_id', sa.String(50), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'stig_rules',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('benchmark_id', sa.String(36), nullable=True),
        sa.Column('rule_id', sa.String(50), nullable=False),
        sa.Column('rule_title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['benchmark_id'], ['stig_benchmarks.id']),
    )

    op.create_table(
        'stig_scan_results',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('benchmark_id', sa.String(36), nullable=True),
        sa.Column('scan_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('total_rules', sa.Integer(), nullable=False),
        sa.Column('passed_rules', sa.Integer(), nullable=False),
        sa.Column('failed_rules', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['benchmark_id'], ['stig_benchmarks.id']),
    )

    op.create_table(
        'scap_profiles',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('profile_name', sa.String(255), nullable=False),
        sa.Column('profile_description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # Audit Evidence tables
    op.create_table(
        'audit_trails',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('resource_type', sa.String(100), nullable=False),
        sa.Column('resource_id', sa.String(36), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('actor', sa.String(255), nullable=True),
        sa.Column('audit_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'evidence_packages',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('package_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('contents', sa.JSON(), nullable=False),
        sa.Column('package_hash', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'automated_evidence_rules',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('rule_name', sa.String(255), nullable=False),
        sa.Column('rule_description', sa.Text(), nullable=True),
        sa.Column('rule_logic', sa.JSON(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    # DFIR tables
    op.create_table(
        'forensic_cases',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('case_name', sa.String(255), nullable=False),
        sa.Column('case_number', sa.String(100), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('opened_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'forensic_evidence',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('case_id', sa.String(36), nullable=True),
        sa.Column('evidence_name', sa.String(255), nullable=False),
        sa.Column('evidence_type', sa.String(100), nullable=False),
        sa.Column('evidence_hash', sa.String(255), nullable=True),
        sa.Column('collected_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['case_id'], ['forensic_cases.id']),
    )

    op.create_table(
        'forensic_artifacts',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('evidence_id', sa.String(36), nullable=True),
        sa.Column('artifact_name', sa.String(255), nullable=False),
        sa.Column('artifact_type', sa.String(100), nullable=False),
        sa.Column('artifact_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['evidence_id'], ['forensic_evidence.id']),
    )

    op.create_table(
        'legal_holds',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('case_id', sa.String(36), nullable=True),
        sa.Column('hold_name', sa.String(255), nullable=False),
        sa.Column('hold_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('released_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['case_id'], ['forensic_cases.id']),
    )

    op.create_table(
        'forensic_timeline',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('case_id', sa.String(36), nullable=True),
        sa.Column('event_description', sa.Text(), nullable=False),
        sa.Column('event_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['case_id'], ['forensic_cases.id']),
    )


def downgrade() -> None:
    """Drop all additional tables."""
    tables = [
        'forensic_timeline', 'legal_holds', 'forensic_artifacts', 'forensic_evidence',
        'forensic_cases', 'automated_evidence_rules', 'evidence_packages', 'audit_trails',
        'scap_profiles', 'stig_scan_results', 'stig_rules', 'stig_benchmarks',
        'identity_verifications', 'micro_segments', 'access_decisions',
        'device_trust_profiles', 'zero_trust_policies', 'cui_markings', 'cisa_directives',
        'compliance_assessments', 'compliance_evidence', 'poams', 'compliance_controls',
        'compliance_frameworks', 'remediation_integrations', 'remediation_executions',
        'remediation_playbooks', 'remediation_actions', 'remediation_policies'
    ]
    for table in tables:
        op.drop_table(table)
