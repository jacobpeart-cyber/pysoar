"""ATT&CK knowledge base tables (Enterprise + ICS).

Revision ID: 019
Revises: 018
Create Date: 2026-06-16 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "019"
down_revision: Union[str, None] = "018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _base_cols():
    return [
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "attack_kb_tactics",
        *_base_cols(),
        sa.Column("stix_id", sa.String(80), nullable=False),
        sa.Column("external_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("shortname", sa.String(120), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("domain", sa.String(30), nullable=False),
        sa.Column("attack_version", sa.String(20), nullable=True),
    )
    op.create_index("ix_attack_kb_tactics_stix_id", "attack_kb_tactics", ["stix_id"], unique=True)
    op.create_index("ix_attack_kb_tactics_external_id", "attack_kb_tactics", ["external_id"])
    op.create_index("ix_attack_kb_tactics_domain", "attack_kb_tactics", ["domain"])

    op.create_table(
        "attack_kb_techniques",
        *_base_cols(),
        sa.Column("stix_id", sa.String(80), nullable=False),
        sa.Column("external_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("domain", sa.String(30), nullable=False),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False),
        sa.Column("parent_external_id", sa.String(20), nullable=True),
        sa.Column("tactics", sa.JSON(), nullable=False),
        sa.Column("platforms", sa.JSON(), nullable=False),
        sa.Column("detection", sa.Text(), nullable=True),
        sa.Column("data_sources", sa.JSON(), nullable=False),
        sa.Column("is_deprecated", sa.Boolean(), nullable=False),
        sa.Column("revoked_by", sa.String(20), nullable=True),
        sa.Column("attack_version", sa.String(20), nullable=True),
    )
    op.create_index("ix_attack_kb_techniques_stix_id", "attack_kb_techniques", ["stix_id"], unique=True)
    op.create_index("ix_attack_kb_techniques_external_id", "attack_kb_techniques", ["external_id"])
    op.create_index("ix_attack_kb_techniques_name", "attack_kb_techniques", ["name"])
    op.create_index("ix_attack_kb_techniques_domain", "attack_kb_techniques", ["domain"])
    op.create_index("ix_attack_kb_techniques_parent_external_id", "attack_kb_techniques", ["parent_external_id"])
    op.create_index("ix_attack_tech_domain_sub", "attack_kb_techniques", ["domain", "is_subtechnique"])

    op.create_table(
        "attack_kb_mitigations",
        *_base_cols(),
        sa.Column("stix_id", sa.String(80), nullable=False),
        sa.Column("external_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("domain", sa.String(30), nullable=False),
        sa.Column("is_deprecated", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_attack_kb_mitigations_stix_id", "attack_kb_mitigations", ["stix_id"], unique=True)
    op.create_index("ix_attack_kb_mitigations_external_id", "attack_kb_mitigations", ["external_id"])
    op.create_index("ix_attack_kb_mitigations_domain", "attack_kb_mitigations", ["domain"])

    op.create_table(
        "attack_kb_groups",
        *_base_cols(),
        sa.Column("stix_id", sa.String(80), nullable=False),
        sa.Column("external_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("is_deprecated", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_attack_kb_groups_stix_id", "attack_kb_groups", ["stix_id"], unique=True)
    op.create_index("ix_attack_kb_groups_external_id", "attack_kb_groups", ["external_id"])
    op.create_index("ix_attack_kb_groups_name", "attack_kb_groups", ["name"])

    op.create_table(
        "attack_kb_software",
        *_base_cols(),
        sa.Column("stix_id", sa.String(80), nullable=False),
        sa.Column("external_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("software_type", sa.String(20), nullable=False),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("platforms", sa.JSON(), nullable=False),
        sa.Column("is_deprecated", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_attack_kb_software_stix_id", "attack_kb_software", ["stix_id"], unique=True)
    op.create_index("ix_attack_kb_software_external_id", "attack_kb_software", ["external_id"])
    op.create_index("ix_attack_kb_software_name", "attack_kb_software", ["name"])

    op.create_table(
        "attack_kb_data_components",
        *_base_cols(),
        sa.Column("stix_id", sa.String(80), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("data_source_name", sa.String(255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
    )
    op.create_index("ix_attack_kb_data_components_stix_id", "attack_kb_data_components", ["stix_id"], unique=True)
    op.create_index("ix_attack_kb_data_components_name", "attack_kb_data_components", ["name"])
    op.create_index("ix_attack_kb_data_components_data_source_name", "attack_kb_data_components", ["data_source_name"])

    op.create_table(
        "attack_kb_technique_mitigation",
        *_base_cols(),
        sa.Column("technique_external_id", sa.String(20), nullable=False),
        sa.Column("mitigation_external_id", sa.String(20), nullable=False),
    )
    op.create_index("ix_attack_kb_technique_mitigation_technique_external_id", "attack_kb_technique_mitigation", ["technique_external_id"])
    op.create_index("ix_attack_kb_technique_mitigation_mitigation_external_id", "attack_kb_technique_mitigation", ["mitigation_external_id"])
    op.create_index("ix_attack_tm_pair", "attack_kb_technique_mitigation", ["technique_external_id", "mitigation_external_id"], unique=True)

    op.create_table(
        "attack_kb_group_technique",
        *_base_cols(),
        sa.Column("group_external_id", sa.String(20), nullable=False),
        sa.Column("technique_external_id", sa.String(20), nullable=False),
    )
    op.create_index("ix_attack_kb_group_technique_group_external_id", "attack_kb_group_technique", ["group_external_id"])
    op.create_index("ix_attack_kb_group_technique_technique_external_id", "attack_kb_group_technique", ["technique_external_id"])
    op.create_index("ix_attack_gt_pair", "attack_kb_group_technique", ["group_external_id", "technique_external_id"], unique=True)

    op.create_table(
        "attack_kb_software_technique",
        *_base_cols(),
        sa.Column("software_external_id", sa.String(20), nullable=False),
        sa.Column("technique_external_id", sa.String(20), nullable=False),
    )
    op.create_index("ix_attack_kb_software_technique_software_external_id", "attack_kb_software_technique", ["software_external_id"])
    op.create_index("ix_attack_kb_software_technique_technique_external_id", "attack_kb_software_technique", ["technique_external_id"])
    op.create_index("ix_attack_st_pair", "attack_kb_software_technique", ["software_external_id", "technique_external_id"], unique=True)

    op.create_table(
        "attack_kb_technique_datacomponent",
        *_base_cols(),
        sa.Column("technique_external_id", sa.String(20), nullable=False),
        sa.Column("data_component_name", sa.String(255), nullable=False),
        sa.Column("log_source_name", sa.String(255), nullable=True),
        sa.Column("data_source_name", sa.String(255), nullable=True),
    )
    op.create_index("ix_attack_kb_technique_datacomponent_technique_external_id", "attack_kb_technique_datacomponent", ["technique_external_id"])
    op.create_index("ix_attack_kb_technique_datacomponent_data_component_name", "attack_kb_technique_datacomponent", ["data_component_name"])
    op.create_index("ix_attack_kb_technique_datacomponent_log_source_name", "attack_kb_technique_datacomponent", ["log_source_name"])
    op.create_index("ix_attack_tdc_pair", "attack_kb_technique_datacomponent", ["technique_external_id", "data_component_name", "log_source_name"], unique=True)

    op.create_table(
        "attack_kb_sync_state",
        *_base_cols(),
        sa.Column("attack_version", sa.String(20), nullable=True),
        sa.Column("domains", sa.JSON(), nullable=False),
        sa.Column("object_counts", sa.JSON(), nullable=False),
        sa.Column("source_release", sa.String(80), nullable=True),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("techniques_count", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    for tbl in (
        "attack_kb_sync_state",
        "attack_kb_technique_datacomponent",
        "attack_kb_software_technique",
        "attack_kb_group_technique",
        "attack_kb_technique_mitigation",
        "attack_kb_data_components",
        "attack_kb_software",
        "attack_kb_groups",
        "attack_kb_mitigations",
        "attack_kb_techniques",
        "attack_kb_tactics",
    ):
        op.drop_table(tbl)
