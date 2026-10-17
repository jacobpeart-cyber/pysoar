"""Alembic environment configuration for async SQLAlchemy"""

import asyncio
from logging.config import fileConfig

import sqlalchemy as sa
from alembic import context
from alembic.runtime.migration import MigrationContext, RevisionStep
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from src.core.config import settings
from src.models import Base

# Import all models so they're registered with Base.metadata for autogenerate.
#
# NOTE: models here must stay in sync with the codebase or `alembic upgrade`
# will fail on ImportError. We wrap each module in try/except and log a
# warning so a stale/removed symbol in ONE module does not block migrations
# for the whole platform. For a raw-SQL migration (like 007) we actually
# don't need any of these imports, but they are still kept for
# `alembic revision --autogenerate` support.
import logging as _logging
_log = _logging.getLogger("alembic.env")

# Model modules that failed to import. An empty database is only bootstrapped
# from the models (see _bootstrap_empty_database) when this stays empty, so a
# broken import can never produce a schema that silently lacks its tables.
_import_failures: list[str] = []


def _try_import(name: str, names: list[str]) -> None:
    try:
        mod = __import__(name, fromlist=names)
        for n in names:
            if not hasattr(mod, n):
                _log.warning("alembic env: %s has no attribute %s", name, n)
    except Exception as e:  # noqa: BLE001
        _import_failures.append(f"{name} ({e})")
        _log.warning("alembic env: skipping %s (%s)", name, e)

# Core models
from src.models.user import User
from src.models.alert import Alert
from src.models.incident import Incident
from src.models.playbook import Playbook, PlaybookExecution
from src.models.ioc import IOC
from src.models.asset import Asset
from src.models.audit import AuditLog
from src.models.case import CaseNote, CaseAttachment, CaseTimeline, Task
from src.models.organization import Organization, OrganizationMember, Team, TeamMember
from src.models.api_key import APIKey

# Module-specific models (best-effort so stale names don't break upgrades)
_try_import("src.ai.models", ["MLModel", "AIAnalysis", "ThreatPrediction", "AnomalyDetection"])
_try_import("src.siem.models", ["SIEMDataSource", "DetectionRule", "LogEntry", "CorrelationEvent"])
from src.intel.models import (
    ThreatFeed,
    ThreatIndicator,
    ThreatActor,
    ThreatCampaign,
    IntelReport,
    IndicatorSighting,
)
_try_import("src.hunting.models", ["HuntHypothesis", "HuntNotebook", "HuntFinding", "HuntTemplate", "HuntSession"])
_try_import("src.exposure.models", ["ExposureAsset", "ExposureScan", "AttackSurface", "AssetVulnerability", "RemediationTicket"])
_try_import("src.ueba.models", ["UserBehavior", "BehaviorBaseline", "UEBARiskAlert", "EntityProfile", "PeerGroup", "BehaviorEvent"])
_try_import("src.simulation.models", ["AttackCampaign", "SimulationTest", "AttackTechnique", "AdversaryProfile", "SecurityPostureScore"])
_try_import("src.deception.models", ["Honeypot", "HoneyToken", "DeceptionCampaign", "DecoyInteraction", "Decoy"])
_try_import("src.remediation.models", ["RemediationPolicy", "RemediationAction", "RemediationPlaybook", "RemediationExecution", "RemediationIntegration"])
_try_import("src.compliance.models", ["ComplianceFramework", "ComplianceControl", "POAM", "ComplianceEvidence", "ComplianceAssessment", "CISADirective", "CUIMarking"])
_try_import("src.zerotrust.models", ["ZeroTrustPolicy", "DeviceTrustProfile", "AccessDecision", "MicroSegment", "IdentityVerification"])
_try_import("src.stig.models", ["STIGBenchmark", "STIGRule", "STIGScanResult", "SCAPProfile"])
_try_import("src.audit_evidence.models", ["AuditTrail", "EvidencePackage", "AutomatedEvidenceRule"])
_try_import("src.dfir.models", ["ForensicCase", "ForensicEvidence", "ForensicArtifact", "LegalHold", "ForensicTimeline"])
_try_import("src.itdr.models", ["IdentityThreat", "CredentialMonitor", "PrivilegedAccessEvent", "CredentialExposure", "AccessAnomaly", "IdentityProfile"])
_try_import("src.vulnmgmt.models", ["Vulnerability", "VulnScan", "PatchOperation", "VulnerabilityException", "VulnerabilityInstance", "ScanProfile"])
_try_import("src.supplychain.models", ["SBOMComponent", "SBOM", "SoftwareComponent", "SupplyChainRisk", "VendorAssessment"])
_try_import("src.darkweb.models", ["DarkwebAlert", "CredentialLeak", "DarkwebMonitor", "DarkwebFinding", "DarkwebBrandThreat"])
_try_import("src.integrations.models", ["IntegrationConnector", "InstalledIntegration", "IntegrationAction", "IntegrationExecution", "WebhookEndpoint"])
_try_import("src.agentic.models", ["SOCAgent", "Investigation", "ReasoningChain", "AgentAction", "AgentMemory"])
_try_import("src.playbook_builder.models", ["VisualPlaybook", "PlaybookNode", "PlaybookEdge", "PlaybookNodeExecution", "PlaybookExecution"])
_try_import("src.dlp.models", ["DLPPolicy", "DLPIncident", "DataClassification", "DLPViolation", "SensitiveDataDiscovery"])
_try_import("src.risk_quant.models", ["RiskScenario", "LossAnalysis", "ControlAssessment", "RiskRegister", "FAIRAnalysis", "BusinessImpactAssessment"])
_try_import("src.ot_security.models", ["OTAsset", "OTAlert", "OTZone", "OTIncident", "OTPolicyRule"])
_try_import("src.container_security.models", ["ContainerImage", "ContainerScan", "KubernetesCluster", "K8sSecurityFinding", "RuntimeAlert", "ImageVulnerability"])
_try_import("src.privacy.models", ["DataSubjectRequest", "PrivacyImpactAssessment", "ConsentRecord", "ProcessingRecord", "PrivacyIncident"])
_try_import("src.threat_modeling.models", ["ThreatModel", "ThreatModelComponent", "IdentifiedThreat", "ThreatMitigation", "AttackTree"])
_try_import("src.api_security.models", ["APIEndpoint", "APIVulnerability", "APISecurityPolicy", "APIComplianceCheck", "APIAnomalyDetection"])
_try_import("src.data_lake.models", ["DataSource", "DataPipeline", "UnifiedDataModel", "DataPartition", "QueryJob"])
_try_import("src.collaboration.models", ["WarRoom", "WarRoomMessage", "ActionItem", "SharedArtifact", "IncidentTimeline"])
_try_import("src.phishing_sim.models", ["PhishingCampaign", "PhishingTemplate", "CampaignEvent", "TargetGroup", "SecurityAwarenessScore"])
_try_import("src.agents.models", ["EndpointAgent", "AgentCommand", "AgentResult", "AgentHeartbeat"])
_try_import("src.identity.models", ["SSOConfiguration", "SCIMToken", "Role"])
# Tables the app registers that revisions 019 / 020 create; listed so an empty
# database bootstrapped from the models gets them too.
_try_import("src.attack.models", [])
_try_import("src.llm.models", [])

# Alembic Config object
config = context.config

# Set the SQLAlchemy URL from settings
config.set_main_option("sqlalchemy.url", settings.database_url)

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Model's MetaData object for 'autogenerate' support
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def _database_is_empty(connection: Connection) -> bool:
    """True when the database has no tables, or only an empty ``alembic_version``."""
    tables = set(sa.inspect(connection).get_table_names())
    if tables - {"alembic_version"}:
        return False
    if "alembic_version" in tables:
        return not connection.execute(sa.text("SELECT COUNT(*) FROM alembic_version")).scalar()
    return True


def _upgrades_to_every_head(migration_context: MigrationContext) -> bool:
    """True when the command being run is an upgrade from nothing to every head.

    The work function alembic's command handed to the context is asked for its
    plan from an empty version table: ``alembic upgrade head`` yields upgrade
    ``RevisionStep``s covering every head, while ``stamp`` yields ``StampStep``s
    and ``downgrade`` / ``current`` / ``check`` yield nothing.
    """
    fn = getattr(migration_context, "_migrations_fn", None)
    if fn is None:
        return False
    steps = list(fn((), migration_context))
    if not steps or not all(isinstance(s, RevisionStep) and s.is_upgrade for s in steps):
        return False
    planned = {s.revision.revision for s in steps}
    return set(context.script.get_heads()) <= planned


def _bootstrap_empty_database(connection: Connection) -> None:
    """Create an empty database's schema from the models and stamp it at head.

    Revisions 001-006 created placeholder tables whose columns never matched
    the ORM (e.g. ``iocs.type`` where 007 reads ``iocs.ioc_type``,
    ``threat_indicators.indicator_value`` where 008 reads ``value``), and
    008-019 were written against databases whose tables came from
    ``init_db``'s ``create_all``; replaying the chain on an empty database
    therefore cannot work. Every existing database (production included) got
    its tables from ``create_all`` and then the later revisions, so the
    current models plus a stamp at head is exactly the schema those revisions
    converge on. This is Alembic's documented recipe for new databases
    ("Building an Up to Date Database from Scratch"), done inside
    ``alembic upgrade head`` so that one command serves both fresh installs
    and upgrades. Databases with any table are never touched by this path.
    """
    if _import_failures:
        raise RuntimeError(
            "Refusing to build an empty database from the models: these model "
            "modules failed to import, so their tables would be missing: "
            + "; ".join(_import_failures)
        )
    target_metadata.create_all(connection)
    context.get_context().stamp(context.script, "heads")
    _log.info(
        "alembic env: empty database; created %d tables from the models and stamped %s",
        len(target_metadata.tables),
        ", ".join(context.script.get_heads()),
    )


def do_run_migrations(connection: Connection) -> None:
    """Run migrations with the given connection."""
    context.configure(connection=connection, target_metadata=target_metadata)

    bootstrap = _database_is_empty(connection) and _upgrades_to_every_head(context.get_context())
    if connection.in_transaction():
        # End the read-only transaction the checks above autobegan, so the
        # migration context sees the connection exactly as it was configured.
        connection.commit()
    if bootstrap:
        # One transaction for the schema and the version row (atomic on
        # PostgreSQL; committed explicitly on SQLite, whose DDL alembic
        # otherwise runs outside a transaction).
        with connection.begin():
            _bootstrap_empty_database(connection)
        return

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in 'online' mode with async engine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
