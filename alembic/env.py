"""Alembic environment configuration for async SQLAlchemy"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from src.core.config import settings
from src.models import Base

# Import all models so they're registered with Base.metadata for autogenerate
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

# Module-specific models
from src.ai.models import (
    AIModel,
    AIAnalysis,
    ThreatPrediction,
    AnomalyDetection,
    NLQuery,
)
from src.siem.models import SIEMDataSource, DetectionRule, LogEntry, CorrelationEvent
from src.intel.models import (
    ThreatFeed,
    ThreatIndicator,
    ThreatActor,
    ThreatCampaign,
    IntelReport,
    IndicatorSighting,
)
from src.hunting.models import (
    HuntHypothesis,
    HuntNotebook,
    HuntFinding,
    HuntTemplate,
    HuntSession,
)
from src.exposure.models import (
    ExposureAsset,
    ExposureScan,
    AttackSurface,
    Vulnerability,
    AssetVulnerability,
    RemediationTicket,
)
from src.ai.models import AIModel, AIAnalysis, ThreatPrediction, AnomalyDetection
from src.ueba.models import (
    UserBehavior,
    BehaviorBaseline,
    UEBARiskAlert,
    EntityProfile,
    PeerGroup,
    BehaviorEvent,
)
from src.simulation.models import (
    AttackCampaign,
    SimulationTest,
    AttackTechnique,
    AdversaryProfile,
    SecurityPostureScore,
)
from src.deception.models import (
    Honeypot,
    HoneyToken,
    DeceptionCampaign,
    DecoyInteraction,
    Decoy,
)
from src.remediation.models import (
    RemediationPolicy,
    RemediationAction,
    RemediationPlaybook,
    RemediationExecution,
    RemediationIntegration,
)
from src.compliance.models import (
    ComplianceFramework,
    ComplianceControl,
    POAM,
    ComplianceEvidence,
    ComplianceAssessment,
    CISADirective,
    CUIMarking,
)
from src.zerotrust.models import (
    ZeroTrustPolicy,
    DeviceTrustProfile,
    AccessDecision,
    MicroSegment,
    IdentityVerification,
)
from src.stig.models import (
    STIGBenchmark,
    STIGRule,
    STIGScanResult,
    SCAPProfile,
)
from src.audit_evidence.models import (
    AuditTrail,
    EvidencePackage,
    AutomatedEvidenceRule,
)
from src.dfir.models import (
    ForensicCase,
    ForensicEvidence,
    ForensicArtifact,
    LegalHold,
    ForensicTimeline,
)
from src.itdr.models import (
    IdentityThreat,
    CredentialMonitor,
    PrivilegedAccessEvent,
    CredentialExposure,
    AccessAnomaly,
    IdentityProfile,
)
from src.vulnmgmt.models import (
    Vulnerability as VulnVulnerability,
    VulnScan,
    PatchOperation,
    VulnerabilityException,
    VulnerabilityInstance,
    ScanProfile,
)
from src.supplychain.models import (
    SBOMComponent,
    SBOM,
    SoftwareComponent,
    SupplyChainRisk,
    VendorAssessment,
)
from src.darkweb.models import (
    DarkwebAlert,
    CredentialLeak,
    DarkwebMonitor,
    DarkwebFinding,
    DarkwebBrandThreat,
)
from src.integrations.models import (
    IntegrationConnector,
    InstalledIntegration,
    IntegrationAction,
    IntegrationExecution,
    WebhookEndpoint,
)
from src.agentic.models import (
    SOCAgent,
    Investigation,
    ReasoningChain,
    AgentAction,
    AgentMemory,
)
from src.playbook_builder.models import (
    VisualPlaybook,
    PlaybookNode,
    PlaybookEdge,
    PlaybookNodeExecution,
    PlaybookExecution as PBExecution,
)
from src.dlp.models import (
    DLPPolicy,
    DLPIncident,
    DataClassification,
    DLPViolation,
    SensitiveDataDiscovery,
)
from src.risk_quant.models import (
    RiskScenario,
    LossAnalysis,
    ControlAssessment,
    RiskRegister,
    FAIRAnalysis,
    BusinessImpactAssessment,
)
from src.ot_security.models import (
    OTAsset,
    OTAlert,
    OTZone,
    OTIncident,
    OTPolicyRule,
)
from src.container_security.models import (
    ContainerImage,
    ContainerScan,
    KubernetesCluster,
    K8sSecurityFinding,
    RuntimeAlert,
    ImageVulnerability,
)
from src.privacy.models import (
    DataSubjectRequest,
    PrivacyImpactAssessment,
    ConsentRecord,
    ProcessingRecord,
    PrivacyIncident,
)
from src.threat_modeling.models import (
    ThreatModel,
    ThreatModelComponent,
    IdentifiedThreat,
    ThreatMitigation,
    AttackTree,
)
from src.api_security.models import (
    APIEndpoint,
    APIVulnerability,
    APISecurityPolicy,
    APIComplianceCheck,
    APIAnomalyDetection,
)
from src.data_lake.models import (
    DataSource,
    DataPipeline,
    UnifiedDataModel,
    DataPartition,
    QueryJob,
)
from src.collaboration.models import (
    WarRoom,
    WarRoomMessage,
    ActionItem,
    SharedArtifact,
    IncidentTimeline,
)
from src.phishing_sim.models import (
    PhishingCampaign,
    PhishingTemplate,
    CampaignEvent,
    TargetGroup,
    SecurityAwarenessScore,
)

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


def do_run_migrations(connection: Connection) -> None:
    """Run migrations with the given connection."""
    context.configure(connection=connection, target_metadata=target_metadata)

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
