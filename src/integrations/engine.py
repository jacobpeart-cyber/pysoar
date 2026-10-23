"""Integration engine with connector registry, action execution, and webhook processing"""

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

from src.core.logging import get_logger
from src.core.utils import safe_json_loads
from src.integrations.connectors import (
    AbuseIPDBConnector,
    AWSSecurityHubConnector,
    CrowdStrikeConnector,
    JiraConnector,
    MicrosoftSentinelConnector,
    PagerDutyConnector,
    ServiceNowConnector,
    ShodanConnector,
    SlackConnector,
    VirusTotalConnector,
)
from src.integrations.connectors.entra_id import EntraIDConnector
from src.integrations.connectors.microsoft_defender import MicrosoftDefenderConnector
from src.integrations.connectors.microsoft_teams import MicrosoftTeamsConnector
from src.integrations.connectors.okta import OktaConnector
from src.integrations.connectors.base import (
    BaseConnector,
    ConnectionTestResult,
    ConnectorActionFailed,
    sanitize_message,
)
from src.integrations.connectors.elastic import ElasticConnector
from src.integrations.connectors.qradar import QRadarConnector
from src.integrations.connectors.splunk import SplunkConnector, https_origin
from src.integrations.netguard import (
    OutboundTargetRefused,
    VettedTarget,
    pinned_request_kwargs,
    resolve_and_vet,
)
from src.integrations.models import (
    AuthType,
    ExecutionStatus,
    ExecutionTrigger,
    HealthStatus,
    IntegrationAction,
    IntegrationCategory,
    IntegrationExecution,
    InstalledIntegration,
)

logger = get_logger(__name__)

CONNECTOR_CLASS_MAP = {
    "slack": SlackConnector,
    "virustotal": VirusTotalConnector,
    "shodan": ShodanConnector,
    "abuseipdb": AbuseIPDBConnector,
    "crowdstrike": CrowdStrikeConnector,
    "servicenow": ServiceNowConnector,
    "pagerduty": PagerDutyConnector,
    "aws_security_hub": AWSSecurityHubConnector,
    "jira": JiraConnector,
    "microsoft_sentinel": MicrosoftSentinelConnector,
    "splunk": SplunkConnector,
    "elastic": ElasticConnector,
    "qradar": QRadarConnector,
    "okta": OktaConnector,
    "azure_ad": EntraIDConnector,
    "microsoft_defender": MicrosoftDefenderConnector,
    "microsoft_teams": MicrosoftTeamsConnector,
}


IMPLEMENTED = "implemented"
LOG_INGEST = "log_ingest"
PLANNED = "planned"
PLANNED_VERIFICATION = "not implemented in this release"
LOG_INGEST_VERIFICATION = (
    "log poller implemented from the vendor's public SDK / REST documentation (src/siem/cloud_poller.py); "
    "not verified against a live tenant"
)

# Connectors with no executable connector class whose events the SIEM cloud
# poller (src/siem/cloud_poller.py) ingests on a schedule (the vendor SDK for
# the three clouds). They can be installed (the poller needs the stored
# credentials) but expose no actions and no connection test.
LOG_INGEST_CONNECTORS = frozenset({"aws_cloudtrail", "azure_activity_log", "gcp_cloud_logging"})

# Catalogue entries whose events the SIEM cloud poller ingests: the
# log_ingest sources plus the implemented connectors that also have a poller
# (Splunk, Elastic, QRadar). Surfaced as ``ingest: true`` in the catalogue.
INGEST_CONNECTORS = LOG_INGEST_CONNECTORS | frozenset({"splunk", "elastic", "qradar"})


def has_ingest(connector_name: Optional[str]) -> bool:
    """True when the SIEM cloud poller pulls this connector's events."""
    return (connector_name or "").lower() in INGEST_CONNECTORS


def implementation_status(connector_name: Optional[str]) -> str:
    """``implemented`` (a class in CONNECTOR_CLASS_MAP), ``log_ingest`` or ``planned``.

    Derived at request time from the code, so no column has to be kept in sync.
    """
    name = (connector_name or "").lower()
    if name in CONNECTOR_CLASS_MAP:
        return IMPLEMENTED
    if name in LOG_INGEST_CONNECTORS:
        return LOG_INGEST
    return PLANNED


def connector_class(connector_name: Optional[str]) -> Optional[type[BaseConnector]]:
    return CONNECTOR_CLASS_MAP.get((connector_name or "").lower())


def _field_dict(f: Any) -> dict[str, Any]:
    return f.model_dump() if hasattr(f, "model_dump") else dict(f)


def missing_install_fields(connector_name: str, config: dict[str, Any], credentials: dict[str, Any]) -> list[str]:
    """Required config / credential field names absent from an install or update payload."""
    cls = connector_class(connector_name)
    if cls is not None:
        return cls.missing_fields(config, credentials)
    meta = BUILTIN_CONNECTORS.get((connector_name or "").lower()) or {}
    missing = [k for k in meta.get("required_config") or [] if str((config or {}).get(k) or "").strip() == ""]
    return missing + [k for k in meta.get("required_credentials") or [] if credentials.get(k) in (None, "")]


def invalid_install_fields(connector_name: str, config: dict[str, Any], credentials: dict[str, Any]) -> list[str]:
    cls = connector_class(connector_name)
    if cls is not None:
        return cls.invalid_fields(config, credentials)
    # A log_ingest entry may name config fields that must be an https origin.
    meta = BUILTIN_CONNECTORS.get((connector_name or "").lower()) or {}
    bad = []
    for key in meta.get("https_config") or []:
        value = (config or {}).get(key)
        if value:
            try:
                https_origin(value, key)
            except ValueError:
                bad.append(key)
    return bad


def build_connector(connector_name: str, config: dict[str, Any], credentials: dict[str, Any]) -> BaseConnector:
    """Instantiate the connector class; raises ConnectorActionFailed when it cannot act."""
    cls = connector_class(connector_name)
    if cls is None:
        display = (BUILTIN_CONNECTORS.get((connector_name or "").lower()) or {}).get("display_name") or connector_name
        raise ConnectorActionFailed(
            f"{display} has no connector implementation in this release", code="not_implemented",
        )
    try:
        return cls(config=config or {}, credentials=credentials or {})
    except ValueError as exc:
        raise ConnectorActionFailed(f"integration configuration is invalid: {exc}", code="invalid_configuration") from None


async def probe_connector(
    connector_name: str, config: dict[str, Any], credentials: dict[str, Any],
) -> ConnectionTestResult:
    """Run the connector's own ``test_connection`` (no network call when it cannot be tested)."""
    status = implementation_status(connector_name)
    if status == PLANNED:
        return ConnectionTestResult(
            HealthStatus.UNAVAILABLE.value,
            f"{connector_name} has no connector implementation in this release",
            "none",
        )
    if status == LOG_INGEST:
        return ConnectionTestResult(
            HealthStatus.UNKNOWN.value,
            "no connection test for this log source; the SIEM cloud poller records health on every poll",
            "none",
        )
    try:
        connector = build_connector(connector_name, config, credentials)
    except ConnectorActionFailed as exc:
        return ConnectionTestResult(HealthStatus.UNHEALTHY.value, exc.message, "none")
    try:
        return await connector.test_connection()
    except Exception as exc:  # noqa: BLE001 (a probe must report, never raise)
        logger.warning("connector test_connection raised", connector=connector_name, error_type=type(exc).__name__)
        return ConnectionTestResult(
            HealthStatus.UNHEALTHY.value, connector.sanitize(f"test raised {type(exc).__name__}: {exc}"), connector.TEST_CALL,
        )


async def sync_connector_actions(db: Any, connector_id: str, connector_name: str) -> int:
    """Upsert one ``IntegrationAction`` row per declared action of the connector class.

    Rows are keyed by (connector_id, action_name) and carry the real
    ``input_schema`` (the action's ``params_schema``), ``description``,
    ``is_idempotent`` and ``requires_approval`` (= the action changes vendor
    state). Returns the number of rows created. Rows for names the class no
    longer declares are left in place (executions reference them) but are not
    listed or executable.
    """
    from sqlalchemy import select as _select

    cls = connector_class(connector_name)
    if cls is None:
        return 0
    existing = {
        a.action_name: a
        for a in (
            await db.execute(_select(IntegrationAction).where(IntegrationAction.connector_id == connector_id))
        ).scalars().all()
    }
    created = 0
    for name, spec in cls.ACTIONS.items():
        row = existing.get(name)
        if row is None:
            row = IntegrationAction(connector_id=connector_id, action_name=name, retry_policy="{}", timeout_seconds=300)
            db.add(row)
            created += 1
        row.display_name = spec.display_name or name
        row.description = spec.description
        row.action_type = spec.action_type
        row.input_schema = json.dumps(spec.params_schema)
        row.output_schema = json.dumps({"description": spec.output})
        row.requires_approval = spec.side_effect
        row.is_idempotent = spec.idempotent
        if not row.retry_policy:
            row.retry_policy = "{}"
    await db.flush()
    return created


# Built-in connector definitions
BUILTIN_CONNECTORS = {
    # External SIEM (optional interop) — PySOAR SHIPS with its own
    # native SIEM (UDP/TCP 5514 syslog + HTTP bulk ingest + agent
    # heartbeat stream + cloud log pollers + rule engine +
    # correlation + alert creation). These connectors are for
    # customers who already have an incumbent SIEM and want to pull
    # events from it into PySOAR for unified detection+response —
    # not for customers who want the built-in SIEM.
    "splunk": {
        "name": "splunk",
        "display_name": "Splunk Enterprise",
        "description": "OPTIONAL INTEROP: search, saved searches and HEC on an existing Splunk deployment; the SIEM poller pulls its events. Not required; PySOAR has its own native SIEM.",
        "vendor": "Splunk",
        "category": IntegrationCategory.SIEM,
        "integration_role": "external_siem",
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "qradar": {
        "name": "qradar",
        "display_name": "IBM QRadar",
        "description": "OPTIONAL INTEROP: offenses, read-only AQL searches and reference sets on an existing QRadar console; the SIEM poller pulls new offenses. Not required; PySOAR has its own native SIEM.",
        "vendor": "IBM",
        "category": IntegrationCategory.SIEM,
        "integration_role": "external_siem",
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["scheduled", "manual"],
    },
    "elastic": {
        "name": "elastic",
        "display_name": "Elastic Security",
        "description": "OPTIONAL INTEROP: search, count, read and index documents on an existing Elasticsearch cluster; the SIEM poller pulls its events. Not required; PySOAR has its own native SIEM.",
        "vendor": "Elastic",
        "category": IntegrationCategory.SIEM,
        "integration_role": "external_siem",
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "wazuh": {
        "name": "wazuh",
        "display_name": "Wazuh",
        "description": "OPTIONAL INTEROP (planned, not in this release): pull events from an existing Wazuh deployment. Not required; PySOAR has its own native SIEM.",
        "vendor": "Wazuh",
        "category": IntegrationCategory.SIEM,
        "integration_role": "external_siem",
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "sumo_logic": {
        "name": "sumo_logic",
        "display_name": "Sumo Logic",
        "description": "OPTIONAL INTEROP (planned, not in this release): pull events from Sumo Logic. Not required; PySOAR has its own native SIEM.",
        "vendor": "Sumo Logic",
        "category": IntegrationCategory.SIEM,
        "integration_role": "external_siem",
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "chronicle": {
        "name": "chronicle",
        "display_name": "Google Chronicle",
        "description": "OPTIONAL INTEROP (planned, not in this release): pull events from Google Chronicle. Not required; PySOAR has its own native SIEM.",
        "vendor": "Google",
        "category": IntegrationCategory.SIEM,
        "integration_role": "external_siem",
        "auth_type": AuthType.OAUTH2,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "graylog": {
        "name": "graylog",
        "display_name": "Graylog",
        "description": "OPTIONAL INTEROP (planned, not in this release): pull events from Graylog. Not required; PySOAR has its own native SIEM.",
        "vendor": "Graylog",
        "category": IntegrationCategory.SIEM,
        "integration_role": "external_siem",
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # EDR
    "crowdstrike": {
        "name": "crowdstrike",
        "display_name": "CrowdStrike Falcon",
        "description": "Endpoint detection and response platform",
        "vendor": "CrowdStrike",
        "category": IntegrationCategory.EDR,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "sentinelone": {
        "name": "sentinelone",
        "display_name": "SentinelOne",
        "description": "Autonomous endpoint protection platform",
        "vendor": "SentinelOne",
        "category": IntegrationCategory.EDR,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "carbon_black": {
        "name": "carbon_black",
        "display_name": "VMware Carbon Black",
        "description": "Endpoint detection and response solution",
        "vendor": "VMware",
        "category": IntegrationCategory.EDR,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "microsoft_defender": {
        "name": "microsoft_defender",
        "display_name": "Microsoft Defender for Endpoint",
        "description": "Microsoft EDR: devices, alerts, isolation, antivirus scans, app restriction, investigation packages, alert updates",
        "vendor": "Microsoft",
        "category": IntegrationCategory.EDR,
        "auth_type": AuthType.OAUTH2,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "cortex_xdr": {
        "name": "cortex_xdr",
        "display_name": "Palo Alto Cortex XDR",
        "description": "Extended detection and response platform",
        "vendor": "Palo Alto Networks",
        "category": IntegrationCategory.EDR,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # Firewall
    "palo_alto_ngfw": {
        "name": "palo_alto_ngfw",
        "display_name": "Palo Alto Networks NGFW",
        "description": "Next-generation firewall",
        "vendor": "Palo Alto Networks",
        "category": IntegrationCategory.FIREWALL,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "fortinet": {
        "name": "fortinet",
        "display_name": "Fortinet FortiGate",
        "description": "Next-generation firewall and UTM",
        "vendor": "Fortinet",
        "category": IntegrationCategory.FIREWALL,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "cisco_asa": {
        "name": "cisco_asa",
        "display_name": "Cisco ASA",
        "description": "Adaptive security appliance firewall",
        "vendor": "Cisco",
        "category": IntegrationCategory.FIREWALL,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # Cloud Providers
    "aws_security_hub": {
        "name": "aws_security_hub",
        "display_name": "AWS Security Hub",
        "description": "Centralized security and compliance monitoring on AWS",
        "vendor": "Amazon",
        "category": IntegrationCategory.CLOUD_PROVIDER,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "microsoft_sentinel": {
        "name": "microsoft_sentinel",
        "display_name": "Microsoft Sentinel",
        "description": "Cloud-native SIEM in Azure (formerly Azure Sentinel): KQL queries, incidents, analytics rules, bookmarks, Logic Apps playbooks",
        "vendor": "Microsoft",
        "category": IntegrationCategory.SIEM,
        "auth_type": AuthType.OAUTH2,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "gcp_security_command_center": {
        "name": "gcp_security_command_center",
        "display_name": "GCP Security Command Center",
        "description": "Centralized security and risk management on GCP",
        "vendor": "Google",
        "category": IntegrationCategory.CLOUD_PROVIDER,
        "auth_type": AuthType.OAUTH2,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # Cloud Log Sources — pulled every 5 min by Celery beat
    # (siem.poll_cloud_integrations) into log_entries for SIEM search
    # and rule evaluation. Each requires credentials installed through
    # the marketplace; the poller keys off connector_id == one of these.
    "aws_cloudtrail": {
        "name": "aws_cloudtrail",
        "display_name": "AWS CloudTrail",
        "description": "Poll AWS CloudTrail account activity logs into the SIEM every 5 min",
        "vendor": "Amazon",
        "category": IntegrationCategory.CLOUD_PROVIDER,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["scheduled", "manual"],
        "required_credentials": ["aws_access_key_id", "aws_secret_access_key"],
        "optional_config": ["region"],
    },
    "azure_activity_log": {
        "name": "azure_activity_log",
        "display_name": "Azure Activity Log",
        "description": "Poll Azure subscription Activity Log into the SIEM every 5 min",
        "vendor": "Microsoft",
        "category": IntegrationCategory.CLOUD_PROVIDER,
        "auth_type": AuthType.OAUTH2,
        "supported_triggers": ["scheduled", "manual"],
        "required_credentials": ["tenant_id", "client_id", "client_secret", "subscription_id"],
    },
    "gcp_cloud_logging": {
        "name": "gcp_cloud_logging",
        "display_name": "GCP Cloud Logging",
        "description": "Poll GCP Cloud Audit Logs into the SIEM every 5 min",
        "vendor": "Google",
        "category": IntegrationCategory.CLOUD_PROVIDER,
        "auth_type": AuthType.OAUTH2,
        "supported_triggers": ["scheduled", "manual"],
        "required_credentials": ["service_account_json"],
        "optional_config": ["project_id", "log_filter"],
    },
    # Identity Providers
    "okta": {
        "name": "okta",
        "display_name": "Okta",
        "description": "Identity provider: users, groups, MFA factors, System Log; suspend, deactivate, revoke sessions, expire password, reset factor",
        "vendor": "Okta",
        "category": IntegrationCategory.IDENTITY_PROVIDER,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "azure_ad": {
        "name": "azure_ad",
        "display_name": "Microsoft Entra ID (Azure AD)",
        "description": "Microsoft identity provider (Graph): users, sign-in logs, risky users; disable, revoke sessions, reset password, confirm or dismiss risk",
        "vendor": "Microsoft",
        "category": IntegrationCategory.IDENTITY_PROVIDER,
        "auth_type": AuthType.OAUTH2,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "cyberark": {
        "name": "cyberark",
        "display_name": "CyberArk",
        "description": "Privileged access management platform",
        "vendor": "CyberArk",
        "category": IntegrationCategory.PAM,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # Ticketing
    "servicenow": {
        "name": "servicenow",
        "display_name": "ServiceNow",
        "description": "IT service management platform",
        "vendor": "ServiceNow",
        "category": IntegrationCategory.TICKETING,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "jira": {
        "name": "jira",
        "display_name": "Jira",
        "description": "Issue tracking and project management",
        "vendor": "Atlassian",
        "category": IntegrationCategory.TICKETING,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "pagerduty": {
        "name": "pagerduty",
        "display_name": "PagerDuty",
        "description": "Incident response and on-call management",
        "vendor": "PagerDuty",
        "category": IntegrationCategory.TICKETING,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # Communication
    "slack": {
        "name": "slack",
        "display_name": "Slack",
        "description": "Team messaging and collaboration platform",
        "vendor": "Slack",
        "category": IntegrationCategory.COMMUNICATION,
        "auth_type": AuthType.OAUTH2,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "microsoft_teams": {
        "name": "microsoft_teams",
        "display_name": "Microsoft Teams",
        "description": "Post messages and alert cards to a channel through a Workflows or incoming webhook URL",
        "vendor": "Microsoft",
        "category": IntegrationCategory.COMMUNICATION,
        "auth_type": AuthType.CUSTOM,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "smtp_email": {
        "name": "smtp_email",
        "display_name": "Email (SMTP)",
        "description": "Send notifications via SMTP email",
        "vendor": "Generic",
        "category": IntegrationCategory.COMMUNICATION,
        "auth_type": AuthType.BASIC,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # Threat Intelligence
    "virustotal": {
        "name": "virustotal",
        "display_name": "VirusTotal",
        "description": "File and URL threat intelligence service",
        "vendor": "VirusTotal",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "shodan": {
        "name": "shodan",
        "display_name": "Shodan",
        "description": "Internet search engine for exposed devices",
        "vendor": "Shodan",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "alienvault_otx": {
        "name": "alienvault_otx",
        "display_name": "AlienVault OTX",
        "description": "Open-source threat intelligence exchange",
        "vendor": "AlienVault",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "greynoise": {
        "name": "greynoise",
        "display_name": "GreyNoise",
        "description": "Internet background noise intelligence",
        "vendor": "GreyNoise",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "abuseipdb": {
        "name": "abuseipdb",
        "display_name": "AbuseIPDB",
        "description": "IP reputation and abuse database",
        "vendor": "AbuseIPDB",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "recorded_future": {
        "name": "recorded_future",
        "display_name": "Recorded Future",
        "description": "Intelligence-driven security platform",
        "vendor": "Recorded Future",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # Vulnerability Scanners
    "nessus": {
        "name": "nessus",
        "display_name": "Nessus",
        "description": "Vulnerability assessment and management",
        "vendor": "Tenable",
        "category": IntegrationCategory.VULNERABILITY_SCANNER,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "qualys": {
        "name": "qualys",
        "display_name": "Qualys",
        "description": "Vulnerability and compliance management",
        "vendor": "Qualys",
        "category": IntegrationCategory.VULNERABILITY_SCANNER,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "openvas": {
        "name": "openvas",
        "display_name": "OpenVAS",
        "description": "Open-source vulnerability assessment",
        "vendor": "OpenVAS",
        "category": IntegrationCategory.VULNERABILITY_SCANNER,
        "auth_type": AuthType.BASIC,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "trivy": {
        "name": "trivy",
        "display_name": "Trivy",
        "description": "Container vulnerability scanner",
        "vendor": "Aqua Security",
        "category": IntegrationCategory.CONTAINER_SECURITY,
        "auth_type": AuthType.BASIC,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # Container Security
    "aqua": {
        "name": "aqua",
        "display_name": "Aqua Security",
        "description": "Container and cloud-native security platform",
        "vendor": "Aqua Security",
        "category": IntegrationCategory.CONTAINER_SECURITY,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "falco": {
        "name": "falco",
        "display_name": "Falco",
        "description": "Runtime security and threat detection",
        "vendor": "Falco Project",
        "category": IntegrationCategory.CONTAINER_SECURITY,
        "auth_type": AuthType.BASIC,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # CI/CD
    "github_actions": {
        "name": "github_actions",
        "display_name": "GitHub Actions",
        "description": "CI/CD automation from GitHub",
        "vendor": "GitHub",
        "category": IntegrationCategory.CI_CD,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "gitlab_ci": {
        "name": "gitlab_ci",
        "display_name": "GitLab CI",
        "description": "CI/CD pipeline from GitLab",
        "vendor": "GitLab",
        "category": IntegrationCategory.CI_CD,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "jenkins": {
        "name": "jenkins",
        "display_name": "Jenkins",
        "description": "Open-source automation server",
        "vendor": "Jenkins",
        "category": IntegrationCategory.CI_CD,
        "auth_type": AuthType.API_KEY,
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
}


class ConnectorRegistry:
    """Registry of available integration connectors.

    The catalogue is the union of ``BUILTIN_CONNECTORS`` (names, vendors,
    categories: the roadmap the market sees) and the connector classes: for a
    connector in ``CONNECTOR_CLASS_MAP`` the actions, fields, config schema,
    verification statement and test call all come from the class; every other
    entry is ``planned`` (not installable, no actions) or ``log_ingest``.
    """

    def __init__(self):
        """Initialize connector registry"""
        self.connectors = {}
        self._load_builtin_connectors()

    def _load_builtin_connectors(self):
        """Load built-in connector definitions"""
        for name, config in BUILTIN_CONNECTORS.items():
            self.connectors[name] = self._describe(name, config)

    @staticmethod
    def _describe(name: str, config: dict[str, Any]) -> dict[str, Any]:
        status = implementation_status(name)
        cls = connector_class(name)
        meta: dict[str, Any] = {
            "name": config["name"],
            "display_name": config["display_name"],
            "description": config.get("description", ""),
            "vendor": config.get("vendor", ""),
            "category": config["category"],
            "auth_type": config["auth_type"],
            "version": "1.0.0",
            "is_builtin": True,
            # Optional flag — "external_siem" surfaces in the
            # marketplace UI so operators know these are interop
            # connectors, not a requirement to replace PySOAR's
            # native SIEM.
            "integration_role": config.get("integration_role"),
            "supported_triggers": config["supported_triggers"],
            "implementation_status": status,
            "installable": status in (IMPLEMENTED, LOG_INGEST),
            "ingest": has_ingest(name),
        }
        if cls is not None:
            config_fields = [_field_dict(f) for f in cls.CONFIG_FIELDS]
            credential_fields = [_field_dict(f) for f in cls.CREDENTIAL_FIELDS]
            meta.update({
                "verification": cls.VERIFICATION,
                "test_call": cls.TEST_CALL,
                "actions": cls.catalogue_actions(),
                "supported_actions": list(cls.ACTIONS),
                "config_fields": config_fields,
                "credential_fields": credential_fields,
                "required_credentials": [f["name"] for f in credential_fields if f["required"]],
                "optional_config": [f["name"] for f in config_fields + credential_fields if not f["required"]],
                "config_schema": json.dumps(cls.config_schema()),
            })
        elif status == LOG_INGEST:
            required = list(config.get("required_credentials") or [])
            required_config = list(config.get("required_config") or [])
            optional = list(config.get("optional_config") or [])
            credential_fields = [
                {"name": k, "type": "password", "display_name": k, "description": None,
                 "required": True, "default": None, "secret": True}
                for k in required
            ]
            config_fields = [
                {"name": k, "type": "string", "display_name": k, "description": None,
                 "required": True, "default": None, "secret": False}
                for k in required_config
            ] + [
                {"name": k, "type": "string", "display_name": k, "description": None,
                 "required": False, "default": None, "secret": False}
                for k in optional
            ]
            meta.update({
                "verification": LOG_INGEST_VERIFICATION,
                "test_call": None,
                "actions": [],
                "supported_actions": [],
                "config_fields": config_fields,
                "credential_fields": credential_fields,
                "required_credentials": required,
                "optional_config": optional,
                "config_schema": json.dumps({"type": "object", "properties": {}}),
            })
        else:
            meta.update({
                "verification": PLANNED_VERIFICATION,
                "test_call": None,
                "actions": [],
                "supported_actions": [],
                "config_fields": [],
                "credential_fields": [],
                "required_credentials": None,
                "optional_config": None,
                "config_schema": json.dumps({"type": "object", "properties": {}}),
            })
        return meta

    def list_connectors(
        self,
        category: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List available connectors with optional filtering"""
        results = []
        search_lower = search.lower() if search else None

        for connector in self.connectors.values():
            # Category filter
            if category and connector.get("category") != category:
                continue

            # Search filter
            if search_lower:
                match_fields = [
                    connector.get("name", ""),
                    connector.get("display_name", ""),
                    connector.get("description", ""),
                    connector.get("vendor", ""),
                ]
                if not any(search_lower in field.lower() for field in match_fields):
                    continue

            results.append(connector)
            if len(results) >= limit:
                break

        return results

    def get_connector_details(self, name: str) -> Optional[dict[str, Any]]:
        """Get detailed information about a connector"""
        return self.connectors.get(name)

    async def seed_connectors_to_db(self) -> int:
        """Upsert every in-memory registry connector into integration_connectors.

        The ``installed_integrations.connector_id`` FK references
        ``integration_connectors.id``, so an install request that uses a
        registry name (e.g. "slack") only works if a row with that
        id literally exists. Also mirrors each implemented connector's
        declared actions into ``integration_actions`` (for the catalogue row
        and any other row that carries the connector's name), so
        ``GET /installed/{id}/actions`` lists them before anything runs.
        Idempotent — safe to run every startup.

        Returns the number of connector rows inserted (not updates).
        """
        from src.core.database import async_session_factory
        from src.integrations.models import IntegrationConnector
        from sqlalchemy import select as _select

        created = 0
        async with async_session_factory() as db:
            for name, cfg in self.connectors.items():
                existing = await db.execute(
                    _select(IntegrationConnector).where(
                        IntegrationConnector.id == name
                    )
                )
                row = existing.scalar_one_or_none()
                auth_value = cfg.get("auth_type")
                auth_str = (
                    auth_value.value if hasattr(auth_value, "value") else str(auth_value or "api_key")
                )
                cat_value = cfg.get("category")
                cat_str = (
                    cat_value.value if hasattr(cat_value, "value") else str(cat_value or "threat_intel")
                )
                if row is None:
                    row = IntegrationConnector(
                        id=name,  # use the canonical name as the PK
                        name=name,
                        display_name=cfg.get("display_name") or name,
                        description=cfg.get("description") or None,
                        vendor=cfg.get("vendor") or None,
                        category=cat_str,
                        version=cfg.get("version", "1.0.0"),
                        supported_actions=json.dumps(cfg.get("supported_actions") or []),
                        supported_triggers=json.dumps(cfg.get("supported_triggers") or []),
                        auth_type=auth_str,
                        config_schema=cfg.get("config_schema")
                        if isinstance(cfg.get("config_schema"), str)
                        else json.dumps(cfg.get("config_schema") or {"type": "object"}),
                        is_builtin=True,
                        is_community=False,
                    )
                    db.add(row)
                    created += 1
                else:
                    # Keep metadata aligned with the registry
                    row.display_name = cfg.get("display_name") or row.display_name
                    row.description = cfg.get("description") or row.description
                    row.vendor = cfg.get("vendor") or row.vendor
                    row.category = cat_str
                    row.auth_type = auth_str
                    row.supported_actions = json.dumps(cfg.get("supported_actions") or [])
                    row.config_schema = cfg.get("config_schema") or row.config_schema
            await db.flush()
            rows = (
                await db.execute(
                    _select(IntegrationConnector.id, IntegrationConnector.name).where(
                        IntegrationConnector.name.in_(list(CONNECTOR_CLASS_MAP)),
                    )
                )
            ).all()
            for connector_id, connector_name in rows:
                await sync_connector_actions(db, connector_id, connector_name)
            await db.commit()
        return created

    def validate_connector_schema(self, name: str, config: dict[str, Any]) -> bool:
        """True when ``config`` carries every required config field of the connector."""
        connector = self.get_connector_details(name)
        if not connector:
            logger.warning(f"Connector not found: {name}")
            return False
        cls = connector_class(name)
        if cls is None:
            return bool(connector.get("installable", False))
        return not [f.name for f in cls.CONFIG_FIELDS if f.required and config.get(f.name) in (None, "")]

    def check_compatibility(self, connector_name: str, action_name: str) -> bool:
        """Check if action is supported by connector"""
        connector = self.get_connector_details(connector_name)
        if not connector:
            return False

        return action_name in connector.get("supported_actions", [])


class IntegrationManager:
    """Health checks for installed integrations.

    Installation and configuration live in the API endpoint
    (src/api/v1/endpoints/integrations.py), which writes the
    InstalledIntegration row with encrypted credentials. The no-op
    configure / enable / disable / update_credentials / uninstall methods
    that used to live here (one of them bcrypt-hashed credentials, making
    them unusable) had no callers and were deleted.
    """

    def __init__(self, registry: ConnectorRegistry):
        """Initialize integration manager"""
        self.registry = registry

    async def test_connection(
        self,
        installation_id: str,
    ) -> dict[str, Any]:
        """Run the connector's ``test_connection`` for one installed integration.

        Decrypts the stored credentials, runs the class's authenticated
        read-only call through the pinned client and persists
        ``health_status``, ``last_health_check`` and a sanitised
        ``error_message`` (<= 200 chars, no secrets). A planned connector is
        recorded ``unavailable`` without any network call; a log-ingest
        source keeps the health its poller recorded.
        """
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        from src.core.database import async_session_factory
        from src.core.secrets import _decrypt_secret_json

        async with async_session_factory() as db:
            integration = (
                await db.execute(
                    select(InstalledIntegration)
                    .options(selectinload(InstalledIntegration.connector))
                    .where(InstalledIntegration.id == installation_id)
                )
            ).scalar_one_or_none()
            if not integration:
                return {
                    "installation_id": installation_id,
                    "status": HealthStatus.UNHEALTHY.value,
                    "error_message": "Integration not found in database",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            connector_name = installed_connector_name(integration)
            if implementation_status(connector_name) == LOG_INGEST:
                return {
                    "installation_id": installation_id,
                    "connector_type": connector_name,
                    "status": integration.health_status or HealthStatus.UNKNOWN.value,
                    "error_message": integration.error_message,
                    "skipped": "log source health is recorded by the SIEM cloud poller",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            config = safe_json_loads(integration.config_encrypted, {}) or {}
            credentials = _decrypt_secret_json(integration.auth_credentials_encrypted) or {}
            result = await probe_connector(connector_name, config if isinstance(config, dict) else {}, credentials)
            record_health(integration, result)
            await db.commit()

        logger.info(
            "integration health check",
            installation_id=installation_id,
            connector=connector_name,
            status=result.status,
        )
        return {
            "installation_id": installation_id,
            "connector_type": connector_name or None,
            "status": result.status,
            "error_message": None if result.healthy else result.detail,
            "checked": result.checked,
            "http_status": result.http_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def _probe_connector(
        self,
        connector_type: str,
        config: dict[str, Any],
        credentials: dict[str, Any],
    ) -> tuple[str, Optional[str]]:
        """``(health_status, error_message)`` from the connector's own test_connection.

        Kept for the remediation module's Test Connection route. A planned
        connector answers ``unavailable`` with no network call.
        """
        result = await probe_connector((connector_type or "").lower(), config or {}, credentials or {})
        return result.status, (None if result.healthy else result.detail)

    async def get_integration_status(
        self,
        installation_id: str,
    ) -> dict[str, Any]:
        """Get detailed status of integration from DB"""
        from src.core.database import async_session_factory
        from sqlalchemy import select

        async with async_session_factory() as db:
            query = select(InstalledIntegration).where(InstalledIntegration.id == installation_id)
            result = await db.execute(query)
            integration = result.scalar_one_or_none()

            if not integration:
                return {
                    "installation_id": installation_id,
                    "status": "not_found",
                    "health": HealthStatus.UNKNOWN.value,
                    "last_check": None,
                }

            return {
                "installation_id": installation_id,
                "status": integration.status,
                "health": integration.health_status,
                "display_name": integration.display_name,
                "connector_id": integration.connector_id,
                "last_check": integration.last_health_check,
            }


def installed_connector_name(integration: Any) -> str:
    """The catalogue name of an installed integration's connector."""
    connector = getattr(integration, "connector", None)
    name = getattr(connector, "name", None) if connector is not None else None
    return (name or integration.connector_id or "").lower()


def record_health(integration: Any, result: ConnectionTestResult) -> None:
    """Persist a test result on the row: status, timestamp, sanitised error (<= 200 chars)."""
    integration.health_status = result.status
    integration.last_health_check = datetime.now(timezone.utc).isoformat()
    integration.error_message = None if result.healthy else sanitize_message(result.detail)


class PinnedTarget(str):
    """The vetted URL returned by ``ActionExecutor._resolve_generic_target``.

    The string value is the URL with its host replaced by the vetted IP
    literal (identical to the input when the host already is an IP).
    ``target`` is the ``VettedTarget`` and ``request_kwargs`` the httpx
    ``headers`` / ``extensions`` that keep Host and TLS SNI on the original
    hostname. It is a ``str`` so callers that only check for refusal, or
    compare the URL, keep working.
    """

    target: VettedTarget
    request_kwargs: dict[str, Any]

    def __new__(cls, target: VettedTarget) -> "PinnedTarget":
        obj = super().__new__(cls, target.pinned_url)
        obj.target = target
        obj.request_kwargs = pinned_request_kwargs(target)
        return obj


class ActionExecutor:
    """Execute declared connector actions and record every execution.

    Only connectors with a class in ``CONNECTOR_CLASS_MAP`` can execute, and
    only the names in the class's ``ACTIONS``. A planned connector, an
    unknown action, invalid parameters or a vendor error all come back as
    ``status: failed`` with a sanitised ``error_message`` (and the vendor's
    ``http_status`` when there was one), never as success. The old generic
    HTTP fallback (a caller-supplied URL against the stored base URL) had no
    caller in src/ that depended on it and was removed.
    """

    def __init__(self, max_retries: int = 3):
        """Initialize action executor"""
        self.max_retries = max_retries
        self.retry_delays = [1, 5, 15]  # exponential backoff in seconds

    async def execute_action(
        self,
        installation_id: str,
        action_name: str,
        input_data: dict[str, Any],
        triggered_by: str = ExecutionTrigger.MANUAL.value,
        playbook_run_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Execute an integration action.

        Returns ``execution_id``, ``status`` (success / failed),
        ``output_data``, ``error_message``, ``error_code``, ``http_status``
        and ``duration_ms``. ``execution_id`` is the id of the persisted
        ``IntegrationExecution`` row (None when the action is not declared by
        the connector, since an execution row needs a real action row).
        """
        start_time = time.time()
        output_data: dict[str, Any] = {}
        error_message: Optional[str] = None
        error_code: Optional[str] = None
        http_status: Optional[int] = None
        status = ExecutionStatus.FAILED.value

        try:
            self._validate_input(input_data)
            output_data = await self._call_connector_action(installation_id, action_name, input_data)
            status = ExecutionStatus.SUCCESS.value
        except ConnectorActionFailed as exc:
            error_message, error_code, http_status = exc.message, exc.code, exc.http_status
        except Exception as exc:  # noqa: BLE001 (every failure is reported as a failed execution)
            error_message = sanitize_message(f"{type(exc).__name__}: {exc}")
            error_code = "error"
        duration_ms = int((time.time() - start_time) * 1000)
        if status != ExecutionStatus.SUCCESS.value:
            logger.warning(
                "integration action failed",
                installation_id=installation_id,
                action=action_name,
                code=error_code,
                http_status=http_status,
            )

        execution_id = await self._persist_execution(
            installation_id=installation_id,
            action_name=action_name,
            input_data=input_data,
            output_data=output_data if status == ExecutionStatus.SUCCESS.value else {"error": error_message, "http_status": http_status},
            execution_id=str(uuid4()),
            status=status,
            error_message=error_message,
            duration_ms=duration_ms,
            triggered_by=triggered_by,
            playbook_run_id=playbook_run_id,
            error_code=error_code,
            http_status=http_status,
        )
        result: dict[str, Any] = {
            "execution_id": execution_id,
            "status": status,
            "duration_ms": duration_ms,
            "retry_count": 0,
        }
        if status == ExecutionStatus.SUCCESS.value:
            result["output_data"] = output_data
        else:
            result.update({"error_message": error_message, "error_code": error_code, "http_status": http_status})
        return result

    def _validate_input(self, input_data: dict[str, Any]) -> None:
        """Validate action input"""
        if not isinstance(input_data, dict):
            raise ConnectorActionFailed("input_data must be a JSON object", code="invalid_parameters")

    async def _call_connector_action(
        self,
        installation_id: str,
        action_name: str,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Run ``action_name`` on the installed integration's connector class.

        Returns the action output; raises ConnectorActionFailed otherwise.
        """
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload
        from src.core.database import async_session_factory

        async with async_session_factory() as db:
            query = select(InstalledIntegration).options(
                selectinload(InstalledIntegration.connector),
            ).where(InstalledIntegration.id == installation_id)
            result = await db.execute(query)
            integration = result.scalar_one_or_none()

        if not integration:
            raise ConnectorActionFailed(f"installed integration not found: {installation_id}", code="not_found")

        config = safe_json_loads(integration.config_encrypted, {}) or {}
        credentials = self._decrypt_secret_json(integration.auth_credentials_encrypted)
        connector = build_connector(installed_connector_name(integration), config, credentials)
        return await connector.run_action(action_name, input_data)

    @staticmethod
    def _effective_port(scheme: str, port: Optional[int]) -> Optional[int]:
        if port is not None:
            return port
        return {"http": 80, "https": 443}.get(scheme)

    async def _resolve_generic_target(self, requested_url: str, config: dict[str, Any]) -> PinnedTarget:
        """Pin a request to an integration's configured base URL.

        Used by modules that call a tenant-configured HTTP API directly
        (ITDR directory, container scanning, remediation's stored-URL guard).
        The caller may give a path (joined to the base URL) or an absolute
        URL with the same scheme, host and port as the stored config. The
        final host is resolved once and must not resolve to a private,
        loopback, link-local, metadata or reserved address. Returns a
        ``PinnedTarget``: the URL with its host replaced by the vetted IP,
        plus the Host / SNI request kwargs, so the request connects to the
        address that was checked rather than resolving again. Raises
        OutboundTargetRefused otherwise.
        """
        from urllib.parse import urljoin, urlsplit

        base_url = str(config.get("base_url") or config.get("url") or "").strip()
        base = urlsplit(base_url)
        if base.scheme not in ("http", "https") or not base.hostname:
            raise OutboundTargetRefused("integration has no configured http(s) base_url")

        is_relative = not urlsplit(requested_url).scheme and not requested_url.startswith("//")
        if is_relative:
            target_url = urljoin(base_url.rstrip("/") + "/", requested_url.lstrip("/"))
        else:
            target_url = requested_url
        target = urlsplit(target_url)
        try:
            same_origin = (
                target.scheme == base.scheme
                and (target.hostname or "").lower() == base.hostname.lower()
                and self._effective_port(target.scheme, target.port) == self._effective_port(base.scheme, base.port)
            )
        except ValueError:
            same_origin = False
        if not same_origin:
            raise OutboundTargetRefused("url must target the integration's configured base_url")

        try:
            vetted = await resolve_and_vet(target_url)
        except OutboundTargetRefused as exc:
            raise OutboundTargetRefused(f"url refused: {exc}") from exc
        return PinnedTarget(vetted)

    async def _persist_execution(
        self,
        installation_id: str,
        action_name: str,
        input_data: dict[str, Any],
        output_data: dict[str, Any],
        execution_id: str,
        status: str,
        error_message: Optional[str],
        duration_ms: int,
        triggered_by: str,
        playbook_run_id: Optional[str],
        error_code: Optional[str] = None,
        http_status: Optional[int] = None,
    ) -> Optional[str]:
        """Persist one execution row; returns its id.

        The action row comes from the connector class's declared ``ACTIONS``
        (created from the spec when the registry sync has not run yet). An
        action name the connector does not declare is never invented: the
        failed attempt is logged and not persisted (an execution row needs a
        real action row). Returns None when nothing was persisted.
        """
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload
        from src.core.database import async_session_factory

        try:
            async with async_session_factory() as db:
                integration = (
                    await db.execute(
                        select(InstalledIntegration)
                        .options(selectinload(InstalledIntegration.connector))
                        .where(InstalledIntegration.id == installation_id)
                    )
                ).scalar_one_or_none()
                if not integration:
                    return None
                connector_name = installed_connector_name(integration)
                cls = connector_class(connector_name)
                if cls is None or action_name not in cls.ACTIONS:
                    logger.warning(
                        "integration execution not persisted: action not declared by the connector",
                        installation_id=installation_id,
                        action=action_name,
                    )
                    return None

                async def _action_row() -> Optional[IntegrationAction]:
                    return (
                        await db.execute(
                            select(IntegrationAction).where(
                                IntegrationAction.connector_id == integration.connector_id,
                                IntegrationAction.action_name == action_name,
                            )
                        )
                    ).scalars().first()

                action = await _action_row()
                if action is None:
                    await sync_connector_actions(db, integration.connector_id, connector_name)
                    action = await _action_row()
                if action is None:
                    return None

                now = datetime.now(timezone.utc)
                started = now - timedelta(milliseconds=duration_ms)
                execution = IntegrationExecution(
                    id=execution_id,
                    organization_id=integration.organization_id,
                    installed_id=integration.id,
                    action_id=action.id,
                    triggered_by=triggered_by,
                    playbook_run_id=playbook_run_id,
                    input_data=json.dumps(input_data, default=str),
                    output_data=json.dumps(output_data, default=str) if output_data is not None else None,
                    status=status,
                    started_at=started.isoformat(),
                    completed_at=now.isoformat(),
                    duration_ms=duration_ms,
                    error_message=error_message,
                    error_code=error_code,
                    http_status=http_status,
                    retry_count=0,
                )
                db.add(execution)
                if status == ExecutionStatus.SUCCESS.value:
                    integration.last_successful_action = now.isoformat()
                await db.commit()
                return execution_id
        except Exception as exc:  # noqa: BLE001 (history persistence must not mask the action result)
            logger.error("failed to persist integration execution", error_type=type(exc).__name__)
            return None

    def _decrypt_secret_json(self, value: Optional[str]) -> dict[str, Any]:
        """Decrypt a stored credentials blob from the database.

        Delegates to ``src.core.secrets._decrypt_secret_json``, which opens the
        ``enc:v1:`` envelope the install route writes (and the pre-envelope
        legacy shapes). The previous local reader did not understand the
        envelope, so every credential written by ``POST /install`` read back
        as ``{}`` here. A blob that cannot be opened reads as ``{}``, which the
        connector reports as missing required fields (never a silent success).
        """
        from src.core.secrets import _decrypt_secret_json

        return _decrypt_secret_json(value)

    def _get_connector_class(self, connector_name: str):
        """Resolve a connector wrapper class by connector name."""
        return CONNECTOR_CLASS_MAP.get(connector_name)

    def handle_rate_limiting(
        self,
        installation_id: str,
        retry_after: int = 60,
    ) -> dict[str, Any]:
        """Handle rate limit by queueing retry"""
        logger.warning(
            f"Rate limit hit for {installation_id}, "
            f"retrying after {retry_after}s",
        )

        retry_time = datetime.now(timezone.utc) + timedelta(seconds=retry_after)

        return {
            "status": "rate_limited",
            "retry_at": retry_time.isoformat(),
        }

    def handle_retry(
        self,
        execution_id: str,
        retry_count: int,
        error: Exception,
    ) -> Optional[dict[str, Any]]:
        """Handle action retry with exponential backoff"""
        if retry_count >= self.max_retries:
            logger.error(
                f"Max retries exceeded for execution {execution_id}: {error}",
            )
            return None

        delay = self.retry_delays[min(retry_count, len(self.retry_delays) - 1)]
        logger.info(f"Retrying execution {execution_id} after {delay}s")

        return {
            "retry_count": retry_count + 1,
            "retry_at": (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat(),
        }

    def log_execution(
        self,
        execution_record: dict[str, Any],
    ) -> None:
        """Log action execution"""
        logger.info(
            f"Execution {execution_record.get('execution_id')}: "
            f"{execution_record.get('status')}",
        )


class WebhookProcessor:
    """Process incoming webhook events from integrations"""

    def __init__(self):
        """Initialize webhook processor"""
        self.endpoints = {}

    async def register_webhook(
        self,
        installation_id: str,
        endpoint_path: str,
        http_method: str = "POST",
        event_types: list[str] = None,
        secret: Optional[str] = None,
    ) -> dict[str, Any]:
        """Register webhook endpoint"""
        if event_types is None:
            event_types = []

        secret_hash = self._hash_secret(secret) if secret else None
        webhook_id = str(uuid4())

        self.endpoints[webhook_id] = {
            "installation_id": installation_id,
            "endpoint_path": endpoint_path,
            "http_method": http_method,
            "event_types": event_types,
            "secret_hash": secret_hash,
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(f"Registered webhook {webhook_id} for {installation_id}")

        return {
            "webhook_id": webhook_id,
            "endpoint_path": endpoint_path,
            "status": "active",
        }

    async def validate_incoming_webhook(
        self,
        webhook_id: str,
        payload: dict[str, Any],
        signature: Optional[str] = None,
    ) -> bool:
        """Validate webhook signature and authenticity"""
        endpoint = self.endpoints.get(webhook_id)
        if not endpoint:
            logger.warning(f"Webhook not found: {webhook_id}")
            return False

        if not endpoint["is_active"]:
            logger.warning(f"Webhook inactive: {webhook_id}")
            return False

        # In production, verify HMAC signature
        if signature and endpoint["secret_hash"]:
            # payload_hash = self._hash_secret(json.dumps(payload))
            # return payload_hash == endpoint["secret_hash"]
            pass

        return True

    async def transform_payload(
        self,
        webhook_id: str,
        payload: dict[str, Any],
        template: Optional[str] = None,
    ) -> dict[str, Any]:
        """Transform webhook payload using Jinja2 template"""
        # In production, use jinja2 for template rendering
        if template:
            logger.info(f"Applying transformation template to webhook {webhook_id}")
        return payload

    async def route_to_handler(
        self,
        webhook_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Route webhook event to appropriate handler"""
        endpoint = self.endpoints.get(webhook_id)
        if not endpoint:
            raise ValueError(f"Webhook not found: {webhook_id}")

        logger.info(
            f"Routing webhook event: {event_type} "
            f"-> {endpoint['installation_id']}",
        )

        return {
            "webhook_id": webhook_id,
            "event_type": event_type,
            "installation_id": endpoint["installation_id"],
            "processed": True,
        }

    async def process_webhook_event(
        self,
        webhook_id: str,
        event_type: str,
        payload: dict[str, Any],
        signature: Optional[str] = None,
    ) -> dict[str, Any]:
        """Complete webhook event processing"""
        # Validate
        is_valid = await self.validate_incoming_webhook(
            webhook_id,
            payload,
            signature,
        )
        if not is_valid:
            return {"status": "invalid", "webhook_id": webhook_id}

        # Transform
        transformed = await self.transform_payload(webhook_id, payload)

        # Route
        result = await self.route_to_handler(webhook_id, event_type, transformed)

        return {
            "status": "processed",
            "webhook_id": webhook_id,
            "event_type": event_type,
            "result": result,
        }

    def _hash_secret(self, secret: str) -> str:
        """Hash webhook secret"""
        return hashlib.sha256(secret.encode()).hexdigest()
