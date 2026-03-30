"""Integration engine with connector registry, action execution, and webhook processing"""

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

from src.core.logging import get_logger
from src.integrations.models import (
    ActionType,
    AuthType,
    ExecutionStatus,
    ExecutionTrigger,
    HealthStatus,
    IntegrationAction,
    IntegrationCategory,
    IntegrationConnector,
    IntegrationExecution,
    InstalledIntegration,
    WebhookEndpoint,
)

logger = get_logger(__name__)


# Built-in connector definitions
BUILTIN_CONNECTORS = {
    # SIEM
    "splunk": {
        "name": "splunk",
        "display_name": "Splunk Enterprise",
        "description": "SIEM and data platform for security analytics",
        "vendor": "Splunk",
        "category": IntegrationCategory.SIEM,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "search", "create_alert"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "qradar": {
        "name": "qradar",
        "display_name": "IBM QRadar",
        "description": "Enterprise SIEM for threat detection and response",
        "vendor": "IBM",
        "category": IntegrationCategory.SIEM,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "create_offense", "close_offense"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "elastic": {
        "name": "elastic",
        "display_name": "Elastic Security",
        "description": "Elastic Stack with security analytics and threat hunting",
        "vendor": "Elastic",
        "category": IntegrationCategory.SIEM,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "search", "create_detection"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "wazuh": {
        "name": "wazuh",
        "display_name": "Wazuh",
        "description": "Open-source security monitoring and incident response",
        "vendor": "Wazuh",
        "category": IntegrationCategory.SIEM,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "create_group", "run_agent_command"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "sumo_logic": {
        "name": "sumo_logic",
        "display_name": "Sumo Logic",
        "description": "Cloud-native SIEM and log analytics platform",
        "vendor": "Sumo Logic",
        "category": IntegrationCategory.SIEM,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "create_alert", "search"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "chronicle": {
        "name": "chronicle",
        "display_name": "Google Chronicle",
        "description": "Cloud-native SIEM for threat detection and investigation",
        "vendor": "Google",
        "category": IntegrationCategory.SIEM,
        "auth_type": AuthType.OAUTH2,
        "supported_actions": ["query", "enrich", "search"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "graylog": {
        "name": "graylog",
        "display_name": "Graylog",
        "description": "Open-source log management and SIEM platform",
        "vendor": "Graylog",
        "category": IntegrationCategory.SIEM,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "search", "create_alert"],
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
        "supported_actions": ["query", "contain", "remediate"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "sentinelone": {
        "name": "sentinelone",
        "display_name": "SentinelOne",
        "description": "Autonomous endpoint protection platform",
        "vendor": "SentinelOne",
        "category": IntegrationCategory.EDR,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "contain", "isolate"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "carbon_black": {
        "name": "carbon_black",
        "display_name": "VMware Carbon Black",
        "description": "Endpoint detection and response solution",
        "vendor": "VMware",
        "category": IntegrationCategory.EDR,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "contain", "quarantine"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "microsoft_defender": {
        "name": "microsoft_defender",
        "display_name": "Microsoft Defender for Endpoint",
        "description": "Endpoint detection and response from Microsoft",
        "vendor": "Microsoft",
        "category": IntegrationCategory.EDR,
        "auth_type": AuthType.OAUTH2,
        "supported_actions": ["query", "contain", "isolate"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "cortex_xdr": {
        "name": "cortex_xdr",
        "display_name": "Palo Alto Cortex XDR",
        "description": "Extended detection and response platform",
        "vendor": "Palo Alto Networks",
        "category": IntegrationCategory.EDR,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "contain", "isolate"],
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
        "supported_actions": ["create", "delete", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "fortinet": {
        "name": "fortinet",
        "display_name": "Fortinet FortiGate",
        "description": "Next-generation firewall and UTM",
        "vendor": "Fortinet",
        "category": IntegrationCategory.FIREWALL,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["create", "delete", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "cisco_asa": {
        "name": "cisco_asa",
        "display_name": "Cisco ASA",
        "description": "Adaptive security appliance firewall",
        "vendor": "Cisco",
        "category": IntegrationCategory.FIREWALL,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["create", "delete", "query"],
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
        "supported_actions": ["query", "create", "update"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "azure_sentinel": {
        "name": "azure_sentinel",
        "display_name": "Azure Sentinel",
        "description": "Cloud-native SIEM in Azure",
        "vendor": "Microsoft",
        "category": IntegrationCategory.CLOUD_PROVIDER,
        "auth_type": AuthType.OAUTH2,
        "supported_actions": ["query", "create", "update"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "gcp_security_command_center": {
        "name": "gcp_security_command_center",
        "display_name": "GCP Security Command Center",
        "description": "Centralized security and risk management on GCP",
        "vendor": "Google",
        "category": IntegrationCategory.CLOUD_PROVIDER,
        "auth_type": AuthType.OAUTH2,
        "supported_actions": ["query", "create", "update"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    # Identity Providers
    "okta": {
        "name": "okta",
        "display_name": "Okta",
        "description": "Identity and access management platform",
        "vendor": "Okta",
        "category": IntegrationCategory.IDENTITY_PROVIDER,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "disable_user", "reset_password"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "azure_ad": {
        "name": "azure_ad",
        "display_name": "Azure Active Directory",
        "description": "Identity and access management from Microsoft",
        "vendor": "Microsoft",
        "category": IntegrationCategory.IDENTITY_PROVIDER,
        "auth_type": AuthType.OAUTH2,
        "supported_actions": ["query", "disable_user", "reset_password"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "cyberark": {
        "name": "cyberark",
        "display_name": "CyberArk",
        "description": "Privileged access management platform",
        "vendor": "CyberArk",
        "category": IntegrationCategory.PAM,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["query", "create", "revoke"],
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
        "supported_actions": ["create", "update", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "jira": {
        "name": "jira",
        "display_name": "Jira",
        "description": "Issue tracking and project management",
        "vendor": "Atlassian",
        "category": IntegrationCategory.TICKETING,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["create", "update", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "pagerduty": {
        "name": "pagerduty",
        "display_name": "PagerDuty",
        "description": "Incident response and on-call management",
        "vendor": "PagerDuty",
        "category": IntegrationCategory.TICKETING,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["create", "update", "acknowledge"],
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
        "supported_actions": ["notify", "create_channel", "send_message"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "microsoft_teams": {
        "name": "microsoft_teams",
        "display_name": "Microsoft Teams",
        "description": "Unified communication and collaboration platform",
        "vendor": "Microsoft",
        "category": IntegrationCategory.COMMUNICATION,
        "auth_type": AuthType.OAUTH2,
        "supported_actions": ["notify", "send_message"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "smtp_email": {
        "name": "smtp_email",
        "display_name": "Email (SMTP)",
        "description": "Send notifications via SMTP email",
        "vendor": "Generic",
        "category": IntegrationCategory.COMMUNICATION,
        "auth_type": AuthType.BASIC,
        "supported_actions": ["notify"],
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
        "supported_actions": ["enrich", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "shodan": {
        "name": "shodan",
        "display_name": "Shodan",
        "description": "Internet search engine for exposed devices",
        "vendor": "Shodan",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["enrich", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "alienvault_otx": {
        "name": "alienvault_otx",
        "display_name": "AlienVault OTX",
        "description": "Open-source threat intelligence exchange",
        "vendor": "AlienVault",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["enrich", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "greynoise": {
        "name": "greynoise",
        "display_name": "GreyNoise",
        "description": "Internet background noise intelligence",
        "vendor": "GreyNoise",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["enrich", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "abuseipdb": {
        "name": "abuseipdb",
        "display_name": "AbuseIPDB",
        "description": "IP reputation and abuse database",
        "vendor": "AbuseIPDB",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["enrich", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "recorded_future": {
        "name": "recorded_future",
        "display_name": "Recorded Future",
        "description": "Intelligence-driven security platform",
        "vendor": "Recorded Future",
        "category": IntegrationCategory.THREAT_INTEL,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["enrich", "query"],
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
        "supported_actions": ["scan", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "qualys": {
        "name": "qualys",
        "display_name": "Qualys",
        "description": "Vulnerability and compliance management",
        "vendor": "Qualys",
        "category": IntegrationCategory.VULNERABILITY_SCANNER,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["scan", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "openvas": {
        "name": "openvas",
        "display_name": "OpenVAS",
        "description": "Open-source vulnerability assessment",
        "vendor": "OpenVAS",
        "category": IntegrationCategory.VULNERABILITY_SCANNER,
        "auth_type": AuthType.BASIC,
        "supported_actions": ["scan", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "trivy": {
        "name": "trivy",
        "display_name": "Trivy",
        "description": "Container vulnerability scanner",
        "vendor": "Aqua Security",
        "category": IntegrationCategory.CONTAINER_SECURITY,
        "auth_type": AuthType.BASIC,
        "supported_actions": ["scan", "export"],
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
        "supported_actions": ["scan", "contain", "remediate"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "falco": {
        "name": "falco",
        "display_name": "Falco",
        "description": "Runtime security and threat detection",
        "vendor": "Falco Project",
        "category": IntegrationCategory.CONTAINER_SECURITY,
        "auth_type": AuthType.BASIC,
        "supported_actions": ["query", "notify"],
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
        "supported_actions": ["trigger", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "gitlab_ci": {
        "name": "gitlab_ci",
        "display_name": "GitLab CI",
        "description": "CI/CD pipeline from GitLab",
        "vendor": "GitLab",
        "category": IntegrationCategory.CI_CD,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["trigger", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
    "jenkins": {
        "name": "jenkins",
        "display_name": "Jenkins",
        "description": "Open-source automation server",
        "vendor": "Jenkins",
        "category": IntegrationCategory.CI_CD,
        "auth_type": AuthType.API_KEY,
        "supported_actions": ["trigger", "query"],
        "supported_triggers": ["manual", "scheduled", "webhook"],
    },
}


class ConnectorRegistry:
    """Registry of available integration connectors"""

    def __init__(self):
        """Initialize connector registry"""
        self.connectors = {}
        self._load_builtin_connectors()

    def _load_builtin_connectors(self):
        """Load built-in connector definitions"""
        for name, config in BUILTIN_CONNECTORS.items():
            self.connectors[name] = {
                "name": config["name"],
                "display_name": config["display_name"],
                "description": config.get("description", ""),
                "vendor": config.get("vendor", ""),
                "category": config["category"],
                "auth_type": config["auth_type"],
                "version": "1.0.0",
                "is_builtin": True,
                "supported_actions": config["supported_actions"],
                "supported_triggers": config["supported_triggers"],
                "config_schema": json.dumps({"type": "object", "properties": {}}),
            }

    def register_connector(
        self,
        name: str,
        config: dict[str, Any],
    ) -> None:
        """Register a connector"""
        self.connectors[name] = config
        logger.info(f"Registered connector: {name}")

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

    def validate_connector_schema(self, name: str, config: dict[str, Any]) -> bool:
        """Validate configuration against connector schema"""
        connector = self.get_connector_details(name)
        if not connector:
            logger.warning(f"Connector not found: {name}")
            return False

        # Basic validation - in production, use jsonschema
        return True

    def check_compatibility(self, connector_name: str, action_name: str) -> bool:
        """Check if action is supported by connector"""
        connector = self.get_connector_details(connector_name)
        if not connector:
            return False

        return action_name in connector.get("supported_actions", [])


class IntegrationManager:
    """Manage installed integrations lifecycle"""

    def __init__(self, registry: ConnectorRegistry):
        """Initialize integration manager"""
        self.registry = registry

    async def install_connector(
        self,
        organization_id: str,
        connector_name: str,
        display_name: str,
        config: dict[str, Any],
        credentials: dict[str, Any],
    ) -> dict[str, Any]:
        """Install and configure a connector"""
        # Validate connector exists
        connector_meta = self.registry.get_connector_details(connector_name)
        if not connector_meta:
            raise ValueError(f"Connector not found: {connector_name}")

        # Validate configuration
        if not self.registry.validate_connector_schema(connector_name, config):
            raise ValueError(f"Invalid configuration for {connector_name}")

        # Simulate encryption (in production, use encryption library)
        config_encrypted = json.dumps(config)
        creds_encrypted = json.dumps(credentials)

        logger.info(
            f"Installed {connector_name} for organization {organization_id}",
        )

        return {
            "status": "success",
            "connector": connector_name,
            "display_name": display_name,
            "organization_id": organization_id,
        }

    async def configure_integration(
        self,
        installation_id: str,
        config: dict[str, Any],
        credentials: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Update configuration of installed integration"""
        # Simulate configuration update
        logger.info(f"Configured integration {installation_id}")

        return {
            "status": "success",
            "installation_id": installation_id,
        }

    async def test_connection(
        self,
        installation_id: str,
    ) -> dict[str, Any]:
        """Test health of installed integration"""
        # Simulate health check
        health_status = "healthy"
        error_message = None

        logger.info(f"Health check for {installation_id}: {health_status}")

        return {
            "installation_id": installation_id,
            "status": health_status,
            "error_message": error_message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def enable_integration(
        self,
        installation_id: str,
    ) -> dict[str, Any]:
        """Enable integration"""
        logger.info(f"Enabled integration {installation_id}")
        return {
            "installation_id": installation_id,
            "status": "active",
        }

    async def disable_integration(
        self,
        installation_id: str,
    ) -> dict[str, Any]:
        """Disable integration"""
        logger.info(f"Disabled integration {installation_id}")
        return {
            "installation_id": installation_id,
            "status": "inactive",
        }

    async def update_credentials(
        self,
        installation_id: str,
        credentials: dict[str, Any],
    ) -> dict[str, Any]:
        """Update credentials for integration"""
        logger.info(f"Updated credentials for integration {installation_id}")
        return {
            "installation_id": installation_id,
            "status": "success",
        }

    async def uninstall_integration(
        self,
        installation_id: str,
    ) -> dict[str, Any]:
        """Uninstall integration"""
        logger.info(f"Uninstalled integration {installation_id}")
        return {
            "installation_id": installation_id,
            "status": "uninstalled",
        }

    async def get_integration_status(
        self,
        installation_id: str,
    ) -> dict[str, Any]:
        """Get detailed status of integration"""
        # Simulate status retrieval
        return {
            "installation_id": installation_id,
            "status": "active",
            "health": "healthy",
            "last_check": datetime.now(timezone.utc).isoformat(),
        }


class ActionExecutor:
    """Execute integration actions with rate limiting and retry logic"""

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
        """Execute an integration action"""
        execution_id = str(uuid4())
        start_time = time.time()

        try:
            logger.info(
                f"Executing action {action_name} on {installation_id} "
                f"(execution={execution_id})",
            )

            # Validate input
            self._validate_input(input_data)

            # Execute (simulate with delay)
            output_data = await self._call_connector_action(
                installation_id,
                action_name,
                input_data,
            )

            duration_ms = int((time.time() - start_time) * 1000)

            return {
                "execution_id": execution_id,
                "status": ExecutionStatus.SUCCESS.value,
                "output_data": output_data,
                "duration_ms": duration_ms,
                "retry_count": 0,
            }

        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return {
                "execution_id": execution_id,
                "status": ExecutionStatus.FAILED.value,
                "error_message": str(e),
                "duration_ms": int((time.time() - start_time) * 1000),
            }

    def _validate_input(self, input_data: dict[str, Any]) -> None:
        """Validate action input"""
        if not isinstance(input_data, dict):
            raise ValueError("Input data must be a dictionary")

    async def _call_connector_action(
        self,
        installation_id: str,
        action_name: str,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Call actual connector action (placeholder)"""
        # In production, this would make actual API calls
        await self._simulate_action()
        return {"result": "success", "data": input_data}

    async def _simulate_action(self) -> None:
        """Simulate action execution"""
        import asyncio

        await asyncio.sleep(0.1)

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
