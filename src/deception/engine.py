"""
Deception Technology Engine.

Core logic for deploying, managing, and analyzing honeypots, honeytokens, and decoy assets.
"""

import hashlib
import json
import secrets
import string
from datetime import datetime, timedelta
from typing import Any

from src.core.logging import get_logger
from src.core.config import settings
from src.deception.models import (
    Decoy,
    DecoyInteraction,
    DeceptionCampaign,
    HoneyToken,
)

logger = get_logger(__name__)


class DecoyManager:
    """Manages deployment and lifecycle of decoy assets."""

    # Service emulation templates
    HONEYPOT_CONFIGS = {
        "SSH": {
            "port": 22,
            "banner": "OpenSSH_7.4",
            "auth_attempts_allowed": 3,
            "log_attempts": True,
        },
        "RDP": {
            "port": 3389,
            "service": "Remote Desktop Protocol",
            "authentication": "NTLMv2",
            "capture_credentials": True,
        },
        "HTTP": {
            "port": 80,
            "server": "Apache/2.4.41",
            "ssl_enabled": False,
            "capture_requests": True,
        },
        "HTTPS": {
            "port": 443,
            "server": "Apache/2.4.41",
            "ssl_enabled": True,
            "certificate_valid": False,
        },
        "SMB": {
            "port": 445,
            "service": "File Sharing",
            "os": "Windows",
            "shares": ["admin$", "c$", "backup", "shared_docs"],
        },
        "FTP": {
            "port": 21,
            "banner": "ProFTPD 1.3.5",
            "anonymous_login": True,
            "capture_credentials": True,
        },
        "MySQL": {
            "port": 3306,
            "version": "5.7.31",
            "default_database": "honeypot_db",
            "capture_queries": True,
        },
        "MSSQL": {
            "port": 1433,
            "version": "2017",
            "authentication": "Mixed",
            "capture_queries": True,
        },
    }

    DECOY_FILE_TEMPLATES = {
        "passwords.xlsx": {
            "content_type": "application/vnd.ms-excel",
            "contains": ["admin", "root", "passwords", "credentials"],
        },
        "backup_credentials.txt": {
            "content_type": "text/plain",
            "contains": ["backup", "emergency", "access"],
        },
        "financial_report_2024.pdf": {
            "content_type": "application/pdf",
            "contains": ["financial", "confidential", "sensitive"],
        },
        "employee_database.csv": {
            "content_type": "text/csv",
            "contains": ["employee", "personal", "data"],
        },
        "source_code.zip": {
            "content_type": "application/zip",
            "contains": ["source", "code", "repository"],
        },
    }

    async def deploy_honeypot(self, config: dict) -> Decoy:
        """Deploy a honeypot with realistic service emulation."""
        service = config.get("emulated_service", "SSH").upper()
        if service not in self.HONEYPOT_CONFIGS:
            raise ValueError(f"Unsupported service: {service}")

        service_config = self.HONEYPOT_CONFIGS[service].copy()
        service_config.update(config.get("service_config", {}))

        decoy = Decoy(
            name=config.get("name", f"honeypot_{service.lower()}"),
            decoy_type="honeypot",
            category="network",
            status="deploying",
            emulated_service=service,
            emulated_os=config.get("emulated_os", "Linux"),
            ip_address=config.get("ip_address"),
            hostname=config.get("hostname"),
            fidelity_level=config.get("fidelity_level", "medium"),
            configuration=service_config,
            deployment_target=config.get("deployment_target"),
            alert_on_interaction=config.get("alert_on_interaction", True),
            capture_credentials=config.get("capture_credentials", True),
            capture_payloads=config.get("capture_payloads", True),
            tags=config.get("tags", []),
            organization_id=config.get("organization_id"),
        )

        logger.info(
            f"Deploying honeypot: {decoy.name}",
            extra={
                "decoy_id": decoy.id,
                "service": service,
                "ip": decoy.ip_address,
            },
        )

        return decoy

    async def deploy_honeyfile(
        self, filename: str, location: str, content_type: str = None
    ) -> Decoy:
        """Deploy an enticing decoy file with embedded tracking."""
        if filename not in self.DECOY_FILE_TEMPLATES:
            template = {
                "content_type": content_type or "application/octet-stream",
                "contains": [filename],
            }
        else:
            template = self.DECOY_FILE_TEMPLATES[filename]

        decoy = Decoy(
            name=filename,
            decoy_type="honeyfile",
            category="file",
            status="active",
            deployment_target=location,
            configuration={
                "filename": filename,
                "location": location,
                "content_type": template.get("content_type"),
                "contains_keywords": template.get("contains", []),
                "embedded_tracking": True,
            },
            alert_on_interaction=True,
            capture_payloads=True,
            tags=["file_based_lure"],
            organization_id=None,  # Will be set by caller
        )

        logger.info(
            f"Deploying honeyfile: {filename} at {location}",
            extra={"decoy_id": decoy.id},
        )

        return decoy

    async def deploy_honeycred(
        self, credential_type: str, location: str
    ) -> Decoy:
        """Plant fake credentials in strategic locations."""
        credential_types = {
            "AD": {"format": "domain_account", "location_type": "Active Directory"},
            "CONFIG_FILE": {
                "format": "config_key_value",
                "location_type": "Configuration File",
            },
            "ENV_VAR": {
                "format": "environment_variable",
                "location_type": "Environment Variable",
            },
            "BROWSER": {
                "format": "browser_saved_password",
                "location_type": "Browser Cache",
            },
        }

        if credential_type not in credential_types:
            raise ValueError(f"Unsupported credential type: {credential_type}")

        cred_config = credential_types[credential_type]

        decoy = Decoy(
            name=f"honeycred_{credential_type.lower()}",
            decoy_type="honeycred",
            category="credential",
            status="active",
            deployment_target=location,
            configuration={
                "credential_type": credential_type,
                "format": cred_config["format"],
                "location_type": cred_config["location_type"],
                "location": location,
            },
            alert_on_interaction=True,
            capture_credentials=True,
            tags=["credential_lure"],
            organization_id=None,
        )

        logger.info(
            f"Deploying honeycred ({credential_type}) at {location}",
            extra={"decoy_id": decoy.id},
        )

        return decoy

    async def deploy_breadcrumbs(
        self, target_network: str, breadcrumb_type: str
    ) -> list[Decoy]:
        """Scatter breadcrumbs that lead attackers to honeypots."""
        breadcrumb_types = {
            "DNS": {"description": "DNS entries pointing to honeypots"},
            "FILE_SHARE": {"description": "Fake file shares with enticing names"},
            "REGISTRY": {"description": "Registry entries with suspicious values"},
            "BROWSER_HISTORY": {"description": "Browser history entries"},
        }

        if breadcrumb_type not in breadcrumb_types:
            raise ValueError(f"Unsupported breadcrumb type: {breadcrumb_type}")

        decoys = []
        description = breadcrumb_types[breadcrumb_type]["description"]

        for i in range(3):  # Deploy 3 breadcrumbs of each type
            decoy = Decoy(
                name=f"breadcrumb_{breadcrumb_type.lower()}_{i}",
                decoy_type="breadcrumb",
                category="network",
                status="active",
                deployment_target=target_network,
                configuration={
                    "breadcrumb_type": breadcrumb_type,
                    "description": description,
                    "index": i,
                },
                alert_on_interaction=True,
                tags=["breadcrumb_trail"],
                organization_id=None,
            )
            decoys.append(decoy)

        logger.info(
            f"Deployed {len(decoys)} breadcrumbs ({breadcrumb_type}) in {target_network}"
        )

        return decoys

    async def undeploy_decoy(self, decoy_id: str) -> None:
        """Remove a decoy from deployment."""
        logger.info(f"Undeploying decoy: {decoy_id}")

    async def get_decoy_status(self, decoy_id: str) -> dict:
        """Get current status of a decoy."""
        return {
            "decoy_id": decoy_id,
            "status": "active",
            "interaction_count": 0,
            "last_interaction": None,
        }

    async def rotate_decoys(self, campaign_id: str) -> int:
        """Refresh decoys to avoid attacker fingerprinting."""
        logger.info(f"Rotating decoys for campaign: {campaign_id}")
        return 0  # Number of decoys rotated


class HoneyTokenGenerator:
    """Generates realistic but invalid honeytokens for tracking."""

    def __init__(self):
        self.token_patterns = {
            "aws_key": {
                "prefix": "AKIA",
                "length": 20,
                "charset": string.ascii_uppercase + string.digits,
            },
            "api_key": {
                "prefix": "sk_live_",
                "length": 32,
                "charset": string.ascii_letters + string.digits,
            },
            "database_cred": {
                "prefix": "db_",
                "length": 40,
                "charset": string.ascii_letters + string.digits + "_",
            },
            "jwt_token": {
                "prefix": "eyJ",
                "length": 128,
                "charset": string.ascii_letters + string.digits + "_-",
            },
            "ssh_key": {
                "prefix": "-----BEGIN RSA PRIVATE KEY-----",
                "length": 1700,
                "charset": string.ascii_letters + string.digits + "/+=\n",
            },
        }

    async def generate_aws_key(self) -> HoneyToken:
        """Generate realistic-looking but invalid AWS key pair."""
        access_key_id = "AKIA" + "".join(
            secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)
        )
        secret_access_key = "".join(
            secrets.choice(string.ascii_letters + string.digits + "/") for _ in range(40)
        )

        token_value = f"{access_key_id}:{secret_access_key}"
        token_hash = hashlib.sha256(token_value.encode()).hexdigest()

        honeytoken = HoneyToken(
            name=f"aws_key_{access_key_id[-8:]}",
            token_type="aws_key",
            token_value=token_value,
            token_hash=token_hash,
            status="active",
            alert_severity="critical",
            notification_channels=["email", "slack"],
            organization_id=None,
        )

        logger.info(
            f"Generated AWS honeytokentoken: {honeytoken.name}",
            extra={"token_id": honeytoken.id},
        )

        return honeytoken

    async def generate_api_key(self, service: str = "generic") -> HoneyToken:
        """Generate API key honeytoken for specified service."""
        prefix_map = {
            "stripe": "sk_live_",
            "github": "ghp_",
            "slack": "xoxb-",
            "generic": "api_key_",
        }

        prefix = prefix_map.get(service, "api_key_")
        key_value = prefix + "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
        )

        token_hash = hashlib.sha256(key_value.encode()).hexdigest()

        honeytoken = HoneyToken(
            name=f"api_key_{service}",
            token_type="api_key",
            token_value=key_value,
            token_hash=token_hash,
            deployment_context=f"Placed as API key for {service}",
            status="active",
            alert_severity="critical",
            organization_id=None,
        )

        return honeytoken

    async def generate_database_cred(self, db_type: str = "postgresql") -> HoneyToken:
        """Generate database credential honeytoken."""
        username = f"svc_{secrets.token_hex(4)}"
        password = secrets.token_urlsafe(32)

        token_value = f"{username}:{password}@{db_type}"
        token_hash = hashlib.sha256(token_value.encode()).hexdigest()

        honeytoken = HoneyToken(
            name=f"db_cred_{db_type}_{username}",
            token_type="database_cred",
            token_value=token_value,
            token_hash=token_hash,
            deployment_context=f"Database credentials for {db_type} service account",
            status="active",
            alert_severity="critical",
            organization_id=None,
        )

        return honeytoken

    async def generate_jwt_token(self) -> HoneyToken:
        """Generate JWT token honeytoken."""
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
        signature = "".join(
            secrets.choice(string.ascii_letters + string.digits + "_-") for _ in range(64)
        )

        token_value = f"{header}.{payload}.{signature}"
        token_hash = hashlib.sha256(token_value.encode()).hexdigest()

        honeytoken = HoneyToken(
            name=f"jwt_token",
            token_type="jwt_token",
            token_value=token_value,
            token_hash=token_hash,
            deployment_context="JWT token for API authentication",
            status="active",
            alert_severity="high",
            organization_id=None,
        )

        return honeytoken

    async def generate_ssh_key(self) -> HoneyToken:
        """Generate SSH key honeytoken."""
        key_data = "-----BEGIN RSA PRIVATE KEY-----\n"
        for _ in range(30):
            key_data += "".join(
                secrets.choice(string.ascii_letters + string.digits + "/+=") for _ in range(64)
            )
            key_data += "\n"
        key_data += "-----END RSA PRIVATE KEY-----"

        token_hash = hashlib.sha256(key_data.encode()).hexdigest()

        honeytoken = HoneyToken(
            name=f"ssh_key_{secrets.token_hex(4)}",
            token_type="ssh_key",
            token_value=key_data,
            token_hash=token_hash,
            deployment_context="SSH private key for server access",
            status="active",
            alert_severity="critical",
            organization_id=None,
        )

        return honeytoken

    async def generate_dns_canary(self, domain: str) -> HoneyToken:
        """Generate unique DNS canary subdomain for tracking."""
        canary_id = secrets.token_hex(8)
        canary_domain = f"{canary_id}.canary.{domain}"

        token_hash = hashlib.sha256(canary_domain.encode()).hexdigest()

        honeytoken = HoneyToken(
            name=f"dns_canary_{canary_id}",
            token_type="dns_canary",
            token_value=canary_domain,
            token_hash=token_hash,
            deployment_context=f"DNS canary for domain {domain}",
            status="active",
            alert_severity="high",
            notification_channels=["email", "webhook"],
            organization_id=None,
        )

        return honeytoken

    async def generate_url_canary(self) -> HoneyToken:
        """Generate unique tracking URL honeytoken."""
        tracking_id = secrets.token_urlsafe(16)
        canary_url = f"https://canary.{settings.domain}/track/{tracking_id}"

        token_hash = hashlib.sha256(canary_url.encode()).hexdigest()

        honeytoken = HoneyToken(
            name=f"url_canary_{tracking_id[:8]}",
            token_type="url_canary",
            token_value=canary_url,
            token_hash=token_hash,
            deployment_context="URL canary for web-based tracking",
            status="active",
            alert_severity="high",
            organization_id=None,
        )

        return honeytoken

    async def generate_email_canary(self) -> HoneyToken:
        """Generate unique email canary honeytoken."""
        canary_id = secrets.token_hex(8)
        canary_email = f"alerts+{canary_id}@{settings.domain}"

        token_hash = hashlib.sha256(canary_email.encode()).hexdigest()

        honeytoken = HoneyToken(
            name=f"email_canary_{canary_id}",
            token_type="email_canary",
            token_value=canary_email,
            token_hash=token_hash,
            deployment_context="Email canary for email-based tracking",
            status="active",
            alert_severity="critical",
            notification_channels=["email"],
            organization_id=None,
        )

        return honeytoken

    async def generate_document_beacon(
        self, doc_type: str, title: str
    ) -> HoneyToken:
        """Generate document with embedded tracking beacon."""
        beacon_id = secrets.token_hex(8)
        beacon_url = f"https://canary.{settings.domain}/doc/{beacon_id}"

        token_value = json.dumps(
            {
                "document_type": doc_type,
                "title": title,
                "beacon_url": beacon_url,
                "beacon_id": beacon_id,
            }
        )

        token_hash = hashlib.sha256(token_value.encode()).hexdigest()

        honeytoken = HoneyToken(
            name=f"doc_beacon_{doc_type}_{beacon_id[:8]}",
            token_type="document_beacon",
            token_value=token_value,
            token_hash=token_hash,
            deployment_context=f"Document beacon embedded in {doc_type}",
            status="active",
            alert_severity="high",
            organization_id=None,
        )

        return honeytoken

    async def check_token_usage(self, token_hash: str) -> dict | None:
        """Check if a token has been used/triggered."""
        return None

    def _generate_realistic_string(self, pattern: str, length: int) -> str:
        """Generate realistic-looking random string matching pattern."""
        if pattern == "alphanumeric":
            charset = string.ascii_letters + string.digits
        elif pattern == "hex":
            charset = string.hexdigits[:16]
        elif pattern == "url_safe":
            charset = string.ascii_letters + string.digits + "_-"
        else:
            charset = string.ascii_letters

        return "".join(secrets.choice(charset) for _ in range(length))


class InteractionAnalyzer:
    """Analyzes attacker interactions with decoy assets."""

    # Common attack tool signatures
    TOOL_SIGNATURES = {
        "nmap": ["nmap", "syn scan", "port scan"],
        "metasploit": ["meterpreter", "exploit", "payload"],
        "mimikatz": ["sekurlsa", "lsadump", "token"],
        "psexec": ["ipc$", "service creation", "remote execution"],
        "cobalt_strike": ["beacon", "c2", "callback"],
        "empire": ["powershell", "empire", "agent"],
    }

    # MITRE ATT&CK mapping
    TECHNIQUE_MAP = {
        "scan": ["T1592", "T1592.004"],  # Gather Victim Network Information
        "authentication": ["T1110", "T1110.001"],  # Brute Force
        "credential_use": ["T1110", "T1187"],  # Credential Dumping
        "command": ["T1059", "T1086"],  # Command & Scripting Interpreter
        "file_access": ["T1005", "T1025"],  # Data from Local System
        "data_transfer": ["T1048", "T1041"],  # Data Exfiltration
        "lateral_movement": ["T1570", "T1021"],  # Lateral Tool Transfer
    }

    async def analyze_interaction(
        self, interaction: DecoyInteraction
    ) -> dict[str, Any]:
        """Classify and analyze an attacker interaction."""
        analysis = {
            "interaction_id": interaction.id,
            "interaction_type": interaction.interaction_type,
            "threat_level": interaction.threat_assessment,
            "is_automated": interaction.is_automated_scan,
            "tools_detected": self._detect_tools(interaction),
            "techniques": self._map_techniques(interaction.interaction_type),
            "skill_level": self._estimate_skill_level(interaction),
            "objectives": self._estimate_objectives(interaction),
            "confidence": 0.85,
        }

        return analysis

    def _detect_tools(self, interaction: DecoyInteraction) -> list[str]:
        """Detect attack tools from interaction signatures."""
        detected_tools = []
        interaction_data = json.dumps(
            {
                "commands": interaction.commands_captured,
                "payloads": interaction.payloads_captured,
            }
        )

        for tool, signatures in self.TOOL_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in interaction_data.lower():
                    detected_tools.append(tool)
                    break

        return list(set(detected_tools))

    def _map_techniques(self, interaction_type: str) -> list[str]:
        """Map interaction to MITRE ATT&CK techniques."""
        return self.TECHNIQUE_MAP.get(interaction_type, [])

    def _estimate_skill_level(self, interaction: DecoyInteraction) -> str:
        """Estimate attacker skill level."""
        indicators = {
            "basic": 0,
            "intermediate": 0,
            "advanced": 0,
        }

        if interaction.is_automated_scan:
            indicators["basic"] += 1
        if len(interaction.commands_captured) > 0:
            indicators["intermediate"] += 1
        if len(interaction.payloads_captured) > 0:
            indicators["advanced"] += 1
        if interaction.session_duration_seconds and interaction.session_duration_seconds > 300:
            indicators["advanced"] += 1

        max_level = max(indicators, key=indicators.get)
        return max_level

    def _estimate_objectives(self, interaction: DecoyInteraction) -> list[str]:
        """Estimate attacker objectives."""
        objectives = []

        if interaction.interaction_type in ["scan", "connection"]:
            objectives.append("reconnaissance")
        if interaction.interaction_type in ["authentication", "credential_use"]:
            objectives.append("lateral_movement")
        if interaction.interaction_type in ["command", "file_access"]:
            objectives.append("data_exfiltration")

        return objectives

    async def correlate_interactions(
        self, decoy_id: str, time_window_hours: int = 24
    ) -> dict[str, Any]:
        """Group interactions and build attack timeline."""
        return {
            "decoy_id": decoy_id,
            "time_window_hours": time_window_hours,
            "interaction_groups": [],
            "attack_timeline": [],
            "source_ips": [],
        }

    async def generate_attacker_profile(
        self, source_ip: str, interactions: list[DecoyInteraction]
    ) -> dict[str, Any]:
        """Build comprehensive attacker profile."""
        all_tools = set()
        all_techniques = set()
        skill_levels = []

        for interaction in interactions:
            analysis = await self.analyze_interaction(interaction)
            all_tools.update(analysis.get("tools_detected", []))
            all_techniques.update(analysis.get("techniques", []))
            skill_levels.append(analysis.get("skill_level"))

        profile = {
            "source_ip": source_ip,
            "interaction_count": len(interactions),
            "tools_used": list(all_tools),
            "techniques_observed": list(all_techniques),
            "skill_level": skill_levels[-1] if skill_levels else "unknown",
            "probable_objectives": self._estimate_objectives(interactions[0]),
            "first_seen": interactions[0].created_at if interactions else None,
            "last_seen": interactions[-1].created_at if interactions else None,
        }

        return profile


class DeceptionOrchestrator:
    """Orchestrates multi-decoy deception campaigns."""

    async def create_campaign(
        self,
        objective: str,
        zones: list[str],
        decoy_configs: list[dict],
    ) -> DeceptionCampaign:
        """Create and initialize a deception campaign."""
        campaign = DeceptionCampaign(
            name=f"campaign_{objective}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            description=f"Campaign for {objective}",
            status="active",
            objective=objective,
            coverage_zones=zones,
            created_by=None,  # Will be set by caller
            organization_id=None,  # Will be set by caller
        )

        logger.info(
            f"Created deception campaign: {campaign.name}",
            extra={
                "campaign_id": campaign.id,
                "objective": objective,
                "zones": zones,
            },
        )

        return campaign

    async def get_recommended_deployment(
        self, network_topology: dict
    ) -> list[dict]:
        """Suggest optimal decoy placement based on network layout."""
        recommendations = [
            {
                "zone": "dmz",
                "decoy_type": "honeypot",
                "service": "HTTP",
                "purpose": "Detect external reconnaissance",
            },
            {
                "zone": "internal",
                "decoy_type": "honeycred",
                "location": "/etc/config",
                "purpose": "Detect credential theft",
            },
            {
                "zone": "file_share",
                "decoy_type": "honeyfile",
                "filename": "backup_credentials.txt",
                "purpose": "Detect data exfiltration",
            },
        ]

        return recommendations

    async def assess_campaign_effectiveness(
        self, campaign_id: str
    ) -> dict[str, Any]:
        """Evaluate deception campaign effectiveness."""
        return {
            "campaign_id": campaign_id,
            "effectiveness_score": 0.0,
            "detections": 0,
            "false_positives": 0,
            "coverage": 0.0,
            "recommendations": [],
        }

    async def get_coverage_map(self) -> dict[str, Any]:
        """Show which network zones have deception coverage."""
        return {
            "zones": {
                "dmz": {"covered": True, "decoy_count": 3},
                "internal": {"covered": True, "decoy_count": 5},
                "database": {"covered": False, "decoy_count": 0},
                "file_share": {"covered": True, "decoy_count": 2},
            },
            "total_coverage_percentage": 75.0,
        }
