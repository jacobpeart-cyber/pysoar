"""Threat modeling analysis engines for STRIDE, PASTA, and attack tree generation"""

from typing import Any, Optional
import json
import math
from datetime import datetime

from src.core.logging import get_logger
from src.threat_modeling.models import (
    ThreatModel,
    ThreatModelComponent,
    IdentifiedThreat,
    ThreatMitigation,
    AttackTree,
    ComponentType,
    STRIDECategory,
    LikelihoodLevel,
    ImpactLevel,
    ThreatStatus,
    MitigationType,
)

logger = get_logger(__name__)


class STRIDEAnalyzer:
    """Analyzer for STRIDE threat categories"""

    # Threat patterns per component type
    THREAT_PATTERNS = {
        ComponentType.PROCESS.value: [
            STRIDECategory.SPOOFING,
            STRIDECategory.TAMPERING,
            STRIDECategory.REPUDIATION,
            STRIDECategory.INFORMATION_DISCLOSURE,
            STRIDECategory.DENIAL_OF_SERVICE,
            STRIDECategory.ELEVATION_OF_PRIVILEGE,
        ],
        ComponentType.DATA_STORE.value: [
            STRIDECategory.TAMPERING,
            STRIDECategory.INFORMATION_DISCLOSURE,
            STRIDECategory.DENIAL_OF_SERVICE,
        ],
        ComponentType.DATA_FLOW.value: [
            STRIDECategory.TAMPERING,
            STRIDECategory.INFORMATION_DISCLOSURE,
            STRIDECategory.REPUDIATION,
        ],
        ComponentType.EXTERNAL_ENTITY.value: [
            STRIDECategory.SPOOFING,
            STRIDECategory.REPUDIATION,
        ],
        ComponentType.TRUST_BOUNDARY.value: [
            STRIDECategory.SPOOFING,
            STRIDECategory.ELEVATION_OF_PRIVILEGE,
        ],
        ComponentType.API_ENDPOINT.value: [
            STRIDECategory.SPOOFING,
            STRIDECategory.TAMPERING,
            STRIDECategory.INFORMATION_DISCLOSURE,
            STRIDECategory.DENIAL_OF_SERVICE,
            STRIDECategory.ELEVATION_OF_PRIVILEGE,
        ],
        ComponentType.SERVICE.value: [
            STRIDECategory.SPOOFING,
            STRIDECategory.TAMPERING,
            STRIDECategory.REPUDIATION,
            STRIDECategory.INFORMATION_DISCLOSURE,
            STRIDECategory.DENIAL_OF_SERVICE,
            STRIDECategory.ELEVATION_OF_PRIVILEGE,
        ],
        ComponentType.DATABASE.value: [
            STRIDECategory.TAMPERING,
            STRIDECategory.INFORMATION_DISCLOSURE,
            STRIDECategory.DENIAL_OF_SERVICE,
        ],
        ComponentType.MESSAGE_QUEUE.value: [
            STRIDECategory.TAMPERING,
            STRIDECategory.INFORMATION_DISCLOSURE,
            STRIDECategory.DENIAL_OF_SERVICE,
            STRIDECategory.REPUDIATION,
        ],
    }

    # Generic fallback descriptions (used only when no component-specific
    # text is available; see COMPONENT_THREAT_TEXTS below).
    THREAT_DESCRIPTIONS = {
        STRIDECategory.SPOOFING: "Attacker impersonates a user, service, or system component",
        STRIDECategory.TAMPERING: "Attacker modifies data or code during transmission or at rest",
        STRIDECategory.REPUDIATION: "User denies performing an action without ability to prove otherwise",
        STRIDECategory.INFORMATION_DISCLOSURE: "Sensitive information is exposed to unauthorized parties",
        STRIDECategory.DENIAL_OF_SERVICE: "System unavailability or performance degradation due to attack",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Low-privilege user gains higher-level access",
    }

    # Component-specific threat (description, attack_vectors) by (component_type, STRIDE category).
    # These replace the generic THREAT_DESCRIPTIONS so a threat generated
    # against an `api_endpoint` differs from one generated against a
    # `database` — which is the whole point of component-driven STRIDE.
    COMPONENT_THREAT_TEXTS = {
        # ------- API endpoint -------
        (ComponentType.API_ENDPOINT.value, STRIDECategory.SPOOFING): (
            "Attacker forges or steals an API token (JWT, session cookie, API key) and "
            "invokes {name} as a legitimate caller.",
            ["JWT/session token theft", "API key leak from client code", "OAuth refresh-token replay", "Host header spoofing to bypass SSO"],
        ),
        (ComponentType.API_ENDPOINT.value, STRIDECategory.TAMPERING): (
            "Attacker tampers with request parameters, body, or headers against {name} "
            "to change its behavior (IDOR, parameter pollution, request smuggling).",
            ["Parameter pollution", "HTTP request smuggling", "IDOR on resource IDs", "Unsigned payload tampering"],
        ),
        (ComponentType.API_ENDPOINT.value, STRIDECategory.REPUDIATION): (
            "Requests to {name} are not attributable to an authenticated caller, "
            "or access logs can be altered after the fact.",
            ["Missing caller identity in access log", "Log tampering via service account", "No request_id correlation"],
        ),
        (ComponentType.API_ENDPOINT.value, STRIDECategory.INFORMATION_DISCLOSURE): (
            "{name} leaks sensitive data in responses, error stacks, or side channels.",
            ["Verbose error messages leaking stack traces", "Unauthorized data in response body", "Timing side-channel on auth checks"],
        ),
        (ComponentType.API_ENDPOINT.value, STRIDECategory.DENIAL_OF_SERVICE): (
            "{name} is exhausted by unbounded request volume or expensive queries.",
            ["Unbounded request volume / no rate limit", "Expensive query with attacker-controlled filter", "Slowloris/keepalive exhaustion"],
        ),
        (ComponentType.API_ENDPOINT.value, STRIDECategory.ELEVATION_OF_PRIVILEGE): (
            "Calls to {name} bypass role checks and execute privileged actions as a lower-privilege user.",
            ["Missing authorization on admin routes", "Role check only on frontend", "Parameter-based privilege granting"],
        ),
        # ------- Database / data store -------
        (ComponentType.DATABASE.value, STRIDECategory.TAMPERING): (
            "Attacker injects SQL or writes unauthorized rows into {name}, corrupting data.",
            ["SQL injection through unsanitized input", "Unauthorized DML via overly-broad grants", "Schema tampering via ALTER privileges"],
        ),
        (ComponentType.DATABASE.value, STRIDECategory.INFORMATION_DISCLOSURE): (
            "Attacker extracts sensitive rows from {name} through unauthorized queries or backup theft.",
            ["Blind SQL injection data exfiltration", "Stolen DB backup / snapshot", "Shared read-only credentials leak"],
        ),
        (ComponentType.DATABASE.value, STRIDECategory.DENIAL_OF_SERVICE): (
            "Attacker runs expensive queries or fills {name} to exhaustion.",
            ["Cartesian join / pathological query", "Unbounded insert volume", "Table-space exhaustion"],
        ),
        (ComponentType.DATA_STORE.value, STRIDECategory.TAMPERING): (
            "Attacker modifies objects in {name} (S3 bucket / NFS share / config store).",
            ["Bucket policy misconfiguration", "Writable config store", "Stored file overwrite via signed-URL replay"],
        ),
        (ComponentType.DATA_STORE.value, STRIDECategory.INFORMATION_DISCLOSURE): (
            "{name} exposes stored objects publicly or to overly-broad principals.",
            ["Public bucket / open ACL", "Over-permissioned IAM role", "Missing server-side encryption"],
        ),
        (ComponentType.DATA_STORE.value, STRIDECategory.DENIAL_OF_SERVICE): (
            "{name} is exhausted by unbounded writes or cost-amplifying requests.",
            ["Cost-amplifying request pattern", "Unbounded log ingestion", "Object-count quota exhaustion"],
        ),
        # ------- Data flow (network leg) -------
        (ComponentType.DATA_FLOW.value, STRIDECategory.TAMPERING): (
            "Data on {name} is modified in transit by an on-path attacker.",
            ["Missing/invalid TLS", "TLS downgrade", "Cert pinning bypass", "Network MitM on unprotected leg"],
        ),
        (ComponentType.DATA_FLOW.value, STRIDECategory.INFORMATION_DISCLOSURE): (
            "Traffic on {name} is intercepted and decoded.",
            ["Plaintext transport", "Weak cipher suite", "Traffic capture at ISP / lateral network"],
        ),
        (ComponentType.DATA_FLOW.value, STRIDECategory.REPUDIATION): (
            "Messages on {name} lack signatures or provenance, so origin can't be proven.",
            ["No mTLS", "No message signature", "No sequence numbers / replay-protection"],
        ),
        # ------- External entity -------
        (ComponentType.EXTERNAL_ENTITY.value, STRIDECategory.SPOOFING): (
            "An attacker impersonates the external party {name} (partner / third-party service).",
            ["Domain spoofing / typosquatting partner", "Forged webhook signature", "Stolen vendor API key"],
        ),
        (ComponentType.EXTERNAL_ENTITY.value, STRIDECategory.REPUDIATION): (
            "Actions taken by or on behalf of {name} cannot be linked back to the real external party.",
            ["No webhook signing", "Shared service account across vendors", "Anonymous email from external domain"],
        ),
        # ------- Trust boundary -------
        (ComponentType.TRUST_BOUNDARY.value, STRIDECategory.SPOOFING): (
            "An attacker crosses {name} by presenting a trust token the boundary accepts without revalidation.",
            ["Over-broad service-account trust", "Replayed internal JWT past boundary", "SSRF into trusted network"],
        ),
        (ComponentType.TRUST_BOUNDARY.value, STRIDECategory.ELEVATION_OF_PRIVILEGE): (
            "An attacker inside the lower-trust zone of {name} escalates into the higher-trust zone.",
            ["Network pivot via misconfigured firewall rule", "Shared database role across zones", "Internal endpoint exposed without auth"],
        ),
        # ------- Service (generic backend) -------
        (ComponentType.SERVICE.value, STRIDECategory.ELEVATION_OF_PRIVILEGE): (
            "A caller of {name} exploits a missing role check to perform privileged actions.",
            ["Missing RBAC", "Privileged action behind same endpoint as read", "Deserialization RCE"],
        ),
        (ComponentType.SERVICE.value, STRIDECategory.DENIAL_OF_SERVICE): (
            "{name} is saturated by unbounded requests, memory leaks, or slow downstream calls.",
            ["Unbounded queue / no backpressure", "Amplification via expensive downstream call", "Memory leak under sustained load"],
        ),
        # ------- Process -------
        (ComponentType.PROCESS.value, STRIDECategory.TAMPERING): (
            "An attacker modifies the running {name} process binary or its in-memory state.",
            ["Code injection", "DLL side-loading / LD_PRELOAD", "Process hollowing"],
        ),
        (ComponentType.PROCESS.value, STRIDECategory.ELEVATION_OF_PRIVILEGE): (
            "{name} runs with more privilege than it needs; a compromise escalates access.",
            ["Running as root/SYSTEM unnecessarily", "Setuid / capability over-grant", "Container escape via shared kernel"],
        ),
        # ------- Message queue -------
        (ComponentType.MESSAGE_QUEUE.value, STRIDECategory.TAMPERING): (
            "Messages in {name} are modified or replayed by an attacker who reaches the broker.",
            ["Unsigned message bodies", "Replay of captured messages", "Queue poisoning with malformed body"],
        ),
        (ComponentType.MESSAGE_QUEUE.value, STRIDECategory.INFORMATION_DISCLOSURE): (
            "Messages in {name} are readable by principals that shouldn't see them.",
            ["Over-broad queue read ACL", "Plaintext messages with PII", "Dead-letter queue exposure"],
        ),
    }

    # Common CWE mappings for STRIDE categories
    CWE_MAPPINGS = {
        STRIDECategory.SPOOFING: ["CWE-287", "CWE-295", "CWE-347"],
        STRIDECategory.TAMPERING: ["CWE-434", "CWE-352", "CWE-400"],
        STRIDECategory.REPUDIATION: ["CWE-345"],
        STRIDECategory.INFORMATION_DISCLOSURE: ["CWE-200", "CWE-532", "CWE-327"],
        STRIDECategory.DENIAL_OF_SERVICE: ["CWE-400", "CWE-770", "CWE-674"],
        STRIDECategory.ELEVATION_OF_PRIVILEGE: ["CWE-269", "CWE-276", "CWE-94"],
    }

    def __init__(self):
        """Initialize STRIDE analyzer"""
        self.logger = logger

    def analyze_component(self, component: ThreatModelComponent) -> list[dict]:
        """
        Analyze a single component for STRIDE threats. Threats are
        component-type-specific (an api_endpoint's Spoofing threat is
        "JWT/session theft" — not the same generic text as every other
        component). Likelihood / impact are computed from the component's
        `trust_level` and `data_classification`.
        """
        threats: list[dict] = []
        component_type = component.component_type
        component_name = getattr(component, "name", None) or component_type

        # Only the STRIDE categories that actually apply to this component
        # type are used — the THREAT_PATTERNS table encodes Microsoft's
        # standard mapping (a data store legitimately has no "Spoofing"
        # threat in STRIDE).
        stride_categories = self.THREAT_PATTERNS.get(
            component_type,
            list(STRIDECategory),
        )

        trust_level = (getattr(component, "trust_level", None) or "").lower()
        classification = (getattr(component, "data_classification", None) or "").lower()

        # Likelihood rises when the component sits at an untrusted boundary
        # (user-facing APIs, external entities) and falls for internal
        # authenticated code paths.
        if trust_level in ("external", "untrusted", "public"):
            likelihood = LikelihoodLevel.HIGH.value
        elif trust_level in ("authenticated", "internal"):
            likelihood = LikelihoodLevel.MEDIUM.value
        elif trust_level in ("privileged", "admin"):
            likelihood = LikelihoodLevel.LOW.value
        else:
            likelihood = LikelihoodLevel.MEDIUM.value

        # Base impact is HIGH for data stores / databases — a compromise
        # there tends to mean data breach. Everything else starts MEDIUM.
        if component_type in (ComponentType.DATABASE.value, ComponentType.DATA_STORE.value):
            base_impact = ImpactLevel.HIGH.value
        else:
            base_impact = ImpactLevel.MEDIUM.value

        # Data classification escalates impact — a PUBLIC-labelled component
        # drops one tier, CONFIDENTIAL/RESTRICTED/PII rises one tier.
        def _bump_impact(current: str, direction: int) -> str:
            ladder = [
                ImpactLevel.VERY_LOW.value,
                ImpactLevel.LOW.value,
                ImpactLevel.MEDIUM.value,
                ImpactLevel.HIGH.value,
                ImpactLevel.VERY_HIGH.value,
            ]
            if current not in ladder:
                return current
            idx = max(0, min(len(ladder) - 1, ladder.index(current) + direction))
            return ladder[idx]

        if any(tag in classification for tag in ("public",)):
            base_impact = _bump_impact(base_impact, -1)
        elif any(tag in classification for tag in ("confidential", "restricted", "pii", "phi", "secret")):
            base_impact = _bump_impact(base_impact, +1)

        for category in stride_categories:
            # Information disclosure threats always scale with data classification.
            impact = base_impact
            if category == STRIDECategory.INFORMATION_DISCLOSURE and any(
                tag in classification for tag in ("confidential", "restricted", "pii", "phi", "secret")
            ):
                impact = _bump_impact(impact, +1)

            # Resolve component-specific text + attack vectors if available,
            # otherwise fall back to generic vectors. Description is
            # .format()'d with the component name so every row is anchored
            # to a real target, not a nameless abstraction.
            key = (component_type, category)
            template_text, template_vectors = self.COMPONENT_THREAT_TEXTS.get(
                key,
                (self.THREAT_DESCRIPTIONS[category], self._generic_vectors(category)),
            )
            description = template_text.format(name=component_name)

            threat = {
                "category": category.value,
                "description": description,
                "component_id": component.id,
                "component_type": component_type,
                "component_name": component_name,
                "technology": component.technology_stack,
                "likelihood": likelihood,
                "impact": impact,
                "cwe_ids": self.CWE_MAPPINGS.get(category, []),
                "attack_vectors": template_vectors,
                # First three MITRE techniques for the STRIDE category,
                # pulled from the main map_to_mitre_attack mappings. This
                # gives the analyst a concrete hunt/detection starting
                # point per threat.
                "mitre_techniques": self._top_mitre_for_category(category, limit=3),
            }
            threats.append(threat)

        return threats

    def _generic_vectors(self, category: "STRIDECategory") -> list[str]:
        """Fallback generic vectors when no component-specific mapping exists."""
        if category == STRIDECategory.SPOOFING:
            return ["Credential theft", "Man-in-the-middle", "DNS hijacking"]
        if category == STRIDECategory.TAMPERING:
            return ["Code injection", "Unencrypted transmission", "SQL injection"]
        if category == STRIDECategory.REPUDIATION:
            return ["Insufficient logging", "Log tampering", "Weak audit trails"]
        if category == STRIDECategory.INFORMATION_DISCLOSURE:
            return ["Weak encryption", "Information leakage", "Metadata exposure"]
        if category == STRIDECategory.DENIAL_OF_SERVICE:
            return ["Resource exhaustion", "Flood attacks", "Rate limiting bypass"]
        if category == STRIDECategory.ELEVATION_OF_PRIVILEGE:
            return ["Unpatched vulnerabilities", "Weak permissions", "Privilege escalation"]
        return []

    def _top_mitre_for_category(self, category: "STRIDECategory", limit: int = 3) -> list[str]:
        """Look up the first ``limit`` MITRE ATT&CK technique IDs mapped
        to a STRIDE category. Reuses the large STRIDE→MITRE table in
        ``map_to_mitre_attack``; we just call it on a synthetic stub
        threat to get the list.
        """
        # map_to_mitre_attack takes an IdentifiedThreat row, but it only
        # reads `.stride_category`. Use a tiny anonymous object.
        class _Stub:
            pass
        s = _Stub()
        s.stride_category = category.value if hasattr(category, "value") else str(category)
        try:
            mitres = self.map_to_mitre_attack(s)
        except Exception:
            mitres = []
        return mitres[:limit]

    def auto_generate_threats(
        self, model: ThreatModel, components: list[ThreatModelComponent]
    ) -> list[dict]:
        """
        Auto-generate threats for all components in model

        Args:
            model: Threat model
            components: List of components

        Returns:
            All generated threats
        """
        all_threats = []
        for component in components:
            threats = self.analyze_component(component)
            all_threats.extend(threats)

        return all_threats

    def calculate_risk_score(
        self, likelihood: str, impact: str
    ) -> int:
        """
        Calculate risk score using likelihood × impact matrix

        Args:
            likelihood: Likelihood level
            impact: Impact level

        Returns:
            Risk score (1-25)
        """
        likelihood_values = {
            LikelihoodLevel.VERY_LOW.value: 1,
            LikelihoodLevel.LOW.value: 2,
            LikelihoodLevel.MEDIUM.value: 3,
            LikelihoodLevel.HIGH.value: 4,
            LikelihoodLevel.VERY_HIGH.value: 5,
        }

        impact_values = {
            ImpactLevel.VERY_LOW.value: 1,
            ImpactLevel.LOW.value: 2,
            ImpactLevel.MEDIUM.value: 3,
            ImpactLevel.HIGH.value: 4,
            ImpactLevel.VERY_HIGH.value: 5,
        }

        l_score = likelihood_values.get(likelihood, 3)
        i_score = impact_values.get(impact, 3)

        return l_score * i_score

    def map_to_mitre_attack(self, threat: IdentifiedThreat) -> list[str]:
        """
        Map threat to MITRE ATT&CK techniques

        Args:
            threat: Identified threat

        Returns:
            List of MITRE technique IDs
        """
        # Comprehensive STRIDE-to-MITRE ATT&CK mapping
        mappings = {
            STRIDECategory.SPOOFING: [
                "T1589",    # Gather Victim Identity Information
                "T1598",    # Phishing for Information
                "T1557",    # Adversary-in-the-Middle
                "T1556",    # Modify Authentication Process
                "T1550",    # Use Alternate Authentication Material
                "T1539",    # Steal Web Session Cookie
                "T1528",    # Steal Application Access Token
                "T1558",    # Steal or Forge Kerberos Tickets
                "T1134",    # Access Token Manipulation
                "T1583.001",  # Acquire Infrastructure: Domains
            ],
            STRIDECategory.TAMPERING: [
                "T1565",    # Data Manipulation
                "T1565.001",  # Stored Data Manipulation
                "T1565.002",  # Transmitted Data Manipulation
                "T1565.003",  # Runtime Data Manipulation
                "T1485",    # Data Destruction
                "T1491",    # Defacement
                "T1491.001",  # Internal Defacement
                "T1491.002",  # External Defacement
                "T1195",    # Supply Chain Compromise
                "T1195.002",  # Compromise Software Supply Chain
                "T1059",    # Command and Scripting Interpreter
                "T1055",    # Process Injection
            ],
            STRIDECategory.REPUDIATION: [
                "T1070",    # Indicator Removal
                "T1070.001",  # Clear Windows Event Logs
                "T1070.002",  # Clear Linux or Mac System Logs
                "T1070.003",  # Clear Command History
                "T1070.004",  # File Deletion
                "T1070.006",  # Timestomp
                "T1562",    # Impair Defenses
                "T1562.001",  # Disable or Modify Tools
                "T1562.002",  # Disable Windows Event Logging
                "T1036",    # Masquerading
            ],
            STRIDECategory.INFORMATION_DISCLOSURE: [
                "T1005",    # Data from Local System
                "T1039",    # Data from Network Shared Drive
                "T1025",    # Data from Removable Media
                "T1041",    # Exfiltration Over C2 Channel
                "T1048",    # Exfiltration Over Alternative Protocol
                "T1567",    # Exfiltration Over Web Service
                "T1530",    # Data from Cloud Storage
                "T1119",    # Automated Collection
                "T1213",    # Data from Information Repositories
                "T1114",    # Email Collection
                "T1557",    # Adversary-in-the-Middle
                "T1040",    # Network Sniffing
                "T1552",    # Unsecured Credentials
                "T1003",    # OS Credential Dumping
            ],
            STRIDECategory.DENIAL_OF_SERVICE: [
                "T1499",    # Endpoint Denial of Service
                "T1499.001",  # OS Exhaustion Flood
                "T1499.002",  # Service Exhaustion Flood
                "T1499.003",  # Application Exhaustion Flood
                "T1499.004",  # Application or System Exploitation
                "T1498",    # Network Denial of Service
                "T1498.001",  # Direct Network Flood
                "T1498.002",  # Reflection Amplification
                "T1489",    # Service Stop
                "T1486",    # Data Encrypted for Impact
                "T1561",    # Disk Wipe
                "T1529",    # System Shutdown/Reboot
            ],
            STRIDECategory.ELEVATION_OF_PRIVILEGE: [
                "T1548",    # Abuse Elevation Control Mechanism
                "T1548.001",  # Setuid and Setgid
                "T1548.002",  # Bypass User Account Control
                "T1548.003",  # Sudo and Sudo Caching
                "T1068",    # Exploitation for Privilege Escalation
                "T1134",    # Access Token Manipulation
                "T1078",    # Valid Accounts
                "T1078.001",  # Default Accounts
                "T1078.002",  # Domain Accounts
                "T1078.003",  # Local Accounts
                "T1053",    # Scheduled Task/Job
                "T1546",    # Event Triggered Execution
                "T1547",    # Boot or Logon Autostart Execution
                "T1574",    # Hijack Execution Flow
                "T1055",    # Process Injection
            ],
        }

        category = threat.stride_category
        if category in mappings:
            return mappings[category]

        return []

    def map_to_cwe(self, threat: IdentifiedThreat) -> list[str]:
        """
        Map threat to CWE identifiers

        Args:
            threat: Identified threat

        Returns:
            List of CWE IDs
        """
        if threat.stride_category in self.CWE_MAPPINGS:
            return self.CWE_MAPPINGS[threat.stride_category]

        return []


class PASTAEngine:
    """PASTA (Process for Attack Simulation and Threat Analysis) engine"""

    def __init__(self):
        """Initialize PASTA engine"""
        self.logger = logger

    def stage1_define_objectives(self, model: ThreatModel) -> dict[str, Any]:
        """
        Stage 1: Define business objectives

        Returns:
            Business objectives and goals
        """
        return {
            "stage": 1,
            "name": "Define Objectives",
            "application": model.application_name,
            "version": model.version,
            "scope": model.scope,
            "objectives": ["Identify threats", "Assess risk", "Plan mitigations"],
        }

    def stage2_define_technical_scope(
        self, model: ThreatModel, components: list[ThreatModelComponent] | None = None,
    ) -> dict[str, Any]:
        """
        Stage 2: Define technical scope

        Returns:
            Technical scope and architecture
        """
        components = components or []
        comp_list = [
            {"id": c.id, "name": c.name, "type": c.component_type}
            for c in components
        ]
        data_flows = [
            {"id": c.id, "name": c.name}
            for c in components
            if c.component_type == ComponentType.DATA_FLOW.value
        ]
        trust_boundaries = [
            {"id": c.id, "name": c.name}
            for c in components
            if c.component_type == ComponentType.TRUST_BOUNDARY.value
        ]
        return {
            "stage": 2,
            "name": "Define Technical Scope",
            "architecture": model.architecture_description,
            "components": comp_list,
            "data_flows": data_flows,
            "trust_boundaries": trust_boundaries,
        }

    def stage3_decompose_application(
        self, components: list[ThreatModelComponent]
    ) -> dict[str, Any]:
        """
        Stage 3: Decompose application

        Returns:
            Application decomposition
        """
        return {
            "stage": 3,
            "name": "Decompose Application",
            "component_count": len(components),
            "components": [
                {"id": c.id, "name": c.name, "type": c.component_type}
                for c in components
            ],
        }

    def stage4_threat_analysis(
        self, model: ThreatModel, threats: list[IdentifiedThreat] | None = None,
    ) -> dict[str, Any]:
        """
        Stage 4: Threat analysis

        Returns:
            Threat analysis results
        """
        threats = threats or []
        categories_found = {t.stride_category for t in threats if t.stride_category}
        return {
            "stage": 4,
            "name": "Threat Analysis",
            "methodology": model.methodology,
            "threat_count": len(threats),
            "stride_categories_covered": list(categories_found),
            "status": "completed" if threats else "in_progress",
        }

    def stage5_vulnerability_analysis(
        self, threats: list[IdentifiedThreat]
    ) -> dict[str, Any]:
        """
        Stage 5: Vulnerability analysis

        Returns:
            Vulnerability analysis
        """
        return {
            "stage": 5,
            "name": "Vulnerability Analysis",
            "threat_count": len(threats),
            "high_risk_count": sum(1 for t in threats if t.risk_score > 15),
        }

    def stage6_attack_modeling(
        self, threats: list[IdentifiedThreat]
    ) -> dict[str, Any]:
        """
        Stage 6: Attack modeling

        Returns:
            Attack model data
        """
        likelihood_order = {
            LikelihoodLevel.VERY_LOW.value: 1,
            LikelihoodLevel.LOW.value: 2,
            LikelihoodLevel.MEDIUM.value: 3,
            LikelihoodLevel.HIGH.value: 4,
            LikelihoodLevel.VERY_HIGH.value: 5,
        }
        reverse_order = {v: k for k, v in likelihood_order.items()}
        if threats:
            avg_val = sum(
                likelihood_order.get(t.likelihood, 3) for t in threats
            ) / len(threats)
            avg_likelihood = reverse_order.get(round(avg_val), LikelihoodLevel.MEDIUM.value)
        else:
            avg_likelihood = LikelihoodLevel.MEDIUM.value

        return {
            "stage": 6,
            "name": "Attack Modeling",
            "attack_scenarios": len(threats),
            "average_likelihood": avg_likelihood,
        }

    def stage7_risk_and_impact(
        self, threats: list[IdentifiedThreat]
    ) -> dict[str, Any]:
        """
        Stage 7: Risk and impact analysis

        Returns:
            Risk analysis results
        """
        total_risk = sum(t.risk_score for t in threats) if threats else 0
        avg_risk = total_risk / len(threats) if threats else 0

        return {
            "stage": 7,
            "name": "Risk and Impact",
            "total_threats": len(threats),
            "total_risk_score": total_risk,
            "average_risk_score": round(avg_risk, 2),
        }

    def run_full_pasta(
        self,
        model: ThreatModel,
        components: list[ThreatModelComponent],
        threats: list[IdentifiedThreat],
    ) -> dict[str, Any]:
        """
        Run full PASTA analysis

        Returns:
            Complete PASTA analysis results
        """
        return {
            "stage_1": self.stage1_define_objectives(model),
            "stage_2": self.stage2_define_technical_scope(model, components),
            "stage_3": self.stage3_decompose_application(components),
            "stage_4": self.stage4_threat_analysis(model, threats),
            "stage_5": self.stage5_vulnerability_analysis(threats),
            "stage_6": self.stage6_attack_modeling(threats),
            "stage_7": self.stage7_risk_and_impact(threats),
            "completed_at": datetime.utcnow().isoformat(),
        }


class AttackTreeGenerator:
    """Generator for attack trees from threats"""

    def __init__(self):
        """Initialize attack tree generator"""
        self.logger = logger

    def generate_from_threats(
        self,
        model: ThreatModel,
        threats: list[IdentifiedThreat],
    ) -> dict[str, Any]:
        """
        Generate attack tree from identified threats

        Args:
            model: Threat model
            threats: List of identified threats

        Returns:
            Attack tree structure
        """
        if not threats:
            return {"root_goal": "", "children": []}

        # Create tree from highest risk threats
        sorted_threats = sorted(threats, key=lambda t: t.risk_score, reverse=True)
        tree = self._build_tree_structure(sorted_threats[:10])

        return tree

    def _build_tree_structure(self, threats: list[IdentifiedThreat]) -> dict[str, Any]:
        """
        Build recursive tree structure with AND/OR gates

        Args:
            threats: Top threats to include

        Returns:
            Tree structure
        """
        if not threats:
            return {"goal": "No threats", "children": []}

        root_threat = threats[0]
        children = []

        for threat in threats[1:]:
            children.append({
                "id": threat.id,
                "goal": threat.threat_description[:100],
                "type": "OR",
                "likelihood": threat.likelihood,
                "impact": threat.impact,
                "risk_score": threat.risk_score,
            })

        return {
            "id": root_threat.id,
            "goal": root_threat.threat_description,
            "type": "OR",
            "likelihood": root_threat.likelihood,
            "impact": root_threat.impact,
            "risk_score": root_threat.risk_score,
            "children": children,
        }

    def calculate_path_metrics(
        self, tree: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Calculate real metrics for attack paths (cost, skill, probability)
        derived from the threats actually present in the tree. Previous
        version returned hardcoded fake values (average_cost=5000,
        average_skill="medium", highest_probability=0.75) regardless of
        the input — useless for any real assessment.

        New behavior: walks the tree and computes metrics from each
        threat's risk_score / likelihood / impact fields using standard
        CAPEC-style heuristics.
        """
        threats = self._flatten_tree(tree)
        if not threats:
            return {
                "total_paths": 0,
                "average_cost": 0,
                "average_skill": "unknown",
                "highest_probability": 0.0,
            }

        # Cost heuristic: lower-effort attacks (high-likelihood, low-risk-score)
        # cost attackers less. Scale around 2k-50k USD based on inverse of
        # risk_score + likelihood.
        LIKELIHOOD_WEIGHTS = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
        IMPACT_WEIGHTS = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}

        costs = []
        probabilities = []
        skill_levels = []

        for t in threats:
            lw = LIKELIHOOD_WEIGHTS.get((t.get("likelihood") or "medium").lower(), 0.5)
            iw = IMPACT_WEIGHTS.get((t.get("impact") or "medium").lower(), 0.5)

            # High-likelihood × low-impact = cheap attacks; inverse for costly
            estimated_cost = int(50_000 * (1.0 - lw) + 2000)
            costs.append(estimated_cost)

            # Probability as the product of likelihood weight and a
            # risk_score-normalized confidence (risk_score is 1..25 from the
            # 5x5 matrix).
            rs = float(t.get("risk_score") or 0)
            probability = lw * min(1.0, rs / 25.0) if rs > 0 else lw * 0.5
            probabilities.append(round(probability, 3))

            # Skill inferred from impact: higher impact threats generally
            # require more sophisticated attackers.
            if iw >= 0.75:
                skill_levels.append("high")
            elif iw >= 0.5:
                skill_levels.append("medium")
            else:
                skill_levels.append("low")

        # Most common skill level wins
        skill_counts = {"low": 0, "medium": 0, "high": 0}
        for s in skill_levels:
            skill_counts[s] = skill_counts.get(s, 0) + 1
        dominant_skill = max(skill_counts.items(), key=lambda kv: kv[1])[0]

        return {
            "total_paths": self._count_paths(tree),
            "average_cost": int(sum(costs) / len(costs)),
            "average_skill": dominant_skill,
            "highest_probability": max(probabilities) if probabilities else 0.0,
            "threat_count": len(threats),
        }

    def _flatten_tree(self, tree: dict[str, Any]) -> list[dict[str, Any]]:
        """Recursively flatten an attack tree into a list of threat dicts."""
        out: list[dict[str, Any]] = []
        if not tree or not isinstance(tree, dict):
            return out
        if tree.get("goal") or tree.get("risk_score") is not None:
            out.append(tree)
        for child in tree.get("children", []) or []:
            out.extend(self._flatten_tree(child))
        return out

    def _count_paths(self, node: dict[str, Any]) -> int:
        """Count total attack paths in tree"""
        if not node.get("children"):
            return 1

        # For OR nodes, sum paths; for AND nodes, multiply paths
        node_type = node.get("type", "OR")
        path_count = 0

        if node_type == "OR":
            path_count = sum(self._count_paths(child) for child in node["children"])
            if not node["children"]:
                path_count = 1
        else:  # AND
            path_count = 1
            for child in node["children"]:
                path_count *= self._count_paths(child)

        return max(path_count, 1)

    def find_minimum_cost_path(self, tree: dict[str, Any]) -> dict[str, Any]:
        """Find lowest cost attack path by summing leaf node costs on the cheapest path"""
        if not tree or not tree.get("children"):
            return {
                "path": [],
                "cost_usd": 0,
                "required_skill": "unknown",
                "explanation": "No tree structure available to calculate cost path",
            }

        def _min_cost(node: dict) -> tuple[float, list[str]]:
            """Return (cost, path) for the minimum-cost path through this node."""
            node_cost = node.get("cost_usd", node.get("risk_score", 0) * 100)
            node_label = node.get("goal", "unknown")[:80]
            children = node.get("children", [])
            if not children:
                return (node_cost, [node_label])
            node_type = node.get("type", "OR")
            if node_type == "OR":
                # Pick the cheapest child branch
                best_cost, best_path = min(
                    (_min_cost(c) for c in children), key=lambda x: x[0]
                )
                return (node_cost + best_cost, [node_label] + best_path)
            else:  # AND — must traverse all children
                total = node_cost
                path = [node_label]
                for c in children:
                    c_cost, c_path = _min_cost(c)
                    total += c_cost
                    path.extend(c_path)
                return (total, path)

        cost, path = _min_cost(tree)
        return {
            "path": path,
            "cost_usd": cost,
            "required_skill": "medium",
        }

    def find_highest_probability_path(self, tree: dict[str, Any]) -> dict[str, Any]:
        """Find most likely attack path by calculating from tree structure"""
        if not tree or not tree.get("children"):
            return {
                "path": [],
                "probability": 0.0,
                "likelihood": "none",
                "explanation": "No tree structure available to calculate probability path",
            }

        likelihood_prob = {
            LikelihoodLevel.VERY_LOW.value: 0.1,
            LikelihoodLevel.LOW.value: 0.3,
            LikelihoodLevel.MEDIUM.value: 0.5,
            LikelihoodLevel.HIGH.value: 0.7,
            LikelihoodLevel.VERY_HIGH.value: 0.9,
        }

        def _max_prob(node: dict) -> tuple[float, list[str]]:
            """Return (probability, path) for the highest-probability path."""
            node_prob = likelihood_prob.get(
                node.get("likelihood", ""), 0.5
            )
            node_label = node.get("goal", "unknown")[:80]
            children = node.get("children", [])
            if not children:
                return (node_prob, [node_label])
            node_type = node.get("type", "OR")
            if node_type == "OR":
                # Pick the most likely child branch
                best_prob, best_path = max(
                    (_max_prob(c) for c in children), key=lambda x: x[0]
                )
                return (node_prob * best_prob, [node_label] + best_path)
            else:  # AND — multiply all children probabilities
                combined_prob = node_prob
                path = [node_label]
                for c in children:
                    c_prob, c_path = _max_prob(c)
                    combined_prob *= c_prob
                    path.extend(c_path)
                return (combined_prob, path)

        prob, path = _max_prob(tree)

        if prob >= 0.7:
            level = "high"
        elif prob >= 0.4:
            level = "medium"
        else:
            level = "low"

        return {
            "path": path,
            "probability": round(prob, 4),
            "likelihood": level,
        }

    def visualize_tree_data(self, tree: dict[str, Any]) -> dict[str, Any]:
        """Generate visualization data for frontend"""
        return {
            "nodes": self._extract_nodes(tree),
            "edges": self._extract_edges(tree),
            "layout": "hierarchical",
        }

    def _extract_nodes(
        self, node: dict[str, Any], nodes: Optional[list] = None
    ) -> list[dict]:
        """Extract nodes from tree"""
        if nodes is None:
            nodes = []

        nodes.append({
            "id": node.get("id", "root"),
            "label": node.get("goal", "")[:50],
            "type": node.get("type", "OR"),
            "risk_score": node.get("risk_score", 0),
        })

        for child in node.get("children", []):
            self._extract_nodes(child, nodes)

        return nodes

    def _extract_edges(
        self, node: dict[str, Any], edges: Optional[list] = None, parent_id: Optional[str] = None
    ) -> list[tuple]:
        """Extract edges from tree"""
        if edges is None:
            edges = []

        node_id = node.get("id", "root")
        if parent_id:
            edges.append((parent_id, node_id))

        for child in node.get("children", []):
            self._extract_edges(child, edges, node_id)

        return edges


class MitigationRecommender:
    """Recommends mitigations for threats"""

    # OWASP Top 10 control mappings
    OWASP_CONTROLS = {
        "information_disclosure": ["A01:2021", "A04:2021"],
        "tampering": ["A06:2021"],
        "elevation_of_privilege": ["A01:2021", "A07:2021"],
        "denial_of_service": ["A05:2021"],
    }

    # NIST control mappings
    NIST_CONTROLS = {
        "information_disclosure": ["SC-7", "SC-13"],
        "spoofing": ["IA-2", "IA-4"],
        "elevation_of_privilege": ["AC-6"],
    }

    def __init__(self):
        """Initialize mitigation recommender"""
        self.logger = logger

    def recommend_mitigations(
        self, threat: IdentifiedThreat
    ) -> list[dict[str, Any]]:
        """
        Recommend mitigations based on threat

        Args:
            threat: Identified threat

        Returns:
            List of mitigation recommendations
        """
        recommendations = []

        category = threat.stride_category or ""

        # Map threat to mitigation types
        if "spoofing" in category.lower():
            recommendations.append({
                "type": MitigationType.PREVENTIVE.value,
                "title": "Implement multi-factor authentication",
                "description": "Require MFA for all user authentication",
                "controls": {"nist": ["IA-2", "IA-4"], "owasp": ["A07:2021"]},
                "cost_estimate": 15000,
            })
        elif "tampering" in category.lower():
            recommendations.append({
                "type": MitigationType.PREVENTIVE.value,
                "title": "Implement encryption in transit and at rest",
                "description": "Use TLS 1.3+ and strong encryption algorithms",
                "controls": {"nist": ["SC-7", "SC-13"], "owasp": ["A06:2021"]},
                "cost_estimate": 10000,
            })
        elif "information_disclosure" in category.lower():
            recommendations.append({
                "type": MitigationType.DETECTIVE.value,
                "title": "Implement data loss prevention",
                "description": "Monitor and prevent unauthorized data exfiltration",
                "controls": {"nist": ["SC-7", "AU-12"], "owasp": ["A01:2021"]},
                "cost_estimate": 20000,
            })
        elif "denial_of_service" in category.lower():
            recommendations.append({
                "type": MitigationType.DETECTIVE.value,
                "title": "Implement rate limiting and DDoS protection",
                "description": "Deploy WAF with rate limiting rules",
                "controls": {"nist": ["SC-5"], "owasp": ["A05:2021"]},
                "cost_estimate": 25000,
            })

        return recommendations

    def prioritize_mitigations(
        self, mitigations: list[dict], threat_risk_score: int
    ) -> list[dict]:
        """
        Prioritize mitigations by risk reduction and cost

        Args:
            mitigations: List of mitigations
            threat_risk_score: Risk score of threat

        Returns:
            Prioritized mitigations
        """
        # Score based on threat risk and cost efficiency
        for mit in mitigations:
            risk_reduction = threat_risk_score * 0.7
            cost = mit.get("cost_estimate", 10000)
            efficiency = risk_reduction / cost if cost > 0 else 0
            mit["priority_score"] = efficiency

        return sorted(mitigations, key=lambda m: m["priority_score"], reverse=True)

    def generate_security_requirements(
        self, threat: IdentifiedThreat
    ) -> list[str]:
        """
        Generate security requirements from threat

        Args:
            threat: Identified threat

        Returns:
            List of security requirements
        """
        requirements = [
            "Implement appropriate authentication mechanisms",
            "Ensure data protection and encryption",
            "Maintain audit logs and monitoring",
            "Establish access controls",
        ]

        if "elevation" in (threat.stride_category or "").lower():
            requirements.append("Apply principle of least privilege")

        return requirements

    def auto_create_playbook_triggers(
        self, threat: IdentifiedThreat
    ) -> dict[str, Any]:
        """
        Generate playbook triggers for mitigation

        Args:
            threat: Identified threat

        Returns:
            Playbook trigger configuration
        """
        return {
            "trigger_name": f"Mitigate {threat.stride_category}",
            "threat_id": threat.id,
            "actions": ["notify_security_team", "create_ticket"],
            "conditions": {"risk_score": {"gte": threat.risk_score}},
        }


class ThreatModelValidator:
    """Validates threat models for completeness and coverage"""

    def __init__(self):
        """Initialize validator"""
        self.logger = logger

    def validate_completeness(
        self,
        components: list[ThreatModelComponent],
        threats: list[IdentifiedThreat],
    ) -> dict[str, Any]:
        """
        Validate all components have threats analyzed

        Args:
            components: List of components
            threats: List of threats

        Returns:
            Validation results
        """
        component_ids = {c.id for c in components}
        threat_component_ids = {t.component_id for t in threats if t.component_id}

        missing = component_ids - threat_component_ids
        coverage_percent = (
            (len(threat_component_ids) / len(component_ids) * 100)
            if component_ids
            else 0
        )

        return {
            "valid": len(missing) == 0,
            "coverage_percent": round(coverage_percent, 1),
            "missing_components": list(missing),
            "analyzed_components": len(threat_component_ids),
            "total_components": len(component_ids),
        }

    def validate_coverage(
        self, threats: list[IdentifiedThreat]
    ) -> dict[str, Any]:
        """
        Validate all STRIDE categories covered

        Args:
            threats: List of threats

        Returns:
            STRIDE coverage results
        """
        covered_categories = {
            t.stride_category for t in threats if t.stride_category
        }
        all_categories = {c.value for c in STRIDECategory}
        missing = all_categories - covered_categories

        return {
            "valid": len(missing) == 0,
            "covered_categories": list(covered_categories),
            "missing_categories": list(missing),
            "coverage_percent": round(
                (len(covered_categories) / len(all_categories) * 100), 1
            ),
        }

    def check_stale_models(self, model: ThreatModel) -> bool:
        """
        Check if model is stale (outdated)

        Args:
            model: Threat model

        Returns:
            True if model is considered stale
        """
        from datetime import datetime, timedelta, timezone

        if model.updated_at is None:
            return False

        days_old = (datetime.now(timezone.utc) - model.updated_at).days
        return days_old > 365

    def generate_validation_report(
        self,
        model: ThreatModel,
        components: list[ThreatModelComponent],
        threats: list[IdentifiedThreat],
    ) -> dict[str, Any]:
        """
        Generate comprehensive validation report

        Args:
            model: Threat model
            components: List of components
            threats: List of threats

        Returns:
            Validation report
        """
        completeness = self.validate_completeness(components, threats)
        coverage = self.validate_coverage(threats)
        stale = self.check_stale_models(model)

        return {
            "model_id": model.id,
            "model_name": model.name,
            "timestamp": datetime.utcnow().isoformat(),
            "completeness": completeness,
            "coverage": coverage,
            "is_stale": stale,
            "overall_valid": completeness["valid"] and coverage["valid"],
            "recommendations": self._generate_recommendations(
                completeness, coverage, stale
            ),
        }

    def _generate_recommendations(
        self, completeness: dict, coverage: dict, stale: bool
    ) -> list[str]:
        """Generate recommendations from validation results"""
        recommendations = []

        if not completeness["valid"]:
            recommendations.append(
                f"Analyze threats for {len(completeness['missing_components'])} components"
            )

        if not coverage["valid"]:
            recommendations.append(
                f"Add threats for missing STRIDE categories: {', '.join(coverage['missing_categories'])}"
            )

        if stale:
            recommendations.append("Review and update model due to age")

        if not recommendations:
            recommendations.append("Model is comprehensive and well-maintained")

        return recommendations
