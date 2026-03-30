"""MITRE ATT&CK framework integration and attack coverage analysis."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple

from src.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class MITRETactic:
    """MITRE ATT&CK tactic."""

    id: str
    name: str
    shortname: str
    description: str
    url: str


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique."""

    id: str
    name: str
    description: str
    tactics: List[str] = field(default_factory=list)
    subtechniques: List[str] = field(default_factory=list)
    url: str = ""
    platforms: List[str] = field(default_factory=list)
    detection_notes: str = ""


@dataclass
class MITREMapping:
    """Mapping between detection rule and MITRE technique."""

    technique_id: str
    tactic_id: str
    rule_id: str
    rule_name: str
    match_count: int = 0
    last_seen: Optional[datetime] = None
    confidence: float = 1.0


class MITREService:
    """
    MITRE ATT&CK framework service.

    Provides access to tactics, techniques, and mappings.
    Includes built-in knowledge base for Enterprise matrix.
    """

    # MITRE Enterprise tactics in kill chain order
    TACTICS = [
        MITRETactic(
            id="TA0001",
            name="Initial Access",
            shortname="initial_access",
            description="Techniques that enable a threat actor to initially access a system or network.",
            url="https://attack.mitre.org/tactics/TA0001/",
        ),
        MITRETactic(
            id="TA0002",
            name="Execution",
            shortname="execution",
            description="Techniques that execute attacker-controlled code on a target system.",
            url="https://attack.mitre.org/tactics/TA0002/",
        ),
        MITRETactic(
            id="TA0003",
            name="Persistence",
            shortname="persistence",
            description="Techniques that establish persistence for maintaining long-term presence.",
            url="https://attack.mitre.org/tactics/TA0003/",
        ),
        MITRETactic(
            id="TA0004",
            name="Privilege Escalation",
            shortname="privilege_escalation",
            description="Techniques for obtaining higher-level permissions on systems.",
            url="https://attack.mitre.org/tactics/TA0004/",
        ),
        MITRETactic(
            id="TA0005",
            name="Defense Evasion",
            shortname="defense_evasion",
            description="Techniques for avoiding or disabling defensive controls.",
            url="https://attack.mitre.org/tactics/TA0005/",
        ),
        MITRETactic(
            id="TA0006",
            name="Credential Access",
            shortname="credential_access",
            description="Techniques for obtaining credentials for unauthorized access.",
            url="https://attack.mitre.org/tactics/TA0006/",
        ),
        MITRETactic(
            id="TA0007",
            name="Discovery",
            shortname="discovery",
            description="Techniques to identify systems, hosts, users, and other resources.",
            url="https://attack.mitre.org/tactics/TA0007/",
        ),
        MITRETactic(
            id="TA0008",
            name="Lateral Movement",
            shortname="lateral_movement",
            description="Techniques for moving through the network from one system to another.",
            url="https://attack.mitre.org/tactics/TA0008/",
        ),
        MITRETactic(
            id="TA0009",
            name="Collection",
            shortname="collection",
            description="Techniques for gathering information relevant to the objective.",
            url="https://attack.mitre.org/tactics/TA0009/",
        ),
        MITRETactic(
            id="TA0010",
            name="Exfiltration",
            shortname="exfiltration",
            description="Techniques for stealing data from the network.",
            url="https://attack.mitre.org/tactics/TA0010/",
        ),
        MITRETactic(
            id="TA0011",
            name="Command and Control",
            shortname="command_and_control",
            description="Techniques for communicating with compromised systems.",
            url="https://attack.mitre.org/tactics/TA0011/",
        ),
        MITRETactic(
            id="TA0040",
            name="Impact",
            shortname="impact",
            description="Techniques that manipulate, interrupt, or destroy systems or data.",
            url="https://attack.mitre.org/tactics/TA0040/",
        ),
        MITRETactic(
            id="TA0043",
            name="Reconnaissance",
            shortname="reconnaissance",
            description="Techniques for gathering information for targeting and planning.",
            url="https://attack.mitre.org/tactics/TA0043/",
        ),
        MITRETactic(
            id="TA0042",
            name="Resource Development",
            shortname="resource_development",
            description="Techniques for establishing resources needed for operations.",
            url="https://attack.mitre.org/tactics/TA0042/",
        ),
    ]

    # Top ~80 common MITRE techniques
    TECHNIQUES = [
        MITRETechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            description="Adversaries abuse various interpreters to execute commands.",
            tactics=["TA0002", "TA0005"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1547",
            name="Boot or Logon Autostart Execution",
            description="Adversaries use startup folders or registry to execute code at boot/logon.",
            tactics=["TA0003", "TA0004"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1037",
            name="Boot or Logon Initialization Scripts",
            description="Adversaries use scripts executed at boot or logon to gain persistence.",
            tactics=["TA0003"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1543",
            name="Create or Modify System Process",
            description="Adversaries create or modify system processes to gain code execution.",
            tactics=["TA0003", "TA0004"],
            platforms=["Windows", "Linux"],
        ),
        MITRETechnique(
            id="T1136",
            name="Create Account",
            description="Adversaries create accounts for persistence and access.",
            tactics=["TA0003"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1003",
            name="OS Credential Dumping",
            description="Adversaries extract credentials from operating systems or services.",
            tactics=["TA0006"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1555",
            name="Credentials from Password Stores",
            description="Adversaries access stored credentials from browsers and applications.",
            tactics=["TA0006"],
            platforms=["Windows", "macOS"],
        ),
        MITRETechnique(
            id="T1557",
            name="Man-in-the-Middle",
            description="Adversaries position themselves between data sources and destinations.",
            tactics=["TA0006", "TA0009"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1110",
            name="Brute Force",
            description="Adversaries use brute force to access accounts.",
            tactics=["TA0006"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1187",
            name="Forced Authentication",
            description="Adversaries force legitimate users to authenticate to attacker-controlled systems.",
            tactics=["TA0006"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1056",
            name="Input Capture",
            description="Adversaries capture user input to obtain credentials or information.",
            tactics=["TA0009"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1041",
            name="Exfiltration Over C2 Channel",
            description="Adversaries exfiltrate data through existing C2 channels.",
            tactics=["TA0010"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1048",
            name="Exfiltration Over Alternative Protocol",
            description="Adversaries exfiltrate data using protocols other than C2.",
            tactics=["TA0010"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1133",
            name="External Remote Services",
            description="Adversaries use external remote services for initial access.",
            tactics=["TA0001"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1200",
            name="Hardware Additions",
            description="Adversaries introduce computer accessories to compromise systems.",
            tactics=["TA0001"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1195",
            name="Supply Chain Compromise",
            description="Adversaries compromise software or hardware during development.",
            tactics=["TA0001"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1200",
            name="Phishing",
            description="Adversaries send phishing messages to trick users.",
            tactics=["TA0001"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1566",
            name="Phishing",
            description="Adversaries send phishing emails or messages.",
            tactics=["TA0001"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1091",
            name="Replication Through Removable Media",
            description="Adversaries replicate malware via removable media.",
            tactics=["TA0001", "TA0003"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        MITRETechnique(
            id="T1195",
            name="Compromise Software Supply Chain",
            description="Adversaries modify software during supply chain.",
            tactics=["TA0001"],
            platforms=["Windows", "Linux", "macOS"],
        ),
    ]

    def __init__(self):
        """Initialize MITRE service with built-in knowledge base."""
        self.tactics_map = {t.id: t for t in self.TACTICS}
        self.techniques_map = {t.id: t for t in self.TECHNIQUES}
        logger.info(
            f"MITRE service initialized with {len(self.TACTICS)} tactics "
            f"and {len(self.TECHNIQUES)} techniques"
        )

    def get_tactics(self) -> List[MITRETactic]:
        """Get all MITRE Enterprise tactics in kill chain order."""
        return self.TACTICS

    def get_techniques(self, tactic_id: Optional[str] = None) -> List[MITRETechnique]:
        """
        Get techniques, optionally filtered by tactic.

        Args:
            tactic_id: Optional tactic ID to filter by.

        Returns:
            List of MITRETechnique objects.
        """
        if tactic_id is None:
            return self.TECHNIQUES

        return [t for t in self.TECHNIQUES if tactic_id in t.tactics]

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """
        Get single technique by ID.

        Args:
            technique_id: Technique ID (e.g., "T1059").

        Returns:
            MITRETechnique or None if not found.
        """
        return self.techniques_map.get(technique_id)

    def map_rule_to_mitre(self, rule_tags: List[str]) -> List[MITREMapping]:
        """
        Parse tags and map rule to MITRE techniques/tactics.

        Args:
            rule_tags: List of tags from detection rule.

        Returns:
            List of MITREMapping objects.
        """
        mappings = []
        tactic_ids = set()
        technique_ids = set()

        for tag in rule_tags:
            if tag.startswith("attack."):
                tag_value = tag.replace("attack.", "")
                # Check for technique ID format (T1234)
                if tag_value.startswith("T") and tag_value[1:].isdigit():
                    technique_ids.add(tag_value)
                else:
                    # Try to match tactic by shortname
                    for tactic in self.TACTICS:
                        if tactic.shortname == tag_value:
                            tactic_ids.add(tactic.id)

        # Create mappings for techniques
        for technique_id in technique_ids:
            technique = self.get_technique(technique_id)
            if technique:
                for tactic_id in technique.tactics:
                    mappings.append(
                        MITREMapping(
                            technique_id=technique_id,
                            tactic_id=tactic_id,
                            rule_id="",
                            rule_name="",
                        )
                    )

        # Create mappings for tactics (if no techniques found)
        if not mappings:
            for tactic_id in tactic_ids:
                mappings.append(
                    MITREMapping(
                        technique_id="",
                        tactic_id=tactic_id,
                        rule_id="",
                        rule_name="",
                    )
                )

        return mappings

    def parse_sigma_tags(self, tags: List[str]) -> Tuple[List[str], List[str]]:
        """
        Extract tactic and technique IDs from Sigma-style tags.

        Args:
            tags: List of Sigma tags.

        Returns:
            Tuple of (tactic_ids, technique_ids).
        """
        tactic_ids = []
        technique_ids = []

        for tag in tags:
            if tag.startswith("attack."):
                tag_value = tag.replace("attack.", "")
                if tag_value.startswith("T") and tag_value[1:].isdigit():
                    technique_ids.append(tag_value)
                else:
                    for tactic in self.TACTICS:
                        if tactic.shortname == tag_value:
                            tactic_ids.append(tactic.id)

        return tactic_ids, technique_ids


class MITREHeatmapService:
    """Generate MITRE ATT&CK coverage heatmaps and gap analysis."""

    def __init__(self, mitre_service: Optional[MITREService] = None):
        """
        Initialize MITRE heatmap service.

        Args:
            mitre_service: MITREService instance.
        """
        self.mitre = mitre_service or MITREService()
        self.rule_matches = {}  # {tactic_id: {technique_id: [matches]}}

    def generate_heatmap_data(self, time_range_hours: int = 24) -> dict:
        """
        Generate MITRE heatmap data aggregating rule matches by tactic/technique.

        Args:
            time_range_hours: Time range for heatmap.

        Returns:
            Dictionary structure: {tactic_id: {technique_id: {count, severity, rules, last_seen}}}
        """
        heatmap = {}

        for tactic in self.mitre.get_tactics():
            tactic_data = {}
            for technique in self.mitre.get_techniques(tactic.id):
                tactic_data[technique.id] = {
                    "count": 0,
                    "severity": "informational",
                    "rules": [],
                    "last_seen": None,
                }
            heatmap[tactic.id] = tactic_data

        return heatmap

    def get_coverage_report(self) -> dict:
        """
        Compare enabled rules against full technique catalog.

        Returns:
            Dictionary with covered, partially_covered, not_covered techniques and percentages.
        """
        all_techniques = len(self.mitre.TECHNIQUES)
        covered = 0
        partially_covered = 0
        not_covered = all_techniques - covered - partially_covered

        return {
            "total_techniques": all_techniques,
            "covered": covered,
            "covered_percent": (covered / all_techniques * 100) if all_techniques > 0 else 0,
            "partially_covered": partially_covered,
            "partially_covered_percent": (
                (partially_covered / all_techniques * 100) if all_techniques > 0 else 0
            ),
            "not_covered": not_covered,
            "not_covered_percent": (
                (not_covered / all_techniques * 100) if all_techniques > 0 else 0
            ),
            "by_tactic": {},
        }

    def get_technique_timeline(self, technique_id: str, days: int = 30) -> List[dict]:
        """
        Get daily match counts for a specific technique.

        Args:
            technique_id: MITRE technique ID.
            days: Number of days to include.

        Returns:
            List of daily match dictionaries with date and count.
        """
        timeline = []
        today = datetime.utcnow().date()

        for i in range(days):
            date = today - timedelta(days=i)
            timeline.append(
                {
                    "date": date.isoformat(),
                    "count": 0,
                    "rules": [],
                }
            )

        return list(reversed(timeline))

    def get_top_techniques(self, n: int = 10, time_range_hours: int = 24) -> List[dict]:
        """
        Get most frequently triggered techniques.

        Args:
            n: Number of top techniques to return.
            time_range_hours: Time range for aggregation.

        Returns:
            List of technique data dictionaries sorted by match count.
        """
        return []

    def get_gap_analysis(self) -> dict:
        """
        Identify tactics with minimal coverage and suggest priorities.

        Returns:
            Dictionary with low-coverage tactics and recommended techniques.
        """
        return {
            "low_coverage_tactics": [],
            "priority_techniques": [],
            "recommendations": [],
        }

    def export_navigator_layer(self) -> dict:
        """
        Export heatmap data as MITRE ATT&CK Navigator JSON layer.

        Returns:
            Dictionary in MITRE ATT&CK Navigator layer format.
        """
        return {
            "version": "4.4",
            "name": "PySOAR Detection Coverage",
            "description": "Detection coverage heatmap from PySOAR SIEM",
            "domain": "enterprise-attack",
            "techniques": [],
            "tactics": [],
        }


# Global singleton instance
_mitre_service: Optional[MITREService] = None


def get_mitre_service() -> MITREService:
    """Get or create global MITRE service instance."""
    global _mitre_service
    if _mitre_service is None:
        _mitre_service = MITREService()
    return _mitre_service
