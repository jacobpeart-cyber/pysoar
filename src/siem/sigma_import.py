"""Sigma rule importer for converting official Sigma rules to PySOAR format.

This module provides tools to parse, validate, and convert Sigma detection rules
(https://github.com/SigmaHQ/sigma) into PySOAR's native detection rule format.
Handles Sigma YAML parsing, field mapping, modifier processing, and condition translation.
"""

import base64
import json
import logging
import re
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime
from ipaddress import IPv4Network, AddressValueError
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


class SigmaException(Exception):
    """Base exception for Sigma processing errors."""
    pass


class SigmaFieldMapError(SigmaException):
    """Error mapping Sigma field names."""
    pass


class SigmaConditionError(SigmaException):
    """Error parsing Sigma condition."""
    pass


@dataclass
class SigmaRule:
    """Parsed Sigma rule with all metadata."""

    title: str
    id: str
    status: str = "stable"
    description: str = ""
    author: str = ""
    date: Optional[str] = None
    modified: Optional[str] = None
    references: List[str] = field(default_factory=list)
    logsource: Dict[str, str] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    falsepositives: List[str] = field(default_factory=list)
    level: str = "medium"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


class SigmaModifierHandler:
    """Processes Sigma field value modifiers."""

    @staticmethod
    def apply_modifier(value: Any, modifier: str) -> Any:
        """Apply a Sigma modifier to a value.

        Args:
            value: The value to modify
            modifier: The modifier name (contains, startswith, endswith, re, etc.)

        Returns:
            Modified value or dict with operator specification
        """
        if modifier == "contains":
            return {"contains": value}
        elif modifier == "startswith":
            return {"startswith": value}
        elif modifier == "endswith":
            return {"endswith": value}
        elif modifier == "all":
            return {"all": value if isinstance(value, list) else [value]}
        elif modifier == "re":
            return {"regex": value}
        elif modifier == "base64":
            try:
                decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
                return decoded
            except Exception as e:
                logger.warning(f"Failed to decode base64 value: {e}")
                return value
        elif modifier == "cidr":
            return {"cidr": value if isinstance(value, list) else [value]}
        elif modifier in ("gt", "gte", "lt", "lte"):
            op_map = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
            return {op_map[modifier]: value}
        else:
            logger.warning(f"Unknown modifier: {modifier}")
            return value

    @staticmethod
    def parse_field_with_modifier(field_spec: str) -> Tuple[str, Optional[str]]:
        """Parse field name with optional pipe-delimited modifier.

        Args:
            field_spec: Field specification like "fieldname|modifier"

        Returns:
            Tuple of (field_name, modifier) or (field_name, None)
        """
        if "|" in field_spec:
            parts = field_spec.split("|", 1)
            return parts[0].strip(), parts[1].strip()
        return field_spec.strip(), None


class SigmaFieldMapper:
    """Maps Sigma field names to PySOAR normalized field names."""

    # Logsource to log_type mappings
    LOGSOURCE_TO_LOGTYPE = {
        ("windows", "process_creation"): "endpoint",
        ("windows", "image_load"): "endpoint",
        ("windows", "file_event"): "endpoint",
        ("windows", "raw_access_thread"): "endpoint",
        ("windows", "network_connection"): "network",
        ("windows", "dns_query"): "network",
        ("windows", "registry_event"): "endpoint",
        ("linux", "process_creation"): "endpoint",
        ("linux", "file_change"): "system",
        ("linux", "auth"): "authentication",
        ("linux", "auditd"): "system",
        ("macos", "process_creation"): "endpoint",
        ("application",): "application",
        ("cloud",): "cloud",
        ("firewall",): "network",
        ("proxy",): "network",
        ("webserver",): "application",
        ("database",): "application",
        ("authentication",): "authentication",
    }

    # Common field name mappings from Sigma to PySOAR
    FIELD_MAPPINGS = {
        # Process fields
        "Image": "process_name",
        "image": "process_name",
        "CommandLine": "command_line",
        "commandLine": "command_line",
        "ParentImage": "parent_process_name",
        "ProcessId": "process_id",
        "parentProcessId": "parent_process_id",
        # User/Account fields
        "User": "username",
        "user": "username",
        "UserName": "username",
        "SubjectUserName": "username",
        "TargetUserName": "username",
        "AccountName": "username",
        # Host fields
        "ComputerName": "hostname",
        "Computer": "hostname",
        "Hostname": "hostname",
        "host": "hostname",
        "dns_query": "query",
        "destination": "destination_address",
        "source": "source_address",
        # Network fields
        "DestinationPort": "destination_port",
        "destinationPort": "destination_port",
        "SourcePort": "source_port",
        "sourcePort": "source_port",
        "DestinationIp": "destination_address",
        "destinationIp": "destination_address",
        "SourceIp": "source_address",
        "sourceIp": "source_address",
        "Protocol": "protocol",
        "protocol": "protocol",
        # File fields
        "TargetFilename": "file_path",
        "targetFilename": "file_path",
        "Image": "file_path",
        # Event fields
        "EventID": "event_id",
        "eventID": "event_id",
        "event_id": "event_id",
        "EventType": "event_type",
        "Channel": "channel",
        "channel": "channel",
        # Default pass-through for common fields
        "action": "action",
        "outcome": "outcome",
    }

    @classmethod
    def map_logsource(cls, logsource: Dict[str, str]) -> str:
        """Map Sigma logsource to PySOAR log_type.

        Args:
            logsource: Dict with keys like product, category, service

        Returns:
            PySOAR log_type string
        """
        product = logsource.get("product", "").lower()
        category = logsource.get("category", "").lower()
        service = logsource.get("service", "").lower()

        # Try specific mappings
        for key, logtype in cls.LOGSOURCE_TO_LOGTYPE.items():
            if len(key) == 1:
                if product == key[0] or category == key[0]:
                    return logtype
            elif len(key) == 2:
                if (product == key[0] or category == key[0]) and category == key[1]:
                    return logtype

        # Fallback based on category
        if "auth" in category or "authentication" in category:
            return "authentication"
        elif "network" in category or "dns" in category:
            return "network"
        elif "process" in category or "image" in category:
            return "endpoint"
        elif "file" in category:
            return "system"
        else:
            return "application"

    @classmethod
    def map_field(cls, field_name: str) -> str:
        """Map a Sigma field name to PySOAR normalized field name.

        Args:
            field_name: Original Sigma field name

        Returns:
            Mapped PySOAR field name
        """
        # Check direct mapping
        if field_name in cls.FIELD_MAPPINGS:
            return cls.FIELD_MAPPINGS[field_name]

        # Default: convert to lowercase with underscores
        normalized = field_name.lower().replace(" ", "_")
        return normalized


class SigmaConditionParser:
    """Parses Sigma condition expressions."""

    def __init__(self):
        self.condition_expr = ""
        self.tokens = []

    def parse(self, condition_str: str) -> str:
        """Parse a Sigma condition string.

        Args:
            condition_str: Condition expression like "selection and not filter"

        Returns:
            Normalized condition string compatible with PySOAR engine
        """
        self.condition_expr = condition_str.strip()
        self._tokenize()
        return self._convert_to_pysoar()

    def _tokenize(self):
        """Tokenize the condition expression."""
        # Replace operators with spaces around them
        expr = self.condition_expr
        expr = re.sub(r'\b(and|or|not|of|all|1)\b', r' \1 ', expr, flags=re.IGNORECASE)
        expr = re.sub(r'[()]', r' \g<0> ', expr)
        self.tokens = expr.split()

    def _convert_to_pysoar(self) -> str:
        """Convert tokenized Sigma condition to PySOAR format.

        Returns:
            Condition string for PySOAR rule engine
        """
        result = []
        i = 0

        while i < len(self.tokens):
            token = self.tokens[i]

            if token.lower() == "not":
                result.append("NOT")
            elif token.lower() == "and":
                result.append("AND")
            elif token.lower() == "or":
                result.append("OR")
            elif token == "(":
                result.append("(")
            elif token == ")":
                result.append(")")
            elif token.lower() in ("all", "of"):
                # Handle "all of selection*" or "1 of selection*"
                result.append(token)
            elif token == "*":
                result.append("*")
            elif token and not token.isspace():
                # It's a selection name
                result.append(token)

            i += 1

        return " ".join(result).strip()


class SigmaToDetectionLogic:
    """Converts Sigma detection selections to PySOAR detection_logic."""

    def __init__(self, field_mapper: SigmaFieldMapper = None):
        self.field_mapper = field_mapper or SigmaFieldMapper()

    def convert_selection(
        self,
        selection_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Convert a Sigma selection block to PySOAR format.

        Args:
            selection_data: Selection dict from Sigma rule detection section

        Returns:
            Dict with PySOAR field matchers
        """
        pysoar_selection = {}

        for field_name, field_value in selection_data.items():
            if field_name in ("timewindow", "threshold", "group_by"):
                # Pass through aggregation settings
                pysoar_selection[field_name] = field_value
                continue

            mapped_field = self.field_mapper.map_field(field_name)

            # Handle modifiers in field name
            if "|" in field_name:
                base_field, modifier = SigmaModifierHandler.parse_field_with_modifier(
                    field_name
                )
                mapped_field = self.field_mapper.map_field(base_field)

                if modifier:
                    field_value = SigmaModifierHandler.apply_modifier(
                        field_value, modifier
                    )

            pysoar_selection[mapped_field] = field_value

        return pysoar_selection

    def convert_detection(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """Convert entire Sigma detection section.

        Args:
            detection: Detection section from Sigma rule

        Returns:
            PySOAR detection dict with selections and condition
        """
        pysoar_detection = {}

        # Convert all selections
        for key, value in detection.items():
            if key == "condition":
                continue
            if key in ("timewindow", "threshold", "group_by"):
                pysoar_detection[key] = value
                continue

            if isinstance(value, dict):
                pysoar_detection[key] = self.convert_selection(value)

        # Add condition
        if "condition" in detection:
            parser = SigmaConditionParser()
            pysoar_detection["condition"] = parser.parse(detection["condition"])

        return pysoar_detection


class SigmaImporter:
    """Main Sigma rule importer and converter."""

    def __init__(self):
        self.field_mapper = SigmaFieldMapper()
        self.condition_parser = SigmaConditionParser()
        self.detection_converter = SigmaToDetectionLogic(self.field_mapper)
        self.conversion_reports = {}

    def import_rule(self, yaml_content: str) -> Optional[Dict[str, Any]]:
        """Parse and convert a single Sigma YAML rule.

        Args:
            yaml_content: YAML content as string

        Returns:
            Dict with PySOAR detection rule format or None on error
        """
        try:
            rule_data = yaml.safe_load(yaml_content)
            if not rule_data:
                logger.error("Empty YAML content")
                return None

            sigma_rule = self._parse_sigma_rule(rule_data)
            return self._convert_sigma_to_pysoar(sigma_rule)

        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            return None
        except Exception as e:
            logger.error(f"Error importing rule: {e}")
            return None

    def import_directory(self, path: str) -> List[Dict[str, Any]]:
        """Recursively import all .yml/.yaml files from directory.

        Args:
            path: Directory path

        Returns:
            List of converted rules
        """
        rules = []
        dir_path = Path(path)

        if not dir_path.is_dir():
            logger.error(f"Directory not found: {path}")
            return rules

        for rule_file in dir_path.glob("**/*.y[a]ml"):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    rule = self.import_rule(content)
                    if rule:
                        rules.append(rule)
                        logger.info(f"Imported rule from {rule_file}")
            except Exception as e:
                logger.error(f"Error importing {rule_file}: {e}")

        logger.info(f"Imported {len(rules)} rules from {path}")
        return rules

    def import_from_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch and import a rule from URL.

        Args:
            url: URL to fetch Sigma rule from

        Returns:
            Converted rule dict or None
        """
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                content = response.read().decode("utf-8")
                return self.import_rule(content)
        except Exception as e:
            logger.error(f"Error fetching rule from {url}: {e}")
            return None

    def validate_sigma(self, yaml_content: str) -> Tuple[bool, List[str]]:
        """Validate Sigma rule syntax.

        Args:
            yaml_content: YAML content to validate

        Returns:
            Tuple of (valid, errors) where errors is list of error messages
        """
        errors = []

        try:
            rule_data = yaml.safe_load(yaml_content)
            if not rule_data:
                errors.append("Empty YAML content")
                return False, errors

            # Check required fields
            required = ["title", "id", "detection"]
            for field in required:
                if field not in rule_data:
                    errors.append(f"Missing required field: {field}")

            # Validate detection section
            if "detection" in rule_data:
                detection = rule_data["detection"]
                if not isinstance(detection, dict):
                    errors.append("Detection section must be a dict")
                elif "condition" not in detection:
                    errors.append("Detection section must have condition")

            return len(errors) == 0, errors

        except yaml.YAMLError as e:
            errors.append(f"YAML parsing error: {e}")
            return False, errors

    def get_conversion_report(
        self, sigma_rule: SigmaRule
    ) -> Dict[str, Any]:
        """Generate report of what was converted and approximated.

        Args:
            sigma_rule: Parsed Sigma rule

        Returns:
            Report dict with conversion details
        """
        return {
            "rule_id": sigma_rule.id,
            "title": sigma_rule.title,
            "status": sigma_rule.status,
            "logsource_mapped": self.field_mapper.map_logsource(sigma_rule.logsource),
            "selections_count": len(
                [k for k in sigma_rule.detection.keys() if k != "condition"]
            ),
            "has_aggregation": any(
                k in sigma_rule.detection for k in ("timewindow", "threshold")
            ),
            "mitre_tags": [t for t in sigma_rule.tags if t.startswith("attack.")],
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _parse_sigma_rule(self, rule_data: Dict[str, Any]) -> SigmaRule:
        """Parse raw YAML dict into SigmaRule dataclass.

        Args:
            rule_data: Parsed YAML dict

        Returns:
            SigmaRule instance
        """
        return SigmaRule(
            title=rule_data.get("title", "Untitled"),
            id=rule_data.get("id", "unknown"),
            status=rule_data.get("status", "stable"),
            description=rule_data.get("description", ""),
            author=rule_data.get("author", ""),
            date=rule_data.get("date"),
            modified=rule_data.get("modified"),
            references=rule_data.get("references", []),
            logsource=rule_data.get("logsource", {}),
            detection=rule_data.get("detection", {}),
            falsepositives=rule_data.get("falsepositives", []),
            level=rule_data.get("level", "medium"),
            tags=rule_data.get("tags", []),
        )

    def _convert_sigma_to_pysoar(self, sigma_rule: SigmaRule) -> Dict[str, Any]:
        """Convert SigmaRule to PySOAR DetectionRule format.

        Args:
            sigma_rule: Parsed Sigma rule

        Returns:
            PySOAR rule dict
        """
        # Convert severity
        severity_map = {
            "informational": "informational",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }
        severity = severity_map.get(sigma_rule.level.lower(), "medium")

        # Extract MITRE tactics and techniques from tags
        mitre_tactics = []
        mitre_techniques = []
        for tag in sigma_rule.tags:
            if tag.startswith("attack.t"):
                mitre_techniques.append(tag.replace("attack.", ""))
            elif tag.startswith("attack."):
                mitre_tactics.append(tag.replace("attack.", ""))

        # Convert detection logic
        detection_logic = self.detection_converter.convert_detection(sigma_rule.detection)

        # Build PySOAR rule
        pysoar_rule = {
            "id": sigma_rule.id,
            "title": sigma_rule.title,
            "description": sigma_rule.description,
            "author": sigma_rule.author,
            "severity": severity,
            "status": "active" if sigma_rule.status != "deprecated" else "disabled",
            "logtypes": [self.field_mapper.map_logsource(sigma_rule.logsource)],
            "tags": sigma_rule.tags,
            "references": sigma_rule.references,
            "detection": detection_logic,
            "mitre": {
                "tactics": mitre_tactics,
                "techniques": mitre_techniques,
            },
            "false_positives": sigma_rule.falsepositives,
        }

        # Store conversion report
        self.conversion_reports[sigma_rule.id] = self.get_conversion_report(sigma_rule)

        return pysoar_rule
