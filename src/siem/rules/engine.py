"""Sigma-inspired detection rule engine for PySOAR SIEM.

This module provides a real-time log evaluation engine that processes YAML-based
detection rules against incoming log entries. Rules support complex conditions,
time-window aggregations, and threshold-based detections.
"""

import re
import fnmatch
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from ipaddress import ip_address, ip_network, AddressValueError
import yaml


@dataclass
class RuleMatch:
    """Represents a successful rule match against a log entry."""

    rule_id: str
    rule_title: str
    severity: str
    matched_fields: Dict[str, Any]
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'rule_id': self.rule_id,
            'rule_title': self.rule_title,
            'severity': self.severity,
            'matched_fields': self.matched_fields,
            'mitre_tactics': self.mitre_tactics,
            'mitre_techniques': self.mitre_techniques,
            'timestamp': self.timestamp.isoformat(),
        }


class FieldMatcher:
    """Evaluates a single field condition against log fields."""

    def __init__(self, field_name: str, condition: Any):
        """Initialize a field matcher.

        Args:
            field_name: The name of the field to match
            condition: The condition value (string, list, dict with operators)
        """
        self.field_name = field_name
        self.condition = condition
        self._parse_condition()

    def _parse_condition(self):
        """Parse the condition into operator and value(s)."""
        self.operator = 'exact'
        self.value = self.condition

        # If condition is a dict, extract operator and value
        if isinstance(self.condition, dict):
            if 'regex' in self.condition:
                self.operator = 'regex'
                self.value = self.condition['regex']
            elif 'contains' in self.condition:
                self.operator = 'contains'
                self.value = self.condition['contains']
            elif 'startswith' in self.condition:
                self.operator = 'startswith'
                self.value = self.condition['startswith']
            elif 'endswith' in self.condition:
                self.operator = 'endswith'
                self.value = self.condition['endswith']
            elif 'all' in self.condition:
                self.operator = 'all'
                self.value = self.condition['all']
            elif 'cidr' in self.condition:
                self.operator = 'cidr'
                self.value = self.condition['cidr']
            elif 'exists' in self.condition:
                self.operator = 'exists'
                self.value = self.condition['exists']
            elif '>' in self.condition:
                self.operator = '>'
                self.value = self.condition['>']
            elif '<' in self.condition:
                self.operator = '<'
                self.value = self.condition['<']
            elif '>=' in self.condition:
                self.operator = '>='
                self.value = self.condition['>=']
            elif '<=' in self.condition:
                self.operator = '<='
                self.value = self.condition['<=']
        elif isinstance(self.condition, list):
            # List means "any of" (OR logic)
            self.operator = 'any_of'
            self.value = self.condition

    def matches(self, log_fields: Dict[str, Any]) -> bool:
        """Check if this field matcher matches the log fields.

        Args:
            log_fields: Dictionary of log field values

        Returns:
            True if the field matches the condition
        """
        field_value = log_fields.get(self.field_name)

        if self.operator == 'exists':
            # Check if field exists
            exists = self.field_name in log_fields
            return exists if self.value else not exists

        if self.field_name not in log_fields:
            return False

        if self.operator == 'exact':
            return self._match_exact(field_value)
        elif self.operator == 'any_of':
            return any(self._match_exact(field_value, v) for v in self.value)
        elif self.operator == 'regex':
            return self._match_regex(field_value)
        elif self.operator == 'contains':
            return self._match_contains(field_value)
        elif self.operator == 'startswith':
            return self._match_startswith(field_value)
        elif self.operator == 'endswith':
            return self._match_endswith(field_value)
        elif self.operator == 'all':
            return self._match_all(field_value)
        elif self.operator == 'cidr':
            return self._match_cidr(field_value)
        elif self.operator == '>':
            return self._match_numeric_gt(field_value)
        elif self.operator == '<':
            return self._match_numeric_lt(field_value)
        elif self.operator == '>=':
            return self._match_numeric_gte(field_value)
        elif self.operator == '<=':
            return self._match_numeric_lte(field_value)

        return False

    def _match_exact(self, field_value: Any, condition: Any = None) -> bool:
        """Match exact value, with wildcard support."""
        cond = condition if condition is not None else self.value
        field_str = str(field_value).lower()
        cond_str = str(cond).lower()

        # Check for wildcards
        if '*' in cond_str or '?' in cond_str:
            return fnmatch.fnmatch(field_str, cond_str)

        return field_str == cond_str

    def _match_regex(self, field_value: Any) -> bool:
        """Match using regex pattern."""
        try:
            pattern = re.compile(self.value, re.IGNORECASE)
            return bool(pattern.search(str(field_value)))
        except re.error:
            return False

    def _match_contains(self, field_value: Any) -> bool:
        """Check if field contains the value."""
        return str(self.value).lower() in str(field_value).lower()

    def _match_startswith(self, field_value: Any) -> bool:
        """Check if field starts with the value."""
        return str(field_value).lower().startswith(str(self.value).lower())

    def _match_endswith(self, field_value: Any) -> bool:
        """Check if field ends with the value."""
        return str(field_value).lower().endswith(str(self.value).lower())

    def _match_all(self, field_value: Any) -> bool:
        """Check if field contains all values (for list fields)."""
        if not isinstance(field_value, list):
            field_value = [field_value]
        field_lower = [str(v).lower() for v in field_value]
        return all(str(v).lower() in field_lower for v in self.value)

    def _match_cidr(self, field_value: Any) -> bool:
        """Match IP address against CIDR range."""
        try:
            ip = ip_address(str(field_value))
            cidr_ranges = self.value if isinstance(self.value, list) else [self.value]
            return any(ip in ip_network(cidr, strict=False) for cidr in cidr_ranges)
        except (AddressValueError, ValueError):
            return False

    def _match_numeric_gt(self, field_value: Any) -> bool:
        """Match numeric greater than."""
        try:
            return float(field_value) > float(self.value)
        except (TypeError, ValueError):
            return False

    def _match_numeric_lt(self, field_value: Any) -> bool:
        """Match numeric less than."""
        try:
            return float(field_value) < float(self.value)
        except (TypeError, ValueError):
            return False

    def _match_numeric_gte(self, field_value: Any) -> bool:
        """Match numeric greater than or equal."""
        try:
            return float(field_value) >= float(self.value)
        except (TypeError, ValueError):
            return False

    def _match_numeric_lte(self, field_value: Any) -> bool:
        """Match numeric less than or equal."""
        try:
            return float(field_value) <= float(self.value)
        except (TypeError, ValueError):
            return False


class SelectionBlock:
    """A named group of field matchers with AND logic."""

    def __init__(self, name: str, conditions: Dict[str, Any]):
        """Initialize a selection block.

        Args:
            name: Name of this selection (e.g., 'selection', 'filter1')
            conditions: Dictionary of field -> condition mappings
        """
        self.name = name
        self.matchers: List[FieldMatcher] = []

        for field_name, condition in conditions.items():
            if field_name not in ('timewindow', 'threshold', 'group_by'):
                self.matchers.append(FieldMatcher(field_name, condition))

    def evaluate(self, log_fields: Dict[str, Any]) -> bool:
        """Evaluate all matchers with AND logic.

        Args:
            log_fields: Dictionary of log field values

        Returns:
            True if all matchers match (AND logic)
        """
        return all(matcher.matches(log_fields) for matcher in self.matchers)


class ConditionEvaluator:
    """Evaluates condition expressions with AND, OR, NOT logic."""

    def __init__(self, condition_expr: str):
        """Initialize the condition evaluator.

        Args:
            condition_expr: Expression like "selection AND NOT filter OR selection2"
        """
        self.condition_expr = condition_expr.strip()
        self.tokens = self._tokenize(self.condition_expr)

    def _tokenize(self, expr: str) -> List[str]:
        """Tokenize the condition expression."""
        # Add spaces around operators and parentheses
        expr = re.sub(r'(\(|\))', r' \1 ', expr)
        tokens = expr.split()
        return tokens

    def evaluate(self, selections: Dict[str, bool]) -> bool:
        """Evaluate the condition against selection results.

        Args:
            selections: Dictionary of selection_name -> bool (match result)

        Returns:
            True if the condition is satisfied
        """
        return self._parse_or(self.tokens, selections, [0])[0]

    def _parse_or(
        self,
        tokens: List[str],
        selections: Dict[str, bool],
        pos: List[int],
    ) -> Tuple[bool, int]:
        """Parse OR expressions (lowest precedence)."""
        left, _ = self._parse_and(tokens, selections, pos)

        while pos[0] < len(tokens) and tokens[pos[0]].upper() == 'OR':
            pos[0] += 1
            right, _ = self._parse_and(tokens, selections, pos)
            left = left or right

        return left, pos[0]

    def _parse_and(
        self,
        tokens: List[str],
        selections: Dict[str, bool],
        pos: List[int],
    ) -> Tuple[bool, int]:
        """Parse AND expressions (higher precedence than OR)."""
        left, _ = self._parse_not(tokens, selections, pos)

        while pos[0] < len(tokens) and tokens[pos[0]].upper() == 'AND':
            pos[0] += 1
            right, _ = self._parse_not(tokens, selections, pos)
            left = left and right

        return left, pos[0]

    def _parse_not(
        self,
        tokens: List[str],
        selections: Dict[str, bool],
        pos: List[int],
    ) -> Tuple[bool, int]:
        """Parse NOT expressions (highest precedence)."""
        if pos[0] < len(tokens) and tokens[pos[0]].upper() == 'NOT':
            pos[0] += 1
            result, _ = self._parse_not(tokens, selections, pos)
            return not result, pos[0]

        return self._parse_primary(tokens, selections, pos)

    def _parse_primary(
        self,
        tokens: List[str],
        selections: Dict[str, bool],
        pos: List[int],
    ) -> Tuple[bool, int]:
        """Parse primary expressions (identifiers or parenthesized expressions)."""
        if pos[0] >= len(tokens):
            return False, pos[0]

        token = tokens[pos[0]]

        if token == '(':
            pos[0] += 1
            result, _ = self._parse_or(tokens, selections, pos)
            if pos[0] < len(tokens) and tokens[pos[0]] == ')':
                pos[0] += 1
            return result, pos[0]
        elif token != ')':
            # It's a selection name
            pos[0] += 1
            return selections.get(token, False), pos[0]

        return False, pos[0]


class AggregationTracker:
    """Tracks event counts within time windows for threshold-based detection."""

    def __init__(self, timewindow_seconds: int, threshold: int):
        """Initialize aggregation tracker.

        Args:
            timewindow_seconds: Duration of the sliding time window
            threshold: Number of events required to trigger detection
        """
        self.timewindow = timedelta(seconds=timewindow_seconds)
        self.threshold = threshold
        self.buckets: Dict[str, List[datetime]] = {}
        self.lock = threading.Lock()

    def track_event(self, group_key: str, timestamp: datetime) -> bool:
        """Track an event and check if threshold is exceeded.

        Args:
            group_key: Grouping key (e.g., "src_ip:192.168.1.1")
            timestamp: Event timestamp

        Returns:
            True if threshold is exceeded within the time window
        """
        with self.lock:
            if group_key not in self.buckets:
                self.buckets[group_key] = []

            # Remove expired timestamps
            cutoff = timestamp - self.timewindow
            self.buckets[group_key] = [
                ts for ts in self.buckets[group_key] if ts > cutoff
            ]

            # Add current event
            self.buckets[group_key].append(timestamp)

            # Check if threshold exceeded
            return len(self.buckets[group_key]) >= self.threshold

    def cleanup_expired(self, current_time: datetime):
        """Remove expired buckets."""
        with self.lock:
            expired_keys = []
            for key, timestamps in self.buckets.items():
                cutoff = current_time - self.timewindow
                if not any(ts > cutoff for ts in timestamps):
                    expired_keys.append(key)

            for key in expired_keys:
                del self.buckets[key]


class DetectionRuleInstance:
    """A loaded, parsed detection rule ready for evaluation."""

    def __init__(self, rule_data: Dict[str, Any]):
        """Initialize a detection rule from parsed YAML data.

        Args:
            rule_data: Dictionary containing rule definition
        """
        self.rule_id = rule_data.get('id', 'unknown')
        self.title = rule_data.get('title', 'Untitled')
        self.description = rule_data.get('description', '')
        self.author = rule_data.get('author', '')
        self.severity = rule_data.get('severity', 'medium')
        self.logtypes = rule_data.get('logtypes', [])
        self.tags = rule_data.get('tags', [])
        self.references = rule_data.get('references', [])

        # MITRE ATT&CK framework
        mitre_data = rule_data.get('mitre', {})
        self.mitre_tactics = mitre_data.get('tactics', [])
        self.mitre_techniques = mitre_data.get('techniques', [])

        # Detection logic
        detection = rule_data.get('detection', {})
        self.condition_expr = detection.get('condition', '')
        self.selections: Dict[str, SelectionBlock] = {}

        # Parse all selection blocks
        for key, conditions in detection.items():
            if key not in ('condition', 'timewindow', 'threshold', 'group_by'):
                self.selections[key] = SelectionBlock(key, conditions)

        # Aggregation settings
        self.timewindow = detection.get('timewindow', 0)
        self.threshold = detection.get('threshold', 0)
        self.group_by = detection.get('group_by', [])

        # Initialize aggregation tracker if needed
        self.aggregator: Optional[AggregationTracker] = None
        if self.timewindow > 0 and self.threshold > 0:
            self.aggregator = AggregationTracker(self.timewindow, self.threshold)

        # Parse condition
        self.condition_evaluator = ConditionEvaluator(self.condition_expr)

        # Status
        self.enabled = rule_data.get('status', 'active').lower() == 'active'

    def evaluate(self, log_fields: Dict[str, Any]) -> Optional[RuleMatch]:
        """Evaluate this rule against a log entry.

        Args:
            log_fields: Dictionary of log field values

        Returns:
            RuleMatch if rule matches, None otherwise
        """
        if not self.enabled:
            return None

        # Evaluate all selections
        selection_results = {}
        for name, selection in self.selections.items():
            selection_results[name] = selection.evaluate(log_fields)

        # Evaluate condition
        if not self.condition_evaluator.evaluate(selection_results):
            return None

        # Check aggregation if configured
        if self.aggregator:
            timestamp = log_fields.get('timestamp')
            if not isinstance(timestamp, datetime):
                try:
                    timestamp = datetime.fromisoformat(str(timestamp))
                except (ValueError, TypeError):
                    timestamp = datetime.utcnow()

            # Build group key from group_by fields
            group_parts = []
            for field in self.group_by:
                value = log_fields.get(field, 'unknown')
                group_parts.append(f"{field}:{value}")
            group_key = '|'.join(group_parts) if group_parts else 'all'

            # Track and check threshold
            if not self.aggregator.track_event(group_key, timestamp):
                return None

        # Rule matched
        return RuleMatch(
            rule_id=self.rule_id,
            rule_title=self.title,
            severity=self.severity,
            matched_fields=log_fields.copy(),
            mitre_tactics=self.mitre_tactics,
            mitre_techniques=self.mitre_techniques,
        )


class RuleEngine:
    """Main detection rule engine for evaluating logs against YAML rules."""

    def __init__(self):
        """Initialize the rule engine."""
        self.rules: Dict[str, DetectionRuleInstance] = {}
        self.lock = threading.RLock()
        self.stats = {
            'rules_loaded': 0,
            'rules_active': 0,
            'total_matches': 0,
            'matches_by_rule': {},
        }

    def load_rules_from_directory(self, path: str) -> int:
        """Load all YAML rules from a directory.

        Args:
            path: Directory path containing .yaml/.yml files

        Returns:
            Number of rules loaded
        """
        dir_path = Path(path)
        if not dir_path.is_dir():
            raise ValueError(f"Directory not found: {path}")

        count = 0
        for yaml_file in dir_path.glob('*.yaml'):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    rule = self.load_rule_from_yaml(content)
                    if rule:
                        count += 1
            except Exception as e:
                print(f"Error loading rule from {yaml_file}: {e}")

        for yaml_file in dir_path.glob('*.yml'):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    rule = self.load_rule_from_yaml(content)
                    if rule:
                        count += 1
            except Exception as e:
                print(f"Error loading rule from {yaml_file}: {e}")

        return count

    def load_rule_from_yaml(self, yaml_content: str) -> Optional[DetectionRuleInstance]:
        """Load and register a rule from YAML content.

        Args:
            yaml_content: YAML content as string

        Returns:
            DetectionRuleInstance if successful, None otherwise
        """
        try:
            rule_data = yaml.safe_load(yaml_content)
            if not rule_data:
                return None

            rule = DetectionRuleInstance(rule_data)
            with self.lock:
                self.rules[rule.rule_id] = rule
                self.stats['rules_loaded'] += 1
                if rule.enabled:
                    self.stats['rules_active'] += 1
                self.stats['matches_by_rule'][rule.rule_id] = 0

            return rule
        except yaml.YAMLError as e:
            print(f"YAML parsing error: {e}")
            return None
        except Exception as e:
            print(f"Error loading rule: {e}")
            return None

    def load_rule_from_model(self, rule_model: Any) -> Optional[DetectionRuleInstance]:
        """Load a rule from a data model/ORM object.

        Args:
            rule_model: Rule model object with .yaml_content or .content attribute

        Returns:
            DetectionRuleInstance if successful, None otherwise
        """
        yaml_content = getattr(
            rule_model, 'yaml_content', getattr(rule_model, 'content', None)
        )
        if not yaml_content:
            return None

        return self.load_rule_from_yaml(yaml_content)

    def evaluate_log(self, log_fields: Dict[str, Any]) -> List[RuleMatch]:
        """Evaluate a log entry against all active rules.

        Args:
            log_fields: Dictionary of log field values

        Returns:
            List of RuleMatch objects for matching rules
        """
        matches = []

        with self.lock:
            for rule in self.rules.values():
                if not rule.enabled:
                    continue

                match = rule.evaluate(log_fields)
                if match:
                    matches.append(match)
                    self.stats['total_matches'] += 1
                    self.stats['matches_by_rule'][rule.rule_id] += 1

        return matches

    def add_rule(self, rule: DetectionRuleInstance) -> None:
        """Add a rule to the engine.

        Args:
            rule: DetectionRuleInstance to add
        """
        with self.lock:
            self.rules[rule.rule_id] = rule
            if rule.rule_id not in self.stats['matches_by_rule']:
                self.stats['matches_by_rule'][rule.rule_id] = 0

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule from the engine.

        Args:
            rule_id: ID of the rule to remove

        Returns:
            True if removed, False if not found
        """
        with self.lock:
            if rule_id in self.rules:
                del self.rules[rule_id]
                return True
            return False

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule.

        Args:
            rule_id: ID of the rule to enable

        Returns:
            True if enabled, False if not found
        """
        with self.lock:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = True
                return True
            return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule.

        Args:
            rule_id: ID of the rule to disable

        Returns:
            True if disabled, False if not found
        """
        with self.lock:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = False
                return True
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics.

        Returns:
            Dictionary with rule counts and match statistics
        """
        with self.lock:
            return {
                'rules_loaded': len(self.rules),
                'rules_active': sum(1 for r in self.rules.values() if r.enabled),
                'total_matches': self.stats['total_matches'],
                'matches_by_rule': self.stats['matches_by_rule'].copy(),
            }

    def get_rule(self, rule_id: str) -> Optional[DetectionRuleInstance]:
        """Get a rule by ID.

        Args:
            rule_id: ID of the rule to retrieve

        Returns:
            DetectionRuleInstance or None if not found
        """
        with self.lock:
            return self.rules.get(rule_id)

    def list_rules(self, enabled_only: bool = False) -> List[DetectionRuleInstance]:
        """List all rules.

        Args:
            enabled_only: If True, only return enabled rules

        Returns:
            List of DetectionRuleInstance objects
        """
        with self.lock:
            rules = list(self.rules.values())
            if enabled_only:
                rules = [r for r in rules if r.enabled]
            return rules
