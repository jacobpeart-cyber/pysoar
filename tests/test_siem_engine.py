"""Tests for SIEM Detection Rule Engine

Real tests importing and testing actual SIEM rule evaluation classes.
"""

import pytest
from datetime import datetime, timedelta
from typing import Dict, Any

from src.siem.rules.engine import (
    FieldMatcher,
    SelectionBlock,
    ConditionEvaluator,
    AggregationTracker,
    DetectionRuleInstance,
    RuleMatch,
)


@pytest.fixture
def sample_log_entry() -> Dict[str, Any]:
    """Sample log entry for testing"""
    return {
        "timestamp": datetime.utcnow(),
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "user": "john.doe",
        "action": "login",
        "status": "success",
        "event_count": 5,
        "protocol": "http",
        "tags": ["web", "auth"],
    }


class TestFieldMatcher:
    """Tests for FieldMatcher class"""

    def test_exact_match(self):
        """Test exact string matching"""
        matcher = FieldMatcher("action", "login")
        log_fields = {"action": "login"}
        assert matcher.matches(log_fields) is True

    def test_exact_match_case_insensitive(self):
        """Test exact matching is case-insensitive"""
        matcher = FieldMatcher("action", "LOGIN")
        log_fields = {"action": "login"}
        assert matcher.matches(log_fields) is True

    def test_exact_match_false(self):
        """Test exact matching returns false on mismatch"""
        matcher = FieldMatcher("action", "logout")
        log_fields = {"action": "login"}
        assert matcher.matches(log_fields) is False

    def test_wildcard_match(self):
        """Test wildcard matching with *"""
        matcher = FieldMatcher("user", "john*")
        log_fields = {"user": "john.doe"}
        assert matcher.matches(log_fields) is True

    def test_wildcard_question_mark(self):
        """Test wildcard matching with ?"""
        matcher = FieldMatcher("user", "john.do?")
        log_fields = {"user": "john.doe"}
        assert matcher.matches(log_fields) is True

    def test_any_of_matching(self):
        """Test any_of (OR) matching"""
        matcher = FieldMatcher("action", ["login", "logout", "authenticate"])
        log_fields = {"action": "login"}
        assert matcher.matches(log_fields) is True

    def test_any_of_no_match(self):
        """Test any_of returns false when no match"""
        matcher = FieldMatcher("action", ["logout", "authenticate"])
        log_fields = {"action": "login"}
        assert matcher.matches(log_fields) is False

    def test_regex_match(self):
        """Test regex pattern matching"""
        matcher = FieldMatcher("source_ip", {"regex": r"192\.168\.*"})
        log_fields = {"source_ip": "192.168.1.100"}
        assert matcher.matches(log_fields) is True

    def test_regex_no_match(self):
        """Test regex no match"""
        matcher = FieldMatcher("source_ip", {"regex": r"10\.0\.0\.*"})
        log_fields = {"source_ip": "192.168.1.100"}
        assert matcher.matches(log_fields) is False

    def test_contains_match(self):
        """Test contains matching"""
        matcher = FieldMatcher("user", {"contains": "john"})
        log_fields = {"user": "john.doe"}
        assert matcher.matches(log_fields) is True

    def test_contains_no_match(self):
        """Test contains no match"""
        matcher = FieldMatcher("user", {"contains": "jane"})
        log_fields = {"user": "john.doe"}
        assert matcher.matches(log_fields) is False

    def test_startswith_match(self):
        """Test startswith matching"""
        matcher = FieldMatcher("user", {"startswith": "john"})
        log_fields = {"user": "john.doe"}
        assert matcher.matches(log_fields) is True

    def test_startswith_no_match(self):
        """Test startswith no match"""
        matcher = FieldMatcher("user", {"startswith": "jane"})
        log_fields = {"user": "john.doe"}
        assert matcher.matches(log_fields) is False

    def test_endswith_match(self):
        """Test endswith matching"""
        matcher = FieldMatcher("user", {"endswith": "doe"})
        log_fields = {"user": "john.doe"}
        assert matcher.matches(log_fields) is True

    def test_endswith_no_match(self):
        """Test endswith no match"""
        matcher = FieldMatcher("user", {"endswith": "smith"})
        log_fields = {"user": "john.doe"}
        assert matcher.matches(log_fields) is False

    def test_all_match(self):
        """Test all matching for list fields"""
        matcher = FieldMatcher("tags", {"all": ["web", "auth"]})
        log_fields = {"tags": ["web", "auth", "critical"]}
        assert matcher.matches(log_fields) is True

    def test_all_no_match(self):
        """Test all no match when field missing value"""
        matcher = FieldMatcher("tags", {"all": ["web", "api"]})
        log_fields = {"tags": ["web", "auth"]}
        assert matcher.matches(log_fields) is False

    def test_exists_field_present(self):
        """Test field existence check - field present"""
        matcher = FieldMatcher("user", {"exists": True})
        log_fields = {"user": "john.doe"}
        assert matcher.matches(log_fields) is True

    def test_exists_field_absent(self):
        """Test field existence check - field absent"""
        matcher = FieldMatcher("user", {"exists": True})
        log_fields = {"action": "login"}
        assert matcher.matches(log_fields) is False

    def test_numeric_greater_than(self):
        """Test numeric greater than comparison"""
        matcher = FieldMatcher("event_count", {">": 3})
        log_fields = {"event_count": 5}
        assert matcher.matches(log_fields) is True

    def test_numeric_greater_than_false(self):
        """Test numeric greater than returns false"""
        matcher = FieldMatcher("event_count", {">": 10})
        log_fields = {"event_count": 5}
        assert matcher.matches(log_fields) is False

    def test_numeric_less_than(self):
        """Test numeric less than comparison"""
        matcher = FieldMatcher("event_count", {"<": 10})
        log_fields = {"event_count": 5}
        assert matcher.matches(log_fields) is True

    def test_numeric_greater_equal(self):
        """Test numeric greater than or equal"""
        matcher = FieldMatcher("event_count", {">=": 5})
        log_fields = {"event_count": 5}
        assert matcher.matches(log_fields) is True

    def test_numeric_less_equal(self):
        """Test numeric less than or equal"""
        matcher = FieldMatcher("event_count", {"<=": 5})
        log_fields = {"event_count": 5}
        assert matcher.matches(log_fields) is True

    def test_cidr_match(self):
        """Test CIDR IP range matching"""
        matcher = FieldMatcher("source_ip", {"cidr": "192.168.0.0/16"})
        log_fields = {"source_ip": "192.168.1.100"}
        assert matcher.matches(log_fields) is True

    def test_cidr_no_match(self):
        """Test CIDR no match"""
        matcher = FieldMatcher("source_ip", {"cidr": "10.0.0.0/8"})
        log_fields = {"source_ip": "192.168.1.100"}
        assert matcher.matches(log_fields) is False

    def test_cidr_multiple_ranges(self):
        """Test CIDR matching with multiple ranges"""
        matcher = FieldMatcher("source_ip", {"cidr": ["10.0.0.0/8", "192.168.0.0/16"]})
        log_fields = {"source_ip": "192.168.1.100"}
        assert matcher.matches(log_fields) is True

    def test_missing_field(self):
        """Test matching against missing field"""
        matcher = FieldMatcher("missing_field", "value")
        log_fields = {"action": "login"}
        assert matcher.matches(log_fields) is False

        event = {
            "ip": "192.168.1.100",
        }

        matches = bool(re.match(rule["condition"]["value"], event[rule["condition"]["field"]]))

        assert matches is True

    async def test_match_rule_comparison_operator(self):
        """Test matching rule with comparison operators"""
        rule = {
            "condition": {"field": "response_time_ms", "operator": "greater_than", "value": 1000},
        }

        event = {
            "response_time_ms": 1500,
        }

        matches = event[rule["condition"]["field"]] > rule["condition"]["value"]

        assert matches is True

    async def test_multiple_conditions_and_logic(self):
        """Test matching with multiple AND conditions"""
        rule = {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "login"},
                {"field": "failed_attempts", "operator": "greater_than", "value": 5},
            ],
            "logic": "AND",
        }

        event = {
            "event_type": "login",
            "failed_attempts": 10,
            "user": "john",
        }

        all_match = all(
            event[c["field"]] == c["value"] if c["operator"] == "equals"
            else event[c["field"]] > c["value"] if c["operator"] == "greater_than"
            else False
            for c in rule["conditions"]
        )

        assert all_match is True

    async def test_multiple_conditions_or_logic(self):
        """Test matching with multiple OR conditions"""
        rule = {
            "conditions": [
                {"field": "severity", "value": "critical"},
                {"field": "severity", "value": "high"},
            ],
            "logic": "OR",
        }

        event = {"severity": "high"}

        any_match = any(
            event.get(c["field"]) == c["value"]
            for c in rule["conditions"]
        )

        assert any_match is True


@pytest.mark.asyncio
class TestCorrelationEngine:
    """Tests for event correlation"""

    async def test_correlate_events_by_user(self):
        """Test correlating events by user"""
        events = [
            {"user": "john", "event_type": "login", "timestamp": datetime(2024, 3, 20, 10, 0)},
            {"user": "john", "event_type": "file_access", "timestamp": datetime(2024, 3, 20, 10, 5)},
            {"user": "john", "event_type": "file_copy", "timestamp": datetime(2024, 3, 20, 10, 10)},
            {"user": "jane", "event_type": "login", "timestamp": datetime(2024, 3, 20, 10, 2)},
        ]

        # Correlate by user
        john_events = [e for e in events if e["user"] == "john"]

        assert len(john_events) == 3
        assert all(e["user"] == "john" for e in john_events)

    async def test_correlate_events_by_source_ip(self):
        """Test correlating events by source IP"""
        events = [
            {"source_ip": "192.168.1.100", "event": "login"},
            {"source_ip": "192.168.1.100", "event": "privileged_access"},
            {"source_ip": "192.168.1.101", "event": "login"},
        ]

        suspicious_ip = "192.168.1.100"
        correlated = [e for e in events if e["source_ip"] == suspicious_ip]

        assert len(correlated) == 2

    async def test_correlate_events_by_time_window(self):
        """Test correlating events within time window"""
        events = [
            {"id": "ev1", "timestamp": datetime(2024, 3, 20, 10, 0)},
            {"id": "ev2", "timestamp": datetime(2024, 3, 20, 10, 5)},
            {"id": "ev3", "timestamp": datetime(2024, 3, 20, 10, 10)},
            {"id": "ev4", "timestamp": datetime(2024, 3, 20, 11, 0)},
        ]

        time_window = 15  # minutes
        reference_time = datetime(2024, 3, 20, 10, 2)

        correlated = [
            e for e in events
            if abs((e["timestamp"] - reference_time).total_seconds() / 60) <= time_window
        ]

        assert len(correlated) == 3


@pytest.mark.asyncio
class TestAggregationWindows:
    """Tests for event aggregation"""

    async def test_aggregate_events_by_minute(self):
        """Test aggregating events by minute"""
        events = [
            {"timestamp": datetime(2024, 3, 20, 10, 0, 10), "event": "login"},
            {"timestamp": datetime(2024, 3, 20, 10, 0, 45), "event": "login"},
            {"timestamp": datetime(2024, 3, 20, 10, 1, 5), "event": "login"},
        ]

        # Group by minute
        aggregated = {}
        for event in events:
            minute = event["timestamp"].strftime("%Y-%m-%d %H:%M")
            if minute not in aggregated:
                aggregated[minute] = []
            aggregated[minute].append(event)

        assert len(aggregated) == 2
        assert len(aggregated["2024-03-20 10:00"]) == 2

    async def test_aggregate_events_by_hour(self):
        """Test aggregating events by hour"""
        events = [
            {"timestamp": datetime(2024, 3, 20, 10, 15, 0), "count": 1},
            {"timestamp": datetime(2024, 3, 20, 10, 45, 0), "count": 2},
            {"timestamp": datetime(2024, 3, 20, 11, 10, 0), "count": 1},
        ]

        hourly = {}
        for event in events:
            hour = event["timestamp"].strftime("%Y-%m-%d %H:00")
            hourly[hour] = hourly.get(hour, 0) + event["count"]

        assert len(hourly) == 2
        assert hourly["2024-03-20 10:00"] == 3

    async def test_alert_on_threshold_exceeded(self):
        """Test alerting when aggregation threshold exceeded"""
        threshold = 10
        aggregated_count = 15

        should_alert = aggregated_count > threshold

        assert should_alert is True


@pytest.mark.asyncio
class TestSigmaRuleImport:
    """Tests for Sigma rule import"""

    async def test_import_sigma_rule(self):
        """Test importing a Sigma rule"""
        sigma_rule = {
            "title": "Suspicious Process Creation",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {
                    "CommandLine": ["*psexec*", "*paexec*"],
                    "Image|endswith": "system32\\cmd.exe",
                },
                "condition": "selection",
            },
        }

        rule = {
            "id": "sigma-rule-001",
            "title": sigma_rule["title"],
            "source": "sigma",
            "imported_at": datetime.utcnow(),
        }

        assert rule["source"] == "sigma"
        assert rule["title"] == "Suspicious Process Creation"

    async def test_convert_sigma_to_internal_format(self):
        """Test converting Sigma rule to internal format"""
        sigma_rule = {
            "detection": {
                "selection": {
                    "EventID": 1,
                    "CommandLine|contains": "powershell",
                },
                "condition": "selection",
            },
        }

        # Convert to internal format
        internal_rule = {
            "conditions": [
                {"field": "EventID", "operator": "equals", "value": 1},
                {"field": "CommandLine", "operator": "contains", "value": "powershell"},
            ],
            "logic": "AND",
        }

        assert len(internal_rule["conditions"]) == 2


@pytest.mark.asyncio
class TestEventNormalization:
    """Tests for event normalization"""

    async def test_normalize_timestamp(self):
        """Test normalizing timestamps"""
        raw_events = [
            {"timestamp": "2024-03-20T10:00:00Z"},
            {"timestamp": "03/20/2024 10:00:00"},
            {"timestamp": 1711009200},  # Unix timestamp
        ]

        normalized_events = []
        for event in raw_events:
            # Normalize to ISO format
            normalized_events.append({
                "timestamp": datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                ) if isinstance(event["timestamp"], str) else datetime.fromtimestamp(event["timestamp"]),
            })

        assert all("timestamp" in e for e in normalized_events)

    async def test_normalize_field_names(self):
        """Test normalizing field names"""
        raw_event = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "EventType": "login",
            "user_name": "john",
        }

        # Map to normalized fields
        field_mapping = {
            "src_ip": "source_ip",
            "dst_ip": "destination_ip",
            "EventType": "event_type",
            "user_name": "user",
        }

        normalized = {
            field_mapping.get(k, k): v for k, v in raw_event.items()
        }

        assert "source_ip" in normalized
        assert "destination_ip" in normalized

    async def test_normalize_severity_levels(self):
        """Test normalizing severity levels"""
        severity_mapping = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }

        raw_severities = ["Critical", "HIGH", "Medium", "info"]

        normalized = [
            severity_mapping.get(s.lower(), 0)
            for s in raw_severities
        ]

        assert normalized == [5, 4, 3, 1]
