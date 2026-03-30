"""
SIEM Correlation Engine for detecting multi-stage attacks and reducing alert fatigue.

This module provides a correlation engine that groups related security events across
time windows to identify attack patterns, lateral movement, and complex security incidents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Set, Tuple
from collections import defaultdict
import threading
import uuid
from enum import Enum


class MITREATTACKTactic(Enum):
    """MITRE ATT&CK tactics for attack chain tracking."""
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    COMMAND_AND_CONTROL = "Command and Control"
    IMPACT = "Impact"


class CorrelationSeverity(Enum):
    """Severity levels for correlation results."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AggregatedEvent:
    """Represents aggregated similar events within a time window."""
    group_key: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    sources: Set[str] = field(default_factory=set)
    targets: Set[str] = field(default_factory=set)
    sample_events: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "group_key": self.group_key,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "sources": list(self.sources),
            "targets": list(self.targets),
            "sample_events": self.sample_events,
        }


@dataclass
class CorrelationResult:
    """Represents the result of correlation analysis."""
    correlation_id: str
    strategy_name: str
    events: List[dict]
    severity: CorrelationSeverity
    description: str
    mitre_chain: List[str]
    timespan_start: datetime
    timespan_end: datetime

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "correlation_id": self.correlation_id,
            "strategy_name": self.strategy_name,
            "event_count": len(self.events),
            "severity": self.severity.value,
            "description": self.description,
            "mitre_chain": self.mitre_chain,
            "timespan_start": self.timespan_start.isoformat(),
            "timespan_end": self.timespan_end.isoformat(),
            "events": self.events,
        }


class CorrelationStrategy(ABC):
    """
    Abstract base class for correlation strategies.

    Correlation strategies define how to group related events and detect patterns.
    """

    @abstractmethod
    def should_correlate(self, event_a: dict, event_b: dict) -> bool:
        """
        Determine if two events should be correlated.

        Args:
            event_a: First security event
            event_b: Second security event

        Returns:
            True if events should be correlated together
        """
        pass

    @abstractmethod
    def get_correlation_key(self, event: dict) -> str:
        """
        Generate a correlation key for grouping events.

        Args:
            event: Security event

        Returns:
            Correlation key for the event
        """
        pass

    @abstractmethod
    def analyze_correlation(
        self, events: List[dict], time_window: timedelta
    ) -> Optional[CorrelationResult]:
        """
        Analyze correlated events to detect patterns.

        Args:
            events: List of related events
            time_window: Time window for correlation

        Returns:
            CorrelationResult if pattern detected, None otherwise
        """
        pass


class SessionCorrelation(CorrelationStrategy):
    """
    Groups events by same username + source_address within a time window.

    Detects patterns like: failed login -> successful login -> lateral movement
    """

    def should_correlate(self, event_a: dict, event_b: dict) -> bool:
        """Check if events involve the same user and source address."""
        return (
            event_a.get("username") == event_b.get("username")
            and event_a.get("source_address") == event_b.get("source_address")
        )

    def get_correlation_key(self, event: dict) -> str:
        """Generate key based on username and source address."""
        username = event.get("username", "unknown")
        source = event.get("source_address", "unknown")
        return f"session:{username}:{source}"

    def analyze_correlation(
        self, events: List[dict], time_window: timedelta
    ) -> Optional[CorrelationResult]:
        """
        Detect suspicious session patterns.

        Patterns detected:
        - Multiple failed logins followed by success (brute force)
        - Failed login followed by lateral movement (compromised account)
        - Multiple different destinations (lateral movement)
        """
        if len(events) < 2:
            return None

        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        event_types = [e.get("event_type", "").lower() for e in sorted_events]

        # Detect brute force: failed logins -> success
        failed_count = sum(1 for et in event_types if "failed" in et or "denied" in et)
        success_count = sum(
            1 for et in event_types if "success" in et and "failed" not in et
        )

        # Detect lateral movement: login -> multiple remote actions
        destinations = set()
        for event in sorted_events:
            if event.get("destination_address"):
                destinations.add(event["destination_address"])

        severity = CorrelationSeverity.LOW
        mitre_chain = []
        description_parts = []

        if failed_count >= 3 and success_count > 0:
            severity = CorrelationSeverity.HIGH
            mitre_chain.append(MITREATTACKTactic.CREDENTIAL_ACCESS.value)
            mitre_chain.append(MITREATTACKTactic.INITIAL_ACCESS.value)
            description_parts.append(
                f"{failed_count} failed login attempts followed by success"
            )

        if len(destinations) > 2:
            severity = CorrelationSeverity.HIGH
            if MITREATTACKTactic.LATERAL_MOVEMENT.value not in mitre_chain:
                mitre_chain.append(MITREATTACKTactic.LATERAL_MOVEMENT.value)
            description_parts.append(f"Activity on {len(destinations)} different hosts")

        if not description_parts:
            return None

        timespan_start = datetime.fromisoformat(
            sorted_events[0].get("timestamp", datetime.now().isoformat())
        )
        timespan_end = datetime.fromisoformat(
            sorted_events[-1].get("timestamp", datetime.now().isoformat())
        )

        return CorrelationResult(
            correlation_id=f"session_{uuid.uuid4().hex[:8]}",
            strategy_name="SessionCorrelation",
            events=sorted_events,
            severity=severity,
            description=" | ".join(description_parts),
            mitre_chain=mitre_chain,
            timespan_start=timespan_start,
            timespan_end=timespan_end,
        )


class HostCorrelation(CorrelationStrategy):
    """
    Groups events by same hostname/destination_address.

    Detects patterns like: scan -> exploit -> persistence on a single host
    """

    def should_correlate(self, event_a: dict, event_b: dict) -> bool:
        """Check if events involve the same destination host."""
        dest_a = event_a.get("destination_address") or event_a.get("hostname")
        dest_b = event_b.get("destination_address") or event_b.get("hostname")
        return dest_a == dest_b and dest_a is not None

    def get_correlation_key(self, event: dict) -> str:
        """Generate key based on destination address or hostname."""
        destination = event.get("destination_address") or event.get("hostname")
        if not destination:
            destination = "unknown"
        return f"host:{destination}"

    def analyze_correlation(
        self, events: List[dict], time_window: timedelta
    ) -> Optional[CorrelationResult]:
        """
        Detect attack patterns against a single host.

        Patterns detected:
        - Network scans followed by exploitation attempts
        - Multiple exploitation attempts
        - Exploitation followed by persistence indicators
        """
        if len(events) < 2:
            return None

        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        event_types = [e.get("event_type", "").lower() for e in sorted_events]

        # Count different attack stages
        scan_count = sum(1 for et in event_types if "scan" in et or "probe" in et)
        exploit_count = sum(1 for et in event_types if "exploit" in et)
        persistence_count = sum(
            1 for et in event_types if "persistence" in et or "install" in et
        )
        success_count = sum(1 for et in event_types if "success" in et)

        severity = CorrelationSeverity.LOW
        mitre_chain = []
        description_parts = []

        # Detect scan -> exploit pattern
        if scan_count >= 2 and exploit_count > 0:
            severity = CorrelationSeverity.HIGH
            mitre_chain = [
                MITREATTACKTactic.DISCOVERY.value,
                MITREATTACKTactic.EXECUTION.value,
            ]
            description_parts.append(f"Network scan ({scan_count} events) followed by exploitation")

        # Detect successful exploitation
        if exploit_count >= 2 or (exploit_count >= 1 and success_count > 0):
            severity = CorrelationSeverity.CRITICAL
            if MITREATTACKTactic.EXECUTION.value not in mitre_chain:
                mitre_chain.append(MITREATTACKTactic.EXECUTION.value)
            description_parts.append(f"Multiple exploitation attempts ({exploit_count} events)")

        # Detect post-exploitation persistence
        if persistence_count > 0:
            severity = CorrelationSeverity.CRITICAL
            if MITREATTACKTactic.PERSISTENCE.value not in mitre_chain:
                mitre_chain.append(MITREATTACKTactic.PERSISTENCE.value)
            description_parts.append(f"Persistence indicators detected ({persistence_count} events)")

        if not description_parts:
            return None

        timespan_start = datetime.fromisoformat(
            sorted_events[0].get("timestamp", datetime.now().isoformat())
        )
        timespan_end = datetime.fromisoformat(
            sorted_events[-1].get("timestamp", datetime.now().isoformat())
        )

        return CorrelationResult(
            correlation_id=f"host_{uuid.uuid4().hex[:8]}",
            strategy_name="HostCorrelation",
            events=sorted_events,
            severity=severity,
            description=" | ".join(description_parts),
            mitre_chain=mitre_chain,
            timespan_start=timespan_start,
            timespan_end=timespan_end,
        )


class AttackChainCorrelation(CorrelationStrategy):
    """
    Defines and tracks multi-stage attack patterns using MITRE ATT&CK tactics.

    Tracks progression: Initial Access -> Execution -> Persistence -> Lateral Movement
    """

    # Define standard attack chains and their tactics
    ATTACK_CHAINS = {
        "initial_compromise": [
            MITREATTACKTactic.INITIAL_ACCESS,
            MITREATTACKTactic.EXECUTION,
        ],
        "privilege_escalation": [
            MITREATTACKTactic.EXECUTION,
            MITREATTACKTactic.PRIVILEGE_ESCALATION,
        ],
        "persistence_establishment": [
            MITREATTACKTactic.PRIVILEGE_ESCALATION,
            MITREATTACKTactic.PERSISTENCE,
        ],
        "lateral_movement": [
            MITREATTACKTactic.PERSISTENCE,
            MITREATTACKTactic.LATERAL_MOVEMENT,
        ],
        "data_exfiltration": [
            MITREATTACKTactic.COLLECTION,
            MITREATTACKTactic.EXFILTRATION,
        ],
    }

    # Map event types to MITRE tactics
    EVENT_TYPE_TO_TACTIC = {
        "exploit": MITREATTACKTactic.EXECUTION,
        "privilege_escalation": MITREATTACKTactic.PRIVILEGE_ESCALATION,
        "persistence": MITREATTACKTactic.PERSISTENCE,
        "lateral_movement": MITREATTACKTactic.LATERAL_MOVEMENT,
        "reconnaissance": MITREATTACKTactic.DISCOVERY,
        "phishing": MITREATTACKTactic.INITIAL_ACCESS,
        "malware": MITREATTACKTactic.EXECUTION,
        "registry_modification": MITREATTACKTactic.PERSISTENCE,
        "process_injection": MITREATTACKTactic.DEFENSE_EVASION,
        "credential_dumping": MITREATTACKTactic.CREDENTIAL_ACCESS,
        "exfiltration": MITREATTACKTactic.EXFILTRATION,
    }

    def should_correlate(self, event_a: dict, event_b: dict) -> bool:
        """
        Check if events are part of the same attack chain.

        Events correlate if they:
        - Involve related tactics
        - Share source or destination context
        - Occur within reasonable timeframe
        """
        tactic_a = self._get_event_tactic(event_a)
        tactic_b = self._get_event_tactic(event_b)

        # Same source or destination often indicates same attack
        same_source = event_a.get("source_address") == event_b.get("source_address")
        same_dest = event_a.get("destination_address") == event_b.get(
            "destination_address"
        )
        same_user = event_a.get("username") == event_b.get("username")

        return (
            (tactic_a is not None and tactic_b is not None)
            and (same_source or same_dest or same_user)
        )

    def get_correlation_key(self, event: dict) -> str:
        """Generate key based on tactic and context."""
        tactic = self._get_event_tactic(event)
        tactic_name = tactic.value if tactic else "unknown"
        source = event.get("source_address", "unknown")
        return f"attack_chain:{source}:{tactic_name}"

    def _get_event_tactic(self, event: dict) -> Optional[MITREATTACKTactic]:
        """Map event type to MITRE tactic."""
        event_type = event.get("event_type", "").lower()
        return self.EVENT_TYPE_TO_TACTIC.get(event_type)

    def analyze_correlation(
        self, events: List[dict], time_window: timedelta
    ) -> Optional[CorrelationResult]:
        """
        Detect multi-stage attack patterns based on MITRE ATT&CK tactics.

        Returns correlation if:
        - Events follow a known attack chain
        - Multiple tactics are represented
        - Events span the expected attack progression
        """
        if len(events) < 2:
            return None

        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

        # Extract tactics from events
        tactics_sequence = []
        for event in sorted_events:
            tactic = self._get_event_tactic(event)
            if tactic:
                tactics_sequence.append(tactic)

        if len(set(tactics_sequence)) < 2:
            return None  # Need at least 2 different tactics

        # Check if tactics match any known attack chain
        detected_chain = None
        for chain_name, chain_tactics in self.ATTACK_CHAINS.items():
            if self._matches_chain(tactics_sequence, chain_tactics):
                detected_chain = chain_name
                break

        if not detected_chain:
            return None

        severity = self._calculate_severity(tactics_sequence)
        tactic_names = [t.value for t in set(tactics_sequence)]

        timespan_start = datetime.fromisoformat(
            sorted_events[0].get("timestamp", datetime.now().isoformat())
        )
        timespan_end = datetime.fromisoformat(
            sorted_events[-1].get("timestamp", datetime.now().isoformat())
        )

        return CorrelationResult(
            correlation_id=f"chain_{uuid.uuid4().hex[:8]}",
            strategy_name="AttackChainCorrelation",
            events=sorted_events,
            severity=severity,
            description=f"Multi-stage attack detected: {detected_chain.replace('_', ' ').title()}",
            mitre_chain=tactic_names,
            timespan_start=timespan_start,
            timespan_end=timespan_end,
        )

    def _matches_chain(
        self, tactics: List[MITREATTACKTactic], chain: List[MITREATTACKTactic]
    ) -> bool:
        """Check if tactics sequence matches a known chain."""
        unique_tactics = list(dict.fromkeys(tactics))  # Preserve order, remove duplicates
        return len(unique_tactics) >= len(chain) and all(
            t in unique_tactics for t in chain
        )

    def _calculate_severity(self, tactics: List[MITREATTACKTactic]) -> CorrelationSeverity:
        """Calculate severity based on tactic progression."""
        tactic_set = set(tactics)

        # CRITICAL: Full attack chain detected
        if (
            MITREATTACKTactic.INITIAL_ACCESS in tactic_set
            and MITREATTACKTactic.PERSISTENCE in tactic_set
            and MITREATTACKTactic.EXFILTRATION in tactic_set
        ):
            return CorrelationSeverity.CRITICAL

        # HIGH: Multiple stages including lateral movement or persistence
        if (
            MITREATTACKTactic.PRIVILEGE_ESCALATION in tactic_set
            or MITREATTACKTactic.LATERAL_MOVEMENT in tactic_set
        ):
            return CorrelationSeverity.HIGH

        # MEDIUM: Initial execution and persistence
        if (
            MITREATTACKTactic.EXECUTION in tactic_set
            and MITREATTACKTactic.PERSISTENCE in tactic_set
        ):
            return CorrelationSeverity.MEDIUM

        return CorrelationSeverity.LOW


class EventAggregator:
    """
    Aggregates similar events within a time window.

    Groups events by configurable fields and produces summary statistics.
    """

    def __init__(
        self,
        grouping_fields: List[str],
        aggregation_threshold: int = 5,
        time_window: timedelta = timedelta(minutes=5),
    ):
        """
        Initialize EventAggregator.

        Args:
            grouping_fields: Fields to group events by (e.g., ['source_address', 'alert_type'])
            aggregation_threshold: Number of events before aggregation
            time_window: Time window for aggregation
        """
        self.grouping_fields = grouping_fields
        self.aggregation_threshold = aggregation_threshold
        self.time_window = time_window
        self._buffer: Dict[str, List[dict]] = defaultdict(list)
        self._lock = threading.Lock()

    def _generate_group_key(self, event: dict) -> str:
        """Generate grouping key from event."""
        key_parts = []
        for field in self.grouping_fields:
            value = event.get(field, "unknown")
            key_parts.append(f"{field}={value}")
        return "|".join(key_parts)

    def add_event(self, event: dict) -> Optional[AggregatedEvent]:
        """
        Add event to aggregator.

        Returns AggregatedEvent when threshold is met, None otherwise.

        Args:
            event: Security event to add

        Returns:
            AggregatedEvent if aggregation threshold is met, None otherwise
        """
        with self._lock:
            group_key = self._generate_group_key(event)
            self._buffer[group_key].append(event)

            events = self._buffer[group_key]
            if len(events) >= self.aggregation_threshold:
                # Check if events span expected time window
                timestamps = [
                    datetime.fromisoformat(e.get("timestamp", datetime.now().isoformat()))
                    for e in events
                ]
                time_span = max(timestamps) - min(timestamps)

                if time_span <= self.time_window:
                    aggregated = self._create_aggregated_event(group_key, events)
                    del self._buffer[group_key]
                    return aggregated

        return None

    def _create_aggregated_event(
        self, group_key: str, events: List[dict]
    ) -> AggregatedEvent:
        """Create aggregated event from buffer."""
        timestamps = [
            datetime.fromisoformat(e.get("timestamp", datetime.now().isoformat()))
            for e in events
        ]
        sources = set(e.get("source_address") for e in events if e.get("source_address"))
        targets = set(
            e.get("destination_address") for e in events if e.get("destination_address")
        )

        return AggregatedEvent(
            group_key=group_key,
            event_count=len(events),
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            sources=sources,
            targets=targets,
            sample_events=events[:3],  # Keep first 3 as samples
        )

    def flush(self) -> List[AggregatedEvent]:
        """Flush all buffered events and return aggregated results."""
        with self._lock:
            results = []
            for group_key, events in self._buffer.items():
                if events:
                    results.append(self._create_aggregated_event(group_key, events))
            self._buffer.clear()
            return results

    def get_buffer_stats(self) -> dict:
        """Get statistics about the aggregation buffer."""
        with self._lock:
            total_events = sum(len(events) for events in self._buffer.values())
            return {
                "total_events": total_events,
                "total_groups": len(self._buffer),
                "largest_group": max(
                    (len(events) for events in self._buffer.values()), default=0
                ),
            }


class CorrelationEngine:
    """
    Main SIEM correlation engine.

    Manages multiple correlation strategies and processes events through them.
    """

    def __init__(
        self,
        strategies: Optional[List[CorrelationStrategy]] = None,
        max_buffer_size: int = 10000,
        time_window: timedelta = timedelta(minutes=30),
    ):
        """
        Initialize CorrelationEngine.

        Args:
            strategies: List of correlation strategies to use
            max_buffer_size: Maximum events to keep in memory
            time_window: Time window for correlation analysis
        """
        self.strategies = strategies or [
            SessionCorrelation(),
            HostCorrelation(),
            AttackChainCorrelation(),
        ]
        self.max_buffer_size = max_buffer_size
        self.time_window = time_window

        self._event_buffer: List[dict] = []
        self._correlations: Dict[str, CorrelationResult] = {}
        self._strategy_buffers: Dict[str, Dict[str, List[dict]]] = {
            strategy.__class__.__name__: defaultdict(list) for strategy in self.strategies
        }
        self._lock = threading.RLock()
        self._stats = {
            "total_events_processed": 0,
            "total_correlations_found": 0,
            "cleanup_runs": 0,
        }

    def process_event(self, event: dict) -> List[CorrelationResult]:
        """
        Process a security event through correlation engine.

        Args:
            event: Security event to process

        Returns:
            List of CorrelationResult objects for detected patterns
        """
        with self._lock:
            # Ensure event has timestamp
            if "timestamp" not in event:
                event["timestamp"] = datetime.now().isoformat()

            self._event_buffer.append(event)
            self._stats["total_events_processed"] += 1

            # Maintain max buffer size
            if len(self._event_buffer) > self.max_buffer_size:
                self._event_buffer = self._event_buffer[-self.max_buffer_size :]

            results = []

            # Process through each strategy
            for strategy in self.strategies:
                strategy_name = strategy.__class__.__name__
                buffer = self._strategy_buffers[strategy_name]

                # Get correlation key
                corr_key = strategy.get_correlation_key(event)
                buffer[corr_key].append(event)

                # Try to correlate events in this group
                correlated_events = buffer[corr_key]
                if len(correlated_events) >= 2:
                    # Check all pairs for correlation
                    for i in range(len(correlated_events) - 1):
                        if strategy.should_correlate(
                            correlated_events[i], correlated_events[-1]
                        ):
                            # Analyze this group
                            result = strategy.analyze_correlation(
                                correlated_events, self.time_window
                            )
                            if result:
                                self._correlations[result.correlation_id] = result
                                results.append(result)
                                self._stats["total_correlations_found"] += 1
                                break

            return results

    def get_active_correlations(self) -> List[dict]:
        """
        Get all active correlations.

        Returns:
            List of active correlation results as dictionaries
        """
        with self._lock:
            return [corr.to_dict() for corr in self._correlations.values()]

    def cleanup_expired(self) -> int:
        """
        Remove correlation windows older than configured time_window.

        Returns:
            Number of expired correlations removed
        """
        with self._lock:
            now = datetime.now()
            expired_ids = []

            for corr_id, result in self._correlations.items():
                age = now - result.timespan_end
                if age > self.time_window:
                    expired_ids.append(corr_id)

            for corr_id in expired_ids:
                del self._correlations[corr_id]

            self._stats["cleanup_runs"] += 1
            return len(expired_ids)

    def get_stats(self) -> dict:
        """
        Get engine statistics.

        Returns:
            Dictionary containing engine statistics
        """
        with self._lock:
            return {
                **self._stats,
                "active_correlations": len(self._correlations),
                "buffered_events": len(self._event_buffer),
                "buffer_utilization": f"{(len(self._event_buffer) / self.max_buffer_size * 100):.1f}%",
            }

    def clear(self) -> None:
        """Clear all buffers and correlations."""
        with self._lock:
            self._event_buffer.clear()
            self._correlations.clear()
            for buffer in self._strategy_buffers.values():
                buffer.clear()
