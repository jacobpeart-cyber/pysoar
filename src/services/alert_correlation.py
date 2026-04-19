"""Alert Correlation Service - Auto-creates incidents from alerts based on rules"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.models.alert import Alert, AlertSeverity, AlertStatus
from src.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentType
from src.intel.models import ThreatIndicator as IOC
from src.models.playbook import ExecutionStatus, Playbook, PlaybookExecution, PlaybookStatus, PlaybookTrigger

logger = get_logger(__name__)


# Mapping from alert severity to incident severity
SEVERITY_MAP = {
    "critical": IncidentSeverity.CRITICAL.value,
    "high": IncidentSeverity.HIGH.value,
    "medium": IncidentSeverity.MEDIUM.value,
    "low": IncidentSeverity.LOW.value,
}

# Mapping from alert category to incident type
CATEGORY_TO_TYPE = {
    "malware": IncidentType.MALWARE.value,
    "phishing": IncidentType.PHISHING.value,
    "data_exfiltration": IncidentType.DATA_BREACH.value,
    "unauthorized_access": IncidentType.UNAUTHORIZED_ACCESS.value,
    "denial_of_service": IncidentType.DOS.value,
    "insider_threat": IncidentType.INSIDER_THREAT.value,
    "ransomware": IncidentType.RANSOMWARE.value,
    "apt": IncidentType.APT.value,
}


class CorrelationRule:
    """Base class for correlation rules"""

    def __init__(
        self,
        name: str,
        description: str,
        auto_create_incident: bool = True,
        incident_severity: Optional[str] = None,
        incident_type: Optional[str] = None,
    ):
        self.name = name
        self.description = description
        self.auto_create_incident = auto_create_incident
        self.incident_severity = incident_severity
        self.incident_type = incident_type

    def matches(self, alert: Alert) -> bool:
        """Check if alert matches this rule (sync path — stateless rules)"""
        raise NotImplementedError

    async def matches_async(self, alert: Alert) -> bool:
        """Async check for rules that need DB access. Defaults to sync matches()."""
        return self.matches(alert)

    def get_incident_title(self, alert: Alert) -> str:
        """Generate incident title from alert"""
        return f"[{alert.severity.upper()}] {alert.title}"

    def get_incident_description(self, alert: Alert) -> str:
        """Generate incident description from alert"""
        return f"Auto-created from alert: {alert.title}\n\n{alert.description or ''}"


class SeverityRule(CorrelationRule):
    """Create incident based on alert severity"""

    def __init__(self, min_severity: str = "high"):
        super().__init__(
            name="High Severity Alert",
            description=f"Auto-create incident for {min_severity}+ severity alerts",
        )
        self.severity_levels = ["low", "medium", "high", "critical"]
        self.min_severity = min_severity

    def matches(self, alert: Alert) -> bool:
        alert_level = self.severity_levels.index(alert.severity) if alert.severity in self.severity_levels else 0
        min_level = self.severity_levels.index(self.min_severity) if self.min_severity in self.severity_levels else 0
        return alert_level >= min_level


class CategoryRule(CorrelationRule):
    """Create incident based on alert category"""

    def __init__(self, categories: list[str]):
        super().__init__(
            name="Category Match",
            description=f"Auto-create incident for alerts in categories: {categories}",
        )
        self.categories = categories

    def matches(self, alert: Alert) -> bool:
        return alert.category in self.categories if alert.category else False


class SourceRule(CorrelationRule):
    """Create incident based on alert source"""

    def __init__(self, sources: list[str]):
        super().__init__(
            name="Source Match",
            description=f"Auto-create incident for alerts from sources: {sources}",
        )
        self.sources = sources

    def matches(self, alert: Alert) -> bool:
        return alert.source in self.sources if alert.source else False


class RepeatedAlertRule(CorrelationRule):
    """Create incident when same alert repeats multiple times"""

    def __init__(self, threshold: int = 5, time_window_minutes: int = 60):
        super().__init__(
            name="Repeated Alerts",
            description=f"Auto-create incident when alert repeats {threshold}+ times in {time_window_minutes} minutes",
        )
        self.threshold = threshold
        self.time_window_minutes = time_window_minutes
        self._db: Optional[AsyncSession] = None

    def set_db(self, db: AsyncSession) -> None:
        """Set the database session for DB-backed counting"""
        self._db = db

    def matches(self, alert: Alert) -> bool:
        # Sync path cannot query the async DB; callers should always use
        # matches_async() for this rule. Return False here so a misbehaving
        # sync caller doesn't fire incidents without evidence.
        logger.warning(
            "RepeatedAlertRule.matches() called synchronously — rule only "
            "functions via matches_async() with an AsyncSession",
        )
        return False

    async def matches_async(self, alert: Alert) -> bool:
        """Check alert repetition count from the DB within the time window."""
        if not self._db:
            return False
        return await self._matches_async(alert)

    async def _matches_async(self, alert: Alert) -> bool:
        """Check alert repetition count from the database within time window"""
        from sqlalchemy import func as sa_func
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self.time_window_minutes)
        key = f"{alert.source}:{alert.title}"

        count_query = select(sa_func.count()).select_from(Alert).where(
            Alert.source == alert.source,
            Alert.title == alert.title,
            Alert.created_at >= cutoff,
        )
        if alert.organization_id:
            count_query = count_query.where(Alert.organization_id == alert.organization_id)

        result = await self._db.execute(count_query)
        count = result.scalar() or 0
        return count >= self.threshold

    def get_incident_title(self, alert: Alert) -> str:
        return f"[REPEATED] {alert.title}"


class MultiHostRule(CorrelationRule):
    """Create incident when same alert affects multiple hosts"""

    def __init__(self, threshold: int = 3):
        super().__init__(
            name="Multi-Host Alert",
            description=f"Auto-create incident when alert affects {threshold}+ hosts",
        )
        self.threshold = threshold
        self._alert_hosts: dict[str, set] = {}

    def matches(self, alert: Alert) -> bool:
        if not alert.hostname:
            return False
        key = f"{alert.source}:{alert.title}"
        if key not in self._alert_hosts:
            self._alert_hosts[key] = set()
        self._alert_hosts[key].add(alert.hostname)
        return len(self._alert_hosts[key]) >= self.threshold

    def get_incident_title(self, alert: Alert) -> str:
        key = f"{alert.source}:{alert.title}"
        host_count = len(self._alert_hosts.get(key, set()))
        return f"[MULTI-HOST] {alert.title} (affecting {host_count} hosts)"


class AlertCorrelationService:
    """Service for correlating alerts and creating incidents"""

    def __init__(self, db: AsyncSession):
        self.db = db
        repeated_rule = RepeatedAlertRule(threshold=5, time_window_minutes=30)
        repeated_rule.set_db(db)
        self.rules: list[CorrelationRule] = [
            SeverityRule(min_severity="critical"),
            CategoryRule(categories=["ransomware", "apt", "data_exfiltration"]),
            repeated_rule,
            MultiHostRule(threshold=3),
        ]

    def add_rule(self, rule: CorrelationRule):
        """Add a correlation rule"""
        self.rules.append(rule)

    async def process_alert(
        self,
        alert: Alert,
        notify_callback: Optional[callable] = None,
    ) -> Optional[Incident]:
        """Process an alert through correlation rules and optionally create incident"""

        # Skip if alert already has an incident
        if alert.incident_id:
            logger.debug(f"Alert {alert.id} already linked to incident {alert.incident_id}")
            return None

        # Check each rule (async so DB-backed rules like RepeatedAlertRule work)
        for rule in self.rules:
            if await rule.matches_async(alert):
                logger.info(f"Alert {alert.id} matched rule: {rule.name}")

                if rule.auto_create_incident:
                    incident = await self._create_incident_from_alert(alert, rule)

                    if notify_callback:
                        await notify_callback("incident_created", {
                            "incident_id": incident.id,
                            "alert_id": alert.id,
                            "rule": rule.name,
                            "title": incident.title,
                        })

                    return incident

        return None

    async def _create_incident_from_alert(
        self,
        alert: Alert,
        rule: CorrelationRule,
    ) -> Incident:
        """Create an incident from an alert"""

        # Determine incident type from alert category
        incident_type = IncidentType.OTHER.value
        if alert.category:
            incident_type = CATEGORY_TO_TYPE.get(alert.category, IncidentType.OTHER.value)
        if rule.incident_type:
            incident_type = rule.incident_type

        # Determine severity
        incident_severity = SEVERITY_MAP.get(alert.severity, IncidentSeverity.MEDIUM.value)
        if rule.incident_severity:
            incident_severity = rule.incident_severity

        # Build affected systems list
        affected_systems = []
        if alert.hostname:
            affected_systems.append(alert.hostname)
        if alert.source_ip:
            affected_systems.append(alert.source_ip)

        # Build affected users list
        affected_users = []
        if alert.username:
            affected_users.append(alert.username)

        # Create incident
        incident = Incident(
            title=rule.get_incident_title(alert),
            description=rule.get_incident_description(alert),
            severity=incident_severity,
            status=IncidentStatus.OPEN.value,
            incident_type=incident_type,
            priority=1 if incident_severity == "critical" else 2 if incident_severity == "high" else 3,
            detected_at=datetime.now(timezone.utc).isoformat(),
            affected_systems=json.dumps(affected_systems) if affected_systems else None,
            affected_users=json.dumps(affected_users) if affected_users else None,
            tags=alert.tags,  # Copy tags from alert
        )

        self.db.add(incident)
        await self.db.flush()
        await self.db.refresh(incident)

        # Link alert to incident
        alert.incident_id = incident.id
        alert.status = AlertStatus.INVESTIGATING.value
        await self.db.flush()

        logger.info(f"Created incident {incident.id} from alert {alert.id}")

        return incident

    async def check_threat_intel_match(self, alert: Alert) -> list[IOC]:
        """Check if any indicators in the alert match known IOCs in the database.

        Extracts IPs, domains, file hashes, and URLs from the alert and queries
        the IOC table for active matches. If a match is found the alert severity
        is escalated to critical and a note is appended to the description.

        Returns the list of matched IOC records (may be empty).
        """
        # Collect indicator values from the alert fields
        indicator_values: list[str] = []
        for field in ("source_ip", "destination_ip", "domain", "file_hash", "url"):
            value = getattr(alert, field, None)
            if value:
                indicator_values.append(value)

        if not indicator_values:
            return []

        # Query active IOCs whose value matches any of the alert indicators
        result = await self.db.execute(
            select(IOC).where(
                IOC.is_active == True,  # noqa: E712
                IOC.is_whitelisted == False,  # noqa: E712
                IOC.value.in_(indicator_values),
            )
        )
        matched_iocs: list[IOC] = list(result.scalars().all())

        if not matched_iocs:
            return []

        # Build a human-readable summary of the matches
        match_details = []
        now = datetime.now(timezone.utc)
        for ioc in matched_iocs:
            match_details.append(
                f"  - IOC match: {ioc.indicator_type} = {ioc.value} "
                f"(severity={ioc.severity}, source={ioc.source or 'N/A'})"
            )

            # Bump sighting count on the IOC
            ioc.sighting_count = (ioc.sighting_count or 0) + 1
            ioc.last_sighting_at = now
            ioc.last_seen = now

        note = (
            "\n\n--- Threat Intel IOC Match ---\n"
            + "\n".join(match_details)
            + "\nAlert severity escalated to CRITICAL due to IOC match."
        )

        # Escalate the alert
        alert.severity = AlertSeverity.CRITICAL.value
        alert.description = (alert.description or "") + note

        await self.db.flush()

        logger.warning(
            f"Alert {alert.id} matched {len(matched_iocs)} threat intel IOC(s) — "
            f"severity escalated to critical"
        )

        return matched_iocs

    async def link_alert_to_incident(
        self,
        alert_id: str,
        incident_id: str,
    ) -> bool:
        """Manually link an alert to an existing incident"""
        result = await self.db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()

        if not alert:
            return False

        result = await self.db.execute(select(Incident).where(Incident.id == incident_id))
        incident = result.scalar_one_or_none()

        if not incident:
            return False

        alert.incident_id = incident_id
        await self.db.flush()

        logger.info(f"Linked alert {alert_id} to incident {incident_id}")
        return True

    async def find_related_alerts(
        self,
        alert: Alert,
        time_window_hours: int = 24,
    ) -> list[Alert]:
        """Find alerts that might be related to the given alert"""
        query = select(Alert).where(Alert.id != alert.id)

        # Filter by same source IP
        if alert.source_ip:
            query = query.where(Alert.source_ip == alert.source_ip)

        # Or same hostname
        elif alert.hostname:
            query = query.where(Alert.hostname == alert.hostname)

        # Or same category
        elif alert.category:
            query = query.where(Alert.category == alert.category)

        query = query.limit(50)

        result = await self.db.execute(query)
        return list(result.scalars().all())


def _alert_matches_trigger_conditions(alert: Alert, conditions: dict[str, Any]) -> bool:
    """Check if an alert matches a playbook's trigger conditions.

    Supported condition keys:
        - severity: single value or list, e.g. "critical" or ["critical", "high"]
        - category: single value or list
        - source: single value or list
        - alert_type: single value or list
        - any_alert: if True, matches every alert (catch-all)
    All specified conditions must match (AND logic).
    """
    if conditions.get("any_alert"):
        return True

    for key in ("severity", "category", "source", "alert_type"):
        expected = conditions.get(key)
        if expected is None:
            continue

        actual = getattr(alert, key, None)
        if actual is None:
            return False

        if isinstance(expected, list):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False

    return True


async def auto_trigger_playbooks(
    db: AsyncSession,
    alert: Alert,
    incident: Optional[Incident] = None,
) -> list[str]:
    """Find playbooks whose trigger conditions match the alert and execute them.

    Returns a list of execution IDs that were created.
    """
    from src.services.playbook_engine import PlaybookEngine

    # Query all enabled, active playbooks with trigger_type == "alert"
    result = await db.execute(
        select(Playbook).where(
            Playbook.is_enabled == True,
            Playbook.status == PlaybookStatus.ACTIVE.value,
            Playbook.trigger_type == PlaybookTrigger.ALERT.value,
        )
    )
    playbooks = list(result.scalars().all())

    if not playbooks:
        logger.debug("No active alert-triggered playbooks found")
        return []

    execution_ids: list[str] = []

    for playbook in playbooks:
        # Parse trigger_conditions JSON
        try:
            conditions = json.loads(playbook.trigger_conditions) if playbook.trigger_conditions else {}
        except (json.JSONDecodeError, TypeError):
            logger.warning(f"Playbook {playbook.id} ({playbook.name}) has invalid trigger_conditions, skipping")
            continue

        if not _alert_matches_trigger_conditions(alert, conditions):
            continue

        logger.info(
            f"Auto-triggering playbook '{playbook.name}' (id={playbook.id}) "
            f"for alert {alert.id} (severity={alert.severity}, category={alert.category})"
        )

        # Build context / input_data for the execution
        steps = json.loads(playbook.steps) if playbook.steps else []
        input_data: dict[str, Any] = {
            "alert_id": alert.id,
            "alert_title": alert.title,
            "alert_severity": alert.severity,
            "alert_category": alert.category,
            "alert_source": alert.source,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "hostname": alert.hostname,
            "username": alert.username,
        }
        if incident:
            input_data["incident_id"] = incident.id
            input_data["incident_title"] = incident.title

        # Create execution record
        execution = PlaybookExecution(
            playbook_id=playbook.id,
            incident_id=incident.id if incident else None,
            status=ExecutionStatus.PENDING.value,
            total_steps=len(steps),
            input_data=json.dumps(input_data),
            triggered_by="system",
            trigger_source=f"auto_alert:{alert.id}",
        )
        db.add(execution)
        await db.flush()
        await db.refresh(execution)

        # Execute the playbook
        try:
            engine = PlaybookEngine(db)
            await engine.execute(execution.id)
            logger.info(
                f"Playbook '{playbook.name}' execution {execution.id} finished "
                f"with status={execution.status}"
            )
        except Exception as exc:
            logger.error(
                f"Playbook '{playbook.name}' execution {execution.id} "
                f"raised an exception: {exc}"
            )

        execution_ids.append(execution.id)

    if execution_ids:
        logger.info(
            f"Auto-triggered {len(execution_ids)} playbook(s) for alert {alert.id}: "
            f"{execution_ids}"
        )
    else:
        logger.debug(f"No playbooks matched trigger conditions for alert {alert.id}")

    return execution_ids


async def process_new_alert(
    db: AsyncSession,
    alert: Alert,
    notify_callback: Optional[callable] = None,
) -> Optional[Incident]:
    """Convenience function to process a new alert through correlation,
    check threat intel IOCs, then auto-trigger any matching playbooks."""
    service = AlertCorrelationService(db)

    # Check alert indicators against known threat intel IOCs
    try:
        matched_iocs = await service.check_threat_intel_match(alert)
        if matched_iocs:
            logger.info(
                f"Alert {alert.id} matched {len(matched_iocs)} IOC(s) — "
                f"severity escalated before correlation"
            )
    except Exception as exc:
        logger.error(f"Error during threat intel IOC check for alert {alert.id}: {exc}")

    incident = await service.process_alert(alert, notify_callback)

    # Auto-trigger playbooks whose conditions match this alert
    try:
        await auto_trigger_playbooks(db, alert, incident)
    except Exception as exc:
        logger.error(f"Error during auto-trigger playbooks for alert {alert.id}: {exc}")

    return incident
