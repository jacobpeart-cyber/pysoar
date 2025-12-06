"""Alert Correlation Service - Auto-creates incidents from alerts based on rules"""

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.models.alert import Alert, AlertStatus
from src.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentType

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
        """Check if alert matches this rule"""
        raise NotImplementedError

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
        self._alert_counts: dict[str, int] = {}

    def matches(self, alert: Alert) -> bool:
        # Simplified - in production, track in database with timestamps
        key = f"{alert.source}:{alert.title}"
        self._alert_counts[key] = self._alert_counts.get(key, 0) + 1
        return self._alert_counts[key] >= self.threshold

    def get_incident_title(self, alert: Alert) -> str:
        return f"[REPEATED] {alert.title} ({self._alert_counts.get(f'{alert.source}:{alert.title}', 0)} occurrences)"


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
        self.rules: list[CorrelationRule] = [
            SeverityRule(min_severity="critical"),
            CategoryRule(categories=["ransomware", "apt", "data_exfiltration"]),
            RepeatedAlertRule(threshold=5, time_window_minutes=30),
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

        # Check each rule
        for rule in self.rules:
            if rule.matches(alert):
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


async def process_new_alert(
    db: AsyncSession,
    alert: Alert,
    notify_callback: Optional[callable] = None,
) -> Optional[Incident]:
    """Convenience function to process a new alert through correlation"""
    service = AlertCorrelationService(db)
    return await service.process_alert(alert, notify_callback)
