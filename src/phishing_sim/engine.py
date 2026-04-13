"""
Phishing Simulation Engine - Core business logic for campaigns, templates,
events, awareness scoring, and training management.

Provides CampaignManager, TemplateEngine, EventTracker, AwarenessScorer,
and TrainingManager classes for comprehensive phishing simulation workflows.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
import hashlib
import json
import re
from uuid import uuid4

from src.core.logging import get_logger

logger = get_logger(__name__)


class CampaignManager:
    """Manages phishing campaign lifecycle: create, launch, pause, end, analyze."""

    def __init__(self):
        """Initialize campaign manager."""
        self.campaigns = {}
        self.campaign_metrics = {}

    def create_campaign(
        self,
        name: str,
        description: str,
        campaign_type: str,
        template_id: str,
        target_group_id: str,
        send_schedule: dict[str, Any],
        difficulty_level: str,
        created_by: str,
        organization_id: str,
    ) -> dict[str, Any]:
        """
        Create a new phishing campaign in draft status.

        Args:
            name: Campaign name
            description: Campaign description
            campaign_type: Type of phishing attack
            template_id: Template to use
            target_group_id: Target group
            send_schedule: Scheduling configuration
            difficulty_level: Difficulty level
            created_by: User ID creating campaign
            organization_id: Organization context

        Returns:
            Campaign data dictionary
        """
        campaign_id = str(uuid4())
        now = datetime.now(timezone.utc)

        campaign = {
            "id": campaign_id,
            "name": name,
            "description": description,
            "campaign_type": campaign_type,
            "status": "draft",
            "template_id": template_id,
            "target_group_id": target_group_id,
            "send_schedule": send_schedule,
            "start_date": None,
            "end_date": None,
            "total_targets": 0,
            "emails_sent": 0,
            "emails_opened": 0,
            "links_clicked": 0,
            "credentials_submitted": 0,
            "attachments_opened": 0,
            "reported_count": 0,
            "difficulty_level": difficulty_level,
            "created_by": created_by,
            "organization_id": organization_id,
            "created_at": now,
            "updated_at": now,
        }

        self.campaigns[campaign_id] = campaign
        self.campaign_metrics[campaign_id] = {
            "start_time": None,
            "completion_time": None,
            "metrics_snapshots": [],
        }

        logger.info(
            f"Created campaign: {name}",
            extra={
                "campaign_id": campaign_id,
                "type": campaign_type,
                "organization_id": organization_id,
            },
        )

        return campaign

    def launch_campaign(
        self, campaign_id: str, total_targets: int
    ) -> dict[str, Any]:
        """
        Launch a campaign - send emails in batches based on schedule.

        Args:
            campaign_id: Campaign ID
            total_targets: Total number of targets

        Returns:
            Launch result with batch info
        """
        if campaign_id not in self.campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        campaign = self.campaigns[campaign_id]
        if campaign["status"] != "draft":
            raise ValueError(f"Campaign must be in draft status, got {campaign['status']}")

        campaign["status"] = "active"
        campaign["start_date"] = datetime.now(timezone.utc)
        campaign["total_targets"] = total_targets
        campaign["updated_at"] = datetime.now(timezone.utc)

        self.campaign_metrics[campaign_id]["start_time"] = datetime.now(timezone.utc)

        schedule = campaign["send_schedule"]
        batch_size = schedule.get("batch_size", 50)
        batches = (total_targets + batch_size - 1) // batch_size

        logger.info(
            f"Launched campaign {campaign_id}",
            extra={
                "total_targets": total_targets,
                "batches": batches,
                "batch_size": batch_size,
            },
        )

        return {
            "campaign_id": campaign_id,
            "status": "active",
            "total_targets": total_targets,
            "batches_queued": batches,
            "batch_size": batch_size,
        }

    def pause_campaign(self, campaign_id: str) -> dict[str, Any]:
        """Pause an active campaign."""
        if campaign_id not in self.campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        campaign = self.campaigns[campaign_id]
        if campaign["status"] != "active":
            raise ValueError(f"Campaign must be active to pause, got {campaign['status']}")

        campaign["status"] = "paused"
        campaign["updated_at"] = datetime.now(timezone.utc)

        logger.info(f"Paused campaign {campaign_id}")

        return {"campaign_id": campaign_id, "status": "paused"}

    def resume_campaign(self, campaign_id: str) -> dict[str, Any]:
        """Resume a paused campaign."""
        if campaign_id not in self.campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        campaign = self.campaigns[campaign_id]
        if campaign["status"] != "paused":
            raise ValueError(f"Campaign must be paused to resume, got {campaign['status']}")

        campaign["status"] = "active"
        campaign["updated_at"] = datetime.now(timezone.utc)

        logger.info(f"Resumed campaign {campaign_id}")

        return {"campaign_id": campaign_id, "status": "active"}

    def end_campaign(self, campaign_id: str) -> dict[str, Any]:
        """End a campaign - calculate final metrics."""
        if campaign_id not in self.campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        campaign = self.campaigns[campaign_id]
        if campaign["status"] not in ["active", "paused"]:
            raise ValueError(f"Campaign must be active or paused, got {campaign['status']}")

        campaign["status"] = "completed"
        campaign["end_date"] = datetime.now(timezone.utc)
        campaign["updated_at"] = datetime.now(timezone.utc)

        self.campaign_metrics[campaign_id]["completion_time"] = datetime.now(timezone.utc)

        metrics = self.calculate_campaign_metrics(campaign_id)

        logger.info(
            f"Ended campaign {campaign_id}",
            extra={"metrics": metrics},
        )

        return {"campaign_id": campaign_id, "status": "completed", "metrics": metrics}

    def clone_campaign(
        self, source_campaign_id: str, new_name: str, organization_id: str
    ) -> dict[str, Any]:
        """Clone an existing campaign with new name."""
        if source_campaign_id not in self.campaigns:
            raise ValueError(f"Campaign {source_campaign_id} not found")

        source = self.campaigns[source_campaign_id]
        cloned = self.create_campaign(
            name=new_name,
            description=source["description"],
            campaign_type=source["campaign_type"],
            template_id=source["template_id"],
            target_group_id=source["target_group_id"],
            send_schedule=source["send_schedule"],
            difficulty_level=source["difficulty_level"],
            created_by=source["created_by"],
            organization_id=organization_id,
        )

        logger.info(
            f"Cloned campaign {source_campaign_id} to {cloned['id']}",
            extra={"new_name": new_name},
        )

        return cloned

    def schedule_campaign(
        self, campaign_id: str, start_time: datetime
    ) -> dict[str, Any]:
        """Schedule a campaign to start at specific time."""
        if campaign_id not in self.campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        campaign = self.campaigns[campaign_id]
        if campaign["status"] != "draft":
            raise ValueError(f"Campaign must be in draft status to schedule")

        campaign["status"] = "scheduled"
        campaign["start_date"] = start_time
        campaign["updated_at"] = datetime.now(timezone.utc)

        logger.info(
            f"Scheduled campaign {campaign_id}",
            extra={"start_time": start_time.isoformat()},
        )

        return {"campaign_id": campaign_id, "status": "scheduled", "start_time": start_time}

    def get_campaign_results(self, campaign_id: str) -> dict[str, Any]:
        """Get current results for a campaign."""
        if campaign_id not in self.campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        campaign = self.campaigns[campaign_id]

        return {
            "campaign_id": campaign_id,
            "name": campaign["name"],
            "status": campaign["status"],
            "total_targets": campaign["total_targets"],
            "emails_sent": campaign["emails_sent"],
            "emails_opened": campaign["emails_opened"],
            "open_rate": (
                campaign["emails_opened"] / campaign["emails_sent"] * 100
                if campaign["emails_sent"] > 0
                else 0
            ),
            "links_clicked": campaign["links_clicked"],
            "click_rate": (
                campaign["links_clicked"] / campaign["emails_sent"] * 100
                if campaign["emails_sent"] > 0
                else 0
            ),
            "credentials_submitted": campaign["credentials_submitted"],
            "submission_rate": (
                campaign["credentials_submitted"] / campaign["emails_sent"] * 100
                if campaign["emails_sent"] > 0
                else 0
            ),
            "reported_count": campaign["reported_count"],
            "reported_rate": (
                campaign["reported_count"] / campaign["emails_sent"] * 100
                if campaign["emails_sent"] > 0
                else 0
            ),
        }

    def calculate_campaign_metrics(self, campaign_id: str) -> dict[str, Any]:
        """Calculate comprehensive metrics for a campaign."""
        if campaign_id not in self.campaigns:
            raise ValueError(f"Campaign {campaign_id} not found")

        campaign = self.campaigns[campaign_id]
        metrics_data = self.campaign_metrics.get(campaign_id, {})

        total_targets = campaign["total_targets"] or 1
        emails_sent = campaign["emails_sent"] or 1

        return {
            "open_rate": campaign["emails_opened"] / emails_sent * 100,
            "click_rate": campaign["links_clicked"] / emails_sent * 100,
            "submission_rate": campaign["credentials_submitted"] / emails_sent * 100,
            "report_rate": campaign["reported_count"] / emails_sent * 100,
            "attachment_open_rate": campaign["attachments_opened"] / emails_sent * 100,
            "vulnerability_index": (
                (campaign["links_clicked"] + campaign["credentials_submitted"])
                / emails_sent
                * 100
            ),
            "security_score": max(
                0,
                100
                - (
                    (campaign["links_clicked"] + campaign["credentials_submitted"])
                    / emails_sent
                    * 100
                ),
            ),
            "duration_hours": (
                (metrics_data.get("completion_time") - metrics_data.get("start_time")).total_seconds() / 3600
                if metrics_data.get("start_time") and metrics_data.get("completion_time")
                else 0
            ),
        }


class TemplateEngine:
    """Template management and personalization."""

    def __init__(self):
        """Initialize template engine."""
        self.templates = {}
        self.tracking_pixels = {}

    def create_template(
        self,
        name: str,
        category: str,
        difficulty: str,
        subject_line: str,
        sender_name: str,
        sender_email: str,
        html_body: str,
        landing_page_html: str | None,
        indicators_of_phishing: list[str],
        organization_id: str,
        **kwargs,
    ) -> dict[str, Any]:
        """Create a new phishing template."""
        template_id = str(uuid4())

        template = {
            "id": template_id,
            "name": name,
            "description": kwargs.get("description"),
            "category": category,
            "difficulty": difficulty,
            "subject_line": subject_line,
            "sender_name": sender_name,
            "sender_email": sender_email,
            "html_body": html_body,
            "text_body": kwargs.get("text_body"),
            "landing_page_html": landing_page_html,
            "has_attachment": kwargs.get("has_attachment", False),
            "attachment_name": kwargs.get("attachment_name"),
            "indicators_of_phishing": indicators_of_phishing,
            "training_content_on_fail": kwargs.get("training_content_on_fail"),
            "language": kwargs.get("language", "en"),
            "is_seasonal": kwargs.get("is_seasonal", False),
            "usage_count": 0,
            "average_click_rate": 0.0,
            "organization_id": organization_id,
        }

        self.templates[template_id] = template

        logger.info(
            f"Created template: {name}",
            extra={"template_id": template_id, "category": category},
        )

        return template

    def render_template(
        self,
        template_id: str,
        target_data: dict[str, Any],
    ) -> dict[str, str]:
        """
        Render template with personalized target data.

        Args:
            template_id: Template ID
            target_data: {name, email, department, role, etc.}

        Returns:
            Rendered subject_line and html_body with personalization
        """
        if template_id not in self.templates:
            raise ValueError(f"Template {template_id} not found")

        template = self.templates[template_id]

        # Personalize subject line and body with target data
        subject = self._personalize_text(template["subject_line"], target_data)
        html = self._personalize_text(template["html_body"], target_data)

        return {
            "subject_line": subject,
            "html_body": html,
            "sender_name": template["sender_name"],
            "sender_email": template["sender_email"],
        }

    def _personalize_text(self, text: str, data: dict[str, Any]) -> str:
        """Personalize text with placeholders like {{name}}, {{department}}."""
        result = text
        for key, value in data.items():
            placeholder = f"{{{{{key}}}}}"
            result = result.replace(placeholder, str(value))
        return result

    def generate_landing_page(
        self,
        template_id: str,
        campaign_id: str,
        target_email: str,
    ) -> dict[str, str]:
        """
        Generate personalized landing page with tracking.

        Args:
            template_id: Template ID
            campaign_id: Campaign ID
            target_email: Target email for tracking

        Returns:
            Landing page HTML with tracking pixel
        """
        if template_id not in self.templates:
            raise ValueError(f"Template {template_id} not found")

        template = self.templates[template_id]
        landing_html = template.get("landing_page_html", "")

        # Add tracking pixel
        pixel_id = self._create_unique_tracking_link(campaign_id, target_email)
        tracking_pixel = f'<img src="/api/v1/phishing_sim/track/pixel/{pixel_id}" width="1" height="1" alt="" />'

        landing_html += f"\n{tracking_pixel}"

        return {
            "html": landing_html,
            "tracking_id": pixel_id,
            "url": f"/phishing/landing/{pixel_id}",
        }

    def add_tracking_pixels(self, html: str, tracking_ids: list[str]) -> str:
        """Add tracking pixels to HTML body."""
        for pixel_id in tracking_ids:
            pixel = f'<img src="/api/v1/phishing_sim/track/pixel/{pixel_id}" width="1" height="1" style="display:none;" />'
            html += f"\n{pixel}"
        return html

    def create_unique_tracking_links(
        self,
        campaign_id: str,
        targets: list[str],
    ) -> dict[str, str]:
        """
        Create unique tracking links for each target.

        Args:
            campaign_id: Campaign ID
            targets: List of target emails

        Returns:
            Dict mapping email -> unique tracking link
        """
        links = {}
        for email in targets:
            link_id = self._create_unique_tracking_link(campaign_id, email)
            links[email] = f"/phishing/click/{link_id}"
            self.tracking_pixels[link_id] = {
                "campaign_id": campaign_id,
                "email": email,
                "created_at": datetime.now(timezone.utc),
            }
        return links

    def _create_unique_tracking_link(self, campaign_id: str, email: str) -> str:
        """Generate unique tracking link hash."""
        data = f"{campaign_id}:{email}:{uuid4()}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]

    def validate_template(self, template_id: str) -> dict[str, Any]:
        """Validate template for broken links and rendering issues."""
        if template_id not in self.templates:
            raise ValueError(f"Template {template_id} not found")

        template = self.templates[template_id]
        issues = []

        # Check for broken placeholders
        html = template["html_body"]
        placeholder_pattern = r"\{\{(\w+)\}\}"
        placeholders = re.findall(placeholder_pattern, html)

        for placeholder in placeholders:
            if placeholder not in ["name", "email", "department", "role", "title"]:
                issues.append(f"Unknown placeholder: {{{{{placeholder}}}}}")

        # Check for malformed links
        link_pattern = r'href=["\']([^"\']+)["\']'
        links = re.findall(link_pattern, html)
        for link in links:
            if not link.startswith(("http", "/", "mailto:")):
                issues.append(f"Potentially malformed link: {link}")

        return {
            "template_id": template_id,
            "is_valid": len(issues) == 0,
            "issues": issues,
            "placeholders_found": placeholders,
            "links_found": len(links),
        }

    def get_template_effectiveness(self, template_id: str) -> dict[str, Any]:
        """Get historical effectiveness metrics for a template."""
        if template_id not in self.templates:
            raise ValueError(f"Template {template_id} not found")

        template = self.templates[template_id]

        return {
            "template_id": template_id,
            "name": template["name"],
            "usage_count": template["usage_count"],
            "average_click_rate": template["average_click_rate"],
            "category": template["category"],
            "difficulty": template["difficulty"],
            "effectiveness_rating": self._rate_effectiveness(template["average_click_rate"]),
        }

    def _rate_effectiveness(self, click_rate: float) -> str:
        """Rate template effectiveness based on click rate."""
        if click_rate < 5:
            return "very_low"
        elif click_rate < 15:
            return "low"
        elif click_rate < 30:
            return "moderate"
        elif click_rate < 50:
            return "high"
        else:
            return "very_high"


class EventTracker:
    """Track and record phishing campaign events."""

    def __init__(self):
        """Initialize event tracker."""
        self.events = {}
        self.event_timeline = {}

    def record_event(
        self,
        campaign_id: str,
        target_email: str,
        event_type: str,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Record a campaign event.

        Args:
            campaign_id: Campaign ID
            target_email: Target email
            event_type: Type of event
            **kwargs: Additional event data (ip_address, user_agent, geo_location, etc.)

        Returns:
            Event record
        """
        event_id = str(uuid4())
        event = {
            "id": event_id,
            "campaign_id": campaign_id,
            "target_email": target_email,
            "target_name": kwargs.get("target_name"),
            "event_type": event_type,
            "event_timestamp": datetime.now(timezone.utc),
            "ip_address": kwargs.get("ip_address"),
            "user_agent": kwargs.get("user_agent"),
            "geo_location": kwargs.get("geo_location"),
            "device_type": kwargs.get("device_type"),
            "time_to_action_seconds": kwargs.get("time_to_action_seconds"),
        }

        key = f"{campaign_id}:{target_email}"
        if key not in self.events:
            self.events[key] = []
        self.events[key].append(event)

        if campaign_id not in self.event_timeline:
            self.event_timeline[campaign_id] = []
        self.event_timeline[campaign_id].append(event)

        logger.info(
            f"Recorded event: {event_type}",
            extra={
                "campaign_id": campaign_id,
                "email": target_email,
                "event_type": event_type,
            },
        )

        return event

    def process_email_open(
        self,
        campaign_id: str,
        target_email: str,
        ip_address: str,
        user_agent: str,
        **kwargs,
    ) -> dict[str, Any]:
        """Process email open event."""
        return self.record_event(
            campaign_id,
            target_email,
            "email_opened",
            ip_address=ip_address,
            user_agent=user_agent,
            **kwargs,
        )

    def process_link_click(
        self,
        campaign_id: str,
        target_email: str,
        link_url: str,
        ip_address: str,
        **kwargs,
    ) -> dict[str, Any]:
        """Process link click event."""
        return self.record_event(
            campaign_id,
            target_email,
            "link_clicked",
            ip_address=ip_address,
            **kwargs,
        )

    def process_credential_submit(
        self,
        campaign_id: str,
        target_email: str,
        ip_address: str,
        **kwargs,
    ) -> dict[str, Any]:
        """Process credential submission event."""
        return self.record_event(
            campaign_id,
            target_email,
            "credential_submitted",
            ip_address=ip_address,
            **kwargs,
        )

    def process_report(
        self,
        campaign_id: str,
        target_email: str,
        reported_to: str = "security_team",
        **kwargs,
    ) -> dict[str, Any]:
        """
        Process user reported phishing - this is a WIN.

        Args:
            campaign_id: Campaign ID
            target_email: Email of user who reported
            reported_to: Who/where it was reported to
            **kwargs: Additional data

        Returns:
            Report event record
        """
        event = self.record_event(
            campaign_id,
            target_email,
            "reported_as_phishing",
            **kwargs,
        )

        logger.info(
            f"Phishing reported by {target_email} - SECURITY WIN",
            extra={
                "campaign_id": campaign_id,
                "reported_to": reported_to,
            },
        )

        return event

    def calculate_time_to_action(
        self,
        campaign_id: str,
        target_email: str,
        action_type: str,
    ) -> int | None:
        """Calculate seconds from email send to action (click/submit)."""
        key = f"{campaign_id}:{target_email}"
        if key not in self.events:
            return None

        events = self.events[key]
        send_event = next((e for e in events if e["event_type"] == "email_sent"), None)
        action_event = next((e for e in events if e["event_type"] == action_type), None)

        if send_event and action_event:
            delta = action_event["event_timestamp"] - send_event["event_timestamp"]
            return int(delta.total_seconds())

        return None

    def generate_event_timeline(
        self, campaign_id: str, target_email: str | None = None
    ) -> list[dict[str, Any]]:
        """Generate event timeline for campaign or specific target."""
        events = []

        if target_email:
            key = f"{campaign_id}:{target_email}"
            events = self.events.get(key, [])
        else:
            events = self.event_timeline.get(campaign_id, [])

        # Sort by timestamp
        events = sorted(events, key=lambda e: e["event_timestamp"])

        return [
            {
                "timestamp": e["event_timestamp"].isoformat(),
                "event_type": e["event_type"],
                "target_email": e["target_email"],
                "ip_address": e.get("ip_address"),
                "device_type": e.get("device_type"),
            }
            for e in events
        ]


class AwarenessScorer:
    """Calculate user and department security awareness scores."""

    def __init__(self):
        """Initialize awareness scorer."""
        self.user_scores = {}
        self.department_stats = {}

    def calculate_user_score(
        self,
        user_email: str,
        user_name: str,
        reported: int = 0,
        no_action: int = 0,
        clicked: int = 0,
        submitted_credentials: int = 0,
        training_completed: int = 0,
        department: str | None = None,
    ) -> dict[str, Any]:
        """
        Calculate weighted user awareness score.

        Scoring: reported +20, no action +10, opened -5, clicked -15, credentials -30
        Final: 0-100 scale

        Args:
            user_email: User email
            user_name: User name
            reported: Times reported phishing
            no_action: Times took no action
            clicked: Times clicked malicious link
            submitted_credentials: Times submitted credentials
            training_completed: Training modules completed
            department: Department name

        Returns:
            User score data
        """
        # Calculate component scores
        report_points = reported * 20
        no_action_points = no_action * 10
        click_penalty = clicked * -15
        credential_penalty = submitted_credentials * -30
        training_bonus = min(training_completed * 5, 25)

        raw_score = report_points + no_action_points + click_penalty + credential_penalty + training_bonus

        # Normalize to 0-100
        overall_score = max(0, min(100, 50 + raw_score))

        # Determine risk category
        risk_category = self._categorize_risk(overall_score)

        user_score = {
            "user_email": user_email,
            "user_name": user_name,
            "department": department,
            "overall_score": overall_score,
            "phishing_score": self._calculate_phishing_component(
                clicked, submitted_credentials, reported
            ),
            "training_completion_rate": 0.0,
            "campaigns_participated": reported + clicked + submitted_credentials + no_action,
            "times_clicked": clicked,
            "times_reported": reported,
            "times_submitted_credentials": submitted_credentials,
            "risk_category": risk_category,
        }

        self.user_scores[user_email] = user_score

        logger.info(
            f"Calculated awareness score for {user_email}",
            extra={
                "overall_score": overall_score,
                "risk_category": risk_category,
            },
        )

        return user_score

    def _calculate_phishing_component(
        self, clicked: int, submitted: int, reported: int
    ) -> int:
        """Calculate phishing-specific vulnerability score."""
        total_interactions = clicked + submitted + reported or 1
        vulnerability = (clicked + submitted) / total_interactions * 100
        return max(0, min(100, 100 - vulnerability))

    def _categorize_risk(self, score: int) -> str:
        """Categorize user into risk level based on score."""
        if score >= 90:
            return "champion"
        elif score >= 70:
            return "low_risk"
        elif score >= 50:
            return "moderate_risk"
        elif score >= 30:
            return "high_risk"
        else:
            return "critical_risk"

    def calculate_department_scores(
        self, department: str
    ) -> dict[str, Any]:
        """Calculate aggregate scores for a department."""
        dept_users = [s for s in self.user_scores.values() if s["department"] == department]

        if not dept_users:
            return {
                "department": department,
                "user_count": 0,
                "avg_score": 0,
                "avg_phishing_score": 0,
                "risk_distribution": {},
            }

        scores = [u["overall_score"] for u in dept_users]
        phishing_scores = [u["phishing_score"] for u in dept_users]

        risk_dist = {}
        for user in dept_users:
            cat = user["risk_category"]
            risk_dist[cat] = risk_dist.get(cat, 0) + 1

        dept_stat = {
            "department": department,
            "user_count": len(dept_users),
            "avg_score": sum(scores) / len(scores),
            "avg_phishing_score": sum(phishing_scores) / len(phishing_scores),
            "min_score": min(scores),
            "max_score": max(scores),
            "risk_distribution": risk_dist,
        }

        self.department_stats[department] = dept_stat

        return dept_stat

    def identify_high_risk_users(self, threshold: int = 40) -> list[dict[str, Any]]:
        """Identify users above risk threshold."""
        high_risk = [
            s for s in self.user_scores.values() if s["overall_score"] <= threshold
        ]
        return sorted(high_risk, key=lambda x: x["overall_score"])

    def generate_risk_report(self) -> dict[str, Any]:
        """Generate comprehensive risk report."""
        users = list(self.user_scores.values())
        depts = list(self.department_stats.values())

        if not users:
            return {
                "total_users": 0,
                "total_departments": 0,
                "avg_score": 0,
                "high_risk_users": [],
                "critical_risk_users": [],
            }

        all_scores = [u["overall_score"] for u in users]
        high_risk = [u for u in users if u["risk_category"] == "high_risk"]
        critical_risk = [u for u in users if u["risk_category"] == "critical_risk"]

        return {
            "total_users": len(users),
            "total_departments": len(depts),
            "avg_score": sum(all_scores) / len(all_scores),
            "risk_distribution": {
                cat: len([u for u in users if u["risk_category"] == cat])
                for cat in ["champion", "low_risk", "moderate_risk", "high_risk", "critical_risk"]
            },
            "high_risk_users": high_risk,
            "critical_risk_users": critical_risk,
            "top_departments": sorted(depts, key=lambda d: d["avg_score"])[:5],
        }

    def track_improvement_over_time(
        self, user_email: str, history: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Track user score improvement over time."""
        if not history:
            return {"user_email": user_email, "trend": "insufficient_data", "history": []}

        scores = [h["score"] for h in history]
        trend = "improving" if scores[-1] > scores[0] else "declining"

        return {
            "user_email": user_email,
            "trend": trend,
            "improvement": scores[-1] - scores[0],
            "average_score": sum(scores) / len(scores),
            "history": history,
        }

    def recommend_training(
        self, user_email: str, failure_patterns: list[str]
    ) -> list[str]:
        """Recommend training modules based on failure patterns."""
        recommendations = []

        for pattern in failure_patterns:
            if pattern == "credential_harvest":
                recommendations.append("Password Security & Credential Protection")
            elif pattern == "link_click":
                recommendations.append("Spotting Malicious Links & URLs")
            elif pattern == "social_engineering":
                recommendations.append("Social Engineering Tactics & Defense")
            elif pattern == "mobile":
                recommendations.append("Mobile Device Security")
            elif pattern == "physical":
                recommendations.append("Physical Security & Tailgating")

        logger.info(
            f"Recommended training for {user_email}",
            extra={"recommendations": recommendations},
        )

        return list(set(recommendations))

    def benchmark_against_industry(self) -> dict[str, Any]:
        """Benchmark organization against industry standards (2025 avg: 4.1% click rate)."""
        users = list(self.user_scores.values())

        if not users:
            return {
                "organization_click_rate": 0.0,
                "industry_average": 4.1,
                "vs_industry": "N/A",
            }

        total_campaigns = sum(u["campaigns_participated"] for u in users)
        total_clicks = sum(u["times_clicked"] for u in users)

        click_rate = (total_clicks / total_campaigns * 100) if total_campaigns > 0 else 0

        return {
            "organization_click_rate": round(click_rate, 2),
            "industry_average": 4.1,
            "vs_industry": "below_average" if click_rate < 4.1 else "above_average",
            "percentile": self._calculate_percentile(click_rate),
        }

    def _calculate_percentile(self, click_rate: float) -> str:
        """Calculate organization percentile vs industry."""
        if click_rate < 2.0:
            return "top_25"
        elif click_rate < 4.1:
            return "top_50"
        elif click_rate < 8.0:
            return "bottom_50"
        else:
            return "bottom_25"


class TrainingManager:
    """Manage security awareness training assignment and tracking."""

    def __init__(self):
        """Initialize training manager."""
        self.training_assignments = {}
        self.training_content = self._load_training_modules()
        self.certificates = {}

    def _load_training_modules(self) -> dict[str, dict[str, Any]]:
        """Load built-in training modules."""
        return {
            "spotting_phishing": {
                "title": "Spotting Phishing Emails",
                "description": "Learn to identify phishing emails and malicious messages",
                "duration_minutes": 15,
                "modules": [
                    "Email header analysis",
                    "Sender verification",
                    "Link inspection",
                    "Attachment risks",
                ],
            },
            "password_security": {
                "title": "Password Security & Credential Protection",
                "description": "Best practices for password management and credential security",
                "duration_minutes": 20,
                "modules": [
                    "Strong password creation",
                    "MFA setup",
                    "Password manager usage",
                    "Credential sharing risks",
                ],
            },
            "social_engineering": {
                "title": "Social Engineering Tactics & Defense",
                "description": "Understand and defend against social engineering attacks",
                "duration_minutes": 25,
                "modules": [
                    "Common tactics",
                    "Pretext attacks",
                    "Pretexting",
                    "Defense strategies",
                ],
            },
            "mobile_security": {
                "title": "Mobile Device Security",
                "description": "Secure your smartphone and mobile devices",
                "duration_minutes": 20,
                "modules": [
                    "App security",
                    "Public WiFi risks",
                    "Device management",
                    "Mobile phishing",
                ],
            },
            "physical_security": {
                "title": "Physical Security & Tailgating",
                "description": "Prevent unauthorized physical access",
                "duration_minutes": 15,
                "modules": [
                    "Badge security",
                    "Tailgating prevention",
                    "Visitor management",
                    "Facility security",
                ],
            },
            "reporting_procedures": {
                "title": "Security Incident Reporting",
                "description": "How to report security incidents and suspicious activity",
                "duration_minutes": 10,
                "modules": [
                    "When to report",
                    "How to report",
                    "What to include",
                    "Post-report procedures",
                ],
            },
        }

    def assign_training(
        self,
        user_email: str,
        user_name: str,
        module_names: list[str],
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Auto-assign training on phishing failure."""
        assignment_id = str(uuid4())
        now = datetime.now(timezone.utc)

        assignments = []
        for module in module_names:
            if module in self.training_content:
                assignments.append({
                    "module": module,
                    "status": "assigned",
                    "assigned_at": now.isoformat(),
                    "due_date": (now + timedelta(days=7)).isoformat(),
                    "completion_date": None,
                })

        assignment = {
            "id": assignment_id,
            "user_email": user_email,
            "user_name": user_name,
            "modules": assignments,
            "reason": reason or "phishing_failure",
            "created_at": now.isoformat(),
        }

        self.training_assignments[user_email] = assignment

        logger.info(
            f"Assigned training to {user_email}",
            extra={
                "modules": module_names,
                "reason": reason,
            },
        )

        return assignment

    def track_completion(
        self,
        user_email: str,
        module_name: str,
        completion_time_minutes: int,
    ) -> dict[str, Any]:
        """Track training module completion."""
        if user_email not in self.training_assignments:
            raise ValueError(f"No training assignment for {user_email}")

        assignment = self.training_assignments[user_email]
        for mod in assignment["modules"]:
            if mod["module"] == module_name:
                mod["status"] = "completed"
                mod["completion_date"] = datetime.now(timezone.utc).isoformat()
                mod["completion_time_minutes"] = completion_time_minutes

        logger.info(
            f"Completed training: {user_email} - {module_name}",
            extra={"time": completion_time_minutes},
        )

        return assignment

    def get_training_content(self, module_name: str) -> dict[str, Any]:
        """Get training content for a module."""
        if module_name not in self.training_content:
            raise ValueError(f"Module {module_name} not found")

        return self.training_content[module_name]

    def generate_certificate(
        self,
        user_email: str,
        user_name: str,
        training_module: str,
    ) -> dict[str, Any]:
        """Generate training certificate."""
        cert_id = str(uuid4())
        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(days=365)

        certificate = {
            "id": cert_id,
            "user_email": user_email,
            "user_name": user_name,
            "module": training_module,
            "issued_at": now.isoformat(),
            "valid_until": valid_until.isoformat(),
            "certificate_number": f"CERT-{now.strftime('%Y%m%d')}-{cert_id[:8].upper()}",
        }

        key = f"{user_email}:{training_module}"
        self.certificates[key] = certificate

        logger.info(
            f"Generated certificate for {user_email}",
            extra={"module": training_module},
        )

        return certificate

    def calculate_training_roi(
        self,
        users_trained: int,
        pre_training_click_rate: float,
        post_training_click_rate: float,
    ) -> dict[str, Any]:
        """Calculate ROI of training program."""
        click_improvement = pre_training_click_rate - post_training_click_rate
        improvement_percent = (click_improvement / pre_training_click_rate * 100) if pre_training_click_rate > 0 else 0

        # Assume $200 per training delivery, $10k cost per phishing breach
        training_cost = users_trained * 200
        avoided_breaches = users_trained * (click_improvement / 100) * 0.05  # 5% breach rate
        avoided_cost = avoided_breaches * 10000

        roi = ((avoided_cost - training_cost) / training_cost * 100) if training_cost > 0 else 0

        return {
            "users_trained": users_trained,
            "pre_training_click_rate": round(pre_training_click_rate, 2),
            "post_training_click_rate": round(post_training_click_rate, 2),
            "improvement_percent": round(improvement_percent, 2),
            "training_cost": training_cost,
            "avoided_breach_cost": round(avoided_cost, 2),
            "roi_percent": round(roi, 2),
        }
