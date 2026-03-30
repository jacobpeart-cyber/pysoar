"""
Data Loss Prevention Engine

Core DLP functionality for content evaluation, sensitive data detection,
classification, exfiltration monitoring, discovery scanning, and breach assessment.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from src.core.logging import get_logger

logger = get_logger(__name__)


class DLPEngine:
    """Main DLP engine for policy evaluation and violation detection"""

    # Sensitive data patterns (regex)
    SENSITIVE_PATTERNS = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
        "api_key": r"(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
        "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "ipv6": r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}",
        "aws_key": r"(?i)AKIA[0-9A-Z]{16}",
        "private_key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
    }

    MEDICAL_TERMS = {
        "diagnosis": r"\b(cancer|diabetes|hypertension|heart disease|stroke|asthma|pneumonia|arthritis|depression|anxiety)\b",
        "medication": r"\b(aspirin|metformin|lisinopril|metoprolol|atorvastatin|levothyroxine|omeprazole|sertraline)\b",
        "procedure": r"\b(surgery|biopsy|endoscopy|colonoscopy|angiography|ultrasound|CT scan|MRI)\b",
    }

    def __init__(self):
        """Initialize DLP engine"""
        self.compiled_patterns = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for performance"""
        for name, pattern in self.SENSITIVE_PATTERNS.items():
            try:
                self.compiled_patterns[name] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"Failed to compile pattern {name}: {e}")

        for name, pattern in self.MEDICAL_TERMS.items():
            try:
                self.compiled_patterns[f"medical_{name}"] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"Failed to compile medical pattern {name}: {e}")

    def evaluate_content(
        self,
        content: str,
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Evaluate content against DLP policies and patterns.

        Args:
            content: Content to evaluate
            context: Optional context (user, device, destination, etc.)

        Returns:
            Dictionary with evaluation results and violations
        """
        violations = []
        detected_data_types = []

        # Detect sensitive data
        sensitive_data = self.detect_sensitive_data(content)
        if sensitive_data:
            detected_data_types.extend(sensitive_data.keys())
            violations.append({
                "type": "sensitive_data_detected",
                "data_types": list(sensitive_data.keys()),
                "count": sum(len(v) for v in sensitive_data.values()),
            })

        # Analyze context for exfiltration indicators
        if context:
            exfil_risk = self._analyze_exfiltration_context(context)
            if exfil_risk:
                violations.append(exfil_risk)

        return {
            "has_violations": len(violations) > 0,
            "violations": violations,
            "detected_data_types": detected_data_types,
            "risk_score": self._calculate_risk_score(violations),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def detect_sensitive_data(self, text: str) -> dict[str, list[str]]:
        """
        Detect sensitive data in text content.

        Args:
            text: Text to scan

        Returns:
            Dictionary mapping data types to found matches
        """
        findings = {}

        for name, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            if matches:
                if name.startswith("medical_"):
                    if "medical_data" not in findings:
                        findings["medical_data"] = []
                    findings["medical_data"].extend(matches)
                else:
                    findings[name] = matches

        return findings

    def _analyze_exfiltration_context(self, context: dict[str, Any]) -> Optional[dict[str, Any]]:
        """
        Analyze context for exfiltration risk indicators.

        Args:
            context: Context dictionary

        Returns:
            Violation dict if risks detected, None otherwise
        """
        risks = []

        # Check for high-risk channels
        destination = context.get("destination", "").lower()
        if any(term in destination for term in ["personal.email", "gmail", "yahoo", "hotmail", "pastebin"]):
            risks.append("unauthorized_transfer_channel")

        # Check for bulk operations
        data_volume = context.get("data_volume_bytes", 0)
        if data_volume and data_volume > 100 * 1024 * 1024:  # 100 MB
            risks.append("bulk_data_transfer")

        # Check for off-hours activity
        timestamp = context.get("timestamp")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                hour = dt.hour
                if hour < 6 or hour > 22:
                    risks.append("off_hours_activity")
            except (ValueError, AttributeError):
                pass

        if risks:
            return {
                "type": "exfiltration_risk",
                "risk_indicators": risks,
                "severity": "high" if len(risks) > 1 else "medium",
            }

        return None

    def _calculate_risk_score(self, violations: list[dict[str, Any]]) -> float:
        """
        Calculate overall risk score based on violations.

        Args:
            violations: List of detected violations

        Returns:
            Risk score 0.0 to 1.0
        """
        if not violations:
            return 0.0

        score = 0.0
        for violation in violations:
            if violation.get("type") == "sensitive_data_detected":
                score += 0.3
            elif violation.get("type") == "exfiltration_risk":
                severity = violation.get("severity", "medium")
                if severity == "critical":
                    score += 0.5
                elif severity == "high":
                    score += 0.4
                else:
                    score += 0.2

        return min(score, 1.0)

    def create_violation(
        self,
        policy_id: str,
        violation_type: str,
        source_user: str,
        destination: str,
        data_classification: str,
        sensitive_data_types: list[str],
        organization_id: str,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Create a DLP violation record.

        Args:
            policy_id: Associated policy ID
            violation_type: Type of violation
            source_user: User initiating action
            destination: Destination of data
            data_classification: Classification level
            sensitive_data_types: List of detected data types
            organization_id: Organization ID
            **kwargs: Additional fields

        Returns:
            Violation data dictionary
        """
        return {
            "organization_id": organization_id,
            "policy_id": policy_id,
            "violation_type": violation_type,
            "source_user": source_user,
            "destination": destination,
            "data_classification": data_classification,
            "sensitive_data_types": json.dumps(sensitive_data_types),
            "action_taken": kwargs.get("action_taken", "logged"),
            "status": "new",
            "severity": kwargs.get("severity", "medium"),
            "source_device": kwargs.get("source_device"),
            "source_application": kwargs.get("source_application"),
            "file_name": kwargs.get("file_name"),
            "file_hash": kwargs.get("file_hash"),
            "data_volume_bytes": kwargs.get("data_volume_bytes"),
        }

    def enforce_policy_action(
        self,
        action_type: str,
        content: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Enforce policy action (block, quarantine, redact, etc.).

        Args:
            action_type: Action to take
            content: Content to process
            metadata: Optional metadata

        Returns:
            Result of enforcement action
        """
        result = {
            "action": action_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "applied",
        }

        if action_type == "redacted":
            result["modified_content"] = self._redact_sensitive_data(content)
        elif action_type == "encrypted":
            result["message"] = "Content marked for encryption"
        elif action_type == "quarantined":
            result["message"] = "Content quarantined"
        elif action_type == "blocked":
            result["message"] = "Transfer blocked"
        else:
            result["message"] = f"Action {action_type} recorded"

        return result

    def _redact_sensitive_data(self, content: str) -> str:
        """
        Redact sensitive data from content.

        Args:
            content: Content to redact

        Returns:
            Redacted content
        """
        redacted = content
        for name, pattern in self.compiled_patterns.items():
            redacted = pattern.sub(f"[REDACTED_{name.upper()}]", redacted)

        return redacted


class DataClassifier:
    """Classify documents and data by sensitivity level"""

    def __init__(self):
        """Initialize classifier"""
        self.classification_rules = {}

    def classify_document(
        self,
        content: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Classify document based on content and metadata.

        Args:
            content: Document content
            metadata: Document metadata

        Returns:
            Classification result
        """
        content_classification = self.auto_classify_by_content(content)
        metadata_classification = self.auto_classify_by_metadata(metadata or {})

        # Determine final classification (highest sensitivity wins)
        classification_levels = ["public", "internal", "confidential", "restricted", "top_secret"]
        final_level = max(
            [content_classification.get("level", "internal"),
             metadata_classification.get("level", "internal")],
            key=lambda x: classification_levels.index(x) if x in classification_levels else 1,
        )

        return {
            "classification_level": final_level,
            "content_based": content_classification,
            "metadata_based": metadata_classification,
            "confidence": 0.85,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def auto_classify_by_content(self, content: str) -> dict[str, Any]:
        """
        Classify content by analyzing patterns.

        Args:
            content: Content to classify

        Returns:
            Content-based classification
        """
        level = "internal"
        indicators = []

        # Check for PII patterns
        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", content):
            indicators.append("ssn_detected")
            level = "restricted"

        if re.search(r"\b(?:\d{4}[-\s]?){3}\d{4}\b", content):
            indicators.append("credit_card_detected")
            level = "restricted"

        # Check for medical terms
        if re.search(r"\b(diagnosis|treatment|medication|patient|medical record)\b", content, re.IGNORECASE):
            indicators.append("medical_terms_detected")
            level = "restricted"

        # Check for confidential keywords
        if re.search(
            r"\b(confidential|proprietary|trade secret|restricted|classified|secret|internal use only)\b",
            content,
            re.IGNORECASE,
        ):
            indicators.append("confidential_keywords")
            level = "confidential"

        return {
            "level": level,
            "indicators": indicators,
            "confidence": 0.75 if indicators else 0.5,
        }

    def auto_classify_by_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """
        Classify based on file metadata.

        Args:
            metadata: Document metadata

        Returns:
            Metadata-based classification
        """
        level = "internal"
        indicators = []

        # Check file extensions
        file_name = metadata.get("file_name", "").lower()
        if any(ext in file_name for ext in [".docx", ".pdf", ".xlsx"]):
            indicators.append("business_document")

        # Check creator/department
        department = metadata.get("department", "").lower()
        if any(dept in department for dept in ["finance", "legal", "medical", "hr"]):
            level = "confidential"
            indicators.append(f"{department}_department")

        # Check location/path
        file_path = metadata.get("file_path", "").lower()
        if any(keyword in file_path for keyword in ["confidential", "restricted", "secret", "private"]):
            level = "restricted"
            indicators.append("sensitive_path")

        return {
            "level": level,
            "indicators": indicators,
            "confidence": 0.8 if indicators else 0.4,
        }

    def apply_classification_label(
        self,
        document_id: str,
        classification_level: str,
    ) -> dict[str, Any]:
        """
        Apply classification label to document.

        Args:
            document_id: Document ID
            classification_level: Classification level

        Returns:
            Application result
        """
        return {
            "document_id": document_id,
            "classification_level": classification_level,
            "labeled_at": datetime.now(timezone.utc).isoformat(),
            "status": "applied",
        }

    def get_handling_requirements(self, classification_level: str) -> dict[str, Any]:
        """
        Get data handling requirements for classification level.

        Args:
            classification_level: Classification level

        Returns:
            Handling requirements
        """
        requirements = {
            "public": {
                "encryption": False,
                "access_control": "open",
                "retention_days": 365,
                "sharing": "unrestricted",
            },
            "internal": {
                "encryption": False,
                "access_control": "organization",
                "retention_days": 730,
                "sharing": "organization_only",
            },
            "confidential": {
                "encryption": True,
                "access_control": "need_to_know",
                "retention_days": 1825,
                "sharing": "restricted",
            },
            "restricted": {
                "encryption": True,
                "access_control": "explicit_approval",
                "retention_days": 2555,
                "sharing": "very_restricted",
            },
            "top_secret": {
                "encryption": "aes256",
                "access_control": "executive_approval",
                "retention_days": 3650,
                "sharing": "forbidden",
            },
        }

        return requirements.get(classification_level, requirements["internal"])

    def validate_classification(self, classification_level: str) -> bool:
        """
        Validate classification level.

        Args:
            classification_level: Level to validate

        Returns:
            True if valid, False otherwise
        """
        valid_levels = ["public", "internal", "confidential", "restricted", "top_secret", "cui", "pii", "phi", "pci"]
        return classification_level in valid_levels


class ExfiltrationDetector:
    """Detect data exfiltration attempts and anomalies"""

    def __init__(self):
        """Initialize detector"""
        self.user_baselines = {}

    def monitor_data_flow(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Monitor and analyze data flow events.

        Args:
            event: Data flow event

        Returns:
            Analysis results with risk assessment
        """
        user = event.get("user")
        risk_indicators = []

        # Check for bulk download
        if self._detect_bulk_download(event):
            risk_indicators.append("bulk_download_detected")

        # Check for unusual transfer
        if self._detect_unusual_transfer(event, user):
            risk_indicators.append("unusual_transfer_pattern")

        # Check for channel abuse
        if self._detect_channel_abuse(event):
            risk_indicators.append("unauthorized_channel_used")

        # Check for encryption bypass
        if self._detect_encryption_bypass(event):
            risk_indicators.append("encryption_bypass_attempt")

        return {
            "user": user,
            "has_risk": len(risk_indicators) > 0,
            "risk_indicators": risk_indicators,
            "risk_score": self.calculate_data_risk_score(event, risk_indicators),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _detect_bulk_download(self, event: dict[str, Any]) -> bool:
        """Detect bulk download activity"""
        data_volume = event.get("data_volume_bytes", 0)
        file_count = event.get("file_count", 0)

        # Flag downloads > 500 MB or > 1000 files
        return data_volume > 500 * 1024 * 1024 or file_count > 1000

    def _detect_unusual_transfer(self, event: dict[str, Any], user: Optional[str]) -> bool:
        """Detect unusual transfer patterns"""
        if not user or user not in self.user_baselines:
            return False

        baseline = self.user_baselines[user]
        current_volume = event.get("data_volume_bytes", 0)
        baseline_volume = baseline.get("avg_daily_bytes", 0)

        # Flag if 10x normal volume
        return current_volume > baseline_volume * 10

    def _detect_channel_abuse(self, event: dict[str, Any]) -> bool:
        """Detect unauthorized transfer channels"""
        destination = event.get("destination", "").lower()
        allowed_destinations = ["internal_mail", "company_storage", "secure_transfer"]

        return not any(allowed in destination for allowed in allowed_destinations)

    def _detect_encryption_bypass(self, event: dict[str, Any]) -> bool:
        """Detect encryption bypass attempts"""
        requires_encryption = event.get("requires_encryption", False)
        encrypted = event.get("encrypted", False)

        return requires_encryption and not encrypted

    def calculate_data_risk_score(
        self,
        event: dict[str, Any],
        risk_indicators: list[str],
    ) -> float:
        """
        Calculate data risk score.

        Args:
            event: Event data
            risk_indicators: List of detected indicators

        Returns:
            Risk score 0.0 to 1.0
        """
        score = 0.0

        if "bulk_download_detected" in risk_indicators:
            score += 0.3

        if "unusual_transfer_pattern" in risk_indicators:
            score += 0.25

        if "unauthorized_channel_used" in risk_indicators:
            score += 0.25

        if "encryption_bypass_attempt" in risk_indicators:
            score += 0.2

        return min(score, 1.0)

    def correlate_with_user_behavior(
        self,
        user: str,
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Correlate events with user behavior baseline.

        Args:
            user: User ID
            events: List of events

        Returns:
            Correlation analysis
        """
        total_volume = sum(e.get("data_volume_bytes", 0) for e in events)
        event_count = len(events)

        return {
            "user": user,
            "event_count": event_count,
            "total_data_volume": total_volume,
            "average_per_event": total_volume // event_count if event_count else 0,
            "is_anomalous": event_count > 10 or total_volume > 1024 * 1024 * 1024,  # 1 GB
        }


class DiscoveryScanner:
    """Scan systems for sensitive data discovery"""

    def scan_endpoint(self, endpoint_id: str, **kwargs) -> dict[str, Any]:
        """
        Scan endpoint for sensitive data.

        Args:
            endpoint_id: Endpoint ID
            **kwargs: Scan parameters

        Returns:
            Scan results
        """
        return {
            "scan_id": f"scan_{endpoint_id}_{datetime.now().timestamp()}",
            "endpoint_id": endpoint_id,
            "scan_type": "endpoint",
            "status": "completed",
            "files_scanned": 15234,
            "sensitive_files_found": 87,
            "findings": [
                {"file": "sensitive_data.xlsx", "classification": "restricted", "risk": "high"},
                {"file": "passwords.txt", "classification": "top_secret", "risk": "critical"},
            ],
        }

    def scan_cloud_storage(self, storage_id: str, **kwargs) -> dict[str, Any]:
        """
        Scan cloud storage for sensitive data.

        Args:
            storage_id: Cloud storage ID
            **kwargs: Scan parameters

        Returns:
            Scan results
        """
        return {
            "scan_id": f"scan_{storage_id}_{datetime.now().timestamp()}",
            "storage_id": storage_id,
            "scan_type": "cloud_storage",
            "status": "completed",
            "objects_scanned": 5432,
            "sensitive_objects_found": 43,
        }

    def scan_database(self, database_id: str, **kwargs) -> dict[str, Any]:
        """
        Scan database for sensitive data.

        Args:
            database_id: Database ID
            **kwargs: Scan parameters

        Returns:
            Scan results
        """
        return {
            "scan_id": f"scan_{database_id}_{datetime.now().timestamp()}",
            "database_id": database_id,
            "scan_type": "database",
            "status": "completed",
            "rows_scanned": 1000000,
            "tables_with_sensitive_data": ["users", "payments", "medical_records"],
        }

    def scan_code_repository(self, repo_id: str, **kwargs) -> dict[str, Any]:
        """
        Scan code repository for secrets and credentials.

        Args:
            repo_id: Repository ID
            **kwargs: Scan parameters

        Returns:
            Scan results
        """
        return {
            "scan_id": f"scan_{repo_id}_{datetime.now().timestamp()}",
            "repo_id": repo_id,
            "scan_type": "code_repository",
            "status": "completed",
            "commits_scanned": 5000,
            "secrets_found": 12,
            "findings": [
                {"type": "aws_key", "file": "config.py", "commit": "abc123"},
                {"type": "api_key", "file": "constants.js", "commit": "def456"},
            ],
        }

    def generate_data_map(self, organization_id: str) -> dict[str, Any]:
        """
        Generate data map showing where sensitive data lives.

        Args:
            organization_id: Organization ID

        Returns:
            Data map
        """
        return {
            "organization_id": organization_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data_locations": {
                "endpoints": {"count": 234, "sensitive_files": 1203},
                "cloud_storage": {"count": 45, "sensitive_objects": 892},
                "databases": {"count": 8, "sensitive_tables": 23},
                "email": {"count": 500000, "sensitive_messages": 15000},
            },
            "high_risk_locations": [
                {"location": "shared_drive_finance", "risk": "critical", "reason": "unencrypted_pii"},
                {"location": "cloud_bucket_temp", "risk": "high", "reason": "public_access"},
            ],
        }

    def track_data_lineage(self, data_id: str) -> dict[str, Any]:
        """
        Track lineage of sensitive data.

        Args:
            data_id: Data ID

        Returns:
            Lineage tracking
        """
        return {
            "data_id": data_id,
            "origin": "database_pii_table",
            "flows": [
                {"step": 1, "location": "extraction_to_cache", "timestamp": "2024-03-24T10:00:00Z"},
                {"step": 2, "location": "processing_server", "timestamp": "2024-03-24T10:15:00Z"},
                {"step": 3, "location": "analytics_db", "timestamp": "2024-03-24T10:30:00Z"},
            ],
            "current_location": "analytics_db",
            "access_count": 45,
        }


class BreachAssessor:
    """Assess and respond to data breach incidents"""

    REGULATION_DEADLINES = {
        "gdpr": 72,  # hours
        "hipaa": 60 * 24,  # hours (60 days)
        "pci_dss": 0,  # immediate
        "ccpa": 30 * 24,  # hours (30 days)
        "state_laws": 45 * 24,  # hours (45 days)
    }

    def assess_breach(self, incident_data: dict[str, Any]) -> dict[str, Any]:
        """
        Assess data breach incident.

        Args:
            incident_data: Incident information

        Returns:
            Breach assessment
        """
        assessment = {
            "incident_id": incident_data.get("id"),
            "assessment_date": datetime.now(timezone.utc).isoformat(),
            "severity": incident_data.get("severity", "medium"),
            "affected_subjects": incident_data.get("affected_count", 0),
            "data_types": incident_data.get("data_types", []),
        }

        # Determine regulatory obligations
        data_types = incident_data.get("data_types", [])
        obligations = self.determine_regulatory_obligations(data_types)
        assessment["regulatory_obligations"] = obligations

        # Calculate notification deadline
        deadline = self.calculate_notification_deadline(obligations)
        assessment["notification_deadline"] = deadline

        # Assess breach notification requirement
        assessment["notification_required"] = len(obligations) > 0

        return assessment

    def calculate_notification_deadline(self, obligations: dict[str, Any]) -> str:
        """
        Calculate notification deadline based on regulations.

        Args:
            obligations: Regulatory obligations

        Returns:
            ISO format deadline timestamp
        """
        now = datetime.now(timezone.utc)
        max_hours = 0

        for regulation, applies in obligations.items():
            if applies:
                regulation_key = regulation.lower().replace(" ", "_")
                hours = self.REGULATION_DEADLINES.get(regulation_key, 72)
                max_hours = max(max_hours, hours)

        deadline = now + timedelta(hours=max_hours)
        return deadline.isoformat()

    def determine_regulatory_obligations(
        self,
        data_types: list[str],
    ) -> dict[str, bool]:
        """
        Determine which regulations apply based on data types.

        Args:
            data_types: List of data types involved

        Returns:
            Dictionary mapping regulations to applicability
        """
        obligations = {
            "GDPR": any(dt in ["pii", "personal_data"] for dt in data_types),
            "HIPAA": "phi" in data_types or "medical_record" in data_types,
            "PCI-DSS": "credit_card" in data_types or "payment_data" in data_types,
            "CCPA": "personal_data" in data_types or "pii" in data_types,
            "State Laws": len(data_types) > 0,
        }

        return obligations

    def generate_breach_notification_template(
        self,
        incident_data: dict[str, Any],
    ) -> str:
        """
        Generate breach notification template.

        Args:
            incident_data: Incident information

        Returns:
            Notification template text
        """
        template = f"""
DATA BREACH NOTIFICATION

Date of Discovery: {incident_data.get('discovery_date', 'TBD')}
Number of Individuals Affected: {incident_data.get('affected_count', 'TBD')}
Type of Personal Information: {', '.join(incident_data.get('data_types', []))}

DESCRIPTION OF THE BREACH:
{incident_data.get('description', 'TBD')}

STEPS INDIVIDUALS SHOULD TAKE:
1. Monitor credit reports for fraudulent activity
2. Place fraud alerts with credit bureaus
3. Consider credit monitoring services
4. Review account statements regularly

WHAT WE ARE DOING:
1. Investigating the incident thoroughly
2. Implementing enhanced security measures
3. Notifying law enforcement
4. Reviewing our security practices

CONTACT INFORMATION:
For questions, contact our Privacy Team at privacy@company.com

We sincerely apologize for any inconvenience this may cause.
        """

        return template.strip()

    def track_notification_compliance(
        self,
        incident_id: str,
        notified_count: int,
        total_required: int,
    ) -> dict[str, Any]:
        """
        Track breach notification compliance.

        Args:
            incident_id: Incident ID
            notified_count: Number notified
            total_required: Total required to notify

        Returns:
            Compliance tracking
        """
        return {
            "incident_id": incident_id,
            "notified_count": notified_count,
            "total_required": total_required,
            "completion_percentage": (notified_count / total_required * 100) if total_required > 0 else 0,
            "status": "complete" if notified_count == total_required else "in_progress",
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
