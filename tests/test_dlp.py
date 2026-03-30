"""Tests for DLP (Data Loss Prevention) Engine

Real tests importing and testing actual DLP engine classes.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from src.dlp.engine import (
    DLPEngine,
    DataClassifier,
    ExfiltrationDetector,
    DiscoveryScanner,
    BreachAssessor,
)


@pytest.fixture
def dlp_engine():
    """Create DLP engine instance"""
    return DLPEngine()


@pytest.fixture
def data_classifier():
    """Create data classifier instance"""
    return DataClassifier()


@pytest.fixture
def exfiltration_detector():
    """Create exfiltration detector instance"""
    return ExfiltrationDetector()


@pytest.fixture
def discovery_scanner():
    """Create discovery scanner instance"""
    return DiscoveryScanner()


@pytest.fixture
def breach_assessor():
    """Create breach assessor instance"""
    return BreachAssessor()


class TestDLPEngine:
    """Tests for DLPEngine class"""

    def test_engine_initialization(self, dlp_engine):
        """Test DLP engine initializes correctly"""
        assert dlp_engine is not None
        assert hasattr(dlp_engine, 'compiled_patterns')
        assert len(dlp_engine.compiled_patterns) > 0

    def test_detect_ssn(self, dlp_engine):
        """Test detecting SSN in content"""
        content = "Employee SSN: 123-45-6789"
        results = dlp_engine.detect_sensitive_data(content)
        assert "ssn" in results
        assert "123-45-6789" in results["ssn"]

    def test_detect_credit_card(self, dlp_engine):
        """Test detecting credit card numbers"""
        content = "Card: 4532-0151-1283-0366"
        results = dlp_engine.detect_sensitive_data(content)
        assert "credit_card" in results

    def test_detect_email(self, dlp_engine):
        """Test detecting email addresses"""
        content = "Contact john.doe@example.com for details"
        results = dlp_engine.detect_sensitive_data(content)
        assert "email" in results
        assert any("john.doe@example.com" in str(e) for e in results["email"])

    def test_detect_api_key(self, dlp_engine):
        """Test detecting API keys"""
        content = "api_key='sk_live_1234567890abcdefghij'"
        results = dlp_engine.detect_sensitive_data(content)
        assert "api_key" in results

    def test_detect_aws_key(self, dlp_engine):
        """Test detecting AWS keys"""
        content = "AKIAIOSFODNN7EXAMPLE"
        results = dlp_engine.detect_sensitive_data(content)
        assert "aws_key" in results

    def test_detect_multiple_sensitive_types(self, dlp_engine):
        """Test detecting multiple sensitive data types"""
        content = "Name: John, SSN: 123-45-6789, Email: john@example.com, Card: 4532-0151-1283-0366"
        results = dlp_engine.detect_sensitive_data(content)
        assert len(results) >= 3

    def test_evaluate_content_no_violations(self, dlp_engine):
        """Test evaluating content with no violations"""
        content = "This is normal business text with no sensitive data"
        result = dlp_engine.evaluate_content(content)
        assert result["has_violations"] is False
        assert len(result["violations"]) == 0
        assert result["risk_score"] == 0.0

    def test_evaluate_content_with_sensitive_data(self, dlp_engine):
        """Test evaluating content with sensitive data"""
        content = "SSN: 123-45-6789"
        result = dlp_engine.evaluate_content(content)
        assert result["has_violations"] is True
        assert len(result["violations"]) > 0
        assert result["risk_score"] > 0.0

    def test_evaluate_with_exfiltration_context(self, dlp_engine):
        """Test evaluating with exfiltration risk context"""
        content = "Data transfer"
        context = {
            "destination": "gmail.com",
            "data_volume_bytes": 200 * 1024 * 1024,  # 200 MB
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        result = dlp_engine.evaluate_content(content, context)
        assert result["has_violations"] is True

    def test_evaluate_with_off_hours_activity(self, dlp_engine):
        """Test detecting off-hours exfiltration risk"""
        content = "Data"
        context = {
            "destination": "personal.email.com",
            "data_volume_bytes": 10 * 1024 * 1024,
            "timestamp": datetime.now(timezone.utc).replace(hour=3).isoformat(),
        }
        result = dlp_engine.evaluate_content(content, context)
        violations = result.get("violations", [])
        assert any(v.get("type") == "exfiltration_risk" for v in violations)

    def test_create_violation_record(self, dlp_engine):
        """Test creating a violation record"""
        violation = dlp_engine.create_violation(
            policy_id="policy_123",
            violation_type="unauthorized_transfer",
            source_user="john@company.com",
            destination="gmail.com",
            data_classification="restricted",
            sensitive_data_types=["ssn", "email"],
            organization_id="org_123",
            action_taken="blocked",
            severity="high",
        )
        assert violation["policy_id"] == "policy_123"
        assert violation["source_user"] == "john@company.com"
        assert violation["organization_id"] == "org_123"

    def test_enforce_redaction(self, dlp_engine):
        """Test enforcing redaction action"""
        content = "SSN: 123-45-6789"
        result = dlp_engine.enforce_policy_action("redacted", content)
        assert result["action"] == "redacted"
        assert "REDACTED" in result.get("modified_content", "")

    def test_enforce_block(self, dlp_engine):
        """Test enforcing block action"""
        result = dlp_engine.enforce_policy_action("blocked", "content")
        assert result["action"] == "blocked"
        assert result["status"] == "applied"

    def test_enforce_quarantine(self, dlp_engine):
        """Test enforcing quarantine action"""
        result = dlp_engine.enforce_policy_action("quarantined", "content")
        assert result["action"] == "quarantined"
        assert "quarantined" in result["message"].lower()

    def test_enforce_encryption(self, dlp_engine):
        """Test enforcing encryption action"""
        result = dlp_engine.enforce_policy_action("encrypted", "content")
        assert result["action"] == "encrypted"
        assert result["status"] == "applied"

    def test_redact_sensitive_data(self, dlp_engine):
        """Test redaction of multiple sensitive types"""
        content = "SSN: 123-45-6789, Email: john@example.com, AWS: AKIAIOSFODNN7EXAMPLE"
        redacted = dlp_engine._redact_sensitive_data(content)
        assert "[REDACTED" in redacted
        assert "123-45-6789" not in redacted
        assert "john@example.com" not in redacted


class TestDataClassifier:
    """Tests for DataClassifier class"""

    def test_classifier_initialization(self, data_classifier):
        """Test classifier initializes correctly"""
        assert data_classifier is not None

    def test_classify_document_with_ssn(self, data_classifier):
        """Test classifying document with SSN"""
        content = "Employee SSN: 123-45-6789"
        result = data_classifier.classify_document(content)
        assert result["classification_level"] == "restricted"
        assert "ssn_detected" in result["content_based"]["indicators"]

    def test_classify_document_with_credit_card(self, data_classifier):
        """Test classifying document with credit card"""
        content = "Card: 4532-0151-1283-0366"
        result = data_classifier.classify_document(content)
        assert result["classification_level"] == "restricted"

    def test_classify_document_with_medical_terms(self, data_classifier):
        """Test classifying document with medical information"""
        content = "Patient diagnosis: Type 2 Diabetes, treatment: metformin"
        result = data_classifier.classify_document(content)
        assert result["classification_level"] == "restricted"
        assert "medical_terms_detected" in result["content_based"]["indicators"]

    def test_classify_document_with_confidential_keywords(self, data_classifier):
        """Test classifying document with confidential keywords"""
        content = "This is CONFIDENTIAL company proprietary information"
        result = data_classifier.classify_document(content)
        assert result["classification_level"] in ["confidential", "restricted"]

    def test_classify_document_public(self, data_classifier):
        """Test classifying public document"""
        content = "Public announcement about company benefits"
        result = data_classifier.classify_document(content)
        assert result["classification_level"] == "internal"

    def test_auto_classify_by_content(self, data_classifier):
        """Test auto-classification by content"""
        content = "SSN: 123-45-6789"
        result = data_classifier.auto_classify_by_content(content)
        assert result["level"] == "restricted"
        assert result["confidence"] > 0

    def test_auto_classify_by_metadata_finance(self, data_classifier):
        """Test classification by finance department metadata"""
        metadata = {
            "file_name": "financial_report.xlsx",
            "department": "finance",
        }
        result = data_classifier.auto_classify_by_metadata(metadata)
        assert result["level"] == "confidential"
        assert "finance_department" in result["indicators"]

    def test_auto_classify_by_metadata_legal(self, data_classifier):
        """Test classification by legal department metadata"""
        metadata = {
            "file_name": "contract.docx",
            "department": "legal",
        }
        result = data_classifier.auto_classify_by_metadata(metadata)
        assert result["level"] == "confidential"

    def test_auto_classify_by_sensitive_path(self, data_classifier):
        """Test classification by file path"""
        metadata = {
            "file_name": "data.xlsx",
            "file_path": "/restricted/documents/file.xlsx",
        }
        result = data_classifier.auto_classify_by_metadata(metadata)
        assert result["level"] == "restricted"
        assert "sensitive_path" in result["indicators"]

    def test_apply_classification_label(self, data_classifier):
        """Test applying classification label to document"""
        result = data_classifier.apply_classification_label(
            "doc_123",
            "confidential"
        )
        assert result["document_id"] == "doc_123"
        assert result["classification_level"] == "confidential"
        assert result["status"] == "applied"

    def test_get_handling_requirements_public(self, data_classifier):
        """Test getting requirements for public data"""
        reqs = data_classifier.get_handling_requirements("public")
        assert reqs["encryption"] is False
        assert reqs["access_control"] == "open"
        assert reqs["sharing"] == "unrestricted"

    def test_get_handling_requirements_restricted(self, data_classifier):
        """Test getting requirements for restricted data"""
        reqs = data_classifier.get_handling_requirements("restricted")
        assert reqs["encryption"] is True
        assert reqs["access_control"] == "explicit_approval"
        assert reqs["sharing"] == "very_restricted"

    def test_get_handling_requirements_topsecret(self, data_classifier):
        """Test getting requirements for top secret data"""
        reqs = data_classifier.get_handling_requirements("top_secret")
        assert reqs["encryption"] == "aes256"
        assert reqs["access_control"] == "executive_approval"
        assert reqs["sharing"] == "forbidden"

    def test_validate_classification_valid(self, data_classifier):
        """Test validating valid classification levels"""
        assert data_classifier.validate_classification("public") is True
        assert data_classifier.validate_classification("restricted") is True
        assert data_classifier.validate_classification("pii") is True

    def test_validate_classification_invalid(self, data_classifier):
        """Test validating invalid classification level"""
        assert data_classifier.validate_classification("unknown") is False


class TestExfiltrationDetector:
    """Tests for ExfiltrationDetector class"""

    def test_detector_initialization(self, exfiltration_detector):
        """Test detector initializes correctly"""
        assert exfiltration_detector is not None
        assert hasattr(exfiltration_detector, 'user_baselines')

    def test_detect_bulk_download(self, exfiltration_detector):
        """Test detecting bulk download"""
        event = {
            "user": "john@example.com",
            "data_volume_bytes": 600 * 1024 * 1024,  # 600 MB
            "file_count": 500,
            "destination": "external_drive",
        }
        result = exfiltration_detector.monitor_data_flow(event)
        assert result["has_risk"] is True
        assert "bulk_download_detected" in result["risk_indicators"]

    def test_detect_unauthorized_channel(self, exfiltration_detector):
        """Test detecting unauthorized transfer channel"""
        event = {
            "user": "john@example.com",
            "data_volume_bytes": 10 * 1024 * 1024,
            "file_count": 5,
            "destination": "personal_dropbox",
            "requires_encryption": False,
            "encrypted": False,
        }
        result = exfiltration_detector.monitor_data_flow(event)
        assert result["has_risk"] is True
        assert "unauthorized_channel_used" in result["risk_indicators"]

    def test_detect_unusual_transfer_pattern(self, exfiltration_detector):
        """Test detecting unusual transfer pattern"""
        exfiltration_detector.user_baselines["john@example.com"] = {
            "avg_daily_bytes": 100 * 1024 * 1024,  # 100 MB
        }
        event = {
            "user": "john@example.com",
            "data_volume_bytes": 1200 * 1024 * 1024,  # 1.2 GB (10x normal)
            "file_count": 50,
            "destination": "internal_storage",
            "requires_encryption": False,
            "encrypted": False,
        }
        result = exfiltration_detector.monitor_data_flow(event)
        assert result["has_risk"] is True
        assert "unusual_transfer_pattern" in result["risk_indicators"]

    def test_detect_encryption_bypass(self, exfiltration_detector):
        """Test detecting encryption bypass"""
        event = {
            "user": "john@example.com",
            "data_volume_bytes": 50 * 1024 * 1024,
            "file_count": 10,
            "destination": "secure_vault",
            "requires_encryption": True,
            "encrypted": False,
        }
        result = exfiltration_detector.monitor_data_flow(event)
        assert result["has_risk"] is True
        assert "encryption_bypass_attempt" in result["risk_indicators"]

    def test_no_risk_event(self, exfiltration_detector):
        """Test event with no risk indicators"""
        event = {
            "user": "john@example.com",
            "data_volume_bytes": 50 * 1024 * 1024,
            "file_count": 10,
            "destination": "internal_mail",
            "requires_encryption": False,
            "encrypted": False,
        }
        result = exfiltration_detector.monitor_data_flow(event)
        assert result["has_risk"] is False
        assert len(result["risk_indicators"]) == 0
        assert result["risk_score"] == 0.0

    def test_calculate_risk_score_single_indicator(self, exfiltration_detector):
        """Test risk score with single indicator"""
        event = {
            "user": "john@example.com",
            "data_volume_bytes": 600 * 1024 * 1024,
            "file_count": 500,
            "destination": "internal",
            "requires_encryption": False,
            "encrypted": False,
        }
        risk_indicators = ["bulk_download_detected"]
        score = exfiltration_detector.calculate_data_risk_score(event, risk_indicators)
        assert score == 0.3

    def test_calculate_risk_score_multiple_indicators(self, exfiltration_detector):
        """Test risk score with multiple indicators"""
        event = {}
        risk_indicators = [
            "bulk_download_detected",
            "unusual_transfer_pattern",
            "unauthorized_channel_used",
        ]
        score = exfiltration_detector.calculate_data_risk_score(event, risk_indicators)
        assert score > 0.3
        assert score <= 1.0

    def test_correlate_with_user_behavior(self, exfiltration_detector):
        """Test correlating events with user baseline"""
        events = [
            {"data_volume_bytes": 100 * 1024 * 1024},
            {"data_volume_bytes": 150 * 1024 * 1024},
            {"data_volume_bytes": 200 * 1024 * 1024},
        ]
        result = exfiltration_detector.correlate_with_user_behavior(
            "john@example.com",
            events
        )
        assert result["user"] == "john@example.com"
        assert result["event_count"] == 3
        assert result["total_data_volume"] == 450 * 1024 * 1024
        assert result["is_anomalous"] is False

    def test_correlate_anomalous_behavior(self, exfiltration_detector):
        """Test detecting anomalous user behavior"""
        events = [
            {"data_volume_bytes": 100 * 1024 * 1024}
            for _ in range(15)  # 15 events
        ]
        result = exfiltration_detector.correlate_with_user_behavior(
            "john@example.com",
            events
        )
        assert result["is_anomalous"] is True


class TestDiscoveryScanner:
    """Tests for DiscoveryScanner class"""

    def test_scanner_initialization(self, discovery_scanner):
        """Test scanner initializes correctly"""
        assert discovery_scanner is not None

    def test_scan_endpoint(self, discovery_scanner):
        """Test scanning endpoint"""
        result = discovery_scanner.scan_endpoint("endpoint_123")
        assert result["endpoint_id"] == "endpoint_123"
        assert result["scan_type"] == "endpoint"
        assert result["status"] == "completed"
        assert result["files_scanned"] > 0
        assert result["sensitive_files_found"] > 0

    def test_scan_cloud_storage(self, discovery_scanner):
        """Test scanning cloud storage"""
        result = discovery_scanner.scan_cloud_storage("storage_123")
        assert result["storage_id"] == "storage_123"
        assert result["scan_type"] == "cloud_storage"
        assert result["status"] == "completed"
        assert result["objects_scanned"] > 0

    def test_scan_database(self, discovery_scanner):
        """Test scanning database"""
        result = discovery_scanner.scan_database("db_123")
        assert result["database_id"] == "db_123"
        assert result["scan_type"] == "database"
        assert result["status"] == "completed"
        assert "tables_with_sensitive_data" in result

    def test_scan_code_repository(self, discovery_scanner):
        """Test scanning code repository"""
        result = discovery_scanner.scan_code_repository("repo_123")
        assert result["repo_id"] == "repo_123"
        assert result["scan_type"] == "code_repository"
        assert result["status"] == "completed"
        assert result["secrets_found"] > 0

    def test_generate_data_map(self, discovery_scanner):
        """Test generating data map"""
        result = discovery_scanner.generate_data_map("org_123")
        assert result["organization_id"] == "org_123"
        assert "data_locations" in result
        assert "high_risk_locations" in result

    def test_track_data_lineage(self, discovery_scanner):
        """Test tracking data lineage"""
        result = discovery_scanner.track_data_lineage("data_123")
        assert result["data_id"] == "data_123"
        assert "origin" in result
        assert "flows" in result
        assert "current_location" in result


class TestBreachAssessor:
    """Tests for BreachAssessor class"""

    def test_assessor_initialization(self, breach_assessor):
        """Test assessor initializes correctly"""
        assert breach_assessor is not None
        assert hasattr(breach_assessor, 'REGULATION_DEADLINES')

    def test_assess_breach_with_pii(self, breach_assessor):
        """Test assessing breach with PII"""
        incident = {
            "id": "breach_001",
            "severity": "high",
            "affected_count": 1000,
            "data_types": ["pii", "personal_data"],
        }
        result = breach_assessor.assess_breach(incident)
        assert result["incident_id"] == "breach_001"
        assert result["affected_subjects"] == 1000
        assert result["notification_required"] is True

    def test_assess_breach_with_phi(self, breach_assessor):
        """Test assessing breach with PHI (medical data)"""
        incident = {
            "id": "breach_002",
            "severity": "critical",
            "affected_count": 5000,
            "data_types": ["phi", "medical_record"],
        }
        result = breach_assessor.assess_breach(incident)
        assert result["notification_required"] is True

    def test_assess_breach_with_credit_cards(self, breach_assessor):
        """Test assessing breach with credit card data"""
        incident = {
            "id": "breach_003",
            "severity": "critical",
            "affected_count": 10000,
            "data_types": ["credit_card", "payment_data"],
        }
        result = breach_assessor.assess_breach(incident)
        assert result["notification_required"] is True

    def test_determine_regulatory_obligations_gdpr(self, breach_assessor):
        """Test determining GDPR obligations"""
        obligations = breach_assessor.determine_regulatory_obligations(["pii"])
        assert obligations["GDPR"] is True
        assert obligations["State Laws"] is True

    def test_determine_regulatory_obligations_hipaa(self, breach_assessor):
        """Test determining HIPAA obligations"""
        obligations = breach_assessor.determine_regulatory_obligations(["phi"])
        assert obligations["HIPAA"] is True

    def test_determine_regulatory_obligations_pci_dss(self, breach_assessor):
        """Test determining PCI-DSS obligations"""
        obligations = breach_assessor.determine_regulatory_obligations(["credit_card"])
        assert obligations["PCI-DSS"] is True

    def test_calculate_notification_deadline_gdpr(self, breach_assessor):
        """Test GDPR 72-hour deadline"""
        obligations = {"GDPR": True}
        deadline_str = breach_assessor.calculate_notification_deadline(obligations)
        deadline = datetime.fromisoformat(deadline_str)
        now = datetime.now(timezone.utc)
        hours_diff = (deadline - now).total_seconds() / 3600
        assert 71 < hours_diff < 73

    def test_calculate_notification_deadline_hipaa(self, breach_assessor):
        """Test HIPAA notification deadline"""
        obligations = {"HIPAA": True}
        deadline_str = breach_assessor.calculate_notification_deadline(obligations)
        deadline = datetime.fromisoformat(deadline_str)
        now = datetime.now(timezone.utc)
        days_diff = (deadline - now).total_seconds() / (3600 * 24)
        assert 59 < days_diff < 61

    def test_generate_breach_notification_template(self, breach_assessor):
        """Test generating breach notification template"""
        incident = {
            "discovery_date": "2024-03-24",
            "affected_count": 1000,
            "data_types": ["pii", "email"],
            "description": "Unauthorized access to user database",
        }
        template = breach_assessor.generate_breach_notification_template(incident)
        assert "DATA BREACH NOTIFICATION" in template
        assert "1000" in template
        assert "pii" in template.lower() or "email" in template

    def test_track_notification_compliance_complete(self, breach_assessor):
        """Test tracking complete notification"""
        result = breach_assessor.track_notification_compliance(
            "breach_001",
            notified_count=1000,
            total_required=1000
        )
        assert result["incident_id"] == "breach_001"
        assert result["completion_percentage"] == 100.0
        assert result["status"] == "complete"

    def test_track_notification_compliance_in_progress(self, breach_assessor):
        """Test tracking in-progress notification"""
        result = breach_assessor.track_notification_compliance(
            "breach_001",
            notified_count=500,
            total_required=1000
        )
        assert result["completion_percentage"] == 50.0
        assert result["status"] == "in_progress"
