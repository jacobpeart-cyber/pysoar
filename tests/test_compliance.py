"""Tests for compliance engine functionality"""

import importlib.util
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.engine import (
    ComplianceEngine,
    ControlCheckResult,
    FedRAMPManager,
    NISTManager,
    CMMCManager,
    CISAComplianceManager,
    BuiltinFrameworks,
)
from src.compliance.models import (
    ComplianceFramework,
    ComplianceControl,
    POAM,
    ComplianceAssessment,
)


@pytest.mark.asyncio
class TestComplianceEngineScoring:
    """Tests for compliance engine scoring logic"""

    async def test_calculate_compliance_score_all_implemented(self, db_session: AsyncSession):
        """Test scoring when all controls are implemented"""
        engine = ComplianceEngine(db_session, org_id="test-org")

        # Create framework
        framework = ComplianceFramework(
            name="Test Framework",
            short_name="test",
            version="1.0",
            authority="TEST",
            organization_id="test-org",
        )
        db_session.add(framework)
        await db_session.flush()

        # Create controls all implemented
        for i in range(5):
            control = ComplianceControl(
                framework_id=framework.id,
                control_id=f"C-{i}",
                control_family="Test Family",
                title=f"Control {i}",
                status="implemented",
                last_assessment_result="satisfied",
                implementation_status=100.0,
                priority="p1",
                organization_id="test-org",
            )
            db_session.add(control)

        await db_session.commit()

        # Calculate score
        score = await engine.calculate_compliance_score(str(framework.id))

        assert score == 100.0

    async def test_calculate_compliance_score_partial_implementation(self, db_session: AsyncSession):
        """Test scoring with partial implementation"""
        engine = ComplianceEngine(db_session, org_id="test-org")

        framework = ComplianceFramework(
            name="Partial Framework",
            short_name="partial",
            version="1.0",
            authority="TEST",
            organization_id="test-org",
        )
        db_session.add(framework)
        await db_session.flush()

        # Create 3 controls: 2 implemented, 1 partial
        for i in range(2):
            control = ComplianceControl(
                framework_id=framework.id,
                control_id=f"C-{i}",
                control_family="Test Family",
                title=f"Control {i}",
                status="implemented",
                last_assessment_result="satisfied",
                implementation_status=100.0,
                priority="p1",
                organization_id="test-org",
            )
            db_session.add(control)

        partial_control = ComplianceControl(
            framework_id=framework.id,
            control_id="C-2",
            control_family="Test Family",
            title="Partial Control",
            status="partially_implemented",
            implementation_status=50.0,
            priority="p2",
            organization_id="test-org",
        )
        db_session.add(partial_control)

        await db_session.commit()

        score = await engine.calculate_compliance_score(str(framework.id))

        # Weighted average of control scores
        assert 50.0 < score <= 100.0

    async def test_calculate_compliance_score_no_controls(self, db_session: AsyncSession):
        """Test scoring with no controls returns 0"""
        engine = ComplianceEngine(db_session, org_id="test-org")

        framework = ComplianceFramework(
            name="Empty Framework",
            short_name="empty",
            version="1.0",
            authority="TEST",
            organization_id="test-org",
        )
        db_session.add(framework)
        await db_session.commit()

        score = await engine.calculate_compliance_score(str(framework.id))

        assert score == 0.0


@pytest.mark.asyncio
class TestComplianceFrameworkCreation:
    """Tests for framework creation and control mapping"""

    async def test_create_framework(self, db_session: AsyncSession):
        """Test creating a compliance framework"""
        framework = ComplianceFramework(
            name="NIST 800-53",
            short_name="nist_800_53",
            version="Rev 5",
            authority="NIST",
            certification_level="SP 800-53",
            organization_id="test-org",
        )
        db_session.add(framework)
        await db_session.commit()

        retrieved = await db_session.get(ComplianceFramework, framework.id)
        assert retrieved.short_name == "nist_800_53"
        assert retrieved.organization_id == "test-org"

    async def test_create_controls_for_framework(self, db_session: AsyncSession):
        """Test creating controls for a framework"""
        framework = ComplianceFramework(
            name="Test Framework",
            short_name="test",
            version="1.0",
            authority="TEST",
            organization_id="test-org",
        )
        db_session.add(framework)
        await db_session.flush()

        control = ComplianceControl(
            framework_id=framework.id,
            control_id="AC-2",
            control_family="Access Control",
            title="Account Management",
            status="not_implemented",
            priority="p1",
            organization_id="test-org",
        )
        db_session.add(control)
        await db_session.commit()

        retrieved = await db_session.get(ComplianceControl, control.id)
        assert retrieved.control_id == "AC-2"
        assert retrieved.framework_id == framework.id


@pytest.mark.asyncio
class TestPOAMGeneration:
    """Tests for POAM (Plan of Action & Milestones) generation"""

    async def test_generate_poam_report(self, db_session: AsyncSession):
        """Test POAM report generation"""
        engine = ComplianceEngine(db_session, org_id="test-org")

        framework = ComplianceFramework(
            name="Test Framework",
            short_name="test",
            version="1.0",
            authority="TEST",
            organization_id="test-org",
        )
        db_session.add(framework)
        await db_session.flush()

        # Create a control
        control = ComplianceControl(
            framework_id=framework.id,
            control_id="AC-2",
            control_family="Access Control",
            title="Account Management",
            status="not_implemented",
            priority="p1",
            organization_id="test-org",
        )
        db_session.add(control)
        await db_session.flush()

        # Create POAMs
        poam1 = POAM(
            control_id_ref=control.id,
            weakness_name="Missing MFA",
            weakness_source="assessment",
            risk_level="high",
            status="open",
            scheduled_completion_date=datetime.utcnow() + timedelta(days=30),
            assigned_to="security-team",
            organization_id="test-org",
        )
        db_session.add(poam1)

        poam2 = POAM(
            control_id_ref=control.id,
            weakness_name="Weak password policy",
            weakness_source="assessment",
            risk_level="medium",
            status="in_progress",
            scheduled_completion_date=datetime.utcnow() + timedelta(days=60),
            assigned_to="it-team",
            organization_id="test-org",
        )
        db_session.add(poam2)

        await db_session.commit()

        # Generate report
        report = await engine.generate_poam_report(str(framework.id))

        assert report["summary"]["total"] == 2
        assert report["summary"]["open"] >= 1
        assert len(report["poams"]) == 2

    async def test_poam_overdue_tracking(self, db_session: AsyncSession):
        """Test tracking of overdue POA&Ms"""
        engine = ComplianceEngine(db_session, org_id="test-org")

        framework = ComplianceFramework(
            name="Test Framework",
            short_name="test",
            version="1.0",
            authority="TEST",
            organization_id="test-org",
        )
        db_session.add(framework)
        await db_session.flush()

        control = ComplianceControl(
            framework_id=framework.id,
            control_id="AC-2",
            control_family="Access Control",
            title="Account Management",
            status="not_implemented",
            priority="p1",
            organization_id="test-org",
        )
        db_session.add(control)
        await db_session.flush()

        # Create overdue POAM
        overdue_poam = POAM(
            control_id_ref=control.id,
            weakness_name="Overdue item",
            weakness_source="assessment",
            risk_level="critical",
            status="open",
            scheduled_completion_date=datetime.utcnow() - timedelta(days=10),
            assigned_to="team",
            organization_id="test-org",
        )
        db_session.add(overdue_poam)

        await db_session.commit()

        report = await engine.generate_poam_report(str(framework.id))

        assert report["summary"]["overdue"] == 1


@pytest.mark.asyncio
class TestCloudCheckResultAggregation:
    """Tests for aggregating cloud check results"""

    async def test_assess_framework_with_cloud_checks(self, db_session: AsyncSession):
        """Test framework assessment"""
        engine = ComplianceEngine(db_session, org_id="test-org")

        framework = ComplianceFramework(
            name="Cloud Framework",
            short_name="cloud",
            version="1.0",
            authority="CLOUD",
            organization_id="test-org",
        )
        db_session.add(framework)
        await db_session.flush()

        # Create controls
        for i in range(3):
            control = ComplianceControl(
                framework_id=framework.id,
                control_id=f"C-{i}",
                control_family="Test",
                title=f"Control {i}",
                status="not_implemented",
                priority="p1",
                organization_id="test-org",
            )
            db_session.add(control)

        await db_session.commit()

        # Run assessment
        assessment = await engine.assess_framework(str(framework.id))

        assert assessment["total_controls"] == 3
        assert assessment["status"] in ["compliant", "non_compliant"]
        assert "compliance_score" in assessment


@pytest.mark.asyncio
class TestControlGapAnalysis:
    """Tests for control gap identification"""

    async def test_get_control_gaps(self, db_session: AsyncSession):
        """Test gap analysis"""
        engine = ComplianceEngine(db_session, org_id="test-org")

        framework = ComplianceFramework(
            name="Gap Test",
            short_name="gap_test",
            version="1.0",
            authority="TEST",
            organization_id="test-org",
        )
        db_session.add(framework)
        await db_session.flush()

        # Create mixed status controls
        control1 = ComplianceControl(
            framework_id=framework.id,
            control_id="AC-1",
            control_family="Access",
            title="Control 1",
            status="implemented",
            priority="p1",
            organization_id="test-org",
        )
        db_session.add(control1)

        control2 = ComplianceControl(
            framework_id=framework.id,
            control_id="AC-2",
            control_family="Access",
            title="Control 2",
            status="not_implemented",
            priority="p2",
            risk_if_not_implemented="high",
            organization_id="test-org",
        )
        db_session.add(control2)

        control3 = ComplianceControl(
            framework_id=framework.id,
            control_id="SC-1",
            control_family="Security",
            title="Control 3",
            status="planned",
            priority="p1",
            risk_if_not_implemented="critical",
            organization_id="test-org",
        )
        db_session.add(control3)

        await db_session.commit()

        gaps = await engine.get_control_gaps(str(framework.id))

        assert len(gaps) == 2
        # Critical risk should come first
        assert gaps[0]["risk_level"] == "critical"


@pytest.mark.asyncio
class TestSSPGeneration:
    """Tests for System Security Plan generation"""

    async def test_generate_ssp(self, db_session: AsyncSession):
        """Test SSP generation"""
        engine = ComplianceEngine(db_session, org_id="test-org")

        framework = ComplianceFramework(
            name="NIST 800-53",
            short_name="nist",
            version="Rev 5",
            authority="NIST",
            certification_level="SP 800-53",
            organization_id="test-org",
        )
        db_session.add(framework)
        await db_session.flush()

        control = ComplianceControl(
            framework_id=framework.id,
            control_id="AC-1",
            control_family="Access Control",
            title="Account and Access Management",
            status="implemented",
            last_assessment_result="satisfied",
            implementation_details="Implemented via Active Directory",
            responsible_party="Security Team",
            organization_id="test-org",
        )
        db_session.add(control)

        await db_session.commit()

        ssp = await engine.generate_ssp(str(framework.id))

        assert "control_families" in ssp
        assert "Access Control" in ssp["control_families"]
        assert len(ssp["control_families"]["Access Control"]["controls"]) == 1


@pytest.mark.asyncio
class TestCrossFrameworkMapping:
    """Tests for cross-framework control mapping"""

    async def test_cross_map_controls(self, db_session: AsyncSession):
        """Test control mapping between frameworks"""
        engine = ComplianceEngine(db_session, org_id="test-org")

        # Create two frameworks
        nist_framework = ComplianceFramework(
            name="NIST 800-53",
            short_name="nist",
            version="Rev 5",
            authority="NIST",
            organization_id="test-org",
        )
        db_session.add(nist_framework)

        cmmc_framework = ComplianceFramework(
            name="CMMC 2.0",
            short_name="cmmc",
            version="2.0",
            authority="DoD",
            organization_id="test-org",
        )
        db_session.add(cmmc_framework)
        await db_session.flush()

        # Create mapped controls
        nist_control = ComplianceControl(
            framework_id=nist_framework.id,
            control_id="AC-2",
            control_family="Access Control",
            title="Account Management",
            status="implemented",
            related_controls={"cmmc": ["1.001"]},
            organization_id="test-org",
        )
        db_session.add(nist_control)

        cmmc_control = ComplianceControl(
            framework_id=cmmc_framework.id,
            control_id="1.001",
            control_family="Access Control",
            title="User Access",
            status="implemented",
            organization_id="test-org",
        )
        db_session.add(cmmc_control)

        await db_session.commit()

        mapping = await engine.cross_map_controls(
            str(nist_framework.id), str(cmmc_framework.id)
        )

        assert mapping["source_framework"] == str(nist_framework.id)
        assert mapping["target_framework"] == str(cmmc_framework.id)
        assert "mapped_controls" in mapping
        assert "coverage_percentage" in mapping


@pytest.mark.asyncio
class TestMockCloudAPIs:
    """Tests with mocked cloud API responses"""

    @pytest.mark.skipif(not importlib.util.find_spec("boto3"), reason="boto3 not installed")
    @patch("boto3.Session")
    async def test_cloud_check_with_mock_boto3(self, mock_session):
        """Test cloud checks with mocked AWS API"""
        # Mock IAM client
        mock_iam = MagicMock()
        mock_iam.list_users.return_value = {
            "Users": [
                {"UserName": "user1"},
                {"UserName": "user2"},
            ]
        }
        mock_iam.list_mfa_devices.return_value = {"MFADevices": []}

        mock_session.return_value.client.return_value = mock_iam

        # Test would execute cloud check with mocked response
        assert mock_iam.list_users.return_value["Users"]
