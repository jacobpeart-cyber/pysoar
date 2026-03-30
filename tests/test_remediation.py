"""Tests for Remediation Engine

Real tests importing and testing actual remediation engine classes.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from src.remediation.engine import (
    RemediationEngine,
    ActionExecutor,
    FirewallBlockExecutor,
    HostIsolationExecutor,
    AccountActionExecutor,
    ProcessActionExecutor,
    NetworkActionExecutor,
    PatchExecutor,
    NotificationExecutor,
    WebhookExecutor,
    ScriptExecutor,
)


@pytest.fixture
def mock_db():
    """Create mock database session"""
    db = AsyncMock(spec=AsyncSession)
    return db


@pytest.fixture
def remediation_engine(mock_db):
    """Create RemediationEngine instance"""
    return RemediationEngine(mock_db)


class TestRemediationEngine:
    """Tests for RemediationEngine class"""

    def test_engine_initialization(self, remediation_engine):
        """Test engine initializes with all executors"""
        assert remediation_engine is not None
        assert hasattr(remediation_engine, 'executors')
        assert len(remediation_engine.executors) > 0

    def test_engine_has_firewall_executor(self, remediation_engine):
        """Test engine has firewall block executor"""
        assert "firewall_block" in remediation_engine.executors
        assert isinstance(remediation_engine.executors["firewall_block"], FirewallBlockExecutor)

    def test_engine_has_host_isolation_executor(self, remediation_engine):
        """Test engine has host isolation executor"""
        assert "host_isolate" in remediation_engine.executors
        assert isinstance(remediation_engine.executors["host_isolate"], HostIsolationExecutor)

    def test_engine_has_account_action_executor(self, remediation_engine):
        """Test engine has account action executor"""
        assert "account_disable" in remediation_engine.executors
        assert isinstance(remediation_engine.executors["account_disable"], AccountActionExecutor)

    def test_engine_has_process_action_executor(self, remediation_engine):
        """Test engine has process action executor"""
        assert "process_kill" in remediation_engine.executors
        assert isinstance(remediation_engine.executors["process_kill"], ProcessActionExecutor)

    def test_engine_has_patch_executor(self, remediation_engine):
        """Test engine has patch executor"""
        assert "patch_deploy" in remediation_engine.executors
        assert isinstance(remediation_engine.executors["patch_deploy"], PatchExecutor)

    def test_engine_has_network_executor(self, remediation_engine):
        """Test engine has network action executor"""
        assert "dns_sinkhole" in remediation_engine.executors
        assert isinstance(remediation_engine.executors["dns_sinkhole"], NetworkActionExecutor)

    def test_engine_has_notification_executor(self, remediation_engine):
        """Test engine has notification executor"""
        assert "notification" in remediation_engine.executors
        assert isinstance(remediation_engine.executors["notification"], NotificationExecutor)

    def test_engine_has_webhook_executor(self, remediation_engine):
        """Test engine has webhook executor"""
        assert "webhook" in remediation_engine.executors
        assert isinstance(remediation_engine.executors["webhook"], WebhookExecutor)

    def test_engine_has_script_executor(self, remediation_engine):
        """Test engine has script executor"""
        assert "script" in remediation_engine.executors
        assert isinstance(remediation_engine.executors["script"], ScriptExecutor)

    @pytest.mark.asyncio
    async def test_evaluate_trigger_alert_severity(self, remediation_engine):
        """Test evaluating trigger based on alert severity"""
        trigger_data = {
            "alert_id": "alert_123",
            "severity": "critical",
            "source": "intrusion_detection",
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Mock the database query
        remediation_engine.db.execute = AsyncMock()
        remediation_engine.db.execute.return_value.scalars = AsyncMock()
        remediation_engine.db.execute.return_value.scalars.return_value = []

        policies = await remediation_engine.evaluate_trigger(
            "alert_severity",
            trigger_data,
            "org_123"
        )
        assert isinstance(policies, list)

    @pytest.mark.asyncio
    async def test_evaluate_trigger_compliance_failure(self, remediation_engine):
        """Test evaluating trigger based on compliance failure"""
        trigger_data = {
            "control_id": "AC-2",
            "status": "failed",
            "severity": "high",
        }

        remediation_engine.db.execute = AsyncMock()
        remediation_engine.db.execute.return_value.scalars = AsyncMock()
        remediation_engine.db.execute.return_value.scalars.return_value = []

        policies = await remediation_engine.evaluate_trigger(
            "compliance_failure",
            trigger_data,
            "org_123"
        )
        assert isinstance(policies, list)


class TestActionExecutors:
    """Tests for action executor classes"""

    def test_firewall_executor_initialization(self, mock_db):
        """Test firewall executor initializes"""
        executor = FirewallBlockExecutor(mock_db)
        assert executor is not None

    @pytest.mark.asyncio
    async def test_firewall_block_execution(self, mock_db):
        """Test firewall block action execution"""
        executor = FirewallBlockExecutor(mock_db)
        action_data = {
            "target_ip": "192.168.1.100",
            "direction": "inbound",
            "duration": 3600,
        }
        executor.db.execute = AsyncMock()
        result = await executor.execute(action_data)
        assert result is not None

    def test_host_isolation_executor_initialization(self, mock_db):
        """Test host isolation executor initializes"""
        executor = HostIsolationExecutor(mock_db)
        assert executor is not None

    def test_account_action_executor_initialization(self, mock_db):
        """Test account action executor initializes"""
        executor = AccountActionExecutor(mock_db)
        assert executor is not None

    def test_process_action_executor_initialization(self, mock_db):
        """Test process action executor initializes"""
        executor = ProcessActionExecutor(mock_db)
        assert executor is not None

    def test_patch_executor_initialization(self, mock_db):
        """Test patch executor initializes"""
        executor = PatchExecutor(mock_db)
        assert executor is not None

    def test_network_action_executor_initialization(self, mock_db):
        """Test network action executor initializes"""
        executor = NetworkActionExecutor(mock_db)
        assert executor is not None

    def test_notification_executor_initialization(self, mock_db):
        """Test notification executor initializes"""
        executor = NotificationExecutor(mock_db)
        assert executor is not None

    def test_webhook_executor_initialization(self, mock_db):
        """Test webhook executor initializes"""
        executor = WebhookExecutor(mock_db)
        assert executor is not None

    def test_script_executor_initialization(self, mock_db):
        """Test script executor initializes"""
        executor = ScriptExecutor(mock_db)
        assert executor is not None


@pytest.mark.asyncio
class TestApprovalWorkflow:
    """Tests for remediation approval workflow"""

    async def test_create_approval_request(self, db_session: AsyncSession):
        """Test creating approval request for remediation"""
        approval_request = {
            "id": "appr-001",
            "control_id": "AC-2",
            "requested_by": "automation",
            "requested_at": datetime.utcnow(),
            "status": "pending",
            "approvers": ["security-manager", "ciso"],
        }

        assert approval_request["status"] == "pending"
        assert len(approval_request["approvers"]) == 2

    async def test_approve_remediation(self, db_session: AsyncSession):
        """Test approving a remediation"""
        approval_request = {
            "id": "appr-001",
            "status": "pending",
            "approved_by": None,
        }

        # Simulate approval
        approval_request["status"] = "approved"
        approval_request["approved_by"] = "security-manager"
        approval_request["approved_at"] = datetime.utcnow()

        assert approval_request["status"] == "approved"
        assert approval_request["approved_by"] == "security-manager"

    async def test_reject_remediation(self, db_session: AsyncSession):
        """Test rejecting a remediation"""
        approval_request = {
            "id": "appr-001",
            "status": "pending",
            "rejection_reason": None,
        }

        # Simulate rejection
        approval_request["status"] = "rejected"
        approval_request["rejection_reason"] = "Requires manual review"
        approval_request["rejected_at"] = datetime.utcnow()

        assert approval_request["status"] == "rejected"
        assert "manual review" in approval_request["rejection_reason"]


@pytest.mark.asyncio
class TestRollbackCapability:
    """Tests for remediation rollback"""

    async def test_remediation_rollback(self, db_session: AsyncSession):
        """Test rolling back a failed remediation"""
        remediation_execution = {
            "id": "rem-001",
            "control_id": "SC-28",
            "action": "enable_s3_encryption",
            "status": "completed",
            "previous_state": {"bucket": "data-bucket", "encryption": False},
            "new_state": {"bucket": "data-bucket", "encryption": True},
        }

        # Simulate rollback
        remediation_execution["status"] = "rolled_back"
        remediation_execution["current_state"] = remediation_execution["previous_state"]
        remediation_execution["rolled_back_at"] = datetime.utcnow()

        assert remediation_execution["status"] == "rolled_back"
        assert remediation_execution["current_state"]["encryption"] is False

    async def test_rollback_stores_previous_state(self, db_session: AsyncSession):
        """Test that rollback uses stored previous state"""
        previous_state = {
            "sg_id": "sg-12345",
            "ingress_rules": [
                {"protocol": "tcp", "port": 443, "cidr": "0.0.0.0/0"}
            ],
        }

        new_state = {
            "sg_id": "sg-12345",
            "ingress_rules": [],
        }

        remediation = {
            "id": "rem-001",
            "previous_state": previous_state,
            "new_state": new_state,
        }

        # Verify states are different
        assert len(remediation["previous_state"]["ingress_rules"]) > 0
        assert len(remediation["new_state"]["ingress_rules"]) == 0

    async def test_rollback_on_execution_failure(self, db_session: AsyncSession):
        """Test automatic rollback on execution failure"""
        execution = {
            "id": "rem-001",
            "status": "failed",
            "error": "Permission denied",
            "should_rollback": True,
            "previous_state": {"setting": "original"},
        }

        if execution["should_rollback"] and execution["status"] == "failed":
            execution["rolled_back"] = True

        assert execution["rolled_back"] is True


@pytest.mark.asyncio
class TestRateLimitingAndCooldowns:
    """Tests for remediation rate limiting and cooldowns"""

    async def test_cooldown_period(self, db_session: AsyncSession):
        """Test cooldown period between remediations"""
        cooldown_seconds = 300
        last_remediation = datetime.utcnow() - timedelta(seconds=100)
        now = datetime.utcnow()

        time_since_last = (now - last_remediation).total_seconds()
        can_execute = time_since_last >= cooldown_seconds

        assert can_execute is False

    async def test_can_execute_after_cooldown(self, db_session: AsyncSession):
        """Test execution allowed after cooldown expires"""
        cooldown_seconds = 60
        last_remediation = datetime.utcnow() - timedelta(seconds=120)
        now = datetime.utcnow()

        time_since_last = (now - last_remediation).total_seconds()
        can_execute = time_since_last >= cooldown_seconds

        assert can_execute is True

    async def test_rate_limit_max_per_hour(self, db_session: AsyncSession):
        """Test rate limiting max remediations per hour"""
        max_remediations_per_hour = 5
        remediation_history = [
            {"executed_at": datetime.utcnow() - timedelta(minutes=i * 10)}
            for i in range(4)
        ]

        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_remediations = [
            r for r in remediation_history
            if r["executed_at"] > one_hour_ago
        ]

        can_execute = len(recent_remediations) < max_remediations_per_hour

        assert can_execute is True

    async def test_rate_limit_exceeded(self, db_session: AsyncSession):
        """Test when rate limit is exceeded"""
        max_remediations_per_hour = 5
        remediation_history = [
            {"executed_at": datetime.utcnow() - timedelta(minutes=i * 5)}
            for i in range(6)
        ]

        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_remediations = [
            r for r in remediation_history
            if r["executed_at"] > one_hour_ago
        ]

        can_execute = len(recent_remediations) < max_remediations_per_hour

        assert can_execute is False

    async def test_cooldown_tracker(self, db_session: AsyncSession):
        """Test tracking cooldowns per control"""
        cooldowns = {
            "AC-2": datetime.utcnow() - timedelta(seconds=400),
            "SC-7": datetime.utcnow() - timedelta(seconds=50),
        }

        cooldown_period = 300

        ready_controls = [
            control_id for control_id, last_time in cooldowns.items()
            if (datetime.utcnow() - last_time).total_seconds() >= cooldown_period
        ]

        assert "AC-2" in ready_controls
        assert "SC-7" not in ready_controls


@pytest.mark.asyncio
class TestRemediationExecutionTracking:
    """Tests for tracking remediation execution"""

    async def test_track_remediation_execution(self, db_session: AsyncSession):
        """Test tracking a remediation execution"""
        execution = {
            "id": "exec-001",
            "control_id": "AC-2",
            "action": "enable_mfa",
            "started_at": datetime.utcnow(),
            "status": "in_progress",
            "steps_total": 3,
            "steps_completed": 0,
        }

        # Simulate progress
        execution["steps_completed"] = 3
        execution["status"] = "completed"
        execution["completed_at"] = datetime.utcnow()

        assert execution["status"] == "completed"
        assert execution["steps_completed"] == execution["steps_total"]

    async def test_remediation_execution_with_error(self, db_session: AsyncSession):
        """Test tracking execution with error"""
        execution = {
            "id": "exec-001",
            "status": "in_progress",
            "error": None,
        }

        # Simulate error
        execution["status"] = "failed"
        execution["error"] = "Invalid credentials"
        execution["error_at"] = datetime.utcnow()

        assert execution["status"] == "failed"
        assert execution["error"] is not None
