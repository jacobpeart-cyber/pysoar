"""
Breach & Attack Simulation (BAS) Engine

Core orchestration, atomic test library, adversary emulation,
and security posture scoring for attack simulations.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_

from src.core.logging import get_logger
from src.core.config import settings
from src.models.base import generate_uuid, utc_now
from src.simulation.models import (
    AttackSimulation,
    AttackTechnique,
    SimulationTest,
    AdversaryProfile,
    SecurityPostureScore,
)

logger = get_logger(__name__)


class SimulationOrchestrator:
    """
    Main orchestrator for attack simulation execution.

    Manages simulation lifecycle: creation, execution, monitoring, and cleanup.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.atomic_library = AtomicTestLibrary(session)

    async def create_simulation(
        self,
        name: str,
        sim_type: str,
        techniques: List[str],
        scope: Dict[str, Any],
        target_environment: str,
        created_by: str,
        organization_id: str,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> AttackSimulation:
        """
        Create a new attack simulation.

        Args:
            name: Simulation name
            sim_type: Type of simulation (atomic_test, attack_chain, etc.)
            techniques: List of MITRE technique IDs to include
            scope: Target scope (hosts, networks, users)
            target_environment: Environment to target (production, staging, lab, isolated)
            created_by: User ID creating the simulation
            organization_id: Organization ID
            description: Optional description
            tags: Optional tags for categorization

        Returns:
            Created AttackSimulation object
        """
        if not await self._validate_scope(scope):
            raise ValueError("Invalid or unsafe simulation scope")

        # Fetch technique details
        mitre_tactics = set()
        mitre_techniques_list = []
        for tech_id in techniques:
            technique = await self.atomic_library.get_technique(tech_id)
            if not technique:
                logger.warning(f"Technique {tech_id} not found")
                continue
            mitre_tactics.add(technique.tactic)
            mitre_techniques_list.append(tech_id)

        simulation = AttackSimulation(
            id=generate_uuid(),
            name=name,
            description=description,
            simulation_type=sim_type,
            status="draft",
            target_environment=target_environment,
            scope=scope,
            mitre_tactics=list(mitre_tactics),
            mitre_techniques=mitre_techniques_list,
            created_by=created_by,
            organization_id=organization_id,
            tags=tags or [],
            created_at=utc_now(),
            updated_at=utc_now(),
        )

        self.session.add(simulation)
        await self.session.commit()
        logger.info(f"Created simulation {simulation.id}: {name}")
        return simulation

    async def start_simulation(self, simulation_id: str) -> Dict[str, Any]:
        """
        Start executing a simulation.

        Args:
            simulation_id: ID of simulation to start

        Returns:
            Dictionary with execution start status and first test info
        """
        simulation = await self._get_simulation(simulation_id)
        if not simulation:
            raise ValueError(f"Simulation {simulation_id} not found")

        if simulation.status not in ["draft", "paused"]:
            raise ValueError(f"Cannot start simulation with status: {simulation.status}")

        # Create test records for each technique
        test_order = 0
        for tech_id in simulation.mitre_techniques:
            technique = await self.atomic_library.get_technique(tech_id)
            if not technique or not technique.is_enabled:
                continue

            test = SimulationTest(
                id=generate_uuid(),
                simulation_id=simulation_id,
                technique_id=technique.id,
                test_name=f"{technique.mitre_id}: {technique.name}",
                test_order=test_order,
                status="pending",
                executor="powershell",  # Default, will be overridden by technique
                created_at=utc_now(),
                updated_at=utc_now(),
            )
            test_order += 1
            self.session.add(test)

        # Update simulation status
        simulation.status = "running"
        simulation.started_at = utc_now()
        simulation.total_tests = test_order
        await self.session.commit()

        logger.info(f"Started simulation {simulation_id} with {test_order} tests")
        return {
            "simulation_id": simulation_id,
            "status": "running",
            "total_tests": test_order,
            "message": f"Simulation started with {test_order} tests"
        }

    async def pause_simulation(self, simulation_id: str) -> None:
        """Pause an ongoing simulation."""
        simulation = await self._get_simulation(simulation_id)
        if not simulation:
            raise ValueError(f"Simulation {simulation_id} not found")

        if simulation.status != "running":
            raise ValueError(f"Cannot pause simulation with status: {simulation.status}")

        simulation.status = "paused"
        simulation.updated_at = utc_now()
        await self.session.commit()
        logger.info(f"Paused simulation {simulation_id}")

    async def cancel_simulation(self, simulation_id: str) -> None:
        """Cancel a simulation and clean up any running tests."""
        simulation = await self._get_simulation(simulation_id)
        if not simulation:
            raise ValueError(f"Simulation {simulation_id} not found")

        if simulation.status in ["completed", "failed", "cancelled"]:
            raise ValueError(f"Cannot cancel simulation with status: {simulation.status}")

        # Cancel all pending/running tests
        stmt = update(SimulationTest).where(
            and_(
                SimulationTest.simulation_id == simulation_id,
                SimulationTest.status.in_(["pending", "running"])
            )
        ).values(status="skipped", updated_at=utc_now())
        await self.session.execute(stmt)

        simulation.status = "cancelled"
        simulation.updated_at = utc_now()
        await self.session.commit()
        logger.info(f"Cancelled simulation {simulation_id}")

    async def get_simulation_progress(self, simulation_id: str) -> Dict[str, Any]:
        """
        Get current progress of a running simulation.

        Returns:
            Dictionary with test counts and current test info
        """
        simulation = await self._get_simulation(simulation_id)
        if not simulation:
            raise ValueError(f"Simulation {simulation_id} not found")

        stmt = select(SimulationTest).where(SimulationTest.simulation_id == simulation_id)
        result = await self.session.execute(stmt)
        tests = result.scalars().all()

        pending_count = sum(1 for t in tests if t.status == "pending")
        running_count = sum(1 for t in tests if t.status == "running")
        completed_count = sum(1 for t in tests if t.status in ["passed", "failed", "blocked"])

        current_test = next((t for t in tests if t.status == "running"), None)

        return {
            "simulation_id": simulation_id,
            "status": simulation.status,
            "pending_tests": pending_count,
            "running_tests": running_count,
            "completed_tests": completed_count,
            "total_tests": simulation.total_tests,
            "current_test": current_test.test_name if current_test else None,
            "progress_percent": int((completed_count / max(simulation.total_tests, 1)) * 100)
        }

    async def _execute_test(self, test: SimulationTest) -> Dict[str, Any]:
        """
        Execute a single test within a simulation.

        Args:
            test: SimulationTest record to execute

        Returns:
            Dictionary with execution results
        """
        technique = await self.atomic_library.get_technique(test.technique_id)
        if not technique:
            test.status = "error"
            test.error_output = "Technique not found"
            await self.session.commit()
            return {"status": "error", "message": "Technique not found"}

        test.status = "running"
        test.started_at = utc_now()
        await self.session.commit()

        try:
            # Get appropriate test command for platform
            test_cmd = technique.test_commands[0] if technique.test_commands else None
            if not test_cmd:
                raise ValueError("No test command defined for technique")

            command = test_cmd.get("command")
            cleanup = test_cmd.get("cleanup")
            test.executor = test_cmd.get("executor", "powershell")
            test.command_executed = command

            # Try to execute the atomic test on a real endpoint agent if
            # one is available in scope. Fall back to coverage-only
            # scoring if no agent matches or the agent doesn't respond
            # within the dispatch window. Either way the detection score
            # is still computed from the DetectionRule table, so the
            # security posture number remains well-defined regardless of
            # whether a physical host was involved.
            agent_result = await self._try_dispatch_to_agent(
                test=test,
                technique=technique,
                command=command,
                executor=test_cmd.get("executor", "sh"),
            )

            if agent_result is not None:
                test.output = agent_result.stdout or ""
                if agent_result.stderr:
                    test.error_output = agent_result.stderr
                test.status = "passed" if agent_result.status == "success" else "error"
            else:
                # No live agent — score against detection rule coverage only
                test.output = (
                    f"[COVERAGE-ONLY] Technique {technique.mitre_id} plan:\n"
                    f"  executor: {test_cmd.get('executor', 'powershell')}\n"
                    f"  command: {command}\n"
                    f"  description: {technique.description or ''}\n"
                    f"  (No BAS-capable agent enrolled in scope — "
                    f"scored against detection rule coverage only.)"
                )
                test.status = "passed"

            # Deterministic detection lookup against active detection rules
            detected = await self._check_detection(test, technique)
            test.was_detected = detected

            # Run cleanup if test passed and cleanup command exists
            if cleanup:
                cleanup_success = await self._run_cleanup(test, cleanup)
                test.cleanup_status = "completed" if cleanup_success else "failed"

            test.status = "passed" if detected else "blocked"

        except Exception as e:
            test.status = "error"
            test.error_output = str(e)
            logger.error(f"Error executing test {test.id}: {str(e)}")

        test.completed_at = utc_now()
        await self.session.commit()

        return {
            "test_id": test.id,
            "status": test.status,
            "detected": test.was_detected,
            "detection_time": test.detection_time_seconds
        }

    async def _try_dispatch_to_agent(
        self,
        test: SimulationTest,
        technique: "AttackTechnique",
        command: str,
        executor: str,
        max_wait_seconds: int = 30,
    ):
        """Dispatch this atomic test to a live BAS-capable endpoint agent.

        The simulation's ``scope`` may contain a ``target_host`` hint. We
        look for an ACTIVE agent whose hostname matches the hint AND has
        the ``bas`` capability. If one exists, we issue a
        ``run_atomic_test`` command via AgentService (which chains the
        audit hash) and poll the agent_results table until a row lands
        or we time out. Returns the AgentResult row, or None if no agent
        matched or the agent didn't report back in time.

        Any exception here is non-fatal — the test simply degrades to
        coverage-only scoring rather than failing the whole simulation.
        """
        try:
            from src.agents.capabilities import AgentAction, AgentCapability
            from src.agents.models import AgentCommand, AgentResult, EndpointAgent
            from src.agents.service import AgentService

            simulation = await self._get_simulation(test.simulation_id)
            if simulation is None:
                return None

            scope = simulation.scope or {}
            target_host = scope.get("target_host") if isinstance(scope, dict) else None
            org_id = simulation.organization_id

            agent_query = select(EndpointAgent).where(
                EndpointAgent.status == "active"
            )
            if org_id:
                agent_query = agent_query.where(EndpointAgent.organization_id == org_id)
            if target_host:
                agent_query = agent_query.where(EndpointAgent.hostname == target_host)

            result = await self.session.execute(agent_query)
            candidates = list(result.scalars().all())

            agent = None
            for candidate in candidates:
                caps = candidate.capabilities or []
                if AgentCapability.BAS.value in caps:
                    agent = candidate
                    break

            if agent is None:
                return None

            svc = AgentService(self.session)
            payload = {
                "command": command,
                "executor": executor,
                "mitre_id": technique.mitre_id,
            }
            cmd = await svc.issue_command(
                agent=agent,
                action=AgentAction.RUN_ATOMIC_TEST.value,
                payload=payload,
                simulation_id=test.simulation_id,
            )
            await self.session.commit()

            # Poll for the result. The agent polls on its own ~30s cycle
            # so we wait up to max_wait_seconds before bailing out.
            deadline = time.time() + max_wait_seconds
            poll_interval = 2
            while time.time() < deadline:
                await asyncio.sleep(poll_interval)
                result_row = (
                    await self.session.execute(
                        select(AgentResult).where(AgentResult.command_id == cmd.id)
                    )
                ).scalar_one_or_none()
                if result_row is not None:
                    return result_row
                # Refresh command to see if it expired / rejected
                cmd_row = (
                    await self.session.execute(
                        select(AgentCommand).where(AgentCommand.id == cmd.id)
                    )
                ).scalar_one_or_none()
                if cmd_row and cmd_row.status in ("rejected", "expired", "failed"):
                    break
            return None
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                f"Agent dispatch failed for test {test.id}: {exc} — "
                f"falling back to coverage-only scoring"
            )
            return None

    async def _check_detection(
        self,
        test: SimulationTest,
        technique: "AttackTechnique",
    ) -> bool:
        """
        Determine whether this technique is covered by the org's detection rules.

        This is the scoring heart of the BAS engine. It is **deterministic**
        (the same technique always scores the same way for a given ruleset)
        and it reflects the *real* coverage of the platform's DetectionRule
        table. That way the security posture score actually measures
        something — "do you have a rule that claims to detect this MITRE
        technique?" — instead of random noise.

        Detection is granted if ANY active detection rule lists this
        technique's mitre_id in its ``mitre_techniques`` JSON array.
        """
        from src.siem.models import DetectionRule, RuleStatus

        mitre_id = technique.mitre_id
        if not mitre_id:
            return False

        # Active detection rules whose mitre_techniques contains this id.
        # ``mitre_techniques`` is a Text column holding a JSON array, so we
        # use SQL LIKE to pre-filter and then confirm in Python against a
        # parsed list to avoid false positives (e.g. "T1059" matching "T10591").
        stmt = select(DetectionRule).where(
            and_(
                DetectionRule.status == RuleStatus.ACTIVE.value,
                DetectionRule.mitre_techniques.is_not(None),
                DetectionRule.mitre_techniques.like(f"%{mitre_id}%"),
            )
        )
        result = await self.session.execute(stmt)
        candidates = list(result.scalars().all())

        matching_rule = None
        for rule in candidates:
            try:
                rule_techniques = json.loads(rule.mitre_techniques or "[]")
            except (ValueError, TypeError):
                continue
            if isinstance(rule_techniques, list) and mitre_id in rule_techniques:
                matching_rule = rule
                break

        if matching_rule is None:
            return False

        test.detection_time_seconds = 0  # instantaneous: we're scoring coverage, not latency
        test.detection_source = f"detection_rule:{matching_rule.name}"
        test.detection_details = {
            "rule_id": matching_rule.id,
            "rule_name": matching_rule.name,
            "rule_title": matching_rule.title,
            "alert_severity": matching_rule.severity,
            "matched_at": utc_now().isoformat(),
            "match_type": "mitre_technique_mapping",
        }
        return True

    async def _run_cleanup(self, test: SimulationTest, cleanup_command: str) -> bool:
        """
        Dispatch the cleanup command to the endpoint agent that ran the
        test, using the same capability-gated RUN_ATOMIC_TEST action the
        simulation itself used. Polls the AgentCommand record for
        completion and returns True iff the agent reports success.

        If no connected agent exists for the target, records the command
        on the row with cleanup_status='pending_agent' and returns False
        — we don't claim success for work that didn't happen.
        """
        from src.agents.models import EndpointAgent, AgentCommand, AgentResult
        from src.agents.service import AgentService, AgentServiceError
        import asyncio as _asyncio
        import time as _time

        test.cleanup_command = cleanup_command
        target = getattr(test, "target_host", None) or getattr(test, "target", None)

        if not target:
            logger.warning(
                "Simulation test %s has no target host; cleanup command "
                "recorded but not dispatched", test.id,
            )
            test.cleanup_status = "no_target"
            return False

        result = await self.db.execute(
            select(EndpointAgent).where(
                EndpointAgent.hostname == target,
                EndpointAgent.status == "active",
            )
        )
        agent = result.scalar_one_or_none()

        if not agent:
            logger.warning(
                "No active agent for target %s; cleanup for test %s deferred",
                target, test.id,
            )
            test.cleanup_status = "pending_agent"
            return False

        service = AgentService(self.db)
        try:
            cmd = await service.issue_command(
                agent=agent,
                action="run_atomic_test",
                payload={
                    "command": cleanup_command,
                    "is_cleanup": True,
                    "simulation_test_id": test.id,
                },
                simulation_id=getattr(test, "simulation_id", None),
                approval_override=True,
            )
            await self.db.commit()
        except AgentServiceError as e:
            logger.error("Cleanup dispatch failed for test %s: %s", test.id, e)
            test.cleanup_status = "dispatch_failed"
            return False

        # Poll for completion — cleanup should return within the command's
        # 15-minute expiry window. We wait up to 5 minutes here.
        deadline = _time.monotonic() + 300
        while _time.monotonic() < deadline:
            await _asyncio.sleep(5)
            refreshed = (await self.db.execute(
                select(AgentCommand).where(AgentCommand.id == cmd.id)
            )).scalar_one_or_none()
            if not refreshed:
                break
            if refreshed.status == "completed":
                test.cleanup_status = "completed"
                logger.info("Cleanup completed for test %s on agent %s", test.id, agent.id)
                return True
            if refreshed.status in ("failed", "expired", "rejected"):
                test.cleanup_status = refreshed.status
                logger.warning(
                    "Cleanup %s for test %s on agent %s", refreshed.status, test.id, agent.id,
                )
                return False

        test.cleanup_status = "timeout"
        logger.warning("Cleanup timed out for test %s on agent %s", test.id, agent.id)
        return False

    async def _validate_scope(self, scope: Dict[str, Any]) -> bool:
        """
        Validate simulation scope for safety.

        Args:
            scope: Scope dictionary with target details

        Returns:
            True if scope is valid and safe
        """
        # Empty scope is valid (lab environment, no specific targets)
        if not scope:
            return True

        # Validate no overly broad targets
        hosts = scope.get("hosts", [])
        if isinstance(hosts, str) and hosts == "*":
            return False  # Reject wildcard all hosts

        return True

    async def _get_simulation(self, simulation_id: str) -> Optional[AttackSimulation]:
        """Helper to fetch a simulation by ID."""
        stmt = select(AttackSimulation).where(AttackSimulation.id == simulation_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()


class AtomicTestLibrary:
    """
    Library of MITRE ATT&CK techniques with test commands and detection expectations.

    Provides access to atomic tests and built-in technique definitions.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.builtin_techniques = {}

    async def load_builtin_techniques(self) -> int:
        """
        Load built-in MITRE ATT&CK techniques into the database.

        Returns:
            Number of techniques loaded
        """
        builtin_techniques = [
            {
                "mitre_id": "T1059.001",
                "name": "PowerShell",
                "tactic": "Execution",
                "description": "Execution via PowerShell",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "Get-Process | Select-Object ProcessName, Id",
                        "cleanup": "# No cleanup needed"
                    }
                ],
                "detection_sources": ["EDR", "Endpoint Logging"],
                "expected_detection": "PowerShell process execution detected",
                "risk_level": "medium",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1059.001-1"
            },
            {
                "mitre_id": "T1059.004",
                "name": "Unix Shell",
                "tactic": "Execution",
                "description": "Execution via Unix shell",
                "platform": ["linux", "macos"],
                "test_commands": [
                    {
                        "platform": "linux",
                        "executor": "bash",
                        "command": "ps aux | grep bash",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["Auditd", "Syslog"],
                "expected_detection": "Shell command execution detected",
                "risk_level": "medium",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1059.004-1"
            },
            {
                "mitre_id": "T1053.005",
                "name": "Scheduled Task/Job",
                "tactic": "Persistence",
                "description": "Create scheduled task for persistence",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "Get-ScheduledTask -TaskName test_task -ErrorAction SilentlyContinue",
                        "cleanup": "Unregister-ScheduledTask -TaskName test_task -Confirm:$false -ErrorAction SilentlyContinue"
                    }
                ],
                "detection_sources": ["Sysmon", "Windows Event Log"],
                "expected_detection": "Scheduled task creation detected",
                "risk_level": "high",
                "requires_privileges": "admin",
                "is_safe": True,
                "atomic_test_ref": "T1053.005-1"
            },
            {
                "mitre_id": "T1547.001",
                "name": "Registry Run Keys / Startup Folder",
                "tactic": "Persistence",
                "description": "Modify registry run keys for persistence",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "Get-Item 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' | Select-Object Property",
                        "cleanup": "# Removal would require admin"
                    }
                ],
                "detection_sources": ["Sysmon", "EDR"],
                "expected_detection": "Registry modification detected",
                "risk_level": "high",
                "requires_privileges": "admin",
                "is_safe": True,
                "atomic_test_ref": "T1547.001-1"
            },
            {
                "mitre_id": "T1003.001",
                "name": "LSASS Memory Dump",
                "tactic": "Credential Access",
                "description": "Simulated LSASS memory dump (safe test)",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "# Simulated: tasklist | findstr lsass",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["EDR", "Sysmon"],
                "expected_detection": "LSASS dump attempt detected",
                "risk_level": "critical",
                "requires_privileges": "admin",
                "is_safe": True,
                "atomic_test_ref": "T1003.001-1"
            },
            {
                "mitre_id": "T1021.001",
                "name": "Remote Desktop Protocol",
                "tactic": "Lateral Movement",
                "description": "Test RDP lateral movement detection",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "cmd",
                        "command": "mstsc /v:127.0.0.1 /admin",
                        "cleanup": "# Connection would close"
                    }
                ],
                "detection_sources": ["Network IDS", "Endpoint Logging"],
                "expected_detection": "RDP connection attempt detected",
                "risk_level": "high",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1021.001-1"
            },
            {
                "mitre_id": "T1021.006",
                "name": "WinRM",
                "tactic": "Lateral Movement",
                "description": "Test WinRM lateral movement detection",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "Invoke-Command -ComputerName localhost -ScriptBlock { whoami }",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["WinRM Event Logs", "EDR"],
                "expected_detection": "WinRM remote execution detected",
                "risk_level": "high",
                "requires_privileges": "admin",
                "is_safe": True,
                "atomic_test_ref": "T1021.006-1"
            },
            {
                "mitre_id": "T1048.003",
                "name": "Exfiltration Over DNS",
                "tactic": "Exfiltration",
                "description": "Test DNS-based data exfiltration detection",
                "platform": ["windows", "linux"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "[System.Net.Dns]::GetHostByName('exfil.test.local')",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["DNS Sinkhole", "Network IDS"],
                "expected_detection": "Suspicious DNS query detected",
                "risk_level": "high",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1048.003-1"
            },
            {
                "mitre_id": "T1071.001",
                "name": "Application Layer Protocol: HTTP/HTTPS",
                "tactic": "Command and Control",
                "description": "Test HTTP/HTTPS C2 communication detection",
                "platform": ["windows", "linux"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "Invoke-WebRequest -Uri 'http://test.local/beacon' -UseBasicParsing",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["Web Proxy", "Network IDS"],
                "expected_detection": "Suspicious HTTP communication detected",
                "risk_level": "high",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1071.001-1"
            },
            {
                "mitre_id": "T1110.001",
                "name": "Brute Force: Password Guessing",
                "tactic": "Credential Access",
                "description": "Simulated brute force password attack",
                "platform": ["windows", "linux"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "# Simulated brute force - no actual attempts",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["Auth Logs", "WAF"],
                "expected_detection": "Multiple failed authentication attempts detected",
                "risk_level": "high",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1110.001-1"
            },
            {
                "mitre_id": "T1136.001",
                "name": "Create Account: Local Account",
                "tactic": "Persistence",
                "description": "Create a local user account for persistence",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "Get-LocalUser | Select-Object Name",
                        "cleanup": "# Account removal requires admin"
                    }
                ],
                "detection_sources": ["EDR", "Event Logs"],
                "expected_detection": "Local account creation detected",
                "risk_level": "high",
                "requires_privileges": "admin",
                "is_safe": True,
                "atomic_test_ref": "T1136.001-1"
            },
            {
                "mitre_id": "T1070.001",
                "name": "Indicator Removal: Clear Windows Event Logs",
                "tactic": "Defense Evasion",
                "description": "Test clearing Windows Event Logs detection",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "Get-EventLog -LogName Application -Newest 1",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["EDR", "SIEM"],
                "expected_detection": "Event log clearing attempt detected",
                "risk_level": "high",
                "requires_privileges": "admin",
                "is_safe": True,
                "atomic_test_ref": "T1070.001-1"
            },
            {
                "mitre_id": "T1055.001",
                "name": "Process Injection: Dynamic-link Library Injection",
                "tactic": "Defense Evasion",
                "description": "Simulated DLL injection test (safe version)",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "Get-Process -Name explorer | Select-Object ProcessName, Id",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["EDR", "Sysmon"],
                "expected_detection": "Process injection attempt detected",
                "risk_level": "critical",
                "requires_privileges": "admin",
                "is_safe": True,
                "atomic_test_ref": "T1055.001-1"
            },
            {
                "mitre_id": "T1027",
                "name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion",
                "description": "Test obfuscated script detection",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "powershell",
                        "command": "# Base64-obfuscated command would be here in real test",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["EDR", "SIEM"],
                "expected_detection": "Obfuscated command execution detected",
                "risk_level": "high",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1027-1"
            },
            {
                "mitre_id": "T1082",
                "name": "System Information Discovery",
                "tactic": "Discovery",
                "description": "Discover system information",
                "platform": ["windows", "linux"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "cmd",
                        "command": "systeminfo",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["EDR"],
                "expected_detection": "System information discovery detected",
                "risk_level": "low",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1082-1"
            },
            {
                "mitre_id": "T1083",
                "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "description": "Discover files and directories",
                "platform": ["windows", "linux"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "cmd",
                        "command": "dir C:\\ /s /b",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["EDR"],
                "expected_detection": "File system enumeration detected",
                "risk_level": "low",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1083-1"
            },
            {
                "mitre_id": "T1018",
                "name": "Remote System Discovery",
                "tactic": "Discovery",
                "description": "Discover remote systems on network",
                "platform": ["windows"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "cmd",
                        "command": "net view",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["Network IDS", "EDR"],
                "expected_detection": "Network reconnaissance detected",
                "risk_level": "medium",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1018-1"
            },
            {
                "mitre_id": "T1016",
                "name": "System Network Configuration Discovery",
                "tactic": "Discovery",
                "description": "Discover network configuration",
                "platform": ["windows", "linux"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "cmd",
                        "command": "ipconfig /all",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["EDR"],
                "expected_detection": "Network configuration discovery detected",
                "risk_level": "low",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1016-1"
            },
            {
                "mitre_id": "T1049",
                "name": "System Network Connections Discovery",
                "tactic": "Discovery",
                "description": "Discover active network connections",
                "platform": ["windows", "linux"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "cmd",
                        "command": "netstat -ano",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["EDR"],
                "expected_detection": "Network connection enumeration detected",
                "risk_level": "low",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1049-1"
            },
            {
                "mitre_id": "T1057",
                "name": "Process Discovery",
                "tactic": "Discovery",
                "description": "Discover running processes",
                "platform": ["windows", "linux"],
                "test_commands": [
                    {
                        "platform": "windows",
                        "executor": "cmd",
                        "command": "tasklist /v",
                        "cleanup": "# No cleanup"
                    }
                ],
                "detection_sources": ["EDR"],
                "expected_detection": "Process enumeration detected",
                "risk_level": "low",
                "requires_privileges": "user",
                "is_safe": True,
                "atomic_test_ref": "T1057-1"
            },
        ]

        count = 0
        for tech_data in builtin_techniques:
            # Check if already exists
            stmt = select(AttackTechnique).where(AttackTechnique.mitre_id == tech_data["mitre_id"])
            result = await self.session.execute(stmt)
            if result.scalar_one_or_none():
                continue

            technique = AttackTechnique(
                id=generate_uuid(),
                mitre_id=tech_data["mitre_id"],
                name=tech_data["name"],
                tactic=tech_data["tactic"],
                description=tech_data.get("description"),
                platform=tech_data.get("platform", []),
                test_commands=tech_data.get("test_commands", []),
                detection_sources=tech_data.get("detection_sources", []),
                expected_detection=tech_data.get("expected_detection"),
                risk_level=tech_data.get("risk_level", "medium"),
                requires_privileges=tech_data.get("requires_privileges", "user"),
                is_safe=tech_data.get("is_safe", True),
                is_enabled=True,
                atomic_test_ref=tech_data.get("atomic_test_ref"),
                tags=tech_data.get("tags", []),
                created_at=utc_now(),
                updated_at=utc_now(),
            )
            self.session.add(technique)
            count += 1

        await self.session.commit()
        logger.info(f"Loaded {count} built-in techniques")
        return count

    async def get_technique(self, mitre_id_or_id: str) -> Optional[AttackTechnique]:
        """
        Get a technique by MITRE ID or database ID.

        Args:
            mitre_id_or_id: MITRE ID (e.g., "T1059.001") or database UUID

        Returns:
            AttackTechnique object or None if not found
        """
        if mitre_id_or_id.startswith("T"):
            # Query by MITRE ID
            stmt = select(AttackTechnique).where(AttackTechnique.mitre_id == mitre_id_or_id)
        else:
            # Query by database ID
            stmt = select(AttackTechnique).where(AttackTechnique.id == mitre_id_or_id)

        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_techniques_by_tactic(self, tactic: str) -> List[AttackTechnique]:
        """Get all techniques for a specific MITRE tactic."""
        stmt = select(AttackTechnique).where(
            and_(
                AttackTechnique.tactic == tactic,
                AttackTechnique.is_enabled == True
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def search_techniques(self, query: str) -> List[AttackTechnique]:
        """Search techniques by name or MITRE ID."""
        stmt = select(AttackTechnique).where(
            (AttackTechnique.name.ilike(f"%{query}%")) |
            (AttackTechnique.mitre_id.ilike(f"%{query}%"))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_safe_techniques(self) -> List[AttackTechnique]:
        """Get only production-safe techniques."""
        stmt = select(AttackTechnique).where(
            and_(
                AttackTechnique.is_safe == True,
                AttackTechnique.is_enabled == True
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()


class AdversaryEmulator:
    """
    Emulates known threat actor attack patterns and tactics.

    Provides adversary profiles and orchestrates emulation simulations.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.atomic_library = AtomicTestLibrary(session)

    async def load_builtin_profiles(self) -> int:
        """Load built-in adversary profiles (APT groups, etc.)."""
        builtin_profiles = [
            {
                "name": "APT29 (Cozy Bear)",
                "description": "Russian state-sponsored APT group known for sophisticated supply chain attacks",
                "sophistication": "apt",
                "attack_chain": [
                    "T1566.002",  # Phishing
                    "T1203",      # Exploitation for Client Execution
                    "T1547.001",  # Registry Run Keys / Startup Folder
                    "T1056.001",  # Keylogging
                    "T1005",      # Data from Local System
                    "T1041",      # Exfiltration Over C2 Channel
                ],
                "objectives": ["Establish persistence", "Steal credentials", "Data exfiltration"],
                "ttps": ["T1566.002", "T1203", "T1547.001", "T1056.001", "T1005", "T1041"],
                "target_sectors": ["Government", "Think tanks", "Energy"],
                "tools_used": ["WellMail", "Outlook Web Access", "Custom backdoors"],
                "is_builtin": True,
            },
            {
                "name": "APT28 (Fancy Bear)",
                "description": "Russian military intelligence APT group focused on espionage",
                "sophistication": "apt",
                "attack_chain": [
                    "T1566.002",  # Spear phishing
                    "T1059.001",  # PowerShell
                    "T1547.001",  # Persistence
                    "T1555",      # Credentials from Password Stores
                    "T1555.003",  # Credentials from Web Browsers
                    "T1020",      # Automated Exfiltration
                ],
                "objectives": ["Credential theft", "Espionage", "Long-term access"],
                "ttps": ["T1566.002", "T1059.001", "T1547.001", "T1555", "T1555.003", "T1020"],
                "target_sectors": ["Government", "Military", "Political organizations"],
                "tools_used": ["X-Agent", "X-Tunnel", "Mimikatz"],
                "is_builtin": True,
            },
            {
                "name": "FIN7",
                "description": "Financially motivated threat group targeting retail and hospitality",
                "sophistication": "advanced",
                "attack_chain": [
                    "T1566.002",  # Phishing with malware
                    "T1203",      # Exploitation
                    "T1547.001",  # Registry Run Keys
                    "T1021.001",  # Remote Desktop Protocol
                    "T1110.001",  # Brute force
                    "T1005",      # Data from Local System
                    "T1048.003",  # Exfiltration Over DNS
                ],
                "objectives": ["POS system access", "Payment data theft", "Financial gain"],
                "ttps": ["T1566.002", "T1203", "T1547.001", "T1021.001", "T1110.001", "T1048.003"],
                "target_sectors": ["Retail", "Hospitality", "Financial"],
                "tools_used": ["Carbanak", "Anunak", "Custom tools"],
                "is_builtin": True,
            },
            {
                "name": "Lazarus Group",
                "description": "North Korean threat group with focus on financial institutions and cryptocurrency",
                "sophistication": "apt",
                "attack_chain": [
                    "T1566.002",  # Phishing
                    "T1203",      # Exploitation
                    "T1574.001",  # DLL Search Order Hijacking
                    "T1021.001",  # RDP
                    "T1005",      # Local data exfiltration
                    "T1048.001",  # Exfiltration Over C2
                ],
                "objectives": ["Financial theft", "Cryptocurrency theft", "System disruption"],
                "ttps": ["T1566.002", "T1203", "T1574.001", "T1021.001", "T1048.001"],
                "target_sectors": ["Financial services", "Cryptocurrency exchanges", "Government"],
                "tools_used": ["MATA framework", "Destover", "Hidden Cobra tools"],
                "is_builtin": True,
            },
            {
                "name": "Generic Ransomware Actor",
                "description": "Generic ransomware deployment pattern",
                "sophistication": "intermediate",
                "attack_chain": [
                    "T1566.001",  # Phishing with attachment
                    "T1204.002",  # User Execution
                    "T1059.001",  # PowerShell
                    "T1547.001",  # Persistence
                    "T1021.001",  # Lateral Movement RDP
                    "T1486",      # Data encrypted for impact
                ],
                "objectives": ["Data encryption", "Ransom demand", "Extortion"],
                "ttps": ["T1566.001", "T1204.002", "T1059.001", "T1547.001", "T1021.001", "T1486"],
                "target_sectors": ["All sectors"],
                "tools_used": ["Living off the land binaries", "Ransomware variants"],
                "is_builtin": True,
            },
        ]

        count = 0
        for profile_data in builtin_profiles:
            # Check if already exists
            stmt = select(AdversaryProfile).where(AdversaryProfile.name == profile_data["name"])
            result = await self.session.execute(stmt)
            if result.scalar_one_or_none():
                continue

            profile = AdversaryProfile(
                id=generate_uuid(),
                name=profile_data["name"],
                description=profile_data.get("description"),
                sophistication=profile_data.get("sophistication", "intermediate"),
                attack_chain=profile_data.get("attack_chain", []),
                objectives=profile_data.get("objectives", []),
                ttps=profile_data.get("ttps", []),
                target_sectors=profile_data.get("target_sectors", []),
                tools_used=profile_data.get("tools_used", []),
                is_builtin=profile_data.get("is_builtin", True),
                organization_id=None,  # Built-in profiles are global reference data
                created_at=utc_now(),
                updated_at=utc_now(),
            )
            self.session.add(profile)
            count += 1

        await self.session.commit()
        logger.info(f"Loaded {count} built-in adversary profiles")
        return count

    async def create_emulation_plan(
        self,
        adversary_id: str,
        organization_id: Optional[str],
        created_by: str,
    ) -> AttackSimulation:
        """Create an attack simulation based on an adversary profile.

        ``created_by`` must be a real user id — attack_simulations.created_by
        is an FK into the users table. Previously this method hardcoded
        "system" which violated the FK and blew up every emulation.
        """
        stmt = select(AdversaryProfile).where(AdversaryProfile.id == adversary_id)
        result = await self.session.execute(stmt)
        profile = result.scalar_one_or_none()

        if not profile:
            raise ValueError(f"Adversary profile {adversary_id} not found")

        orchestrator = SimulationOrchestrator(self.session)
        simulation = await orchestrator.create_simulation(
            name=f"{profile.name} Emulation Plan",
            sim_type="adversary_emulation",
            techniques=profile.ttps,
            scope={"target": "lab_environment"},
            target_environment="lab",
            created_by=created_by,
            organization_id=organization_id,
            description=f"Emulation of {profile.name} attack patterns: {', '.join(profile.objectives)}"
        )

        return simulation

    async def get_attack_chain(self, adversary_id: str) -> List[Dict[str, Any]]:
        """Get the ordered attack chain for an adversary."""
        stmt = select(AdversaryProfile).where(AdversaryProfile.id == adversary_id)
        result = await self.session.execute(stmt)
        profile = result.scalar_one_or_none()

        if not profile:
            raise ValueError(f"Adversary profile {adversary_id} not found")

        chain = []
        for i, tech_id in enumerate(profile.attack_chain):
            technique = await self.atomic_library.get_technique(tech_id)
            if technique:
                chain.append({
                    "order": i + 1,
                    "mitre_id": technique.mitre_id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                    "description": technique.description,
                })

        return chain


class PostureScorer:
    """
    Calculates security posture scores and provides gap analysis.

    Evaluates detection coverage, prevention effectiveness, and response capabilities.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def calculate_posture_score(self, simulation_id: str) -> SecurityPostureScore:
        """
        Calculate overall security posture score for a simulation.

        Args:
            simulation_id: ID of completed simulation

        Returns:
            SecurityPostureScore object
        """
        simulation = await self._get_simulation(simulation_id)
        if not simulation:
            raise ValueError(f"Simulation {simulation_id} not found")

        # Get all tests
        stmt = select(SimulationTest).where(SimulationTest.simulation_id == simulation_id)
        result = await self.session.execute(stmt)
        tests = result.scalars().all()

        if not tests:
            score = 0.0
            breakdown = {}
        else:
            detected_count = sum(1 for t in tests if t.was_detected)
            total_count = len(tests)
            detection_score = (detected_count / total_count * 100) if total_count > 0 else 0

            # Calculate tactic-based scores
            tactic_scores = {}
            for tactic in simulation.mitre_tactics:
                tactic_tests = [t for t in tests if hasattr(t, 'technique_id')]
                if tactic_tests:
                    tactic_detected = sum(1 for t in tactic_tests if t.was_detected)
                    tactic_scores[tactic] = (tactic_detected / len(tactic_tests) * 100)

            score = detection_score
            breakdown = {
                "detection_rate": detection_score,
                "by_tactic": tactic_scores,
                "tests_detected": detected_count,
                "tests_total": total_count,
            }

        posture_score = SecurityPostureScore(
            id=generate_uuid(),
            simulation_id=simulation_id,
            score_type="overall",
            score=score,
            max_score=100.0,
            breakdown=breakdown,
            assessed_at=utc_now(),
            organization_id=simulation.organization_id,
            created_at=utc_now(),
            updated_at=utc_now(),
        )

        self.session.add(posture_score)
        await self.session.commit()
        return posture_score

    async def generate_gap_analysis(self, simulation_id: str) -> List[Dict[str, Any]]:
        """
        Generate gap analysis identifying undetected techniques.

        Args:
            simulation_id: ID of simulation to analyze

        Returns:
            List of undetected techniques with recommendations
        """
        stmt = select(SimulationTest).where(SimulationTest.simulation_id == simulation_id)
        result = await self.session.execute(stmt)
        tests = result.scalars().all()

        gaps = []
        for test in tests:
            if not test.was_detected and test.status in ["passed", "failed", "blocked"]:
                technique = await self._get_technique(test.technique_id)
                if technique:
                    gaps.append({
                        "mitre_id": technique.mitre_id,
                        "technique_name": technique.name,
                        "tactic": technique.tactic,
                        "risk_level": technique.risk_level,
                        "detection_sources": technique.detection_sources,
                        "expected_detection": technique.expected_detection,
                        "recommendation": f"Implement detection rules for {technique.name} (MITRE {technique.mitre_id})"
                    })

        return sorted(gaps, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["risk_level"], 4))

    async def compare_scores(self, current_id: str, previous_id: str) -> Dict[str, Any]:
        """Compare two security posture scores to identify improvements or regressions."""
        current = await self._get_score(current_id)
        previous = await self._get_score(previous_id)

        if not current or not previous:
            raise ValueError("One or both scores not found")

        delta = current.score - previous.score
        improvement = delta > 0

        return {
            "current_score": current.score,
            "previous_score": previous.score,
            "delta": delta,
            "improvement": improvement,
            "change_percent": (delta / max(previous.score, 1)) * 100,
        }

    async def generate_executive_report(self, simulation_id: str) -> Dict[str, Any]:
        """Generate comprehensive executive report for a simulation."""
        simulation = await self._get_simulation(simulation_id)
        if not simulation:
            raise ValueError(f"Simulation {simulation_id} not found")

        posture_score = await self.calculate_posture_score(simulation_id)
        gaps = await self.generate_gap_analysis(simulation_id)

        return {
            "simulation_name": simulation.name,
            "simulation_id": simulation.id,
            "overall_score": posture_score.score,
            "total_tests": simulation.total_tests,
            "tests_detected": simulation.blocked_tests,
            "detection_rate_percent": ((simulation.blocked_tests / max(simulation.total_tests, 1)) * 100),
            "techniques_assessed": len(simulation.mitre_techniques),
            "tactics_covered": simulation.mitre_tactics,
            "undetected_gaps": len(gaps),
            "critical_gaps": len([g for g in gaps if g["risk_level"] == "critical"]),
            "top_recommendations": [g["recommendation"] for g in gaps[:5]],
            "assessed_at": posture_score.assessed_at.isoformat(),
        }

    async def _get_simulation(self, simulation_id: str) -> Optional[AttackSimulation]:
        """Helper to fetch a simulation by ID."""
        stmt = select(AttackSimulation).where(AttackSimulation.id == simulation_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_score(self, score_id: str) -> Optional[SecurityPostureScore]:
        """Helper to fetch a score by ID."""
        stmt = select(SecurityPostureScore).where(SecurityPostureScore.id == score_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_technique(self, technique_id: str) -> Optional[AttackTechnique]:
        """Helper to fetch a technique by ID."""
        stmt = select(AttackTechnique).where(AttackTechnique.id == technique_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
