"""
REST API endpoints for Breach & Attack Simulation (BAS) engine.

Provides endpoints for simulation management, technique discovery,
adversary emulation, and security posture assessment.
"""

from typing import Annotated, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy import or_, select as sa_select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db as get_async_session
from src.core.logging import get_logger
from src.services.automation import AutomationService
from src.api.deps import (
    get_current_active_user as get_current_user,
    CurrentUser,
    DatabaseSession,
    OrganizationId,
    require_role,
)
from src.models.user import User, UserRole
from src.simulation.engine import (
    SimulationOrchestrator,
    AtomicTestLibrary,
    AdversaryEmulator,
    PostureScorer,
)
from src.simulation.models import (
    AttackSimulation,
    AttackTechnique,
    AdversaryProfile,
    SecurityPostureScore,
)
from src.schemas.simulation import (
    AttackSimulationSchema,
    AttackTechniqueSchema,
    AdversaryProfileSchema,
    SecurityPostureScoreSchema,
    SimulationTestSchema,
    SimulationCreateRequest,
    SimulationProgressResponse,
    PostureScoreResponse,
    GapAnalysisResponse,
    GapAnalysisItem,
    SimulationDetailResponse,
    SimulationReportResponse,
    SimulationListResponse,
    TechniqueListResponse,
    AdversaryListResponse,
    AdversaryEmulationPlanResponse,
    AttackChainItem,
    DashboardStatsResponse,
    TacticPostureItem,
    TacticPostureResponse,
)
from src.simulation.tasks import (
    execute_simulation,
    calculate_posture_scores,
    generate_simulation_report,
    cleanup_simulation_artifacts,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/simulation", tags=["simulation"])

# Role gates. Viewers are read-only. Analysts create and steer simulations;
# anything that executes atomic tests on live endpoints is admin-only.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminOnlyUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


async def _get_org_simulation(
    session: AsyncSession, simulation_id: str, org_id: str,
) -> AttackSimulation:
    """The caller's simulation, or 404 (also for another tenant's id)."""
    simulation = (
        await session.execute(
            sa_select(AttackSimulation).where(
                AttackSimulation.id == simulation_id,
                AttackSimulation.organization_id == org_id,
            ),
        )
    ).scalar_one_or_none()
    if simulation is None:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return simulation


def _visible_adversary(org_id: str):
    """Adversary profiles a tenant may see: global built-ins plus its own."""
    return or_(
        AdversaryProfile.organization_id == org_id,
        AdversaryProfile.organization_id.is_(None),
    )


# ==================== TARGETS (real enrolled BAS agents) ====================

@router.get("/targets")
async def list_bas_targets(
    org_id: OrganizationId,
    session: DatabaseSession = None,
) -> list[dict]:
    """List active, BAS-capable endpoint agents enrolled in this org.

    The AttackSimulation UI uses this to populate the "target host"
    picker so users can only run real tests against real agents.
    Returns [] when no BAS-capable agent is enrolled; the UI renders a
    "coverage-only mode" banner in that case instead of silently
    defaulting to a non-existent hostname.
    """
    from sqlalchemy import select as _sel
    from src.agents.capabilities import AgentCapability
    from src.agents.models import EndpointAgent

    stmt = _sel(EndpointAgent).where(
        EndpointAgent.status == "active",
        EndpointAgent.organization_id == org_id,
    )
    rows = list((await session.execute(stmt)).scalars().all())

    targets = []
    for a in rows:
        caps = a.capabilities or []
        if AgentCapability.BAS.value not in caps:
            continue
        targets.append({
            "id": a.id,
            "hostname": a.hostname,
            "capabilities": caps,
            "last_checkin": a.last_checkin.isoformat() if getattr(a, "last_checkin", None) else None,
            "os_type": getattr(a, "os_type", None),
        })
    return targets


# ==================== SIMULATIONS ====================

@router.post("/simulations")
async def create_simulation(
    request: SimulationCreateRequest,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    session: DatabaseSession = None,
):
    """Create a new attack simulation."""
    try:
        orchestrator = SimulationOrchestrator(session)
        simulation = await orchestrator.create_simulation(
            name=request.name,
            sim_type=request.simulation_type,
            techniques=request.techniques,
            scope=request.scope,
            target_environment=request.target_environment,
            created_by=str(current_user.id),
            organization_id=org_id,
            description=request.description,
            tags=request.tags,
        )

        # Return as dict to avoid response_model serialization issues
        return {
            "id": simulation.id,
            "name": simulation.name,
            "description": simulation.description,
            "simulation_type": simulation.simulation_type,
            "status": simulation.status,
            "target_environment": simulation.target_environment,
            "created_by": simulation.created_by,
            "organization_id": simulation.organization_id,
            "created_at": str(simulation.created_at),
            "updated_at": str(simulation.updated_at),
        }

    except Exception as e:
        logger.error(f"Error creating simulation: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Failed to create simulation: {str(e)[:200]}")


@router.get("/simulations", response_model=SimulationListResponse)
async def list_simulations(
    org_id: OrganizationId,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    environment: Optional[str] = None,
    session: DatabaseSession = None,
) -> SimulationListResponse:
    """
    List simulations with filtering.

    Args:
        skip: Number of records to skip
        limit: Maximum records to return
        status: Filter by status
        environment: Filter by target environment
        session: Database session
        current_user: Current user ID

    Returns:
        List of simulations
    """
    try:
        from sqlalchemy import select, and_, func

        stmt = select(AttackSimulation)

        # Add filters
        filters = [AttackSimulation.organization_id == org_id]
        if status:
            filters.append(AttackSimulation.status == status)
        if environment:
            filters.append(AttackSimulation.target_environment == environment)

        stmt = stmt.where(and_(*filters))

        # Get total count with proper query
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_result = await session.execute(count_stmt)
        total = total_result.scalar() or 0

        result = await session.execute(stmt.offset(skip).limit(limit))
        simulations = result.scalars().all()

        return SimulationListResponse(
            total=total,
            page=skip // limit,
            page_size=limit,
            simulations=[AttackSimulationSchema.model_validate(s) for s in simulations],
        )

    except Exception as e:
        logger.error(f"Error listing simulations: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/simulations/{simulation_id}", response_model=SimulationDetailResponse)
async def get_simulation_detail(
    simulation_id: str,
    org_id: OrganizationId,
    session: DatabaseSession = None,
) -> SimulationDetailResponse:
    """
    Get detailed simulation information with test results.

    Args:
        simulation_id: ID of simulation
        session: Database session
        current_user: Current user ID

    Returns:
        Detailed simulation with all test results
    """
    try:
        from sqlalchemy import select

        # Get simulation
        simulation = await _get_org_simulation(session, simulation_id, org_id)

        # Get tests
        from src.simulation.models import SimulationTest
        stmt = select(SimulationTest).where(SimulationTest.simulation_id == simulation_id)
        result = await session.execute(stmt)
        tests = result.scalars().all()

        # Get posture score
        stmt = select(SecurityPostureScore).where(
            SecurityPostureScore.simulation_id == simulation_id
        ).order_by(SecurityPostureScore.created_at.desc())
        result = await session.execute(stmt)
        posture_score = result.scalar_one_or_none()

        return SimulationDetailResponse(
            simulation=AttackSimulationSchema.model_validate(simulation),
            tests=[SimulationTestSchema.model_validate(t) for t in tests],
            posture_score=SecurityPostureScoreSchema.model_validate(posture_score) if posture_score else None,
            execution_summary={
                "total_tests": simulation.total_tests,
                "passed_tests": simulation.passed_tests,
                "failed_tests": simulation.failed_tests,
                "blocked_tests": simulation.blocked_tests,
                "detection_rate": simulation.detection_rate,
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting simulation detail: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.post("/simulations/{simulation_id}/start")
async def start_simulation(
    simulation_id: str,
    org_id: OrganizationId,
    current_user: AdminOnlyUser = None,
    session: DatabaseSession = None,
) -> dict:
    """
    Start executing a simulation.

    Args:
        simulation_id: ID of simulation to start
        session: Database session
        current_user: Current user ID

    Returns:
        Execution start status
    """
    await _get_org_simulation(session, simulation_id, org_id)
    try:
        orchestrator = SimulationOrchestrator(session)
        result = await orchestrator.start_simulation(simulation_id)

        # Queue async execution task
        execute_simulation.delay(simulation_id, org_id)

        return result

    except Exception as e:
        logger.error(f"Error starting simulation: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.post("/simulations/{simulation_id}/pause")
async def pause_simulation(
    simulation_id: str,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    session: DatabaseSession = None,
) -> dict:
    """
    Pause a running simulation.

    Args:
        simulation_id: ID of simulation to pause
        session: Database session
        current_user: Current user ID

    Returns:
        Success message
    """
    await _get_org_simulation(session, simulation_id, org_id)
    try:
        orchestrator = SimulationOrchestrator(session)
        await orchestrator.pause_simulation(simulation_id)
        return {"status": "paused", "simulation_id": simulation_id}

    except Exception as e:
        logger.error(f"Error pausing simulation: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.post("/simulations/{simulation_id}/cancel")
async def cancel_simulation(
    simulation_id: str,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    session: DatabaseSession = None,
) -> dict:
    """
    Cancel a simulation.

    Args:
        simulation_id: ID of simulation to cancel
        session: Database session
        current_user: Current user ID

    Returns:
        Success message
    """
    await _get_org_simulation(session, simulation_id, org_id)
    try:
        orchestrator = SimulationOrchestrator(session)
        await orchestrator.cancel_simulation(simulation_id)
        return {"status": "cancelled", "simulation_id": simulation_id}

    except Exception as e:
        logger.error(f"Error cancelling simulation: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/simulations/{simulation_id}/progress", response_model=SimulationProgressResponse)
async def get_simulation_progress(
    simulation_id: str,
    org_id: OrganizationId,
    session: DatabaseSession = None,
) -> SimulationProgressResponse:
    """
    Get live progress of a running simulation.

    Args:
        simulation_id: ID of simulation
        session: Database session
        current_user: Current user ID

    Returns:
        Progress information
    """
    await _get_org_simulation(session, simulation_id, org_id)
    try:
        orchestrator = SimulationOrchestrator(session)
        progress = await orchestrator.get_simulation_progress(simulation_id)
        return SimulationProgressResponse(**progress)

    except Exception as e:
        logger.error(f"Error getting progress: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/simulations/{simulation_id}/report", response_model=SimulationReportResponse)
async def get_simulation_report(
    simulation_id: str,
    org_id: OrganizationId,
    session: DatabaseSession = None,
) -> SimulationReportResponse:
    """
    Get detailed simulation report.

    Args:
        simulation_id: ID of simulation
        session: Database session
        current_user: Current user ID

    Returns:
        Executive report
    """
    await _get_org_simulation(session, simulation_id, org_id)
    try:
        scorer = PostureScorer(session)
        report = await scorer.generate_executive_report(simulation_id)
        return SimulationReportResponse(**report)

    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== TECHNIQUES ====================

@router.get("/techniques", response_model=TechniqueListResponse)
async def list_techniques(
    org_id: OrganizationId,
    tactic: Optional[str] = None,
    platform: Optional[str] = None,
    risk_level: Optional[str] = None,
    safe_only: bool = False,
    session: DatabaseSession = None,
) -> TechniqueListResponse:
    """
    Browse technique library with filtering.

    Args:
        tactic: Filter by MITRE tactic
        platform: Filter by platform (windows, linux, macos)
        risk_level: Filter by risk level
        safe_only: Return only production-safe techniques
        session: Database session
        current_user: Current user ID

    Returns:
        List of techniques with facets
    """
    try:
        from sqlalchemy import select
        library = AtomicTestLibrary(session)

        # Ensure techniques are loaded
        await library.load_builtin_techniques()

        if safe_only:
            techniques = await library.get_safe_techniques()
            # get_safe_techniques ignores tactic; apply it here so the two
            # filters combine instead of safe_only silently dropping tactic.
            if tactic:
                techniques = [t for t in techniques if t.tactic == tactic]
        elif tactic:
            techniques = await library.get_techniques_by_tactic(tactic)
        else:
            stmt = select(AttackTechnique)
            result = await session.execute(stmt)
            techniques = result.scalars().all()

        # Apply additional filters
        if platform:
            techniques = [t for t in techniques if platform in t.platform]
        if risk_level:
            techniques = [t for t in techniques if t.risk_level == risk_level]

        # Build facets
        tactics = {}
        for t in techniques:
            tactics[t.tactic] = tactics.get(t.tactic, 0) + 1

        return TechniqueListResponse(
            total=len(techniques),
            techniques=[AttackTechniqueSchema.model_validate(t) for t in techniques],
            facets={
                "by_tactic": tactics,
                "by_risk_level": {},
            }
        )

    except Exception as e:
        logger.error(f"Error listing techniques: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/techniques/{mitre_id}", response_model=AttackTechniqueSchema)
async def get_technique(
    mitre_id: str,
    org_id: OrganizationId,
    session: DatabaseSession = None,
) -> AttackTechniqueSchema:
    """
    Get technique details.

    Args:
        mitre_id: MITRE technique ID (e.g., T1059.001)
        session: Database session
        current_user: Current user ID

    Returns:
        Technique details
    """
    try:
        library = AtomicTestLibrary(session)
        technique = await library.get_technique(mitre_id)

        if not technique:
            raise HTTPException(status_code=404, detail="Technique not found")

        return AttackTechniqueSchema.model_validate(technique)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting technique: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.post("/techniques/{mitre_id}/test")
async def test_technique(
    mitre_id: str,
    org_id: OrganizationId,
    current_user: AdminOnlyUser = None,
    payload: Optional[dict] = Body(default=None),
    session: DatabaseSession = None,
) -> dict:
    """
    Run a single-technique simulation end-to-end synchronously.

    The frontend "Run Test" button posts with no body, so ``payload`` is
    optional. A target host may be provided in ``payload["target_host"]``;
    when omitted, the engine picks any active BAS-capable agent for this
    org. The old ``"lab-target"`` default silently sent every test to the
    coverage-only path because no agent has that hostname.

    If the technique is NOT covered by any detection rule, we fire
    on_simulation_result so the agentic SOC pipeline can generate a
    mitigation recommendation or a hunt task.
    """
    try:
        library = AtomicTestLibrary(session)
        technique = await library.get_technique(mitre_id)

        if not technique:
            raise HTTPException(status_code=404, detail="Technique not found")

        target_host: Optional[str] = None
        if isinstance(payload, dict) and payload.get("target_host"):
            target_host = str(payload["target_host"])

        orchestrator = SimulationOrchestrator(session)
        scope: dict = {}
        if target_host:
            scope["target_host"] = target_host
        simulation = await orchestrator.create_simulation(
            name=f"Single Test: {mitre_id}",
            sim_type="atomic_test",
            techniques=[mitre_id],
            scope=scope,
            target_environment="lab",
            created_by=str(current_user.id),
            organization_id=org_id,
        )

        await orchestrator.start_simulation(simulation.id)

        # Execute the tests synchronously (single technique, fast) so the
        # caller gets a real result instead of "executing".
        from src.simulation.models import SimulationTest
        from sqlalchemy import select as _sel
        tests_q = _sel(SimulationTest).where(
            SimulationTest.simulation_id == simulation.id
        )
        tests = list((await session.execute(tests_q)).scalars().all())
        detected_any = False
        for t in tests:
            try:
                await orchestrator._execute_test(t)
                if t.was_detected:
                    detected_any = True
            except Exception as test_exc:  # noqa: BLE001
                logger.error(f"Failed to execute test {t.id}: {test_exc}")

        # Fire automation ONLY on real defender miss — i.e. not a single
        # detection rule claims to cover this technique.
        if not detected_any:
            try:
                automation = AutomationService(session)
                await automation.on_simulation_result(
                    technique_id=technique.mitre_id,
                    technique_name=technique.name,
                    result="undetected",
                    organization_id=org_id,
                )
            except Exception as e:  # noqa: BLE001
                logger.error(f"Automation on_simulation_result failed: {e}")

        # Roll up: set simulation.status=completed/failed + aggregate counts.
        roll = await orchestrator.finalize_simulation(simulation.id)

        # Reload tests to pick up execution_mode stamp from _execute_test.
        tests = list((await session.execute(tests_q)).scalars().all())
        execution_mode = "real"
        for t in tests:
            if (t.detection_details or {}).get("execution_mode") == "coverage_only":
                execution_mode = "coverage_only"
                break

        # Reload the sim so scope reflects any host-fallback stamping
        # the engine did when target_host missed.
        sim_final = await orchestrator._get_simulation(simulation.id)
        actual_target_host = None
        if sim_final and isinstance(sim_final.scope, dict):
            actual_target_host = (
                sim_final.scope.get("actual_target_host")
                or sim_final.scope.get("target_host")
            )

        return {
            "simulation_id": simulation.id,
            "status": roll["status"],
            "technique": mitre_id,
            "target_host": target_host,
            "actual_target_host": actual_target_host,
            "execution_mode": execution_mode,
            "detected": detected_any,
            "tests_executed": len(tests),
            "detection_rate": roll["detection_rate"],
            "overall_score": roll["overall_score"],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error testing technique: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== ADVERSARY EMULATION ====================

@router.get("/adversaries", response_model=AdversaryListResponse)
async def list_adversaries(
    org_id: OrganizationId,
    builtin_only: bool = False,
    session: DatabaseSession = None,
) -> AdversaryListResponse:
    """
    List adversary profiles.

    Args:
        builtin_only: Show only built-in profiles
        session: Database session
        current_user: Current user ID

    Returns:
        List of adversary profiles
    """
    try:
        from sqlalchemy import select

        emulator = AdversaryEmulator(session)
        await emulator.load_builtin_profiles()

        stmt = select(AdversaryProfile).where(_visible_adversary(org_id))
        if builtin_only:
            stmt = stmt.where(AdversaryProfile.is_builtin == True)

        result = await session.execute(stmt)
        adversaries = result.scalars().all()

        return AdversaryListResponse(
            total=len(adversaries),
            adversaries=[AdversaryProfileSchema.model_validate(a) for a in adversaries],
        )

    except Exception as e:
        logger.error(f"Error listing adversaries: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/adversaries/{adversary_id}", response_model=AdversaryProfileSchema)
async def get_adversary(
    adversary_id: str,
    org_id: OrganizationId,
    session: DatabaseSession = None,
) -> AdversaryProfileSchema:
    """
    Get adversary profile details.

    Args:
        adversary_id: ID of adversary
        session: Database session
        current_user: Current user ID

    Returns:
        Adversary profile
    """
    try:
        from sqlalchemy import select

        stmt = select(AdversaryProfile).where(
            AdversaryProfile.id == adversary_id, _visible_adversary(org_id),
        )
        result = await session.execute(stmt)
        adversary = result.scalar_one_or_none()

        if not adversary:
            raise HTTPException(status_code=404, detail="Adversary not found")

        return AdversaryProfileSchema.model_validate(adversary)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting adversary: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.post("/adversaries/{adversary_id}/emulate", response_model=SimulationDetailResponse)
async def create_emulation_plan(
    adversary_id: str,
    org_id: OrganizationId,
    current_user: AdminOnlyUser = None,
    session: DatabaseSession = None,
) -> SimulationDetailResponse:
    """
    Create an attack simulation emulating an adversary.

    Args:
        adversary_id: ID of adversary to emulate
        session: Database session
        current_user: Current user ID

    Returns:
        Created simulation
    """
    visible = (
        await session.execute(
            sa_select(AdversaryProfile.id).where(
                AdversaryProfile.id == adversary_id, _visible_adversary(org_id),
            ),
        )
    ).scalar_one_or_none()
    if visible is None:
        raise HTTPException(status_code=404, detail="Adversary not found")
    try:
        emulator = AdversaryEmulator(session)
        simulation = await emulator.create_emulation_plan(
            adversary_id,
            org_id,
            created_by=str(current_user.id),
        )

        # Actually run the plan — previously the button just created a
        # draft record and pretended the simulation was underway.
        orchestrator = SimulationOrchestrator(session)
        try:
            await orchestrator.start_simulation(simulation.id)
        except Exception as start_exc:  # noqa: BLE001
            logger.warning(f"start_simulation failed for {simulation.id}: {start_exc}")

        # Execute all of the plan's tests in-process so the user sees real
        # pass/fail numbers immediately. Adversary chains are 8-11 techniques
        # and the scoring is a cheap DB lookup, so this is fast.
        from src.simulation.models import SimulationTest
        from sqlalchemy import select as _sel
        tests = list((await session.execute(
            _sel(SimulationTest).where(SimulationTest.simulation_id == simulation.id)
        )).scalars().all())

        for t in tests:
            try:
                await orchestrator._execute_test(t)
            except Exception as test_exc:  # noqa: BLE001
                logger.error(f"Failed to execute emulation test {t.id}: {test_exc}")

        # Roll up counts + set completed/failed via the shared helper so
        # every code path produces the same aggregate semantics.
        await orchestrator.finalize_simulation(simulation.id)

        await session.flush()
        await session.refresh(simulation)
        tests = list((await session.execute(
            _sel(SimulationTest).where(SimulationTest.simulation_id == simulation.id)
        )).scalars().all())

        return SimulationDetailResponse(
            simulation=AttackSimulationSchema.model_validate(simulation),
            tests=[SimulationTestSchema.model_validate(t) for t in tests],
            execution_summary={
                "status": "completed",
                "total_tests": len(tests),
                "passed_tests": simulation.passed_tests,
                "failed_tests": simulation.failed_tests,
                "blocked_tests": simulation.blocked_tests,
                "detection_rate": simulation.detection_rate,
            },
        )

    except Exception as e:
        logger.error(f"Error creating emulation plan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== SECURITY POSTURE ====================

@router.get("/posture", response_model=PostureScoreResponse)
async def get_current_posture(
    org_id: OrganizationId,
    session: DatabaseSession = None,
) -> PostureScoreResponse:
    """
    Get current security posture score.

    Args:
        session: Database session
        current_user: Current user ID

    Returns:
        Current posture score
    """
    try:
        from sqlalchemy import select, desc

        # Scoped to the caller's org so another tenant's score never shows here.
        stmt = (
            select(SecurityPostureScore)
            .where(SecurityPostureScore.organization_id == org_id)
            .order_by(desc(SecurityPostureScore.assessed_at))
            .limit(1)
        )
        result = await session.execute(stmt)
        score = result.scalar_one_or_none()

        if not score:
            # No assessment has run yet. score=None (not 0) so the page says
            # "not available" instead of presenting an invented 0/100.
            return PostureScoreResponse(
                score_type="overall",
                score=None,
                max_score=100.0,
                breakdown={},
                recommendations=[],
            )

        return PostureScoreResponse(
            simulation_id=score.simulation_id,
            score_type=score.score_type,
            score=score.score,
            max_score=score.max_score,
            breakdown=score.breakdown,
            assessed_at=score.assessed_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting posture: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/posture/by-tactic", response_model=TacticPostureResponse)
async def get_posture_by_tactic(
    org_id: OrganizationId,
    session: DatabaseSession = None,
) -> TacticPostureResponse:
    """Per-tactic detection posture computed from this org's completed runs.

    Every MITRE tactic present in the technique library is listed. For each,
    the detection rate is the share of this organisation's executed
    simulation tests (completed runs) for techniques in that tactic that the
    detection pipeline caught. Tactics with no executed test are reported
    ``not_assessed`` with ``detection_rate=None`` — never an invented 0%.
    """
    from sqlalchemy import func, select

    from src.simulation.models import SimulationTest

    # Universe of tactics = every tactic in the technique catalogue.
    tactics_stmt = select(AttackTechnique.tactic).distinct()
    all_tactics = [t for (t,) in (await session.execute(tactics_stmt)).all() if t]

    # Executed tests per tactic for this org's completed simulations.
    detected_count = func.count(SimulationTest.id).filter(
        SimulationTest.was_detected.is_(True),
    )
    rows_stmt = (
        select(
            AttackTechnique.tactic,
            func.count(SimulationTest.id).label("total"),
            detected_count.label("detected"),
        )
        .select_from(SimulationTest)
        .join(AttackTechnique, SimulationTest.technique_id == AttackTechnique.id)
        .join(AttackSimulation, SimulationTest.simulation_id == AttackSimulation.id)
        .where(
            AttackSimulation.status == "completed",
            AttackSimulation.organization_id == org_id,
        )
        .group_by(AttackTechnique.tactic)
    )
    rows = (await session.execute(rows_stmt)).all()
    counts = {
        tactic: (int(total or 0), int(detected or 0))
        for tactic, total, detected in rows
    }

    items: list[TacticPostureItem] = []
    assessed = 0
    for tactic in sorted(all_tactics):
        total, detected = counts.get(tactic, (0, 0))
        if total > 0:
            assessed += 1
            items.append(
                TacticPostureItem(
                    tactic=tactic,
                    status="assessed",
                    tests_total=total,
                    tests_detected=detected,
                    detection_rate=round((detected / total) * 100.0, 1),
                ),
            )
        else:
            items.append(
                TacticPostureItem(
                    tactic=tactic,
                    status="not_assessed",
                    tests_total=0,
                    tests_detected=0,
                    detection_rate=None,
                ),
            )

    return TacticPostureResponse(
        tactics=items,
        assessed_tactics=assessed,
        not_assessed_tactics=len(items) - assessed,
    )


@router.get("/posture/gaps", response_model=GapAnalysisResponse)
async def get_gap_analysis(
    org_id: OrganizationId,
    simulation_id: Optional[str] = None,
    session: DatabaseSession = None,
) -> GapAnalysisResponse:
    """
    Get gap analysis for simulation.

    Args:
        simulation_id: ID of simulation (uses latest if not specified)
        session: Database session
        current_user: Current user ID

    Returns:
        Gap analysis with recommendations
    """
    try:
        from sqlalchemy import select, desc

        if not simulation_id:
            stmt = (
                select(AttackSimulation)
                .where(AttackSimulation.organization_id == org_id)
                .order_by(desc(AttackSimulation.completed_at).nullslast())
                .limit(1)
            )
            result = await session.execute(stmt)
            simulation = result.scalar_one_or_none()
            if not simulation:
                raise HTTPException(status_code=404, detail="No simulations found")
            simulation_id = simulation.id
        else:
            await _get_org_simulation(session, simulation_id, org_id)

        scorer = PostureScorer(session)
        gaps = await scorer.generate_gap_analysis(simulation_id)

        # Count by risk level
        critical = sum(1 for g in gaps if g["risk_level"] == "critical")
        high = sum(1 for g in gaps if g["risk_level"] == "high")
        medium = sum(1 for g in gaps if g["risk_level"] == "medium")
        low = sum(1 for g in gaps if g["risk_level"] == "low")

        return GapAnalysisResponse(
            simulation_id=simulation_id,
            total_gaps=len(gaps),
            critical_gaps=critical,
            high_gaps=high,
            medium_gaps=medium,
            low_gaps=low,
            gaps=[GapAnalysisItem(**g) for g in gaps],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting gap analysis: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== DASHBOARD ====================

@router.get("/dashboard", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    org_id: OrganizationId,
    session: DatabaseSession = None,
) -> DashboardStatsResponse:
    """
    Get BAS dashboard statistics and recent activity.

    Args:
        session: Database session
        current_user: Current user ID

    Returns:
        Dashboard statistics
    """
    try:
        from sqlalchemy import select, func, desc, and_
        from src.simulation.models import SimulationTest

        # Make sure the built-in technique catalog AND adversary profiles
        # are loaded so the dashboard counts aren't 0 on a cold database.
        # Both loaders are idempotent (skip rows that already exist).
        try:
            await AtomicTestLibrary(session).load_builtin_techniques()
            await AdversaryEmulator(session).load_builtin_profiles()
        except Exception as load_exc:  # noqa: BLE001
            logger.warning(f"Builtin BAS loader failed on dashboard: {load_exc}")

        def _org(q):
            return q.where(AttackSimulation.organization_id == org_id)

        # Count simulations by status (scoped to org)
        total_sims = (await session.execute(_org(select(func.count(AttackSimulation.id))))).scalar() or 0
        completed = (await session.execute(
            _org(select(func.count(AttackSimulation.id))).where(AttackSimulation.status == "completed")
        )).scalar() or 0
        running = (await session.execute(
            _org(select(func.count(AttackSimulation.id))).where(AttackSimulation.status == "running")
        )).scalar() or 0

        # Library-level counts: techniques are a global catalogue; adversary
        # profiles are the global built-ins plus this org's own.
        technique_count = (await session.execute(select(func.count(AttackTechnique.id)))).scalar() or 0
        adversary_count = (await session.execute(
            select(func.count(AdversaryProfile.id)).where(_visible_adversary(org_id)),
        )).scalar() or 0

        # Averages over completed simulations for this org
        # None (not 0) when no completed run has a value, so the page can
        # say "not available" rather than report a 0% detection rate.
        avg_detection = (await session.execute(
            _org(select(func.avg(AttackSimulation.detection_rate))).where(
                AttackSimulation.status == "completed"
            )
        )).scalar()
        avg_posture = (await session.execute(
            _org(select(func.avg(AttackSimulation.overall_score))).where(
                AttackSimulation.status == "completed"
            )
        )).scalar()

        # --- Real top_tactics (detection rate per MITRE tactic) ---
        # Join SimulationTest -> AttackTechnique -> group by tactic, compute
        # detection rate = was_detected_count / total_count per tactic.
        # Using count(...).filter(...) avoids dialect-specific boolean casts.
        tactic_stmt = (
            select(
                AttackTechnique.tactic,
                func.count(SimulationTest.id).label("total"),
                func.count(SimulationTest.id).filter(
                    SimulationTest.was_detected == True  # noqa: E712
                ).label("detected"),
            )
            .select_from(SimulationTest)
            .join(AttackTechnique, SimulationTest.technique_id == AttackTechnique.id)
            .join(AttackSimulation, SimulationTest.simulation_id == AttackSimulation.id)
            .where(
                AttackSimulation.status == "completed",
                AttackSimulation.organization_id == org_id,
            )
            .group_by(AttackTechnique.tactic)
        )

        top_tactics: list[dict] = []
        tactic_result = await session.execute(tactic_stmt)
        for tactic, total, detected in tactic_result.all():
            total = int(total or 0)
            detected = int(detected or 0)
            if total > 0:
                top_tactics.append({
                    "tactic": tactic or "unknown",
                    "total": total,
                    "detection_rate": round((detected / total) * 100.0, 1),
                })
        top_tactics.sort(key=lambda x: x["detection_rate"], reverse=True)
        top_tactics = top_tactics[:10]

        # --- Real recent_simulations (last 10) ---
        # Postgres requires NULLS LAST to follow the direction, not wrap it.
        recent_stmt = _org(select(AttackSimulation)).order_by(
            AttackSimulation.completed_at.desc().nullslast(),
            AttackSimulation.created_at.desc(),
        ).limit(10)
        recent_rows = (await session.execute(recent_stmt)).scalars().all()
        recent_simulations = [AttackSimulationSchema.model_validate(s) for s in recent_rows]

        # --- Real security_trends from SecurityPostureScore history ---
        trends_stmt = (
            select(SecurityPostureScore.score)
            .where(SecurityPostureScore.organization_id == org_id)
            .order_by(desc(SecurityPostureScore.assessed_at))
            .limit(12)
        )
        trend_scores = [float(s) for s in (await session.execute(trends_stmt)).scalars().all()]
        trend_scores.reverse()  # oldest -> newest for chart consumption

        detection_trend_stmt = _org(
            select(AttackSimulation.detection_rate).where(AttackSimulation.status == "completed")
        ).order_by(desc(AttackSimulation.completed_at)).limit(12)
        detection_rates = [
            float(r or 0.0)
            for r in (await session.execute(detection_trend_stmt)).scalars().all()
        ]
        detection_rates.reverse()

        return DashboardStatsResponse(
            total_simulations=total_sims,
            completed_simulations=completed,
            running_simulations=running,
            average_detection_rate=round(float(avg_detection), 1) if avg_detection is not None else None,
            average_posture_score=round(float(avg_posture), 1) if avg_posture is not None else None,
            techniques_in_library=technique_count,
            adversary_profiles=adversary_count,
            top_tactics=top_tactics,
            recent_simulations=recent_simulations,
            security_trends={
                "scores": trend_scores,
                "detection_rates": detection_rates,
            }
        )

    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")
