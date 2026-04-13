"""
REST API endpoints for Breach & Attack Simulation (BAS) engine.

Provides endpoints for simulation management, technique discovery,
adversary emulation, and security posture assessment.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db as get_async_session
from src.core.logging import get_logger
from src.services.automation import AutomationService
from src.api.deps import get_current_active_user as get_current_user, CurrentUser, DatabaseSession
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
)
from src.simulation.tasks import (
    execute_simulation,
    calculate_posture_scores,
    generate_simulation_report,
    cleanup_simulation_artifacts,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/simulation", tags=["simulation"])


# ==================== SIMULATIONS ====================

@router.post("/simulations")
async def create_simulation(
    request: SimulationCreateRequest,
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
):
    """Create a new attack simulation."""
    try:
        org_id = getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
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

        org_id = getattr(current_user, "organization_id", None)

        stmt = select(AttackSimulation)

        # Add filters
        filters = []
        if org_id is not None:
            filters.append(AttackSimulation.organization_id == org_id)
        if status:
            filters.append(AttackSimulation.status == status)
        if environment:
            filters.append(AttackSimulation.target_environment == environment)

        if filters:
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
    current_user: CurrentUser = None,
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
        stmt = select(AttackSimulation).where(AttackSimulation.id == simulation_id)
        result = await session.execute(stmt)
        simulation = result.scalar_one_or_none()

        if not simulation:
            raise HTTPException(status_code=404, detail="Simulation not found")

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
    current_user: CurrentUser = None,
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
    try:
        org_id = getattr(current_user, "organization_id", None)
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
    current_user: CurrentUser = None,
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
    current_user: CurrentUser = None,
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
    current_user: CurrentUser = None,
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
    current_user: CurrentUser = None,
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
    current_user: CurrentUser = None,
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


@router.get("/techniques/coverage")
async def get_coverage_map(
    current_user: CurrentUser = None,
    session: DatabaseSession = None,
) -> dict:
    """
    Get detection coverage map of techniques.

    Returns which techniques are detected by existing rules.

    Args:
        session: Database session
        current_user: Current user ID

    Returns:
        Coverage map by tactic and technique
    """
    try:
        library = AtomicTestLibrary(session)
        techniques = await library.get_safe_techniques()

        coverage = {}
        for technique in techniques:
            if technique.tactic not in coverage:
                coverage[technique.tactic] = {"total": 0, "detected": 0, "techniques": []}

            coverage[technique.tactic]["total"] += 1
            detected = bool(technique.detection_sources)
            if detected:
                coverage[technique.tactic]["detected"] += 1

            coverage[technique.tactic]["techniques"].append({
                "mitre_id": technique.mitre_id,
                "name": technique.name,
                "detection_sources": technique.detection_sources,
            })

        return coverage

    except Exception as e:
        logger.error(f"Error getting coverage: {str(e)}")
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/techniques/{mitre_id}", response_model=AttackTechniqueSchema)
async def get_technique(
    mitre_id: str,
    current_user: CurrentUser = None,
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
    current_user: CurrentUser = None,
    payload: Optional[dict] = Body(default=None),
    session: DatabaseSession = None,
) -> dict:
    """
    Run a single-technique simulation end-to-end synchronously.

    The frontend "Run Test" button posts with no body, so ``payload`` is
    optional. A target host may be provided in ``payload["target_host"]``
    (defaults to "lab-target"). This endpoint creates a one-technique
    simulation, starts it, executes the coverage check in-process, and
    returns the real pass/fail result — not a fake "executing" status.

    If the technique is NOT covered by any detection rule, we fire
    on_simulation_result so the agentic SOC pipeline can generate a
    mitigation recommendation or a hunt task.
    """
    try:
        library = AtomicTestLibrary(session)
        technique = await library.get_technique(mitre_id)

        if not technique:
            raise HTTPException(status_code=404, detail="Technique not found")

        target_host = "lab-target"
        if isinstance(payload, dict) and payload.get("target_host"):
            target_host = str(payload["target_host"])

        org_id = getattr(current_user, "organization_id", None)
        orchestrator = SimulationOrchestrator(session)
        simulation = await orchestrator.create_simulation(
            name=f"Single Test: {mitre_id}",
            sim_type="atomic_test",
            techniques=[mitre_id],
            scope={"target_host": target_host},
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

        await session.flush()

        return {
            "simulation_id": simulation.id,
            "status": "completed",
            "technique": mitre_id,
            "target_host": target_host,
            "detected": detected_any,
            "tests_executed": len(tests),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error testing technique: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== ADVERSARY EMULATION ====================

@router.get("/adversaries", response_model=AdversaryListResponse)
async def list_adversaries(
    current_user: CurrentUser = None,
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

        stmt = select(AdversaryProfile)
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
    current_user: CurrentUser = None,
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

        stmt = select(AdversaryProfile).where(AdversaryProfile.id == adversary_id)
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
    current_user: CurrentUser = None,
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
    try:
        org_id = getattr(current_user, "organization_id", None)
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

        # Finalize simulation stats
        simulation.passed_tests = sum(1 for t in tests if t.was_detected)
        simulation.failed_tests = sum(1 for t in tests if not t.was_detected and t.status != "error")
        simulation.blocked_tests = sum(1 for t in tests if t.status == "error")
        if tests:
            simulation.detection_rate = (simulation.passed_tests / len(tests)) * 100
            simulation.overall_score = simulation.detection_rate
        simulation.status = "completed"
        simulation.completed_at = __import__("src.models.base", fromlist=["utc_now"]).utc_now()
        if simulation.started_at:
            simulation.duration_seconds = int(
                (simulation.completed_at - simulation.started_at).total_seconds()
            )

        await session.flush()
        await session.refresh(simulation)

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
    current_user: CurrentUser = None,
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

        stmt = select(SecurityPostureScore).order_by(desc(SecurityPostureScore.assessed_at)).limit(1)
        result = await session.execute(stmt)
        score = result.scalar_one_or_none()

        if not score:
            raise HTTPException(status_code=404, detail="No posture scores found")

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


@router.get("/posture/gaps", response_model=GapAnalysisResponse)
async def get_gap_analysis(
    current_user: CurrentUser = None,
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
            stmt = select(AttackSimulation).order_by(desc(AttackSimulation.completed_at)).limit(1)
            result = await session.execute(stmt)
            simulation = result.scalar_one_or_none()
            if not simulation:
                raise HTTPException(status_code=404, detail="No simulations found")
            simulation_id = simulation.id

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
    current_user: CurrentUser = None,
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

        org_id = getattr(current_user, "organization_id", None)

        # Make sure the built-in technique catalog AND adversary profiles
        # are loaded so the dashboard counts aren't 0 on a cold database.
        # Both loaders are idempotent (skip rows that already exist).
        try:
            await AtomicTestLibrary(session).load_builtin_techniques()
            await AdversaryEmulator(session).load_builtin_profiles()
        except Exception as load_exc:  # noqa: BLE001
            logger.warning(f"Builtin BAS loader failed on dashboard: {load_exc}")

        def _org(q):
            if org_id is None:
                return q
            return q.where(AttackSimulation.organization_id == org_id)

        # Count simulations by status (scoped to org)
        total_sims = (await session.execute(_org(select(func.count(AttackSimulation.id))))).scalar() or 0
        completed = (await session.execute(
            _org(select(func.count(AttackSimulation.id))).where(AttackSimulation.status == "completed")
        )).scalar() or 0
        running = (await session.execute(
            _org(select(func.count(AttackSimulation.id))).where(AttackSimulation.status == "running")
        )).scalar() or 0

        # Library-level counts (techniques and adversary profiles are global)
        technique_count = (await session.execute(select(func.count(AttackTechnique.id)))).scalar() or 0
        adversary_count = (await session.execute(select(func.count(AdversaryProfile.id)))).scalar() or 0

        # Averages over completed simulations for this org
        avg_detection = (await session.execute(
            _org(select(func.avg(AttackSimulation.detection_rate))).where(
                AttackSimulation.status == "completed"
            )
        )).scalar() or 0.0
        avg_posture = (await session.execute(
            _org(select(func.avg(AttackSimulation.overall_score))).where(
                AttackSimulation.status == "completed"
            )
        )).scalar() or 0.0

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
            .where(AttackSimulation.status == "completed")
            .group_by(AttackTechnique.tactic)
        )
        if org_id is not None:
            tactic_stmt = tactic_stmt.where(AttackSimulation.organization_id == org_id)

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
            .order_by(desc(SecurityPostureScore.assessed_at))
            .limit(12)
        )
        if org_id is not None:
            # Posture scores belong to simulations; join through to filter by org
            trends_stmt = (
                select(SecurityPostureScore.score)
                .join(AttackSimulation, SecurityPostureScore.simulation_id == AttackSimulation.id)
                .where(AttackSimulation.organization_id == org_id)
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
            average_detection_rate=round(float(avg_detection), 1),
            average_posture_score=round(float(avg_posture), 1),
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
