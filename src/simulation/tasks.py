"""
Celery tasks for asynchronous BAS engine operations.

Handles long-running simulation execution, detection monitoring,
posture scoring, and report generation.
"""

from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from celery import Celery; app = Celery()
from src.core.logging import get_logger
from src.core.config import settings
from src.models.base import utc_now
from src.simulation.engine import (
    SimulationOrchestrator,
    AtomicTestLibrary,
    PostureScorer,
)
from src.simulation.models import (
    AttackSimulation,
    SimulationTest,
    SecurityPostureScore,
)

logger = get_logger(__name__)


@app.task(bind=True, max_retries=3)
def execute_simulation(self, simulation_id: str, organization_id: str) -> dict:
    """
    Execute a complete simulation asynchronously.

    Orchestrates all test execution, monitoring, and cleanup for a simulation.

    Args:
        simulation_id: ID of simulation to execute
        organization_id: Organization context

    Returns:
        Dictionary with execution results and statistics
    """
    try:
        from src.database import get_async_session

        async def run():
            async with get_async_session() as session:
                orchestrator = SimulationOrchestrator(session)
                simulation = await orchestrator._get_simulation(simulation_id)

                if not simulation:
                    raise ValueError(f"Simulation {simulation_id} not found")

                logger.info(f"Starting execution of simulation {simulation_id}")

                # Get all pending tests
                stmt = select(SimulationTest).where(
                    (SimulationTest.simulation_id == simulation_id) &
                    (SimulationTest.status == "pending")
                )
                result = await session.execute(stmt)
                tests = result.scalars().all()

                executed = 0
                for test in tests:
                    try:
                        result = await orchestrator._execute_test(test)
                        executed += 1
                    except Exception as e:
                        logger.error(f"Error executing test {test.id}: {str(e)}")
                        test.status = "error"
                        test.error_output = str(e)
                        await session.commit()

                # Update simulation completion
                simulation.status = "completed"
                simulation.completed_at = utc_now()
                simulation.duration_seconds = int(
                    (simulation.completed_at - simulation.started_at).total_seconds()
                )

                # Recount test statistics
                stmt = select(SimulationTest).where(SimulationTest.simulation_id == simulation_id)
                result = await session.execute(stmt)
                all_tests = result.scalars().all()

                # Count outcomes. In this engine's terminology:
                #   passed_tests  = technique was detected by a rule (defender win)
                #   failed_tests  = technique went undetected (defender miss)
                #   blocked_tests = test errored out / could not run
                simulation.passed_tests = sum(1 for t in all_tests if t.was_detected)
                simulation.failed_tests = sum(
                    1 for t in all_tests if not t.was_detected and t.status != "error"
                )
                simulation.blocked_tests = sum(1 for t in all_tests if t.status == "error")

                if simulation.total_tests > 0:
                    # detection_rate = fraction of techniques covered by a rule.
                    # Previously this used blocked_tests / total, which was
                    # both inverted and counted errors as detections.
                    simulation.detection_rate = (
                        simulation.passed_tests / simulation.total_tests
                    ) * 100
                    simulation.overall_score = simulation.detection_rate

                await session.commit()

                logger.info(
                    f"Simulation {simulation_id} completed: "
                    f"{executed}/{simulation.total_tests} tests executed"
                )

                return {
                    "simulation_id": simulation_id,
                    "status": "completed",
                    "tests_executed": executed,
                    "total_tests": simulation.total_tests,
                    "duration_seconds": simulation.duration_seconds,
                    "detection_rate": simulation.detection_rate,
                }

        # Run async function
        import asyncio
        result = asyncio.run(run())
        return result

    except Exception as exc:
        logger.error(f"Error in execute_simulation: {str(exc)}")
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@app.task(bind=True, max_retries=3)
def execute_single_test(self, test_id: str, organization_id: str) -> dict:
    """
    Execute a single technique test.

    Args:
        test_id: ID of SimulationTest to execute
        organization_id: Organization context

    Returns:
        Dictionary with test execution results
    """
    try:
        from src.database import get_async_session

        async def run():
            async with get_async_session() as session:
                stmt = select(SimulationTest).where(SimulationTest.id == test_id)
                result = await session.execute(stmt)
                test = result.scalar_one_or_none()

                if not test:
                    raise ValueError(f"Test {test_id} not found")

                orchestrator = SimulationOrchestrator(session)
                result = await orchestrator._execute_test(test)

                return result

        import asyncio
        return asyncio.run(run())

    except Exception as exc:
        logger.error(f"Error in execute_single_test: {str(exc)}")
        raise self.retry(exc=exc, countdown=30 * (2 ** self.request.retries))


@app.task(bind=True, max_retries=2)
def check_detection_results(self, simulation_id: str, organization_id: str) -> dict:
    """
    Check if SIEM detected simulation activity.

    Polls SIEM/EDR systems for detection results from running simulation.

    Args:
        simulation_id: ID of simulation to check
        organization_id: Organization context

    Returns:
        Dictionary with detection statistics
    """
    try:
        from src.database import get_async_session

        async def run():
            async with get_async_session() as session:
                stmt = select(SimulationTest).where(
                    (SimulationTest.simulation_id == simulation_id) &
                    (SimulationTest.status == "running")
                )
                result = await session.execute(stmt)
                tests = result.scalars().all()

                detected_count = 0
                for test in tests:
                    detected = await SimulationOrchestrator(session)._check_detection(test)
                    if detected:
                        detected_count += 1

                stmt = select(AttackSimulation).where(AttackSimulation.id == simulation_id)
                result = await session.execute(stmt)
                simulation = result.scalar_one_or_none()

                return {
                    "simulation_id": simulation_id,
                    "tests_detected": detected_count,
                    "total_tests": len(tests),
                    "detection_rate": (detected_count / len(tests) * 100) if tests else 0,
                }

        import asyncio
        return asyncio.run(run())

    except Exception as exc:
        logger.error(f"Error in check_detection_results: {str(exc)}")
        raise self.retry(exc=exc, countdown=30 * (2 ** self.request.retries))


@app.task(bind=True, max_retries=2)
def calculate_posture_scores(self, simulation_id: str, organization_id: str) -> dict:
    """
    Calculate and store security posture scores.

    Analyzes simulation results to generate posture assessment.

    Args:
        simulation_id: ID of completed simulation
        organization_id: Organization context

    Returns:
        Dictionary with score information
    """
    try:
        from src.database import get_async_session

        async def run():
            async with get_async_session() as session:
                scorer = PostureScorer(session)
                posture_score = await scorer.calculate_posture_score(simulation_id)

                return {
                    "simulation_id": simulation_id,
                    "score": posture_score.score,
                    "score_type": posture_score.score_type,
                    "breakdown": posture_score.breakdown,
                }

        import asyncio
        return asyncio.run(run())

    except Exception as exc:
        logger.error(f"Error in calculate_posture_scores: {str(exc)}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@app.task(bind=True)
def run_continuous_validation(self, organization_id: str) -> dict:
    """
    Run periodic automated security testing.

    Executes a continuous validation simulation for ongoing security assessment.

    Args:
        organization_id: Organization context

    Returns:
        Dictionary with validation results
    """
    try:
        from src.database import get_async_session

        async def run():
            async with get_async_session() as session:
                # Get safe techniques for continuous testing
                library = AtomicTestLibrary(session)
                await library.load_builtin_techniques()
                safe_techniques = await library.get_safe_techniques()

                if not safe_techniques:
                    logger.warning("No safe techniques available for continuous validation")
                    return {"status": "no_techniques"}

                # Create validation simulation
                technique_ids = [t.mitre_id for t in safe_techniques[:5]]  # Use first 5 safe techniques

                orchestrator = SimulationOrchestrator(session)
                simulation = await orchestrator.create_simulation(
                    name=f"Continuous Validation - {datetime.now().isoformat()}",
                    sim_type="continuous_validation",
                    techniques=technique_ids,
                    scope={"target": "lab"},
                    target_environment="lab",
                    created_by="system",
                    organization_id=organization_id,
                    description="Automated continuous security validation test"
                )

                # Start the simulation
                await orchestrator.start_simulation(simulation.id)

                logger.info(f"Started continuous validation simulation {simulation.id}")

                return {
                    "simulation_id": simulation.id,
                    "techniques_tested": len(technique_ids),
                    "status": "started"
                }

        import asyncio
        return asyncio.run(run())

    except Exception as exc:
        logger.error(f"Error in run_continuous_validation: {str(exc)}")
        # Don't retry continuous validation task on error
        return {"status": "error", "message": str(exc)}


@app.task(bind=True, max_retries=2)
def generate_simulation_report(self, simulation_id: str, organization_id: str) -> dict:
    """
    Generate comprehensive simulation report.

    Creates detailed report with findings, recommendations, and metrics.

    Args:
        simulation_id: ID of completed simulation
        organization_id: Organization context

    Returns:
        Dictionary with report information
    """
    try:
        from src.database import get_async_session

        async def run():
            async with get_async_session() as session:
                scorer = PostureScorer(session)
                report = await scorer.generate_executive_report(simulation_id)

                logger.info(f"Generated report for simulation {simulation_id}")
                return report

        import asyncio
        return asyncio.run(run())

    except Exception as exc:
        logger.error(f"Error in generate_simulation_report: {str(exc)}")
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@app.task(bind=True)
def cleanup_simulation_artifacts(self, simulation_id: str, organization_id: str) -> dict:
    """
    Clean up any artifacts from simulation tests.

    Performs cleanup of test artifacts, temporary files, and monitoring data.

    Args:
        simulation_id: ID of simulation to clean up
        organization_id: Organization context

    Returns:
        Dictionary with cleanup status
    """
    try:
        from src.database import get_async_session

        async def run():
            async with get_async_session() as session:
                stmt = select(SimulationTest).where(SimulationTest.simulation_id == simulation_id)
                result = await session.execute(stmt)
                tests = result.scalars().all()

                for test in tests:
                    if test.cleanup_command and test.cleanup_status is None:
                        orchestrator = SimulationOrchestrator(session)
                        success = await orchestrator._run_cleanup(test, test.cleanup_command)
                        test.cleanup_status = "completed" if success else "failed"

                await session.commit()

                logger.info(f"Cleanup completed for simulation {simulation_id}")
                return {
                    "simulation_id": simulation_id,
                    "tests_cleaned": len([t for t in tests if t.cleanup_status]),
                    "status": "completed"
                }

        import asyncio
        return asyncio.run(run())

    except Exception as exc:
        logger.error(f"Error in cleanup_simulation_artifacts: {str(exc)}")
        return {"status": "error", "message": str(exc)}
