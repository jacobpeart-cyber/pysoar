"""Celery tasks for Risk Quantification module

Asynchronous tasks for FAIR analysis, risk reviews, control ROI and BIA updates.

Every task works on stored rows only. A row whose inputs are missing or
inconsistent is reported (``missing_inputs`` / ``invalid_fair_input`` with the
field) instead of being filled with invented numbers; the earlier versions
replaced falsy FAIR inputs with hard-coded estimates, assumed a $150,000 /
$45,000 / $25,000 control case, a $300,000 risk appetite and default BIA
impacts.
"""

from datetime import datetime, timezone

from celery import shared_task
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.logging import get_logger
from src.risk_quant.engine import (
    BIAEngine,
    ControlEffectivenessAnalyzer,
    FAIRInputError,
    simulate_analysis,
    store_result,
)
from src.risk_quant.models import (
    BusinessImpactAssessment,
    FAIRAnalysis,
    RiskControl,
    RiskRegister,
)

logger = get_logger(__name__)


def _get_sync_session():
    """Create a synchronous DB session for Celery tasks"""
    sync_url = settings.database_url.replace("+asyncpg", "").replace("+aiosqlite", "")
    engine = create_engine(sync_url)
    return Session(engine)


@shared_task(bind=True, max_retries=3)
def run_fair_simulation(self, analysis_id: str, organization_id: str):
    """Run the FAIR Monte Carlo simulation of one stored analysis.

    Same model, inputs and per-analysis seed as
    ``POST /risk-quantification/fair-analyses/{id}/run-simulation``.
    """
    try:
        logger.info("Starting FAIR simulation", analysis_id=analysis_id)

        with _get_sync_session() as db:
            analysis = db.execute(
                select(FAIRAnalysis).where(
                    FAIRAnalysis.id == analysis_id,
                    FAIRAnalysis.organization_id == organization_id,
                )
            ).scalars().first()

            if not analysis:
                return {"status": "error", "message": "Analysis not found"}

            try:
                result = simulate_analysis(analysis)
            except FAIRInputError as exc:
                logger.warning("FAIR simulation refused: invalid stored input",
                               analysis_id=analysis_id, field=exc.field)
                return {"status": "invalid_fair_input", "analysis_id": analysis_id,
                        "field": exc.field, "detail": exc.detail}

            store_result(analysis, result, datetime.now(timezone.utc))
            db.commit()

        logger.info("FAIR simulation completed", analysis_id=analysis_id, ale_mean=result.ale_mean)
        return {"status": "success", "analysis_id": analysis_id, "ale_mean": result.ale_mean}

    except Exception as exc:
        logger.error(f"FAIR simulation failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def periodic_risk_review(self, organization_id: str):
    """Count register entries whose stored ``next_review`` date has passed."""
    try:
        logger.info("Starting periodic risk review", organization_id=organization_id)

        now = datetime.now(timezone.utc)
        overdue_count = 0
        reviewed_count = 0

        with _get_sync_session() as db:
            risks = db.execute(
                select(RiskRegister).where(RiskRegister.organization_id == organization_id)
            ).scalars().all()

            for risk in risks:
                reviewed_count += 1
                next_review = risk.next_review
                if next_review is not None and next_review.tzinfo is None:
                    next_review = next_review.replace(tzinfo=timezone.utc)
                if next_review and next_review < now:
                    overdue_count += 1

        logger.info("Periodic risk review completed", overdue_count=overdue_count)
        return {"status": "success", "overdue_count": overdue_count, "reviewed_count": reviewed_count}

    except Exception as exc:
        logger.error(f"Periodic risk review failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def control_effectiveness_audit(self, control_id: str, organization_id: str):
    """Recalculate a control's ROI from its register's ALE, effectiveness and cost.

    A financial calculation, not a control test: ``last_tested`` /
    ``test_result`` are not touched.
    """
    try:
        logger.info("Starting control ROI calculation", control_id=control_id)

        analyzer = ControlEffectivenessAnalyzer()

        with _get_sync_session() as db:
            control = db.execute(
                select(RiskControl).where(
                    RiskControl.id == control_id,
                    RiskControl.organization_id == organization_id,
                )
            ).scalars().first()

            if not control:
                return {"status": "error", "message": "Control not found"}

            register = db.execute(
                select(RiskRegister).where(
                    RiskRegister.id == control.risk_register_id,
                    RiskRegister.organization_id == organization_id,
                )
            ).scalars().first()
            if register is None:
                return {"status": "missing_inputs", "control_id": control_id,
                        "missing": "risk_register (the control's register is not in this organisation)"}

            unmitigated_ale = float(register.ale_annual_usd)
            mitigated_ale = unmitigated_ale * (1 - float(control.effectiveness_score or 0) / 100.0)
            roi_data = analyzer.assess_control_roi(unmitigated_ale, mitigated_ale, float(control.cost_annual_usd))

            control.roi_percentage = roi_data["roi_5yr_percent"]
            db.commit()

        logger.info("Control ROI calculation completed", control_id=control_id)
        return {"status": "success", "control_id": control_id, "roi_5yr_percent": roi_data["roi_5yr_percent"]}

    except Exception as exc:
        logger.error(f"Control audit failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def bia_refresh(self, organization_id: str):
    """Recompute the impact figures of every stored BIA (stored values only)."""
    try:
        logger.info("Starting BIA refresh", organization_id=organization_id)

        bia_engine = BIAEngine()
        bia_count = 0
        total_downtime_cost = 0.0

        with _get_sync_session() as db:
            bias = db.execute(
                select(BusinessImpactAssessment).where(
                    BusinessImpactAssessment.organization_id == organization_id
                )
            ).scalars().all()

            for bia in bias:
                impact = bia_engine.assess_business_impact({
                    "financial_impact_per_hour_usd": bia.financial_impact_per_hour_usd,
                    "rto_hours": bia.rto_hours,
                    "reputational_impact_score": bia.reputational_impact_score,
                    "regulatory_impact_score": bia.regulatory_impact_score,
                    "criticality": bia.criticality,
                })
                total_downtime_cost += impact.get("maximum_downtime_cost_usd", 0)
                bia_count += 1

        logger.info("BIA refresh completed", bia_count=bia_count)
        return {"status": "success", "bia_count": bia_count, "total_downtime_cost": total_downtime_cost}

    except Exception as exc:
        logger.error(f"BIA refresh failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def risk_appetite_check(self, organization_id: str):
    """Compare each register entry's stored ALE with its own stored appetite threshold."""
    try:
        logger.info("Starting risk appetite check", organization_id=organization_id)

        exceeding: list[dict] = []
        checked = 0
        with _get_sync_session() as db:
            registers = db.execute(
                select(RiskRegister).where(RiskRegister.organization_id == organization_id)
            ).scalars().all()

            for r in registers:
                checked += 1
                within = float(r.ale_annual_usd) <= float(r.risk_appetite_threshold_usd)
                if r.is_within_appetite != within:
                    r.is_within_appetite = within
                if not within:
                    exceeding.append({
                        "register_id": r.id,
                        "ale_annual_usd": r.ale_annual_usd,
                        "risk_appetite_threshold_usd": r.risk_appetite_threshold_usd,
                    })
            db.commit()

        logger.info("Risk appetite check completed", checked=checked, exceeding=len(exceeding))
        return {
            "status": "success",
            "checked": checked,
            "within_appetite": checked - len(exceeding),
            "exceeding_appetite": exceeding,
        }

    except Exception as exc:
        logger.error(f"Risk appetite check failed: {exc}")
        raise self.retry(exc=exc, countdown=60)
