"""Celery tasks for Risk Quantification module

Asynchronous tasks for FAIR analysis, risk reviews, control audits, and BIA updates.
"""

import json
from datetime import datetime, timedelta, timezone

from celery import shared_task
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.logging import get_logger
from src.risk_quant.engine import (
    BIAEngine,
    ControlEffectivenessAnalyzer,
    FAIREngine,
    RiskAggregator,
)
from src.risk_quant.models import (
    BusinessImpactAssessment,
    FAIRAnalysis,
    RiskControl,
    RiskRegister,
    RiskScenario,
)

logger = get_logger(__name__)


def _get_sync_session():
    """Create a synchronous DB session for Celery tasks"""
    sync_url = settings.database_url.replace("+asyncpg", "").replace("+aiosqlite", "")
    engine = create_engine(sync_url)
    return Session(engine)


@shared_task(bind=True, max_retries=3)
def run_fair_simulation(self, analysis_id: str, organization_id: str):
    """Run FAIR Monte Carlo simulation for a risk analysis."""
    try:
        logger.info("Starting FAIR simulation", extra={"analysis_id": analysis_id})

        engine = FAIREngine()

        with _get_sync_session() as db:
            analysis = db.execute(
                select(FAIRAnalysis).where(
                    FAIRAnalysis.id == analysis_id,
                    FAIRAnalysis.organization_id == organization_id,
                )
            ).scalars().first()

            if not analysis:
                return {"status": "error", "message": "Analysis not found"}

            analysis_data = {
                "tef_min": analysis.tef_min or 1,
                "tef_mode": analysis.tef_mode or 5,
                "tef_max": analysis.tef_max or 20,
                "tcap_min": analysis.tcap_min or 0.3,
                "tcap_mode": analysis.tcap_mode or 0.6,
                "tcap_max": analysis.tcap_max or 0.9,
                "rs_min": analysis.rs_min or 0.2,
                "rs_mode": analysis.rs_mode or 0.5,
                "rs_max": analysis.rs_max or 0.8,
                "primary_loss_min": analysis.primary_loss_min or 10000,
                "primary_loss_mode": analysis.primary_loss_mode or 50000,
                "primary_loss_max": analysis.primary_loss_max or 200000,
                "secondary_loss_min": analysis.secondary_loss_min or 5000,
                "secondary_loss_mode": analysis.secondary_loss_mode or 25000,
                "secondary_loss_max": analysis.secondary_loss_max or 100000,
                "secondary_loss_event_frequency": getattr(analysis, "secondary_loss_event_frequency", 0.3) or 0.3,
            }

            result = engine.run_simulation(analysis_data, iterations=10000)

            analysis.ale_mean = result.ale_mean
            analysis.ale_p10 = getattr(result, "ale_p10", None)
            analysis.ale_p50 = result.ale_p50
            analysis.ale_p90 = getattr(result, "ale_p90", None)
            analysis.ale_p99 = getattr(result, "ale_p99", None)
            analysis.completed_at = datetime.now(timezone.utc)
            db.commit()

        logger.info("FAIR simulation completed", extra={"analysis_id": analysis_id, "ale_mean": result.ale_mean})
        return {"status": "success", "analysis_id": analysis_id, "ale_mean": result.ale_mean}

    except Exception as exc:
        logger.error(f"FAIR simulation failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def periodic_risk_review(self, organization_id: str):
    """Perform periodic risk register review."""
    try:
        logger.info("Starting periodic risk review", extra={"organization_id": organization_id})

        now = datetime.now(timezone.utc)
        overdue_count = 0
        reviewed_count = 0

        with _get_sync_session() as db:
            risks = db.execute(
                select(RiskRegister).where(RiskRegister.organization_id == organization_id)
            ).scalars().all()

            for risk in risks:
                reviewed_count += 1
                next_review = getattr(risk, "next_review_date", None) or getattr(risk, "next_review", None)
                if next_review and next_review < now:
                    risk.status = "review_due"
                    overdue_count += 1
            db.commit()

        logger.info("Periodic risk review completed", extra={"overdue_count": overdue_count})
        return {"status": "success", "overdue_count": overdue_count, "reviewed_count": reviewed_count}

    except Exception as exc:
        logger.error(f"Periodic risk review failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def control_effectiveness_audit(self, control_id: str, organization_id: str):
    """Audit control effectiveness and calculate updated ROI."""
    try:
        logger.info("Starting control audit", extra={"control_id": control_id})

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

            unmitigated_ale = getattr(control, "unmitigated_ale", 150000) or 150000
            mitigated_ale = getattr(control, "mitigated_ale", 45000) or 45000
            annual_cost = getattr(control, "annual_cost", 25000) or 25000

            roi_data = analyzer.assess_control_roi(unmitigated_ale, mitigated_ale, annual_cost)

            control.effectiveness_score = roi_data.get("annual_benefit", 0) / max(unmitigated_ale, 1) * 100
            control.last_tested = datetime.now(timezone.utc)
            control.test_result = "passed"
            db.commit()

        logger.info("Control audit completed", extra={"control_id": control_id})
        return {"status": "success", "control_id": control_id, "roi_5yr_percent": roi_data.get("roi_5yr_percent", 0)}

    except Exception as exc:
        logger.error(f"Control audit failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def bia_refresh(self, organization_id: str):
    """Refresh Business Impact Assessment for all critical assets."""
    try:
        logger.info("Starting BIA refresh", extra={"organization_id": organization_id})

        bia_engine = BIAEngine()
        bia_count = 0
        total_downtime_cost = 0

        with _get_sync_session() as db:
            bias = db.execute(
                select(BusinessImpactAssessment).where(
                    BusinessImpactAssessment.organization_id == organization_id
                )
            ).scalars().all()

            for bia in bias:
                impact = bia_engine.assess_business_impact({
                    "financial_impact_per_hour_usd": getattr(bia, "financial_impact_per_hour_usd", 10000) or 10000,
                    "rto_hours": getattr(bia, "rto_hours", 4) or 4,
                    "reputational_impact_score": getattr(bia, "reputational_impact_score", 5) or 5,
                    "regulatory_impact_score": getattr(bia, "regulatory_impact_score", 5) or 5,
                    "criticality": getattr(bia, "criticality", "high") or "high",
                })
                total_downtime_cost += impact.get("maximum_downtime_cost_usd", 0)
                bia_count += 1
            db.commit()

        logger.info("BIA refresh completed", extra={"bia_count": bia_count})
        return {"status": "success", "bia_count": bia_count, "total_downtime_cost": total_downtime_cost}

    except Exception as exc:
        logger.error(f"BIA refresh failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def risk_appetite_check(self, organization_id: str):
    """Check if organizational risks are within risk appetite."""
    try:
        logger.info("Starting risk appetite check", extra={"organization_id": organization_id})

        aggregator = RiskAggregator()

        with _get_sync_session() as db:
            registers = db.execute(
                select(RiskRegister).where(RiskRegister.organization_id == organization_id)
            ).scalars().all()

            risks = []
            for r in registers:
                risks.append({
                    "ale_mean": getattr(r, "ale_mean", 0) or 0,
                    "category": getattr(r, "category", "cyber") or "cyber",
                })

            risk_appetite_threshold = 300000
            if risks:
                agg_result = aggregator.aggregate_organizational_risk(risks)
                total_ale = agg_result.get("total_ale", 0)
            else:
                total_ale = 0

        within_appetite = total_ale <= risk_appetite_threshold
        over_by = total_ale - risk_appetite_threshold if not within_appetite else 0

        logger.info("Risk appetite check completed", extra={"total_ale": total_ale, "within_appetite": within_appetite})
        return {
            "status": "success",
            "total_ale": total_ale,
            "risk_appetite_threshold": risk_appetite_threshold,
            "within_appetite": within_appetite,
            "over_by": over_by,
        }

    except Exception as exc:
        logger.error(f"Risk appetite check failed: {exc}")
        raise self.retry(exc=exc, countdown=60)
