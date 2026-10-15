"""
Privacy Engineering Engine

Core engines for Data Subject Request processing, Privacy Impact Assessment,
Consent Management, Data Governance, and Privacy Incident handling.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from src.core.logging import get_logger
from src.privacy.models import (
    DataSubjectRequest,
    PrivacyImpactAssessment,
    ConsentRecord,
    DataProcessingRecord,
    PrivacyIncident,
    DSRStatus,
    PIAStatus,
    RiskLevel,
    IncidentStatus,
)

logger = get_logger(__name__)


class DSRProcessor:
    """
    Data Subject Request (DSR) processor for GDPR Article 12-22, CCPA § 1798.100-1798.120.
    Handles access, rectification, erasure, portability, restriction, and objection requests.
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id

    async def receive_request(
        self,
        request_type: str,
        regulation: str,
        subject_name: str,
        subject_email: str,
        subject_identifier: Optional[str] = None,
        processing_notes: Optional[str] = None,
    ) -> DataSubjectRequest:
        """
        Receive and register new Data Subject Request.
        Calculates deadline based on regulation (GDPR: 30 days, CCPA: 45 days).
        """
        logger.info(
            f"Receiving DSR: {request_type} from {subject_email} under {regulation}"
        )

        # Calculate deadline
        if regulation == "gdpr":
            deadline_days = 30
        elif regulation == "ccpa":
            deadline_days = 45
        elif regulation == "lgpd":
            deadline_days = 15
        else:
            deadline_days = 30

        deadline = (
            datetime.now(timezone.utc) + timedelta(days=deadline_days)
        ).isoformat()

        dsr = DataSubjectRequest(
            organization_id=self.org_id,
            request_type=request_type,
            regulation=regulation,
            status=DSRStatus.RECEIVED.value,
            subject_name=subject_name,
            subject_email=subject_email,
            subject_identifier=subject_identifier,
            deadline=deadline,
            processing_notes=processing_notes,
        )

        self.db.add(dsr)
        await self.db.flush()
        logger.info(f"DSR created: {dsr.id}, deadline: {deadline}")
        return dsr

    # Wave 4: identity verification, subject search, export and erasure live
    # in src/privacy/dsr.py and act on the platform's real rows. The methods
    # that used to be here marked DSRs verified / completed without doing
    # anything ("records_deleted" counted consent rows and deleted none).

    async def track_deadline_compliance(self) -> List[Dict[str, Any]]:
        """
        Deadline alerts for open DSRs (received, verified, processing,
        partially complete, appealed): ``BREACHED`` past the stored
        deadline (first breach stamped on ``deadline_breached_at``),
        ``CRITICAL`` within 7 days. Completed and denied requests are closed.
        """
        from src.privacy.dsr import OPEN_STATUSES

        logger.info(f"Tracking deadline compliance for org {self.org_id}")

        stmt = (
            select(DataSubjectRequest)
            .where(
                and_(
                    DataSubjectRequest.organization_id == self.org_id,
                    DataSubjectRequest.status.in_(sorted(OPEN_STATUSES)),
                )
            )
            .order_by(DataSubjectRequest.created_at)
            .limit(5000)
        )
        result = await self.db.execute(stmt)
        pending_dsrs = result.scalars().all()

        compliance_alerts = []
        now = datetime.now(timezone.utc)

        for dsr in pending_dsrs:
            if not dsr.deadline:
                continue
            try:
                deadline_dt = datetime.fromisoformat(str(dsr.deadline).replace("Z", "+00:00"))
            except ValueError:
                continue
            if deadline_dt.tzinfo is None:
                deadline_dt = deadline_dt.replace(tzinfo=timezone.utc)
            delta = deadline_dt - now
            if delta.total_seconds() < 0:
                if dsr.deadline_breached_at is None:
                    dsr.deadline_breached_at = now
                compliance_alerts.append(
                    {
                        "dsr_id": dsr.id,
                        "status": "BREACHED",
                        "days_overdue": abs(delta.days),
                        "subject": dsr.subject_email,
                    }
                )
            elif delta.days < 7:
                compliance_alerts.append(
                    {
                        "dsr_id": dsr.id,
                        "status": "CRITICAL",
                        "days_remaining": delta.days,
                        "subject": dsr.subject_email,
                    }
                )

        logger.info(f"Found {len(compliance_alerts)} deadline compliance issues")
        return compliance_alerts

    async def generate_response(self, dsr_id: str) -> str:
        """
        Generate formal DSR response document/email.
        """
        logger.info(f"Generating response for DSR {dsr_id}")

        stmt = select(DataSubjectRequest).where(
            and_(
                DataSubjectRequest.id == dsr_id,
                DataSubjectRequest.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        dsr = result.scalar_one_or_none()

        if not dsr:
            return ""

        response = f"""
Dear {dsr.subject_name},

Your {dsr.request_type} request under {dsr.regulation.upper()} has been received.

Request ID: {dsr.id}
Received: {dsr.created_at.isoformat()}
Status: {dsr.status}

We will process your request in accordance with applicable regulations.

Best regards,
Data Protection Team
"""

        dsr.response_sent = datetime.now(timezone.utc).isoformat()
        logger.info(f"Response generated for DSR {dsr_id}")
        return response


class PIAEngine:
    """
    Privacy Impact Assessment engine for GDPR Article 35 (DPIA) and PIA best practices.
    Evaluates necessity, proportionality, and risk mitigations.
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id

    async def create_assessment(
        self,
        name: str,
        project_name: str,
        assessment_type: str,
        data_types_processed: Optional[List[str]] = None,
        processing_purposes: Optional[List[str]] = None,
        legal_basis: Optional[str] = None,
        data_subjects_affected: Optional[int] = None,
    ) -> PrivacyImpactAssessment:
        """Create new Privacy Impact Assessment (risk ``not_assessed`` until
        ``assess_risks`` runs)."""
        logger.info(f"Creating PIA: {name} ({assessment_type})")

        pia = PrivacyImpactAssessment(
            organization_id=self.org_id,
            name=name,
            project_name=project_name,
            assessment_type=assessment_type,
            status=PIAStatus.DRAFT.value,
            data_types_processed=json.dumps(data_types_processed) if data_types_processed else None,
            processing_purposes=json.dumps(processing_purposes) if processing_purposes else None,
            legal_basis=legal_basis,
            data_subjects_affected=data_subjects_affected,
            risk_level="not_assessed",
        )

        self.db.add(pia)
        await self.db.flush()
        logger.info(f"PIA created: {pia.id}")
        return pia

    async def evaluate_necessity_proportionality(
        self, pia_id: str, processing_purposes: List[str], data_types: List[str]
    ) -> Dict[str, Any]:
        """
        Evaluate whether processing is necessary and proportionate.
        Implements GDPR proportionality test.
        """
        logger.info(f"Evaluating necessity/proportionality for PIA {pia_id}")

        stmt = select(PrivacyImpactAssessment).where(
            and_(
                PrivacyImpactAssessment.id == pia_id,
                PrivacyImpactAssessment.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        pia = result.scalar_one_or_none()

        if not pia:
            return {"status": "error", "message": f"PIA {pia_id} not found"}

        # Calculate necessity score based on data types count
        # Fewer data types for the stated purposes = higher necessity (less over-collection)
        num_data_types = len(data_types) if data_types else 0
        num_purposes = len(processing_purposes) if processing_purposes else 1
        # Ideal ratio is ~1-2 data types per purpose; penalize over-collection
        type_per_purpose = num_data_types / max(num_purposes, 1)
        if type_per_purpose <= 2:
            necessity_score = 9.0
        elif type_per_purpose <= 4:
            necessity_score = 7.0
        elif type_per_purpose <= 6:
            necessity_score = 5.0
        else:
            necessity_score = 3.0

        # Calculate proportionality score based on legal basis strength and mitigations
        legal_basis = pia.legal_basis or ""
        strong_bases = {"consent", "contract", "legal_obligation", "vital_interest"}
        moderate_bases = {"public_task"}
        if legal_basis in strong_bases:
            proportionality_score = 8.0
        elif legal_basis in moderate_bases:
            proportionality_score = 6.0
        elif legal_basis == "legitimate_interest":
            proportionality_score = 5.0
        else:
            proportionality_score = 4.0

        # Boost proportionality if mitigations are already in place
        if pia.mitigations:
            existing_mitigations = json.loads(pia.mitigations)
            proportionality_score = min(10.0, proportionality_score + len(existing_mitigations) * 0.3)

        # Overall assessment
        avg_score = (necessity_score + proportionality_score) / 2
        if avg_score >= 8.0:
            overall = "PROPORTIONATE"
        elif avg_score >= 5.5:
            overall = "PROPORTIONATE_WITH_MITIGATIONS"
        else:
            overall = "DISPROPORTIONATE"

        # Generate targeted recommendations based on actual weaknesses
        recommendations: List[str] = []
        if necessity_score < 7.0:
            recommendations.append("Reduce data types collected to those strictly necessary for stated purposes")
        if proportionality_score < 7.0:
            recommendations.append("Strengthen legal basis or obtain explicit consent")
        if not pia.mitigations:
            recommendations.append("Implement technical and organizational mitigations")
        if num_data_types > 5:
            recommendations.append("Conduct data minimization review to reduce scope")
        if not recommendations:
            recommendations.append("Maintain current controls and conduct periodic reviews")

        evaluation = {
            "purposes": processing_purposes,
            "data_types": data_types,
            "necessity_score": round(necessity_score, 1),
            "proportionality_score": round(proportionality_score, 1),
            "overall_assessment": overall,
            "recommendations": recommendations,
        }

        pia.processing_purposes = json.dumps(processing_purposes)
        pia.data_types_processed = json.dumps(data_types)

        logger.info(f"Necessity/proportionality evaluation complete for PIA {pia_id}")
        return evaluation

    async def assess_risks(
        self, pia_id: str, data_subjects_count: int, processing_scope: str
    ) -> Dict[str, Any]:
        """
        Assess risks to data subjects (GDPR Article 35).
        Evaluates likelihood and severity of impact.
        """
        logger.info(f"Assessing risks for PIA {pia_id}")

        stmt = select(PrivacyImpactAssessment).where(
            and_(
                PrivacyImpactAssessment.id == pia_id,
                PrivacyImpactAssessment.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        pia = result.scalar_one_or_none()

        if not pia:
            return {"status": "error", "message": f"PIA {pia_id} not found"}

        pia.data_subjects_affected = data_subjects_count

        # Derive risk factors from the PIA's actual properties
        # Scale of processing based on subject count
        if data_subjects_count > 100000:
            scale_risk = 0.9
        elif data_subjects_count > 10000:
            scale_risk = 0.7
        elif data_subjects_count > 1000:
            scale_risk = 0.5
        else:
            scale_risk = 0.2

        # Data sensitivity based on actual data types processed
        sensitive_types = {"health", "biometric", "genetic", "racial", "ethnic",
                          "political", "religious", "sexual_orientation", "criminal"}
        data_types = []
        if pia.data_types_processed:
            data_types = json.loads(pia.data_types_processed)
        has_sensitive = any(
            any(s in dt.lower() for s in sensitive_types)
            for dt in data_types
        )
        data_sensitivity_risk = 0.9 if has_sensitive else 0.3

        # Automated decision-making based on assessment type
        automated_risk = 0.7 if pia.assessment_type in ("dpia", "tia") else 0.3

        # Cross-border transfer risk
        cross_border_risk = 0.0
        if pia.cross_border_transfers:
            destinations = json.loads(pia.cross_border_transfers)
            if len(destinations) > 3:
                cross_border_risk = 0.8
            elif len(destinations) > 0:
                cross_border_risk = 0.5

        # Processing scope risk
        scope_map = {"large_scale": 0.8, "systematic": 0.7, "targeted": 0.4, "limited": 0.2}
        scope_risk = scope_map.get(processing_scope, 0.5)

        # Mitigation factor: having mitigations reduces vulnerability
        if pia.mitigations:
            mitigations_list = json.loads(pia.mitigations)
            vulnerability_risk = max(0.1, 0.8 - len(mitigations_list) * 0.08)
        else:
            vulnerability_risk = 0.8

        risk_factors = {
            "scale_of_processing": scale_risk,
            "data_sensitivity": data_sensitivity_risk,
            "automated_decision": automated_risk,
            "cross_border_transfer": cross_border_risk,
            "processing_scope": scope_risk,
            "vulnerability": round(vulnerability_risk, 2),
        }

        avg_risk = sum(risk_factors.values()) / len(risk_factors)

        if avg_risk >= 0.75:
            risk_level = RiskLevel.CRITICAL.value
        elif avg_risk >= 0.6:
            risk_level = RiskLevel.HIGH.value
        elif avg_risk >= 0.45:
            risk_level = RiskLevel.MEDIUM.value
        else:
            risk_level = RiskLevel.LOW.value

        pia.risk_level = risk_level

        risk_assessment = {
            "risk_level": risk_level,
            "risk_score": round(avg_risk * 100),
            "risk_factors": risk_factors,
            "affected_data_subjects": data_subjects_count,
        }

        logger.info(f"Risk assessment complete: {risk_level}")
        return risk_assessment

    # recommend_mitigations removed (wave 4): it wrote the same eight
    # boilerplate mitigations into every PIA, which then lowered its risk
    # score. Assessors record real mitigations with PATCH /pia/assessments/{id}.

    async def calculate_risk_score(self, pia_id: str) -> float:
        """Calculate composite risk score (0-100)."""
        stmt = select(PrivacyImpactAssessment).where(
            and_(
                PrivacyImpactAssessment.id == pia_id,
                PrivacyImpactAssessment.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        pia = result.scalar_one_or_none()

        if not pia:
            return 0.0

        risk_mapping = {
            RiskLevel.MINIMAL.value: 10.0,
            RiskLevel.LOW.value: 30.0,
            RiskLevel.MEDIUM.value: 50.0,
            RiskLevel.HIGH.value: 75.0,
            RiskLevel.CRITICAL.value: 95.0,
        }

        return risk_mapping.get(pia.risk_level, 50.0)

    async def submit_for_dpo_review(self, pia_id: str) -> bool:
        """Submit PIA for Data Protection Officer review."""
        logger.info(f"Submitting PIA {pia_id} for DPO review")

        stmt = select(PrivacyImpactAssessment).where(
            and_(
                PrivacyImpactAssessment.id == pia_id,
                PrivacyImpactAssessment.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        pia = result.scalar_one_or_none()

        if not pia:
            return False

        pia.status = PIAStatus.IN_REVIEW.value
        pia.dpo_review = True
        logger.info(f"PIA {pia_id} submitted for DPO review")
        return True

    async def generate_pia_report(self, pia_id: str) -> str:
        """Generate formal PIA/DPIA report document."""
        logger.info(f"Generating PIA report for {pia_id}")

        stmt = select(PrivacyImpactAssessment).where(
            and_(
                PrivacyImpactAssessment.id == pia_id,
                PrivacyImpactAssessment.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        pia = result.scalar_one_or_none()

        if not pia:
            return ""

        report = f"""
PRIVACY IMPACT ASSESSMENT REPORT
Assessment ID: {pia.id}
Project: {pia.project_name}
Assessment Type: {pia.assessment_type}
Date: {datetime.now(timezone.utc).isoformat()}

Executive Summary
-----------------
Risk Level: {pia.risk_level}

Processing Activities
---------------------
{pia.processing_purposes}

Data Categories
---------------
{pia.data_types_processed}

Risk Assessment
---------------
{json.dumps(json.loads(pia.mitigations) if pia.mitigations else [])}

DPO Review: {'Completed' if pia.dpo_approval_date else 'Pending'}
"""

        return report


class ConsentManager:
    """
    Consent management for GDPR Article 7 and CCPA § 1798.115.
    Records, validates, and audits consent across purposes.
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id

    async def record_consent(
        self,
        subject_id: str,
        purpose: str,
        legal_basis: str,
        consent_mechanism: str,
        evidence_location: Optional[str] = None,
    ) -> ConsentRecord:
        """
        Record explicit consent with evidence trail.
        """
        logger.info(f"Recording consent for {subject_id}: {purpose}")

        consent = ConsentRecord(
            organization_id=self.org_id,
            subject_id=subject_id,
            purpose=purpose,
            legal_basis=legal_basis,
            consent_given=True,
            consent_date=datetime.now(timezone.utc).isoformat(),
            consent_mechanism=consent_mechanism,
            evidence_location=evidence_location,
        )

        self.db.add(consent)
        await self.db.flush()
        logger.info(f"Consent recorded: {consent.id}")
        return consent

    async def withdraw_consent(self, consent_id: str) -> bool:
        """
        Withdraw previously given consent (GDPR Article 7(3)).
        """
        logger.info(f"Withdrawing consent: {consent_id}")

        stmt = select(ConsentRecord).where(
            and_(
                ConsentRecord.id == consent_id,
                ConsentRecord.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        consent = result.scalar_one_or_none()

        if not consent:
            return False

        consent.consent_given = False
        consent.withdrawal_date = datetime.now(timezone.utc).isoformat()
        logger.info(f"Consent withdrawn: {consent_id}")
        return True

    async def check_consent_validity(self, consent_id: str) -> bool:
        """
        Verify consent is still valid and not withdrawn.
        """
        stmt = select(ConsentRecord).where(
            and_(
                ConsentRecord.id == consent_id,
                ConsentRecord.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        consent = result.scalar_one_or_none()

        if not consent:
            return False

        return consent.consent_given and consent.withdrawal_date is None

    async def audit_consent_trail(self, subject_id: str) -> List[Dict[str, Any]]:
        """
        Generate audit trail of all consents for a subject.
        """
        logger.info(f"Generating consent audit trail for {subject_id}")

        stmt = select(ConsentRecord).where(
            and_(
                ConsentRecord.organization_id == self.org_id,
                ConsentRecord.subject_id == subject_id,
            )
        )
        result = await self.db.execute(stmt)
        consents = result.scalars().all()

        trail = []
        for consent in consents:
            trail.append(
                {
                    "consent_id": consent.id,
                    "purpose": consent.purpose,
                    "consent_given": consent.consent_given,
                    "consent_date": consent.consent_date,
                    "withdrawal_date": consent.withdrawal_date,
                    "mechanism": consent.consent_mechanism,
                }
            )

        return trail

    async def generate_consent_report(self, subject_id: str) -> str:
        """
        Generate consent report for subject.
        """
        logger.info(f"Generating consent report for {subject_id}")
        trail = await self.audit_consent_trail(subject_id)
        return json.dumps(trail, indent=2)

    async def check_purpose_limitation(
        self, subject_id: str, purpose: str
    ) -> bool:
        """
        Verify processing for given purpose has valid consent.
        """
        stmt = select(ConsentRecord).where(
            and_(
                ConsentRecord.organization_id == self.org_id,
                ConsentRecord.subject_id == subject_id,
                ConsentRecord.purpose == purpose,
                ConsentRecord.consent_given == True,
            )
        )
        result = await self.db.execute(stmt)
        consent = result.scalar_one_or_none()

        return consent is not None


class DataGovernance:
    """
    Data Governance for GDPR Article 30 (ROPA), Article 33, and data minimization.
    Records processing activities, validates legal basis, manages retention.
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id

    async def create_processing_record(
        self,
        name: str,
        purpose: str,
        legal_basis: str,
        data_categories: List[str],
        data_subjects: Optional[List[str]] = None,
        recipients: Optional[List[str]] = None,
        retention_period_days: Optional[int] = None,
        dpo_contact: Optional[str] = None,
    ) -> DataProcessingRecord:
        """
        Create Record of Processing Activities (ROPA) entry per GDPR Article 30.
        Every Art. 30 field the caller supplies is stored.
        """
        logger.info(f"Creating processing record: {name}")

        record = DataProcessingRecord(
            organization_id=self.org_id,
            name=name,
            purpose=purpose,
            legal_basis=legal_basis,
            data_categories=json.dumps(data_categories),
            data_subjects=json.dumps(data_subjects) if data_subjects else None,
            recipients=json.dumps(recipients) if recipients else None,
            retention_period_days=retention_period_days,
            dpo_contact=dpo_contact,
        )

        self.db.add(record)
        await self.db.flush()
        logger.info(f"Processing record created: {record.id}")
        return record

    async def validate_legal_basis(
        self, legal_basis: str, processing_context: str
    ) -> bool:
        """
        Validate that legal basis is appropriate for processing context.
        """
        logger.info(f"Validating legal basis: {legal_basis}")

        valid_bases = [
            "consent",
            "contract",
            "legal_obligation",
            "vital_interest",
            "public_task",
            "legitimate_interest",
        ]

        return legal_basis in valid_bases

    async def check_retention_compliance(self) -> List[Dict[str, Any]]:
        """
        Retention-review findings over the stored ROPA records.

        A ROPA record describes a processing activity, not a table, so the
        platform cannot see whether data was actually kept past its retention
        period. What it can check from stored rows is whether each activity
        with a retention period has been reviewed within that period:
        ``NOT_REVIEWED`` (never reviewed) or ``REVIEW_OVERDUE``. (This used to
        report ``RETENTION_EXCEEDED`` from the review date.)
        """
        logger.info(f"Checking retention compliance for org {self.org_id}")

        stmt = select(DataProcessingRecord).where(
            DataProcessingRecord.organization_id == self.org_id
        ).limit(1000)
        result = await self.db.execute(stmt)
        records = result.scalars().all()

        violations = []
        now = datetime.now(timezone.utc)

        for record in records:
            if not record.retention_period_days:
                continue
            if not record.last_reviewed:
                created = record.created_at
                if created is not None and created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_days = (now - created).days if created else 0
                violations.append(
                    {
                        "record_id": record.id,
                        "name": record.name,
                        "status": "NOT_REVIEWED",
                        "days_overdue": max(0, age_days - record.retention_period_days),
                        "detail": "retention period set but the activity has never been reviewed",
                    }
                )
                continue
            last_reviewed_dt = datetime.fromisoformat(record.last_reviewed.replace("Z", "+00:00"))
            if last_reviewed_dt.tzinfo is None:
                last_reviewed_dt = last_reviewed_dt.replace(tzinfo=timezone.utc)
            age_days = (now - last_reviewed_dt).days
            if age_days > record.retention_period_days:
                violations.append(
                    {
                        "record_id": record.id,
                        "name": record.name,
                        "status": "REVIEW_OVERDUE",
                        "days_overdue": age_days - record.retention_period_days,
                        "detail": f"last reviewed {age_days} days ago; retention period {record.retention_period_days} days",
                    }
                )

        logger.info(f"Found {len(violations)} retention violations")
        return violations

    async def audit_cross_border_transfers(self) -> List[Dict[str, Any]]:
        """
        Audit cross-border data transfers for adequacy decisions, SCCs, or BCRs.
        Per GDPR Chapter 5.
        """
        logger.info(f"Auditing cross-border transfers for org {self.org_id}")

        stmt = select(DataProcessingRecord).where(
            and_(
                DataProcessingRecord.organization_id == self.org_id,
                DataProcessingRecord.cross_border_transfers != None,
            )
        )
        result = await self.db.execute(stmt)
        records = result.scalars().all()

        transfers = []
        for record in records:
            if record.cross_border_transfers:
                destinations = json.loads(record.cross_border_transfers)
                transfers.append(
                    {
                        "record_id": record.id,
                        "activity": record.name,
                        "destinations": destinations,
                        "safeguards_required": [
                            "adequacy_decision",
                            "sccs",
                            "bcrs",
                        ],
                    }
                )

        return transfers

    async def generate_ropa(self) -> str:
        """
        Generate Record of Processing Activities report (GDPR Article 30).
        """
        logger.info(f"Generating ROPA for org {self.org_id}")

        stmt = select(DataProcessingRecord).where(
            DataProcessingRecord.organization_id == self.org_id
        )
        result = await self.db.execute(stmt)
        records = result.scalars().all()

        ropa = f"""
RECORD OF PROCESSING ACTIVITIES (ROPA)
Organization: {self.org_id}
Generated: {datetime.now(timezone.utc).isoformat()}

Processing Activities
---------------------
"""

        for record in records:
            ropa += f"""
Activity: {record.name}
Purpose: {record.purpose}
Legal Basis: {record.legal_basis}
Data Categories: {record.data_categories}
Data Subjects: {record.data_subjects or 'not recorded'}
Recipients: {record.recipients or 'not recorded'}
Cross-border Transfers: {record.cross_border_transfers or 'none recorded'}
Retention Period: {record.retention_period_days} days
DPO Contact: {record.dpo_contact or 'not recorded'}
Last Reviewed: {record.last_reviewed}
---
"""

        return ropa

    async def check_data_minimization(self, record_id: str) -> Dict[str, Any]:
        """
        Assess whether data collection respects minimization principle.
        """
        logger.info(f"Checking data minimization for record {record_id}")

        stmt = select(DataProcessingRecord).where(
            and_(
                DataProcessingRecord.id == record_id,
                DataProcessingRecord.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        record = result.scalar_one_or_none()

        if not record:
            return {"status": "error", "message": f"Record {record_id} not found"}

        # Parse actual data categories
        categories: List[str] = []
        if record.data_categories:
            categories = json.loads(record.data_categories)
        num_categories = len(categories)

        # Score based on number of categories relative to purpose complexity
        # Fewer categories for a given purpose = higher minimization score
        # A single-purpose activity with 1-2 categories is ideal (score 10)
        if num_categories == 0:
            minimization_score = 10.0  # No data collected = perfect minimization
        elif num_categories <= 2:
            minimization_score = 9.0
        elif num_categories <= 4:
            minimization_score = 7.0
        elif num_categories <= 6:
            minimization_score = 5.0
        elif num_categories <= 10:
            minimization_score = 3.0
        else:
            minimization_score = 1.0

        # Determine assessment level
        if minimization_score >= 8.0:
            assessment_level = "COMPLIANT"
        elif minimization_score >= 5.0:
            assessment_level = "COMPLIANT_WITH_RECOMMENDATIONS"
        else:
            assessment_level = "NON_COMPLIANT"

        # Generate targeted recommendations
        recommendations: List[str] = []
        if num_categories > 4:
            recommendations.append(
                f"Reduce data categories from {num_categories} to only those strictly necessary for purpose: {record.purpose}"
            )
        if num_categories > 2:
            recommendations.append("Review necessity of each data category against stated purpose")
        if not record.retention_period_days:
            recommendations.append("Define a retention period to limit data storage duration")
        if not recommendations:
            recommendations.append("Data collection is well-minimized; maintain current practices")

        assessment = {
            "record_id": record_id,
            "purpose": record.purpose,
            "data_categories_count": num_categories,
            "data_categories": categories,
            "minimization_score": minimization_score,
            "assessment": assessment_level,
            "recommendations": recommendations,
        }

        return assessment


class PrivacyIncidentManager:
    """
    Privacy Incident management for GDPR Article 33-34, CCPA § 1798.82.
    Tracks breaches, calculates notification obligations, manages response.
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id

    async def report_incident(
        self,
        title: str,
        description: str,
        incident_type: str,
        severity: str,
        data_types: List[str],
        subjects_count: int,
        regulations: Optional[List[str]] = None,
    ) -> PrivacyIncident:
        """
        Report new privacy incident.
        """
        logger.info(f"Reporting privacy incident: {title}")

        incident = PrivacyIncident(
            organization_id=self.org_id,
            title=title,
            description=description,
            incident_type=incident_type,
            severity=severity,
            data_types_affected=json.dumps(data_types),
            subjects_affected_count=subjects_count,
            regulations_implicated=json.dumps([r.lower() for r in regulations]) if regulations else None,
            notification_required=True,
        )

        self.db.add(incident)
        await self.db.flush()
        logger.info(f"Incident reported: {incident.id}")
        return incident

    async def assess_breach_severity(self, incident_id: str) -> Dict[str, Any]:
        """
        Assess breach severity based on impact and scope.
        """
        logger.info(f"Assessing severity for incident {incident_id}")

        stmt = select(PrivacyIncident).where(
            and_(
                PrivacyIncident.id == incident_id,
                PrivacyIncident.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        incident = result.scalar_one_or_none()

        if not incident:
            return {"status": "error", "message": f"Incident {incident_id} not found"}

        # Severity factors derived from the stored incident only (scale and
        # whether special-category data types are involved).
        special = {"health", "medical", "biometric", "genetic", "racial", "ethnic", "political",
                   "religious", "sexual", "criminal", "ssn", "financial", "credit_card", "password"}
        data_types = json.loads(incident.data_types_affected) if incident.data_types_affected else []
        sensitive = any(any(s in str(dt).lower() for s in special) for dt in data_types)
        severity_factors = {
            "subjects_affected_scale": 0.7 if (incident.subjects_affected_count or 0) > 1000 else 0.3,
            "data_sensitivity": 0.9 if sensitive else 0.3,
        }

        avg_severity = sum(severity_factors.values()) / len(severity_factors)

        return {
            "incident_id": incident_id,
            "severity_score": round(avg_severity * 100),
            "severity_factors": severity_factors,
        }

    async def determine_notification_obligations(
        self, incident_id: str
    ) -> Dict[str, Any]:
        """
        Determine notification obligations per regulation:
        - GDPR: Article 33 (authority), Article 34 (subjects)
        - CCPA: § 1798.82 (subjects)
        - HIPAA: 60 days
        """
        logger.info(f"Determining notification obligations for {incident_id}")

        stmt = select(PrivacyIncident).where(
            and_(
                PrivacyIncident.id == incident_id,
                PrivacyIncident.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        incident = result.scalar_one_or_none()

        if not incident:
            return {"status": "error", "message": f"Incident {incident_id} not found"}

        # Obligations follow from the regulations recorded on the incident;
        # nothing is assumed when none were recorded.
        regulations = json.loads(incident.regulations_implicated) if incident.regulations_implicated else []
        regulations = [str(r).lower() for r in regulations]
        obligations: Dict[str, Any] = {
            "regulations_implicated": regulations,
            "notify_supervisory_authority": "gdpr" in regulations,
            "notify_subjects": bool(regulations) and (incident.subjects_affected_count or 0) > 0,
        }
        if "gdpr" in regulations:
            obligations["authority_deadline_hours"] = 72
        if "ccpa" in regulations:
            obligations["subject_deadline_days"] = 30
        if "hipaa" in regulations or "hipaa_right" in regulations:
            obligations["hipaa_deadline_days"] = 60
        if not regulations:
            obligations["status"] = "not_assessed"
            obligations["detail"] = "no regulations are recorded on the incident"

        return obligations

    async def calculate_notification_deadlines(self, incident_id: str) -> Dict[str, str]:
        """
        Calculate notification deadlines by regulation.
        - GDPR: 72 hours to authority
        - CCPA: 30 days to subjects (without unreasonable delay)
        - HIPAA: 60 days
        """
        logger.info(f"Calculating notification deadlines for {incident_id}")

        stmt = select(PrivacyIncident).where(
            and_(
                PrivacyIncident.id == incident_id,
                PrivacyIncident.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        incident = result.scalar_one_or_none()

        if not incident:
            return {}

        # Anchor on when the incident was recorded, not on "now": anchoring on
        # now() moved every deadline forward each time it was recalculated.
        anchor = incident.created_at or datetime.now(timezone.utc)
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)
        regulations = json.loads(incident.regulations_implicated) if incident.regulations_implicated else []
        regulations = [str(r).lower() for r in regulations]
        deadlines: Dict[str, str] = {"anchored_to_reported_at": anchor.isoformat()}
        if "gdpr" in regulations:
            deadlines["gdpr_authority"] = (anchor + timedelta(hours=72)).isoformat()
        if "ccpa" in regulations:
            deadlines["ccpa_subjects"] = (anchor + timedelta(days=30)).isoformat()
        if "hipaa" in regulations or "hipaa_right" in regulations:
            deadlines["hipaa"] = (anchor + timedelta(days=60)).isoformat()
        if len(deadlines) == 1:
            deadlines["status"] = "not_assessed"
            deadlines["detail"] = (
                "no regulations with a notification deadline are recorded on the incident "
                "(set regulations_implicated)"
            )
            return deadlines

        incident.notification_deadline = min(v for k, v in deadlines.items() if k != "anchored_to_reported_at")
        logger.info(f"Deadlines calculated for incident {incident_id}")
        return deadlines

    async def track_notifications(self, incident_id: str) -> bool:
        """
        Track and confirm notifications sent.
        """
        logger.info(f"Tracking notifications for incident {incident_id}")

        stmt = select(PrivacyIncident).where(
            and_(
                PrivacyIncident.id == incident_id,
                PrivacyIncident.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        incident = result.scalar_one_or_none()

        if not incident:
            return False

        incident.supervisory_authority_notified = True
        incident.subjects_notified = True
        logger.info(f"Notifications tracked for incident {incident_id}")
        return True

    async def generate_incident_report(self, incident_id: str) -> str:
        """
        Generate comprehensive incident report for documentation/disclosure.
        """
        logger.info(f"Generating incident report for {incident_id}")

        stmt = select(PrivacyIncident).where(
            and_(
                PrivacyIncident.id == incident_id,
                PrivacyIncident.organization_id == self.org_id,
            )
        )
        result = await self.db.execute(stmt)
        incident = result.scalar_one_or_none()

        if not incident:
            return ""

        report = f"""
PRIVACY INCIDENT REPORT
Incident ID: {incident.id}
Title: {incident.title}
Date Reported: {incident.created_at.isoformat()}
Severity: {incident.severity}
Status: {incident.status}

Description
-----------
{incident.description}

Impact
------
Subjects Affected: {incident.subjects_affected_count}
Data Types: {incident.data_types_affected}
Regulations Implicated: {incident.regulations_implicated}

Response Actions
----------------
{incident.containment_actions}

Root Cause
----------
{incident.root_cause}

Remediation
-----------
{incident.remediation_steps}

Notification Status
-------------------
Supervisory Authority Notified: {incident.supervisory_authority_notified}
Subjects Notified: {incident.subjects_notified}
Deadline: {incident.notification_deadline}
"""

        return report
