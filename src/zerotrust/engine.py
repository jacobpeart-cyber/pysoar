"""Zero Trust Architecture engine for NIST 800-207 implementation

Core components for policy decision, device trust, micro-segmentation,
continuous authentication, and maturity assessment.
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.zerotrust.models import (
    AccessDecision,
    DeviceTrustProfile,
    IdentityVerification,
    MicroSegment,
    ZeroTrustPolicy,
)

logger = get_logger(__name__)


class PolicyDecisionPoint:
    """Policy Decision Point (PDP) - Core access control engine"""

    def __init__(self, db: AsyncSession, organization_id: str):
        self.db = db
        self.organization_id = organization_id

    async def evaluate_access_request(
        self,
        subject_type: str,
        subject_id: str,
        resource_type: str,
        resource_id: str,
        context: dict[str, Any],
    ) -> AccessDecision:
        """Evaluate access request and make allow/deny decision

        Args:
            subject_type: Type of subject (user, service, device, application)
            subject_id: ID of subject
            resource_type: Type of resource (application, data, network_segment, etc)
            resource_id: ID of resource
            context: Contextual information (location, device, time, behavior)

        Returns:
            AccessDecision model with decision and reasoning
        """
        logger.info(
            "evaluating_access_request",
            subject=f"{subject_type}:{subject_id}",
            resource=f"{resource_type}:{resource_id}",
        )

        # Calculate risk scores
        subject_risk = await self._calculate_subject_risk(subject_id)
        context_risk = await self._calculate_context_risk(context)
        device_trust = None
        device_trust_score = None

        if "device_id" in context:
            device_trust = await self._get_device_trust(context["device_id"])
            if device_trust:
                device_trust_score = device_trust.trust_score
                context_risk += (100 - device_trust_score) * 0.2

        # Calculate combined risk score (weighted average)
        combined_risk = (subject_risk * 0.4) + (context_risk * 0.6)

        # Match against policies (highest priority first)
        matching_policies = await self._match_policies(
            subject_type,
            subject_id,
            resource_type,
            resource_id,
            context,
            combined_risk,
        )

        # Make decision
        decision = "deny"
        decision_reason = "No matching policy found"
        policy_id = None
        authentication_method = context.get("authentication_method")
        mfa_completed = context.get("mfa_completed", False)
        risk_factors = []

        if matching_policies:
            policy = matching_policies[0]
            policy_id = policy.id

            # Check if risk exceeds threshold
            if combined_risk > policy.risk_threshold:
                decision = "step_up"
                decision_reason = (
                    f"Risk score {combined_risk:.1f} exceeds threshold {policy.risk_threshold}"
                )
                risk_factors.append(
                    f"elevated_risk_score_{combined_risk:.1f}"
                )
            # Check MFA requirement
            elif policy.requires_mfa and not mfa_completed:
                decision = "challenge"
                decision_reason = "Multi-factor authentication required"
                risk_factors.append("mfa_required")
            # Check device trust requirement
            elif (
                policy.requires_device_trust
                and device_trust_score
                and device_trust_score < policy.minimum_device_trust_score
            ):
                decision = "step_up"
                decision_reason = (
                    f"Device trust score {device_trust_score:.1f} below "
                    f"minimum {policy.minimum_device_trust_score}"
                )
                risk_factors.append(
                    f"low_device_trust_{device_trust_score:.1f}"
                )
            else:
                # Check policy actions
                actions = json.loads(policy.actions) if policy.actions else []
                if "allow" in actions:
                    decision = "allow"
                    decision_reason = f"Policy {policy.name} matched and allowed"
                elif "isolate" in actions:
                    decision = "isolate"
                    decision_reason = f"Policy {policy.name} requires isolation"
                else:
                    decision = "deny"
                    decision_reason = f"Policy {policy.name} denies access"

            # Update policy hit count
            policy.hit_count += 1
            policy.last_triggered_at = datetime.now(timezone.utc)
            self.db.add(policy)

        # Create access decision record
        access_decision = AccessDecision(
            policy_id=policy_id,
            subject_type=subject_type,
            subject_id=subject_id,
            resource_type=resource_type,
            resource_id=resource_id,
            decision=decision,
            risk_score=combined_risk,
            risk_factors=json.dumps(risk_factors),
            context=json.dumps(context),
            authentication_method=authentication_method,
            mfa_completed=mfa_completed,
            device_trust_score=device_trust_score,
            session_id=context.get("session_id"),
            decision_reason=decision_reason,
            organization_id=self.organization_id,
        )

        self.db.add(access_decision)
        await self.db.commit()

        logger.info(
            "access_decision_made",
            decision=decision,
            risk_score=combined_risk,
            policy_id=policy_id,
        )

        return access_decision

    async def continuous_evaluation(self, session_id: str) -> Optional[AccessDecision]:
        """Re-evaluate active session for ongoing risk changes

        Args:
            session_id: Session identifier

        Returns:
            New AccessDecision if re-evaluation needed, None otherwise
        """
        logger.info("continuous_evaluation", session_id=session_id)

        # Query last decision for this session
        result = await self.db.execute(
            select(AccessDecision)
            .where(AccessDecision.session_id == session_id)
            .order_by(desc(AccessDecision.created_at))
            .limit(1)
        )
        last_decision = result.scalar_one_or_none()

        if not last_decision:
            return None

        # Get current context from last decision
        context = json.loads(last_decision.context)

        # Recalculate risk scores
        new_risk = await self._calculate_subject_risk(last_decision.subject_id)

        # Check for significant risk changes (> 20 point delta)
        risk_delta = abs(new_risk - last_decision.risk_score)

        if risk_delta > 20:
            logger.warning(
                "risk_score_changed_significantly",
                session_id=session_id,
                old_risk=last_decision.risk_score,
                new_risk=new_risk,
                delta=risk_delta,
            )

            # If current decision was allow and new risk is high, challenge
            if last_decision.decision == "allow" and new_risk > 70:
                # Trigger step-up authentication
                return await self.evaluate_access_request(
                    last_decision.subject_type,
                    last_decision.subject_id,
                    last_decision.resource_type,
                    last_decision.resource_id,
                    {**context, "risk_change": risk_delta},
                )

        return None

    async def _calculate_subject_risk(self, subject_id: str) -> float:
        """Calculate subject (user/service) risk score

        Factors:
        - Authentication strength
        - User behavior anomalies
        - Failed login attempts
        - Privilege level
        - Account age
        """
        risk_score = 20.0  # Baseline

        # TODO: Integrate with UEBA (User and Entity Behavior Analytics)
        # For now, return baseline
        # In production, this would check:
        # - Recent failed authentications
        # - Unusual access patterns
        # - Privilege escalation attempts
        # - Service account activity patterns

        logger.debug("calculated_subject_risk", subject_id=subject_id, risk=risk_score)
        return risk_score

    async def _calculate_context_risk(self, context: dict[str, Any]) -> float:
        """Calculate contextual risk score

        Factors:
        - Geographic location
        - Time of access
        - Network type (VPN, corporate, public)
        - Access pattern (typical vs anomalous)
        """
        risk_score = 30.0  # Baseline

        # Geographic risk
        if context.get("location"):
            location = context["location"]
            if location.get("is_new_location"):
                risk_score += 15
            if location.get("is_high_risk_country"):
                risk_score += 20

        # Network risk
        if context.get("network_type") == "public":
            risk_score += 10
        elif context.get("network_type") == "vpn":
            risk_score -= 5

        # Time-based risk
        if context.get("is_off_hours"):
            risk_score += 5

        logger.debug("calculated_context_risk", risk=risk_score)
        return min(risk_score, 100.0)  # Cap at 100

    async def _get_device_trust(self, device_id: str) -> Optional[DeviceTrustProfile]:
        """Get device trust profile"""
        result = await self.db.execute(
            select(DeviceTrustProfile)
            .where(
                and_(
                    DeviceTrustProfile.device_id == device_id,
                    DeviceTrustProfile.organization_id == self.organization_id,
                )
            )
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _match_policies(
        self,
        subject_type: str,
        subject_id: str,
        resource_type: str,
        resource_id: str,
        context: dict[str, Any],
        risk_score: float,
    ) -> list[ZeroTrustPolicy]:
        """Find matching policies ordered by priority

        Returns:
            List of matching policies sorted by priority (highest first)
        """
        result = await self.db.execute(
            select(ZeroTrustPolicy)
            .where(
                and_(
                    ZeroTrustPolicy.organization_id == self.organization_id,
                    ZeroTrustPolicy.is_enabled == True,
                )
            )
            .order_by(desc(ZeroTrustPolicy.priority))
        )
        all_policies = result.scalars().all()

        # Simple matching logic (can be extended with more sophisticated matching)
        matching = []
        for policy in all_policies:
            # Basic check: policy risk threshold vs actual risk
            if risk_score <= policy.risk_threshold:
                matching.append(policy)

        logger.debug(
            "matched_policies",
            subject=subject_type,
            resource=resource_type,
            count=len(matching),
        )

        return matching


class DeviceTrustAssessor:
    """Device trust assessment and compliance checking"""

    def __init__(self, db: AsyncSession, organization_id: str):
        self.db = db
        self.organization_id = organization_id

    async def assess_device(self, device_id: str) -> DeviceTrustProfile:
        """Assess device compliance and calculate trust score

        Checks:
        - OS patch level
        - Antivirus status
        - Encryption status
        - Firewall status
        - Certificate validity
        - Jailbreak/root detection
        """
        logger.info("assessing_device", device_id=device_id)

        # Get or create device profile
        result = await self.db.execute(
            select(DeviceTrustProfile)
            .where(
                and_(
                    DeviceTrustProfile.device_id == device_id,
                    DeviceTrustProfile.organization_id == self.organization_id,
                )
            )
            .limit(1)
        )
        device = result.scalar_one_or_none()

        if not device:
            logger.warning("device_not_found_creating", device_id=device_id)
            device = DeviceTrustProfile(
                device_id=device_id,
                device_type="unknown",
                organization_id=self.organization_id,
            )

        # Calculate trust score based on compliance
        compliance_status = json.loads(device.compliance_status or "{}")
        trust_score = self._calculate_trust_score(compliance_status)

        device.trust_score = trust_score
        device.last_assessment_at = datetime.now(timezone.utc)

        # Determine trust level
        if trust_score >= 80:
            device.trust_level = "trusted"
        elif trust_score >= 60:
            device.trust_level = "conditional"
        elif trust_score >= 40:
            device.trust_level = "untrusted"
        else:
            device.trust_level = "blocked"

        self.db.add(device)
        await self.db.commit()

        logger.info(
            "device_assessment_complete",
            device_id=device_id,
            trust_score=trust_score,
            trust_level=device.trust_level,
        )

        return device

    def _calculate_trust_score(self, compliance_status: dict[str, Any]) -> float:
        """Calculate composite trust score from compliance factors

        Factors:
        - OS patched (25%)
        - AV active (25%)
        - Encryption (25%)
        - Firewall (15%)
        - Certificate valid (10%)
        """
        score = 0.0

        if compliance_status.get("os_patched"):
            score += 25
        if compliance_status.get("av_active"):
            score += 25
        if compliance_status.get("encryption_enabled"):
            score += 25
        if compliance_status.get("firewall_on"):
            score += 15
        if compliance_status.get("certificate_valid"):
            score += 10

        # Penalize jailbreak/root
        if compliance_status.get("jailbroken") or compliance_status.get("rooted"):
            score = max(0, score - 50)

        return min(score, 100.0)

    async def update_device_compliance(
        self, device_id: str, compliance_data: dict[str, Any]
    ) -> DeviceTrustProfile:
        """Update device compliance data and recalculate trust score"""
        result = await self.db.execute(
            select(DeviceTrustProfile)
            .where(
                and_(
                    DeviceTrustProfile.device_id == device_id,
                    DeviceTrustProfile.organization_id == self.organization_id,
                )
            )
            .limit(1)
        )
        device = result.scalar_one_or_none()

        if not device:
            raise ValueError(f"Device {device_id} not found")

        # Update compliance status
        current_status = json.loads(device.compliance_status or "{}")
        current_status.update(compliance_data)
        device.compliance_status = json.dumps(current_status)

        # Recalculate trust score
        device.trust_score = self._calculate_trust_score(current_status)
        device.last_assessment_at = datetime.now(timezone.utc)

        self.db.add(device)
        await self.db.commit()

        logger.info(
            "device_compliance_updated",
            device_id=device_id,
            trust_score=device.trust_score,
        )

        return device

    async def get_non_compliant_devices(self) -> list[DeviceTrustProfile]:
        """Get devices below compliance threshold"""
        result = await self.db.execute(
            select(DeviceTrustProfile).where(
                and_(
                    DeviceTrustProfile.organization_id == self.organization_id,
                    DeviceTrustProfile.trust_score < 70,
                )
            )
        )
        return result.scalars().all()


class MicroSegmentationEngine:
    """Micro-segmentation for network and application isolation"""

    def __init__(self, db: AsyncSession, organization_id: str):
        self.db = db
        self.organization_id = organization_id

    async def create_segment(
        self,
        name: str,
        segment_type: str,
        config: dict[str, Any],
    ) -> MicroSegment:
        """Create a new micro-segment

        Args:
            name: Segment name
            segment_type: Type (network, application, data, workload)
            config: Configuration dictionary
        """
        logger.info("creating_segment", name=name, type=segment_type)

        segment = MicroSegment(
            name=name,
            segment_type=segment_type,
            description=config.get("description"),
            cidr_ranges=json.dumps(config.get("cidr_ranges", [])),
            allowed_protocols=json.dumps(config.get("allowed_protocols", [])),
            allowed_ports=json.dumps(config.get("allowed_ports", [])),
            allowed_services=json.dumps(config.get("allowed_services", [])),
            ingress_policies=json.dumps(config.get("ingress_policies", [])),
            egress_policies=json.dumps(config.get("egress_policies", [])),
            trust_level=config.get("trust_level", "zero"),
            organization_id=self.organization_id,
        )

        self.db.add(segment)
        await self.db.commit()

        logger.info("segment_created", segment_id=segment.id, name=name)
        return segment

    async def evaluate_traffic(
        self,
        source: str,
        destination: str,
        protocol: str,
        port: int,
    ) -> dict[str, Any]:
        """Evaluate if traffic is allowed within segments

        Returns:
            {allowed: bool, reason: str, segments: list}
        """
        # TODO: Implement traffic evaluation logic
        # This would check segment policies, allowed protocols/ports, etc.

        return {
            "allowed": True,
            "reason": "No restrictions",
            "segments": [],
        }

    async def detect_lateral_movement(
        self, traffic_data: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Detect suspicious lateral movement patterns

        Returns:
            List of detected anomalies with details
        """
        anomalies = []
        # TODO: Implement lateral movement detection
        return anomalies

    async def get_segment_violations(self, segment_id: str) -> list[dict[str, Any]]:
        """Get policy violations for a segment"""
        result = await self.db.execute(
            select(MicroSegment)
            .where(
                and_(
                    MicroSegment.id == segment_id,
                    MicroSegment.organization_id == self.organization_id,
                )
            )
            .limit(1)
        )
        segment = result.scalar_one_or_none()

        if not segment:
            return []

        # TODO: Return actual violations from audit logs
        return []

    async def visualize_segments(self) -> dict[str, Any]:
        """Get topology data for visualization

        Returns:
            Topology data structure for frontend visualization
        """
        result = await self.db.execute(
            select(MicroSegment).where(
                MicroSegment.organization_id == self.organization_id
            )
        )
        segments = result.scalars().all()

        topology = {
            "segments": [
                {
                    "id": s.id,
                    "name": s.name,
                    "type": s.segment_type,
                    "trust_level": s.trust_level,
                    "violations": s.violation_count,
                }
                for s in segments
            ],
            "connections": [],  # TODO: Populate from traffic data
        }

        return topology


class ContinuousAuthEngine:
    """Continuous authentication and verification"""

    def __init__(self, db: AsyncSession, organization_id: str):
        self.db = db
        self.organization_id = organization_id

    async def initiate_verification(
        self,
        user_id: str,
        verification_type: str,
        trigger_reason: Optional[str] = None,
        context: Optional[dict] = None,
    ) -> IdentityVerification:
        """Initiate identity verification

        Args:
            user_id: User identifier
            verification_type: Type of verification
            trigger_reason: Reason for verification
            context: Contextual information
        """
        logger.info(
            "initiating_verification",
            user_id=user_id,
            type=verification_type,
        )

        context = context or {}

        verification = IdentityVerification(
            user_id=user_id,
            verification_type=verification_type,
            method="pending",  # Will be updated based on challenge
            result="pending",
            risk_score_before=context.get("risk_score", 0),
            risk_score_after=0,
            trigger_reason=trigger_reason,
            device_id=context.get("device_id"),
            source_ip=context.get("source_ip"),
            session_id=context.get("session_id"),
            organization_id=self.organization_id,
        )

        self.db.add(verification)
        await self.db.commit()

        return verification

    async def step_up_authentication(
        self,
        session_id: str,
        required_level: str,
    ) -> dict[str, Any]:
        """Initiate step-up authentication for elevated access

        Args:
            session_id: Current session ID
            required_level: Required authentication level

        Returns:
            Challenge details
        """
        logger.info(
            "step_up_authentication",
            session_id=session_id,
            required_level=required_level,
        )

        # Determine authentication method based on required level
        if required_level == "mfa":
            methods = ["mfa_totp", "mfa_push"]
        elif required_level == "biometric":
            methods = ["biometric"]
        else:
            methods = ["password"]

        return {
            "required_level": required_level,
            "available_methods": methods,
            "challenge_id": f"challenge_{session_id}",
        }

    async def check_session_validity(self, session_id: str) -> bool:
        """Check if session is still valid

        Returns:
            True if valid, False otherwise
        """
        # TODO: Check against session store
        return True

    async def _should_reauthenticate(
        self, session_data: dict[str, Any], risk_delta: float
    ) -> bool:
        """Determine if re-authentication is needed

        Args:
            session_data: Session information
            risk_delta: Change in risk score

        Returns:
            True if re-authentication required
        """
        # Re-auth if risk increased significantly
        if risk_delta > 30:
            return True

        # Re-auth based on session age (e.g., > 1 hour)
        # TODO: Implement session age check

        return False

    def _determine_auth_level(self, risk_score: float) -> str:
        """Determine required authentication level based on risk

        Args:
            risk_score: Current risk score (0-100)

        Returns:
            Auth level: password_only, mfa, biometric
        """
        if risk_score < 40:
            return "password_only"
        elif risk_score < 70:
            return "mfa"
        else:
            return "biometric"


class ZeroTrustScorer:
    """Zero Trust maturity assessment using CISA model"""

    def __init__(self, db: AsyncSession, organization_id: str):
        self.db = db
        self.organization_id = organization_id

    async def calculate_maturity_score(self) -> dict[str, Any]:
        """Calculate overall Zero Trust maturity score

        Returns:
            {overall_score, pillars, maturity_level, recommendations}
        """
        logger.info("calculating_zero_trust_maturity")

        pillars = {
            "identity": await self.assess_pillar("identity"),
            "devices": await self.assess_pillar("devices"),
            "networks": await self.assess_pillar("networks"),
            "applications": await self.assess_pillar("applications"),
            "data": await self.assess_pillar("data"),
        }

        # Calculate overall score (average of pillars)
        overall_score = sum(p["score"] for p in pillars.values()) / len(pillars)

        maturity_level = self.get_maturity_level_from_score(overall_score)
        recommendations = await self.generate_recommendations(pillars)

        return {
            "overall_score": overall_score,
            "maturity_level": maturity_level,
            "pillars": pillars,
            "recommendations": recommendations,
        }

    async def assess_pillar(self, pillar: str) -> dict[str, Any]:
        """Assess specific Zero Trust pillar

        Args:
            pillar: Pillar name (identity, devices, networks, applications, data)

        Returns:
            {pillar, score, maturity_level, details}
        """
        # TODO: Implement pillar-specific assessment logic
        # This would check relevant policies, devices, segments, etc.

        score = 50.0  # Baseline
        maturity_level = "initial"

        return {
            "pillar": pillar,
            "score": score,
            "maturity_level": maturity_level,
            "details": {},
        }

    async def get_maturity_level(self) -> str:
        """Get overall maturity level"""
        score_data = await self.calculate_maturity_score()
        return score_data["maturity_level"]

    def get_maturity_level_from_score(self, score: float) -> str:
        """Map score to maturity level

        CISA Zero Trust Maturity Model:
        - Traditional (0-24): Legacy approaches
        - Initial (25-49): Beginning ZT implementation
        - Advanced (50-74): ZT widely deployed
        - Optimal (75-100): Full ZT maturity
        """
        if score >= 75:
            return "optimal"
        elif score >= 50:
            return "advanced"
        elif score >= 25:
            return "initial"
        else:
            return "traditional"

    async def generate_recommendations(
        self, pillars: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Generate improvement recommendations

        Args:
            pillars: Pillar assessment results

        Returns:
            List of recommendations prioritized by impact
        """
        recommendations = []

        # TODO: Generate pillar-specific recommendations based on gaps

        return recommendations
