"""Zero Trust Architecture engine for NIST 800-207 implementation

Core components for policy decision, device trust, micro-segmentation,
continuous authentication, and maturity assessment.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import and_, desc, func, select
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


def _compare(op: str, observed: Any, expected: Any) -> bool:
    """Boolean compare for policy condition attributes.

    Supported operators (case-insensitive): equals/eq/is, not_equals/ne,
    in, not_in, contains, starts_with, ends_with, greater_than/gt,
    less_than/lt, gte, lte. Missing observed values never satisfy a
    positive match — the PDP fails closed.
    """
    op = (op or "equals").lower()
    if observed is None and op not in ("not_equals", "ne", "not_in"):
        return False
    try:
        if op in ("equals", "eq", "is"):
            return str(observed).lower() == str(expected).lower()
        if op in ("not_equals", "ne"):
            return str(observed).lower() != str(expected).lower()
        if op == "in":
            seq = expected if isinstance(expected, (list, tuple, set)) else [expected]
            return str(observed).lower() in {str(v).lower() for v in seq}
        if op == "not_in":
            seq = expected if isinstance(expected, (list, tuple, set)) else [expected]
            return str(observed).lower() not in {str(v).lower() for v in seq}
        if op == "contains":
            return str(expected).lower() in str(observed).lower()
        if op == "starts_with":
            return str(observed).lower().startswith(str(expected).lower())
        if op == "ends_with":
            return str(observed).lower().endswith(str(expected).lower())
        if op in ("greater_than", "gt"):
            return float(observed) > float(expected)
        if op in ("less_than", "lt"):
            return float(observed) < float(expected)
        if op == "gte":
            return float(observed) >= float(expected)
        if op == "lte":
            return float(observed) <= float(expected)
    except (TypeError, ValueError):
        return False
    # Unknown operator: fail closed rather than silently allow.
    return False


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

            # Location-based force deny: if the matched policy declares
            # blocked_locations and the request originates from one, the
            # configured actions are overridden to deny. This matches the
            # enforcement convention of Cloudflare Access / Okta / Azure
            # Conditional Access — an admin writing "block RU" expects
            # RU requests to be denied, not processed under MFA challenge.
            if self._location_force_deny(policy, context):
                decision = "deny"
                decision_reason = (
                    f"Policy {policy.name} denies access from blocked location"
                )
                risk_factors.append("blocked_location")
                policy.hit_count += 1
                policy.last_triggered_at = datetime.now(timezone.utc)
                self.db.add(policy)
                # Fall through to decision persistence below without the
                # risk / MFA / device-trust branches — a blocked-location
                # deny is absolute.
                matching_policies = []

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

        # Push the verdict into the session-gate cache so the
        # middleware picks up the new state on the very next request —
        # revocation propagates within a single request cycle instead of
        # waiting 30s for the cache to expire.
        sid = context.get("session_id")
        if sid:
            try:
                from src.zerotrust.session_gate import invalidate_session_cache
                await invalidate_session_cache(sid, decision)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "zt_session_cache_push_failed",
                    session_id=sid[:8] if isinstance(sid, str) else None,
                    error=str(exc),
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

        # Check recent failed access decisions for this subject
        recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        failed_result = await self.db.execute(
            select(AccessDecision).where(
                and_(
                    AccessDecision.subject_id == subject_id,
                    AccessDecision.organization_id == self.organization_id,
                    AccessDecision.decision == "deny",
                    AccessDecision.created_at >= recent_cutoff,
                )
            )
        )
        recent_failures = failed_result.scalars().all()
        # Each recent denied access adds to risk
        risk_score += len(recent_failures) * 5.0

        # Check for step-up/challenge decisions (indicates elevated risk context)
        stepup_result = await self.db.execute(
            select(AccessDecision).where(
                and_(
                    AccessDecision.subject_id == subject_id,
                    AccessDecision.organization_id == self.organization_id,
                    AccessDecision.decision.in_(["step_up", "challenge"]),
                    AccessDecision.created_at >= recent_cutoff,
                )
            )
        )
        recent_stepups = stepup_result.scalars().all()
        risk_score += len(recent_stepups) * 3.0

        # Check failed identity verifications
        failed_verif_result = await self.db.execute(
            select(IdentityVerification).where(
                and_(
                    IdentityVerification.user_id == subject_id,
                    IdentityVerification.organization_id == self.organization_id,
                    IdentityVerification.result == "failure",
                    IdentityVerification.created_at >= recent_cutoff,
                )
            )
        )
        failed_verifications = failed_verif_result.scalars().all()
        risk_score += len(failed_verifications) * 10.0

        risk_score = min(risk_score, 100.0)

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

        # Geographic risk. `location` may be a plain country/city string
        # (e.g. "RU") or a structured dict with is_new_location /
        # is_high_risk_country flags. Support both shapes — callers from
        # the UI and from SIEM alert escalation hand us different
        # formats, and a dict/str confusion crashed the evaluator.
        loc = context.get("location")
        if isinstance(loc, dict):
            if loc.get("is_new_location"):
                risk_score += 15
            if loc.get("is_high_risk_country"):
                risk_score += 20
        elif isinstance(loc, str) and loc:
            HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "SY", "BY", "VE"}
            code = loc.strip().upper()[:2]
            if code in HIGH_RISK_COUNTRIES:
                risk_score += 20
            if context.get("is_new_location"):
                risk_score += 15

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
                    ZeroTrustPolicy.is_enabled == True,  # noqa: E712
                )
            )
            .order_by(desc(ZeroTrustPolicy.priority))
        )
        all_policies = result.scalars().all()

        matching: list[ZeroTrustPolicy] = []
        for policy in all_policies:
            # A policy applies to a request only if EVERY scope dimension
            # matches. Previous revision matched on risk_threshold alone,
            # so every enabled policy applied to every resource, location,
            # and hour — a critical Zero Trust audit lie. NIST SP 800-207
            # §3.2.2 requires the PDP to evaluate policy against the full
            # subject/resource/environment tuple before emitting a decision.
            if risk_score > policy.risk_threshold:
                continue
            if not self._policy_type_matches(policy, resource_type):
                continue
            if not self._resource_scope_matches(policy, resource_type, resource_id):
                continue
            if not self._location_scope_matches(policy, context):
                continue
            if not self._time_scope_matches(policy, context):
                continue
            if not self._conditions_match(policy, subject_type, subject_id, resource_type, resource_id, context):
                continue
            matching.append(policy)

        logger.debug(
            "matched_policies",
            subject=subject_type,
            resource=resource_type,
            risk=risk_score,
            count=len(matching),
        )

        return matching

    # ------------------------------------------------------------------
    # Scope evaluators — real NIST SP 800-207 PDP attribute matching.
    # ------------------------------------------------------------------

    @staticmethod
    def _policy_type_matches(policy: ZeroTrustPolicy, resource_type: str) -> bool:
        """`policy_type == 'access'` is the catch-all; typed policies only
        fire on matching resource classes."""
        ptype = (policy.policy_type or "").lower()
        if ptype in ("", "access"):
            return True
        rtype = (resource_type or "").lower()
        # Accept either exact match or common synonyms (network⇄net,
        # workload⇄service, data⇄file, identity⇄user).
        synonyms = {
            "network": {"network", "net", "segment"},
            "workload": {"workload", "service", "app", "application"},
            "data": {"data", "file", "document"},
            "identity": {"identity", "user", "principal", "group"},
            "device": {"device", "endpoint", "host"},
            "visibility": {"visibility", "telemetry", "log"},
        }
        for key, aliases in synonyms.items():
            if ptype == key and rtype in aliases:
                return True
        return ptype == rtype

    @staticmethod
    def _resource_scope_matches(policy: ZeroTrustPolicy, resource_type: str, resource_id: str) -> bool:
        """Honor resource_type / resource_id constraints encoded in the
        `conditions` JSON. Policies without explicit resource conditions
        remain wildcards (they have already passed policy_type)."""
        try:
            conds = json.loads(policy.conditions or "[]")
        except (ValueError, TypeError):
            return True
        if not isinstance(conds, list):
            return True
        for c in conds:
            if not isinstance(c, dict):
                continue
            attr = c.get("attribute")
            op = (c.get("operator") or "equals").lower()
            value = c.get("value")
            observed = None
            if attr in ("resource_type", "resource"):
                observed = resource_type
            elif attr in ("resource_id", "id"):
                observed = resource_id
            else:
                continue
            if not _compare(op, observed, value):
                return False
        return True

    @staticmethod
    def _location_scope_matches(policy: ZeroTrustPolicy, context: dict[str, Any]) -> bool:
        """Scope check for location.

        - `allowed_locations` = positive scope: policy applies only when
          the user is in one of these locations.
        - `blocked_locations` = negative scope + force-deny: policy ALSO
          applies only when the user is in one of these locations, and
          then the action is overridden to deny inside
          evaluate_access_request (see `_location_force_deny`).

        So an admin who writes ``blocked_locations: ["RU"], actions:
        ["deny"]`` gets exactly what they expect: the policy only fires
        for RU requests and always denies them. Matches Cloudflare
        Access / Okta / Azure Conditional Access conventions.
        """
        loc = (context or {}).get("location") or (context or {}).get("country_code") or ""
        ip = (context or {}).get("ip_address") or ""
        try:
            allowed = json.loads(policy.allowed_locations or "[]") or []
            blocked = json.loads(policy.blocked_locations or "[]") or []
        except (ValueError, TypeError):
            allowed, blocked = [], []
        haystack = [str(loc).lower(), str(ip).lower()]
        if allowed and not any(str(a).lower() in haystack for a in allowed):
            return False
        if blocked and not any(str(b).lower() in haystack for b in blocked):
            return False
        return True

    @staticmethod
    def _location_force_deny(policy: ZeroTrustPolicy, context: dict[str, Any]) -> bool:
        """Return True if this policy's blocked_locations covers the
        request's origin, meaning the evaluator MUST emit deny regardless
        of the configured actions array. Called after scope matching."""
        loc = (context or {}).get("location") or (context or {}).get("country_code") or ""
        ip = (context or {}).get("ip_address") or ""
        try:
            blocked = json.loads(policy.blocked_locations or "[]") or []
        except (ValueError, TypeError):
            blocked = []
        if not blocked:
            return False
        haystack = [str(loc).lower(), str(ip).lower()]
        return any(str(b).lower() in haystack for b in blocked)

    @staticmethod
    def _time_scope_matches(policy: ZeroTrustPolicy, context: dict[str, Any]) -> bool:
        """Honor `time_restrictions` = {start_time, end_time, days_of_week}.
        Times are UTC HH:MM strings; days_of_week uses 0=Mon … 6=Sun."""
        try:
            restr = json.loads(policy.time_restrictions or "{}")
        except (ValueError, TypeError):
            return True
        if not isinstance(restr, dict) or not restr:
            return True
        now = datetime.now(timezone.utc)
        days = restr.get("days_of_week")
        if isinstance(days, list) and days and now.weekday() not in days:
            return False
        start = restr.get("start_time")
        end = restr.get("end_time")
        if start and end and isinstance(start, str) and isinstance(end, str):
            try:
                sh, sm = [int(x) for x in start.split(":")[:2]]
                eh, em = [int(x) for x in end.split(":")[:2]]
                minute_now = now.hour * 60 + now.minute
                start_min = sh * 60 + sm
                end_min = eh * 60 + em
                if start_min <= end_min:
                    if not (start_min <= minute_now <= end_min):
                        return False
                else:
                    # Window wraps midnight (e.g. 22:00 → 06:00).
                    if not (minute_now >= start_min or minute_now <= end_min):
                        return False
            except (ValueError, IndexError):
                return True
        return True

    @staticmethod
    def _conditions_match(
        policy: ZeroTrustPolicy,
        subject_type: str,
        subject_id: str,
        resource_type: str,
        resource_id: str,
        context: dict[str, Any],
    ) -> bool:
        """Evaluate non-resource conditions in the policy JSON.
        Supported attributes: subject_type, subject_id, user, group, tag,
        authentication_method, mfa_completed, plus any key present in
        the `context` dict (network_type, location, device_id, etc.)."""
        try:
            conds = json.loads(policy.conditions or "[]")
        except (ValueError, TypeError):
            return True
        if not isinstance(conds, list):
            return True
        for c in conds:
            if not isinstance(c, dict):
                continue
            attr = c.get("attribute")
            if attr in ("resource_type", "resource", "resource_id", "id"):
                # Handled by _resource_scope_matches.
                continue
            op = (c.get("operator") or "equals").lower()
            value = c.get("value")
            if attr == "subject_type":
                observed = subject_type
            elif attr in ("subject_id", "user", "principal"):
                observed = subject_id
            else:
                observed = (context or {}).get(attr)
            if not _compare(op, observed, value):
                return False
        return True


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
            # First-time posture heartbeat for this device — create the
            # profile rather than raise, so Zero Trust coverage is
            # automatic the moment an agent enrolls (no manual step).
            device = DeviceTrustProfile(
                device_id=device_id,
                device_type="managed",
                organization_id=self.organization_id,
                compliance_status=json.dumps({}),
                trust_score=0.0,
                trust_level="unknown",
            )
            self.db.add(device)

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

    @staticmethod
    def _safe_json_list(raw: Optional[str]) -> list:
        """Parse a JSON column that is supposed to be a list, returning
        an empty list on any corruption / manual-edit damage rather
        than crashing the entire evaluate_traffic path."""
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else []
        except (ValueError, TypeError):
            logger.warning(
                "microsegment json column failed to parse; treating as empty",
                extra={"raw": raw[:120]},
            )
            return []

    @staticmethod
    def _ip_in_any_cidr(ip_str: str, cidr_list: list) -> bool:
        """Real network containment check using the stdlib ``ipaddress``
        module. The previous implementation did a substring prefix
        match on the first three octets, which produced wrong answers
        for every prefix that wasn't exactly /24 — e.g. 10.0.0.0/16
        never matched 10.0.5.42, and 10.0.0.0/28 silently matched the
        entire /24."""
        import ipaddress

        try:
            ip = ipaddress.ip_address(ip_str)
        except (ValueError, TypeError):
            return False

        for cidr in cidr_list:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if ip in network:
                    return True
            except (ValueError, TypeError):
                continue
        return False

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
        # Fetch all active segments for the organization
        result = await self.db.execute(
            select(MicroSegment).where(
                and_(
                    MicroSegment.organization_id == self.organization_id,
                    MicroSegment.is_active == True,
                )
            )
        )
        segments = result.scalars().all()

        matched_segments = []
        for segment in segments:
            cidr_ranges = self._safe_json_list(segment.cidr_ranges)
            if not cidr_ranges:
                continue
            if self._ip_in_any_cidr(source, cidr_ranges) or self._ip_in_any_cidr(destination, cidr_ranges):
                matched_segments.append(segment)

        if not matched_segments:
            return {
                "allowed": True,
                "reason": "No segment policies apply to this traffic",
                "segments": [],
            }

        # Evaluate against each matched segment's policies
        for segment in matched_segments:
            allowed_protocols = self._safe_json_list(segment.allowed_protocols)
            allowed_ports_raw = self._safe_json_list(segment.allowed_ports)

            # Check protocol
            if allowed_protocols and protocol not in allowed_protocols:
                return {
                    "allowed": False,
                    "reason": f"Protocol '{protocol}' not allowed in segment '{segment.name}'",
                    "segments": [{"id": segment.id, "name": segment.name}],
                }

            # Check port (tolerate mixed int/str in the JSON column)
            if allowed_ports_raw:
                try:
                    allowed_ports = {int(p) for p in allowed_ports_raw}
                except (TypeError, ValueError):
                    allowed_ports = set()
                if allowed_ports and port not in allowed_ports:
                    return {
                        "allowed": False,
                        "reason": f"Port {port} not allowed in segment '{segment.name}'",
                        "segments": [{"id": segment.id, "name": segment.name}],
                    }

        return {
            "allowed": True,
            "reason": "Traffic permitted by segment policies",
            "segments": [{"id": s.id, "name": s.name} for s in matched_segments],
        }

    async def detect_lateral_movement(
        self, traffic_data: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Detect suspicious lateral movement patterns

        Returns:
            List of detected anomalies with details
        """
        anomalies = []

        # Analyze traffic data for lateral movement patterns
        # Track unique source-destination pairs per source
        source_destinations: dict[str, set[str]] = {}
        source_protocols: dict[str, set[str]] = {}

        for entry in traffic_data:
            src = entry.get("source", "")
            dst = entry.get("destination", "")
            proto = entry.get("protocol", "")

            if src not in source_destinations:
                source_destinations[src] = set()
                source_protocols[src] = set()
            source_destinations[src].add(dst)
            source_protocols[src].add(proto)

        for src, destinations in source_destinations.items():
            # Flag: single source contacting many destinations (fan-out)
            if len(destinations) > 5:
                anomalies.append({
                    "type": "fan_out",
                    "source": src,
                    "destination_count": len(destinations),
                    "severity": "high" if len(destinations) > 10 else "medium",
                    "description": f"Source {src} contacted {len(destinations)} unique destinations",
                })

            # Flag: unusual protocol usage (more than 3 distinct protocols)
            protocols = source_protocols[src]
            if len(protocols) > 3:
                anomalies.append({
                    "type": "protocol_scan",
                    "source": src,
                    "protocols": list(protocols),
                    "severity": "medium",
                    "description": f"Source {src} used {len(protocols)} different protocols",
                })

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

        # Query access decisions that were denied for resources in this segment
        result_decisions = await self.db.execute(
            select(AccessDecision).where(
                and_(
                    AccessDecision.organization_id == self.organization_id,
                    AccessDecision.decision.in_(["deny", "isolate"]),
                    AccessDecision.resource_type == "network_segment",
                    AccessDecision.resource_id == segment_id,
                )
            ).order_by(desc(AccessDecision.created_at)).limit(100)
        )
        denied_decisions = result_decisions.scalars().all()

        violations = []
        for decision in denied_decisions:
            violations.append({
                "id": decision.id,
                "timestamp": decision.created_at.isoformat() if decision.created_at else None,
                "subject": f"{decision.subject_type}:{decision.subject_id}",
                "decision": decision.decision,
                "risk_score": decision.risk_score,
                "reason": decision.decision_reason,
            })

        return violations

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
            "connections": [
                {
                    "from": s.id,
                    "to": target_id,
                }
                for s in segments
                for target_id in [
                    p.get("target_segment")
                    for p in json.loads(s.egress_policies or "[]")
                    if isinstance(p, dict) and p.get("target_segment")
                ]
            ],
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
        # Check the most recent access decision for this session
        result = await self.db.execute(
            select(AccessDecision)
            .where(
                and_(
                    AccessDecision.session_id == session_id,
                    AccessDecision.organization_id == self.organization_id,
                )
            )
            .order_by(desc(AccessDecision.created_at))
            .limit(1)
        )
        last_decision = result.scalar_one_or_none()

        if not last_decision:
            return False

        # Session invalid if last decision was deny or isolate
        if last_decision.decision in ("deny", "isolate"):
            return False

        # Session invalid if older than 8 hours
        if last_decision.created_at:
            session_age = datetime.now(timezone.utc) - last_decision.created_at
            if session_age > timedelta(hours=8):
                return False

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

        # Re-auth based on session age (> 1 hour)
        session_created = session_data.get("created_at")
        if session_created:
            if isinstance(session_created, str):
                session_created = datetime.fromisoformat(session_created)
            session_age = datetime.now(timezone.utc) - session_created
            if session_age > timedelta(hours=1):
                return True

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

        # NIST SP 800-207 defines 7 zero-trust pillars; the previous
        # calculation only scored 5 and hid "visibility & analytics"
        # and "automation & orchestration" from the maturity dashboard.
        pillars = {
            "identity": await self.assess_pillar("identity"),
            "devices": await self.assess_pillar("devices"),
            "networks": await self.assess_pillar("networks"),
            "applications": await self.assess_pillar("applications"),
            "data": await self.assess_pillar("data"),
            "visibility": await self.assess_pillar("visibility"),
            "automation": await self.assess_pillar("automation"),
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
        score = 0.0
        details: dict[str, Any] = {}

        if pillar == "identity":
            # Assess identity pillar: check MFA policies and verification success rates
            policy_result = await self.db.execute(
                select(ZeroTrustPolicy).where(
                    and_(
                        ZeroTrustPolicy.organization_id == self.organization_id,
                        ZeroTrustPolicy.is_enabled == True,
                        ZeroTrustPolicy.policy_type == "identity",
                    )
                )
            )
            identity_policies = policy_result.scalars().all()
            mfa_policies = [p for p in identity_policies if p.requires_mfa]
            details["total_identity_policies"] = len(identity_policies)
            details["mfa_enforced_policies"] = len(mfa_policies)
            # Score: base 20 + up to 40 for policies + 40 for MFA coverage
            score = 20.0
            score += min(len(identity_policies) * 10.0, 40.0)
            if identity_policies:
                mfa_ratio = len(mfa_policies) / len(identity_policies)
                score += mfa_ratio * 40.0

        elif pillar == "devices":
            # Assess device pillar: check device trust scores
            device_result = await self.db.execute(
                select(DeviceTrustProfile).where(
                    DeviceTrustProfile.organization_id == self.organization_id
                )
            )
            devices = device_result.scalars().all()
            details["total_devices"] = len(devices)
            if devices:
                avg_trust = sum(d.trust_score for d in devices) / len(devices)
                compliant = sum(1 for d in devices if d.trust_score >= 70)
                details["average_trust_score"] = round(avg_trust, 1)
                details["compliant_devices"] = compliant
                score = avg_trust  # Device maturity tracks average trust score
            else:
                score = 0.0

        elif pillar == "networks":
            # Assess network pillar: check micro-segmentation coverage
            segment_result = await self.db.execute(
                select(MicroSegment).where(
                    and_(
                        MicroSegment.organization_id == self.organization_id,
                        MicroSegment.is_active == True,
                    )
                )
            )
            segments = segment_result.scalars().all()
            details["total_segments"] = len(segments)
            details["segment_types"] = list({s.segment_type for s in segments})
            # Score: base 10 + up to 90 based on segment count and type diversity
            score = 10.0
            score += min(len(segments) * 8.0, 50.0)
            type_diversity = len(details["segment_types"])
            score += min(type_diversity * 10.0, 40.0)

        elif pillar == "applications":
            # Assess applications pillar: check application-related policies
            app_policy_result = await self.db.execute(
                select(ZeroTrustPolicy).where(
                    and_(
                        ZeroTrustPolicy.organization_id == self.organization_id,
                        ZeroTrustPolicy.is_enabled == True,
                        ZeroTrustPolicy.policy_type.in_(["access", "workload"]),
                    )
                )
            )
            app_policies = app_policy_result.scalars().all()
            details["total_app_policies"] = len(app_policies)
            trust_required = sum(1 for p in app_policies if p.requires_device_trust)
            details["device_trust_required_count"] = trust_required
            score = 15.0
            score += min(len(app_policies) * 8.0, 45.0)
            if app_policies:
                score += (trust_required / len(app_policies)) * 40.0

        elif pillar == "data":
            # Assess data pillar: check data classification policies
            data_policy_result = await self.db.execute(
                select(ZeroTrustPolicy).where(
                    and_(
                        ZeroTrustPolicy.organization_id == self.organization_id,
                        ZeroTrustPolicy.is_enabled == True,
                        ZeroTrustPolicy.policy_type == "data",
                    )
                )
            )
            data_policies = data_policy_result.scalars().all()
            classified = [p for p in data_policies if p.data_classification_required]
            details["total_data_policies"] = len(data_policies)
            details["classified_policies"] = len(classified)
            score = 10.0
            score += min(len(data_policies) * 10.0, 40.0)
            if data_policies:
                score += (len(classified) / len(data_policies)) * 50.0

        elif pillar == "visibility":
            # NIST 800-207 "Visibility & Analytics": measured by the
            # presence of active SIEM detection rules, recent log
            # ingestion, and UEBA entity coverage. The idea is that
            # zero trust requires continuous monitoring, so we give
            # credit for each of those signals existing.
            from datetime import datetime as _dt, timedelta as _td

            active_rules = 0
            log_count_24h = 0
            entity_count = 0
            try:
                from src.siem.models import DetectionRule, LogEntry, RuleStatus
                rules_q = await self.db.execute(
                    select(func.count(DetectionRule.id)).where(
                        DetectionRule.status == RuleStatus.ACTIVE.value
                    )
                )
                active_rules = rules_q.scalar() or 0
                logs_q = await self.db.execute(
                    select(func.count(LogEntry.id)).where(
                        LogEntry.created_at >= _dt.utcnow() - _td(hours=24)
                    )
                )
                log_count_24h = logs_q.scalar() or 0
            except Exception:  # noqa: BLE001
                pass
            try:
                from src.ueba.models import EntityProfile
                entities_q = await self.db.execute(
                    select(func.count(EntityProfile.id)).where(
                        EntityProfile.organization_id == self.organization_id
                    )
                )
                entity_count = entities_q.scalar() or 0
            except Exception:  # noqa: BLE001
                pass

            details["active_detection_rules"] = active_rules
            details["logs_last_24h"] = log_count_24h
            details["ueba_entities"] = entity_count
            # Scoring: 10 baseline + up to 40 for rules + 30 for log
            # ingestion + 20 for UEBA entities.
            score = 10.0
            score += min(active_rules * 2.0, 40.0)
            if log_count_24h > 0:
                score += min((log_count_24h / 1000.0) * 30.0, 30.0)
            score += min(entity_count * 2.0, 20.0)

        elif pillar == "automation":
            # NIST 800-207 "Automation & Orchestration": enabled
            # playbooks, enabled remediation policies, and enrolled
            # endpoint agents. A mature ZT posture automates response
            # rather than relying on humans clicking buttons.
            enabled_playbooks = 0
            enabled_policies = 0
            agent_count = 0
            try:
                from src.models.playbook import Playbook
                pb_q = await self.db.execute(
                    select(func.count(Playbook.id)).where(
                        Playbook.is_enabled == True  # noqa: E712
                    )
                )
                enabled_playbooks = pb_q.scalar() or 0
            except Exception:  # noqa: BLE001
                pass
            try:
                from src.remediation.models import RemediationPolicy
                rp_q = await self.db.execute(
                    select(func.count(RemediationPolicy.id)).where(
                        and_(
                            RemediationPolicy.is_enabled == True,  # noqa: E712
                            RemediationPolicy.organization_id == self.organization_id,
                        )
                    )
                )
                enabled_policies = rp_q.scalar() or 0
            except Exception:  # noqa: BLE001
                pass
            try:
                from src.agents.models import EndpointAgent
                ag_q = await self.db.execute(
                    select(func.count(EndpointAgent.id)).where(
                        EndpointAgent.organization_id == self.organization_id
                    )
                )
                agent_count = ag_q.scalar() or 0
            except Exception:  # noqa: BLE001
                pass

            details["enabled_playbooks"] = enabled_playbooks
            details["enabled_remediation_policies"] = enabled_policies
            details["enrolled_agents"] = agent_count
            # Scoring: 10 baseline + up to 30 for playbooks + 30 for
            # remediation policies + 30 for enrolled agents.
            score = 10.0
            score += min(enabled_playbooks * 5.0, 30.0)
            score += min(enabled_policies * 5.0, 30.0)
            score += min(agent_count * 5.0, 30.0)

        score = min(score, 100.0)
        maturity_level = self.get_maturity_level_from_score(score)

        return {
            "pillar": pillar,
            "score": round(score, 1),
            "maturity_level": maturity_level,
            "details": details,
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

        pillar_recommendations = {
            "identity": [
                {"threshold": 50, "priority": "high", "recommendation": "Enforce MFA on all identity policies to strengthen authentication posture"},
                {"threshold": 75, "priority": "medium", "recommendation": "Implement continuous identity verification with behavioral analytics"},
                {"threshold": 90, "priority": "low", "recommendation": "Add FIDO2/WebAuthn support for phishing-resistant authentication"},
            ],
            "devices": [
                {"threshold": 50, "priority": "high", "recommendation": "Enroll all devices in trust assessment and enforce minimum compliance scores"},
                {"threshold": 75, "priority": "medium", "recommendation": "Enable automated device compliance remediation and real-time posture checks"},
                {"threshold": 90, "priority": "low", "recommendation": "Implement certificate-based device attestation for all endpoints"},
            ],
            "networks": [
                {"threshold": 50, "priority": "high", "recommendation": "Implement micro-segmentation for critical network zones and workloads"},
                {"threshold": 75, "priority": "medium", "recommendation": "Deploy east-west traffic monitoring and automated lateral movement detection"},
                {"threshold": 90, "priority": "low", "recommendation": "Achieve full software-defined perimeter with per-session network access"},
            ],
            "applications": [
                {"threshold": 50, "priority": "high", "recommendation": "Define access policies for all critical applications with device trust requirements"},
                {"threshold": 75, "priority": "medium", "recommendation": "Implement runtime application security monitoring and workload isolation"},
                {"threshold": 90, "priority": "low", "recommendation": "Deploy just-in-time application access with automated privilege expiration"},
            ],
            "data": [
                {"threshold": 50, "priority": "high", "recommendation": "Classify all data assets and apply data-centric access policies"},
                {"threshold": 75, "priority": "medium", "recommendation": "Implement data loss prevention with automated classification enforcement"},
                {"threshold": 90, "priority": "low", "recommendation": "Deploy granular data-level encryption with attribute-based access controls"},
            ],
        }

        for pillar_name, pillar_data in pillars.items():
            score = pillar_data.get("score", 0)
            for rec in pillar_recommendations.get(pillar_name, []):
                if score < rec["threshold"]:
                    recommendations.append({
                        "pillar": pillar_name,
                        "current_score": score,
                        "priority": rec["priority"],
                        "recommendation": rec["recommendation"],
                    })

        # Sort by priority: high > medium > low
        priority_order = {"high": 0, "medium": 1, "low": 2}
        recommendations.sort(key=lambda r: priority_order.get(r["priority"], 99))

        return recommendations
