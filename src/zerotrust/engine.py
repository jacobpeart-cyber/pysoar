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
                    f"elevated_risk_score_{combined_risk:.1f}",
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
                    f"low_device_trust_{device_trust_score:.1f}",
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
        # Only the continuous-verification path (which sets enforce_session)
        # may write the per-request gate cache. What-if evaluations from the
        # API carry a session_id for the record but must never revoke it.
        sid = context.get("session_id")
        if sid and context.get("enforce_session") is True:
            try:
                from src.zerotrust.session_gate import invalidate_session_cache
                await invalidate_session_cache(sid, decision)
            except Exception as exc:
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
            .where(
                and_(
                    AccessDecision.session_id == session_id,
                    AccessDecision.organization_id == self.organization_id,
                ),
            )
            .order_by(desc(AccessDecision.created_at))
            .limit(1),
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
                # Continuous verification is the one path allowed to write the
                # per-request session gate (see evaluate_access_request).
                return await self.evaluate_access_request(
                    last_decision.subject_type,
                    last_decision.subject_id,
                    last_decision.resource_type,
                    last_decision.resource_id,
                    {**context, "risk_change": risk_delta, "enforce_session": True},
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
                ),
            ),
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
                ),
            ),
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
                ),
            ),
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
                ),
            )
            .limit(1),
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
                ),
            )
            .order_by(desc(ZeroTrustPolicy.priority)),
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


#: Posture checks an endpoint agent measures and reports on its heartbeat.
AGENT_POSTURE_CHECKS: tuple[str, ...] = ("os_patched", "av_active", "encryption_enabled", "firewall_on")
#: Every posture check a profile can carry (the last two only from an explicit
#: admin override: the agent does not measure them).
POSTURE_CHECKS: tuple[str, ...] = AGENT_POSTURE_CHECKS + ("certificate_valid", "jailbroken")
NOT_REPORTED = "not_reported"


def _load_status(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def device_posture(device: DeviceTrustProfile) -> dict[str, Any]:
    """Posture fields derived from the stored compliance status only.

    ``compliance_checks`` maps each check to the stored boolean or
    ``"not_reported"``; ``is_compliant`` is None until every agent-measured
    check has been reported (unknown posture is never shown as failing),
    otherwise True when all of them pass and the device is not reported as
    jailbroken / rooted.
    """
    status = _load_status(device.compliance_status)
    checks: dict[str, Any] = {}
    for key in POSTURE_CHECKS:
        value = status.get(key)
        if key == "jailbroken" and value is None and "rooted" in status:
            value = status.get("rooted")
        checks[key] = bool(value) if isinstance(value, bool) else NOT_REPORTED
    reported = [k for k in AGENT_POSTURE_CHECKS if checks[k] != NOT_REPORTED]
    if not any(checks[k] != NOT_REPORTED for k in POSTURE_CHECKS):
        posture_status = NOT_REPORTED
    elif len(reported) < len(AGENT_POSTURE_CHECKS):
        posture_status = "partial"
    else:
        posture_status = "reported"
    if posture_status == "reported":
        is_compliant: Optional[bool] = all(checks[k] is True for k in AGENT_POSTURE_CHECKS) and checks[
            "jailbroken"
        ] is not True
    else:
        is_compliant = None
    return {
        "compliance_checks": checks,
        "is_compliant": is_compliant,
        "posture_status": posture_status,
        "posture_source": status.get("_source"),
        "posture_reported_at": status.get("_reported_at"),
        "compliance_status": {k: v for k, v in status.items() if not str(k).startswith("_")},
    }


def _trust_level(trust_score: float, posture_status: str) -> str:
    if posture_status == NOT_REPORTED:
        return "unknown"
    if trust_score >= 80:
        return "trusted"
    if trust_score >= 60:
        return "conditional"
    if trust_score >= 40:
        return "untrusted"
    return "blocked"


class DeviceTrustAssessor:
    """Device trust assessment and compliance checking"""

    def __init__(self, db: AsyncSession, organization_id: str):
        self.db = db
        self.organization_id = organization_id

    async def _get(self, device_id: str) -> Optional[DeviceTrustProfile]:
        result = await self.db.execute(
            select(DeviceTrustProfile)
            .where(
                and_(
                    DeviceTrustProfile.device_id == device_id,
                    DeviceTrustProfile.organization_id == self.organization_id,
                ),
            )
            .limit(1),
        )
        return result.scalar_one_or_none()

    def _rescore(self, device: DeviceTrustProfile) -> None:
        status = _load_status(device.compliance_status)
        posture = device_posture(device)
        device.trust_score = self._calculate_trust_score(status)
        device.trust_level = _trust_level(device.trust_score, posture["posture_status"])
        checks = posture["compliance_checks"]
        # Mirror the stored checks onto the boolean columns (False only when
        # actually reported False or not reported; the API returns the
        # ``compliance_checks`` map, which keeps the difference).
        device.encryption_enabled = checks["encryption_enabled"] is True
        device.antivirus_active = checks["av_active"] is True
        device.firewall_enabled = checks["firewall_on"] is True
        device.certificate_valid = checks["certificate_valid"] is True
        device.jailbroken = checks["jailbroken"] is True
        device.last_assessment_at = datetime.now(timezone.utc)

    async def assess_device(self, device_id: str) -> DeviceTrustProfile:
        """Recompute a device's trust score from its stored posture.

        Unknown ids are a LookupError (no phantom profile is created). A device
        with no reported posture is ``trust_level="unknown"``, not "blocked".
        """
        logger.info("assessing_device", device_id=device_id)

        device = await self._get(device_id)
        if not device:
            # Assessing an unknown id used to create a phantom "blocked"
            # device in this tenant. Profiles are created by agent telemetry
            # or an admin override (update_device_compliance).
            logger.warning("device_not_found", device_id=device_id)
            raise LookupError(f"device {device_id} not found")

        self._rescore(device)
        self.db.add(device)
        await self.db.commit()

        logger.info(
            "device_assessment_complete",
            device_id=device_id,
            trust_score=device.trust_score,
            trust_level=device.trust_level,
        )

        return device

    def _calculate_trust_score(self, compliance_status: dict[str, Any]) -> float:
        """Calculate composite trust score from reported compliance factors

        Factors (only checks reported True earn points):
        - OS patched (25%)
        - AV active (25%)
        - Encryption (25%)
        - Firewall (15%)
        - Certificate valid (10%)
        """
        score = 0.0

        if compliance_status.get("os_patched") is True:
            score += 25
        if compliance_status.get("av_active") is True:
            score += 25
        if compliance_status.get("encryption_enabled") is True:
            score += 25
        if compliance_status.get("firewall_on") is True:
            score += 15
        if compliance_status.get("certificate_valid") is True:
            score += 10

        # Penalize jailbreak/root
        if compliance_status.get("jailbroken") is True or compliance_status.get("rooted") is True:
            score = max(0, score - 50)

        return min(score, 100.0)

    async def update_device_compliance(
        self,
        device_id: str,
        compliance_data: dict[str, Any],
        *,
        source: Optional[str] = None,
        device_type: str = "unknown",
        hostname: Optional[str] = None,
    ) -> DeviceTrustProfile:
        """Record reported posture for a device, creating its profile in this tenant.

        Upsert within the organisation (device ids are unique per tenant since
        migration 032, so the same id in another tenant is a different row).

        ``source``: ``"admin_override"`` from the API; None means the agent
        heartbeat path when ``device_id`` is an enrolled agent of this tenant.
        Agent posture keeps only the checks the agent measures
        (``AGENT_POSTURE_CHECKS``): the heartbeat also sends constant
        ``certificate_valid=True`` / ``jailbroken=False`` values it never
        measured, and those must not earn trust points.
        """
        agent = None
        if source is None or source == "agent":
            from src.agents.models import EndpointAgent

            agent = (await self.db.execute(
                select(EndpointAgent).where(
                    EndpointAgent.id == device_id,
                    EndpointAgent.organization_id == self.organization_id,
                ),
            )).scalar_one_or_none()
            source = "agent" if agent is not None else (source or "api")

        allowed = AGENT_POSTURE_CHECKS if source == "agent" else POSTURE_CHECKS + ("rooted",)
        data = {k: v for k, v in compliance_data.items() if k in allowed and isinstance(v, bool)}
        now = datetime.now(timezone.utc)

        device = await self._get(device_id)
        if not device:
            device = DeviceTrustProfile(
                organization_id=self.organization_id,
                device_id=device_id,
                device_type=device_type or "unknown",
                hostname=hostname or (agent.hostname if agent is not None else None),
                os_type=agent.os_type if agent is not None else None,
                os_version=agent.os_version if agent is not None else None,
                compliance_status="{}",
                trust_score=0.0,
                trust_level="unknown",
                enrolled_at=now,
            )
            self.db.add(device)
            logger.info("device_profile_created", device_id=device_id, source=source)
        elif agent is not None:
            device.hostname = device.hostname or agent.hostname
            device.os_type = agent.os_type or device.os_type
            device.os_version = agent.os_version or device.os_version

        current_status = _load_status(device.compliance_status)
        current_status.update(data)
        if data:
            current_status["_source"] = source
            current_status["_reported_at"] = now.isoformat()
        device.compliance_status = json.dumps(current_status)
        if source == "agent":
            device.last_seen_at = now

        self._rescore(device)
        self.db.add(device)
        await self.db.commit()

        logger.info(
            "device_compliance_updated",
            device_id=device_id,
            trust_score=device.trust_score,
            source=source,
        )

        return device

    async def get_non_compliant_devices(self) -> list[DeviceTrustProfile]:
        """Devices with reported posture whose trust score is below 70.

        Devices that never reported posture are not "non-compliant": their
        posture is unknown (``trust_level="unknown"``).
        """
        result = await self.db.execute(
            select(DeviceTrustProfile).where(
                and_(
                    DeviceTrustProfile.organization_id == self.organization_id,
                    DeviceTrustProfile.trust_score < 70,
                    DeviceTrustProfile.trust_level != "unknown",
                ),
            ),
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
                ),
            ),
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
        self, traffic_data: list[dict[str, Any]],
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
                ),
            )
            .limit(1),
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
                ),
            ).order_by(desc(AccessDecision.created_at)).limit(100),
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
                MicroSegment.organization_id == self.organization_id,
            ),
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
                ),
            )
            .order_by(desc(AccessDecision.created_at))
            .limit(1),
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
        self, session_data: dict[str, Any], risk_delta: float,
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
    """Zero Trust maturity assessment (CISA ZTMM pillars), from stored configuration.

    Each pillar is a set of weighted criteria (weights sum to 100). A
    criterion's value is a share in [0, 1] measured on this tenant's rows:
    policies, device profiles and their reported posture, micro-segments,
    sessions the policy decision point evaluated, detection rules, log
    ingestion, playbooks, remediation policies and enrolled agents. There are
    no baseline points: a tenant with nothing configured scores 0 in every
    pillar, and a pillar with nothing configured is ``status="not_configured"``.
    """

    #: Window for "recent" activity criteria (sessions, decisions, logs).
    ACTIVITY_WINDOW_DAYS = 30

    def __init__(self, db: AsyncSession, organization_id: str):
        self.db = db
        self.organization_id = organization_id

    async def calculate_maturity_score(self) -> dict[str, Any]:
        """Calculate overall Zero Trust maturity score

        Returns:
            {overall_score, pillars, maturity_level, recommendations,
             configured_pillars}
        """
        logger.info("calculating_zero_trust_maturity")

        pillars = {
            name: await self.assess_pillar(name)
            for name in ("identity", "devices", "networks", "applications", "data", "visibility", "automation")
        }

        overall_score = sum(p["score"] for p in pillars.values()) / len(pillars)

        maturity_level = self.get_maturity_level_from_score(overall_score)
        recommendations = await self.generate_recommendations(pillars)

        return {
            "overall_score": round(overall_score, 1),
            "maturity_level": maturity_level,
            "pillars": pillars,
            "recommendations": recommendations,
            "configured_pillars": sum(1 for p in pillars.values() if p["status"] != "not_configured"),
        }

    async def _count(self, stmt: Any) -> int:
        return int((await self.db.execute(stmt)).scalar() or 0)

    async def _enabled_policies(self, types: Optional[list[str]] = None) -> list[ZeroTrustPolicy]:
        stmt = select(ZeroTrustPolicy).where(
            and_(
                ZeroTrustPolicy.organization_id == self.organization_id,
                ZeroTrustPolicy.is_enabled == True,  # noqa: E712
            ),
        )
        if types:
            stmt = stmt.where(ZeroTrustPolicy.policy_type.in_(types))
        return list((await self.db.execute(stmt)).scalars().all())

    @staticmethod
    def _criterion(key: str, weight: float, value: float, evidence: Any) -> dict[str, Any]:
        value = max(0.0, min(1.0, float(value)))
        return {"key": key, "weight": weight, "value": round(value, 3), "points": round(weight * value, 1),
                "evidence": evidence}

    async def assess_pillar(self, pillar: str) -> dict[str, Any]:
        """Assess one pillar from this tenant's stored configuration.

        Returns:
            {pillar, score, maturity_level, status, criteria, details}
        """
        details: dict[str, Any] = {}
        criteria: list[dict[str, Any]] = []
        since = datetime.now(timezone.utc) - timedelta(days=self.ACTIVITY_WINDOW_DAYS)

        if pillar == "identity":
            identity_policies = await self._enabled_policies(["identity"])
            all_policies = await self._enabled_policies()
            mfa = [p for p in all_policies if p.requires_mfa]
            sessions = await self._count(
                select(func.count(func.distinct(AccessDecision.session_id))).where(
                    and_(
                        AccessDecision.organization_id == self.organization_id,
                        AccessDecision.session_id.is_not(None),
                        AccessDecision.created_at >= since,
                    ),
                ),
            )
            details.update({
                "total_identity_policies": len(identity_policies),
                "enabled_policies": len(all_policies),
                "mfa_enforced_policies": len(mfa),
                "sessions_evaluated_30d": sessions,
            })
            criteria = [
                self._criterion("identity_policies_enabled", 30, 1.0 if identity_policies else 0.0,
                                len(identity_policies)),
                self._criterion("mfa_coverage", 40, len(mfa) / len(all_policies) if all_policies else 0.0,
                                f"{len(mfa)}/{len(all_policies)} enabled policies require MFA"),
                self._criterion("sessions_continuously_evaluated", 30, 1.0 if sessions else 0.0, sessions),
            ]

        elif pillar == "devices":
            devices = list((await self.db.execute(
                select(DeviceTrustProfile).where(DeviceTrustProfile.organization_id == self.organization_id),
            )).scalars().all())
            postures = [device_posture(d) for d in devices]
            reported = [p for p in postures if p["posture_status"] == "reported"]
            compliant = [p for p in reported if p["is_compliant"]]
            details.update({
                "total_devices": len(devices),
                "posture_reported_devices": len(reported),
                "not_reported_devices": sum(1 for p in postures if p["posture_status"] == NOT_REPORTED),
                "compliant_devices": len(compliant),
            })
            if devices:
                details["average_trust_score"] = round(sum(d.trust_score for d in devices) / len(devices), 1)
            criteria = [
                self._criterion("devices_enrolled", 20, 1.0 if devices else 0.0, len(devices)),
                self._criterion("posture_reported", 30, len(reported) / len(devices) if devices else 0.0,
                                f"{len(reported)}/{len(devices)} devices report full posture"),
                self._criterion("devices_compliant", 50, len(compliant) / len(devices) if devices else 0.0,
                                f"{len(compliant)}/{len(devices)} devices compliant"),
            ]

        elif pillar == "networks":
            segments = list((await self.db.execute(
                select(MicroSegment).where(
                    and_(
                        MicroSegment.organization_id == self.organization_id,
                        MicroSegment.is_active == True,  # noqa: E712
                    ),
                ),
            )).scalars().all())
            bound_ids = {p.microsegment_id for p in await self._enabled_policies() if p.microsegment_id}
            with_cidr = [s for s in segments if MicroSegmentationEngine._safe_json_list(s.cidr_ranges)]
            bound = [s for s in segments if s.id in bound_ids]
            details.update({
                "total_segments": len(segments),
                "segment_types": sorted({s.segment_type for s in segments}),
                "segments_with_cidr": len(with_cidr),
                "segments_with_policy": len(bound),
            })
            criteria = [
                self._criterion("segments_active", 30, 1.0 if segments else 0.0, len(segments)),
                self._criterion("segments_with_cidr", 30, len(with_cidr) / len(segments) if segments else 0.0,
                                f"{len(with_cidr)}/{len(segments)} segments define CIDR ranges"),
                self._criterion("segments_policy_bound", 40, len(bound) / len(segments) if segments else 0.0,
                                f"{len(bound)}/{len(segments)} segments referenced by an enabled policy"),
            ]

        elif pillar == "applications":
            app_policies = await self._enabled_policies(["access", "workload"])
            trust_required = [p for p in app_policies if p.requires_device_trust]
            with_conditions = [p for p in app_policies if MicroSegmentationEngine._safe_json_list(p.conditions)]
            details.update({
                "total_app_policies": len(app_policies),
                "device_trust_required_count": len(trust_required),
                "policies_with_conditions": len(with_conditions),
            })
            criteria = [
                self._criterion("access_policies_enabled", 30, 1.0 if app_policies else 0.0, len(app_policies)),
                self._criterion("device_trust_required", 35,
                                len(trust_required) / len(app_policies) if app_policies else 0.0,
                                f"{len(trust_required)}/{len(app_policies)} require device trust"),
                self._criterion("conditions_defined", 35,
                                len(with_conditions) / len(app_policies) if app_policies else 0.0,
                                f"{len(with_conditions)}/{len(app_policies)} define match conditions"),
            ]

        elif pillar == "data":
            data_policies = await self._enabled_policies(["data"])
            classified = [p for p in data_policies if p.data_classification_required]
            details.update({
                "total_data_policies": len(data_policies),
                "classified_policies": len(classified),
            })
            criteria = [
                self._criterion("data_policies_enabled", 40, 1.0 if data_policies else 0.0, len(data_policies)),
                self._criterion("classification_required", 60,
                                len(classified) / len(data_policies) if data_policies else 0.0,
                                f"{len(classified)}/{len(data_policies)} require a data classification"),
            ]

        elif pillar == "visibility":
            from src.siem.models import DetectionRule, LogEntry, RuleStatus
            from src.ueba.models import EntityProfile

            active_rules = await self._count(
                select(func.count(DetectionRule.id)).where(
                    and_(
                        DetectionRule.status == RuleStatus.ACTIVE.value,
                        DetectionRule.organization_id == self.organization_id,
                    ),
                ),
            )
            logs_24h = await self._count(
                select(func.count(LogEntry.id)).where(
                    and_(
                        LogEntry.created_at >= datetime.now(timezone.utc) - timedelta(hours=24),
                        LogEntry.organization_id == self.organization_id,
                    ),
                ),
            )
            entity_count = await self._count(
                select(func.count(EntityProfile.id)).where(EntityProfile.organization_id == self.organization_id),
            )
            decisions = await self._count(
                select(func.count(AccessDecision.id)).where(
                    and_(
                        AccessDecision.organization_id == self.organization_id,
                        AccessDecision.created_at >= since,
                    ),
                ),
            )
            details.update({
                "active_detection_rules": active_rules,
                "logs_last_24h": logs_24h,
                "ueba_entities": entity_count,
                "access_decisions_30d": decisions,
            })
            criteria = [
                self._criterion("active_detection_rules", 30, 1.0 if active_rules else 0.0, active_rules),
                self._criterion("logs_ingested_24h", 30, 1.0 if logs_24h else 0.0, logs_24h),
                self._criterion("ueba_entities_profiled", 20, 1.0 if entity_count else 0.0, entity_count),
                self._criterion("access_decisions_recorded", 20, 1.0 if decisions else 0.0, decisions),
            ]

        elif pillar == "automation":
            from src.agents.models import EndpointAgent
            from src.models.playbook import Playbook
            from src.remediation.models import RemediationPolicy

            enabled_playbooks = await self._count(
                select(func.count(Playbook.id)).where(
                    and_(
                        Playbook.is_enabled == True,  # noqa: E712
                        Playbook.organization_id == self.organization_id,
                    ),
                ),
            )
            enabled_policies = await self._count(
                select(func.count(RemediationPolicy.id)).where(
                    and_(
                        RemediationPolicy.is_enabled == True,  # noqa: E712
                        RemediationPolicy.organization_id == self.organization_id,
                    ),
                ),
            )
            agent_count = await self._count(
                select(func.count(EndpointAgent.id)).where(
                    and_(
                        EndpointAgent.organization_id == self.organization_id,
                        EndpointAgent.status == "active",
                    ),
                ),
            )
            details.update({
                "enabled_playbooks": enabled_playbooks,
                "enabled_remediation_policies": enabled_policies,
                "enrolled_agents": agent_count,
            })
            criteria = [
                self._criterion("playbooks_enabled", 35, 1.0 if enabled_playbooks else 0.0, enabled_playbooks),
                self._criterion("remediation_policies_enabled", 30, 1.0 if enabled_policies else 0.0,
                                enabled_policies),
                self._criterion("active_endpoint_agents", 35, 1.0 if agent_count else 0.0, agent_count),
            ]

        else:
            raise ValueError(f"unknown Zero Trust pillar: {pillar}")

        score = min(sum(c["points"] for c in criteria), 100.0)
        configured = any(c["value"] > 0 for c in criteria)
        return {
            "pillar": pillar,
            "score": round(score, 1),
            "maturity_level": self.get_maturity_level_from_score(score),
            "status": "assessed" if configured else "not_configured",
            "criteria": criteria,
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
        self, pillars: dict[str, dict[str, Any]],
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
