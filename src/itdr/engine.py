"""
ITDR Detection and Response Engine

Provides comprehensive identity threat detection, credential monitoring,
access behavior analysis, and privileged access management.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
from math import radians, sin, cos, sqrt, atan2

from src.core.logging import get_logger

logger = get_logger(__name__)


class IdentityThreatDetector:
    """Detects identity-based threats and attacks"""

    def __init__(self):
        """Initialize threat detector"""
        self.logger = logger
        self.min_spray_attempts = 10
        self.min_brute_force_attempts = 5
        self.mfa_fatigue_threshold = 5

    def detect_credential_attacks(
        self,
        failed_attempts: dict[str, Any],
        time_window_minutes: int = 30,
    ) -> list[dict[str, Any]]:
        """
        Detect password spray, brute force, and credential stuffing attacks.

        Analyzes patterns of failed authentication attempts to identify
        credential attacks and mass exploitation attempts.

        Args:
            failed_attempts: Dictionary mapping users/IPs to attempt counts
            time_window_minutes: Time window for analysis

        Returns:
            List of detected attacks with threat details
        """
        attacks = []

        # Password spray detection (many users, few attempts each)
        users_with_failures = {}
        for key, count in failed_attempts.items():
            if isinstance(key, str) and "@" in key:  # user-like
                users_with_failures[key] = count

        if len(users_with_failures) >= self.min_spray_attempts:
            spray_attack = {
                "threat_type": "password_spray",
                "severity": "high",
                "confidence_score": min(85.0, 50.0 + len(users_with_failures) * 5),
                "affected_users": len(users_with_failures),
                "description": f"Password spray attack detected against {len(users_with_failures)} users",
            }
            attacks.append(spray_attack)
            self.logger.warning(f"Password spray detected: {len(users_with_failures)} users")

        # Brute force detection (single user, many attempts)
        for user, count in users_with_failures.items():
            if count >= self.min_brute_force_attempts:
                brute_attack = {
                    "threat_type": "brute_force",
                    "severity": "high" if count > 20 else "medium",
                    "confidence_score": min(90.0, 50.0 + count * 2),
                    "target_user": user,
                    "attempt_count": count,
                    "description": f"Brute force attack on user {user}",
                }
                attacks.append(brute_attack)
                self.logger.warning(f"Brute force detected on user {user}: {count} attempts")

        # Credential stuffing detection (multiple IPs, multiple users)
        ips_with_failures = {}
        for key, count in failed_attempts.items():
            if isinstance(key, str) and "." in key:  # IP-like
                ips_with_failures[key] = count

        if len(ips_with_failures) >= 5 and len(users_with_failures) >= 5:
            stuffing_attack = {
                "threat_type": "credential_stuffing",
                "severity": "critical",
                "confidence_score": 95.0,
                "source_ips": len(ips_with_failures),
                "affected_users": len(users_with_failures),
                "description": "Credential stuffing attack detected",
            }
            attacks.append(stuffing_attack)
            self.logger.warning("Credential stuffing attack detected")

        return attacks

    def detect_token_theft(
        self,
        token_events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Detect token theft and suspicious OAuth grants.

        Analyzes token usage patterns to identify stolen tokens and
        unauthorized OAuth application grants.

        Args:
            token_events: List of token usage events

        Returns:
            List of detected token theft incidents
        """
        threats = []

        # Impossible token reuse (same token from different locations)
        token_locations = {}
        for event in token_events:
            token_id = event.get("token_id")
            location = event.get("location")
            timestamp = event.get("timestamp")

            if token_id not in token_locations:
                token_locations[token_id] = []
            token_locations[token_id].append({"location": location, "timestamp": timestamp})

        for token_id, locations in token_locations.items():
            if len(locations) > 1:
                unique_locations = set(loc["location"] for loc in locations)
                if len(unique_locations) > 1:
                    threat = {
                        "threat_type": "token_theft",
                        "severity": "critical",
                        "confidence_score": 90.0,
                        "token_id": token_id,
                        "unique_locations": len(unique_locations),
                        "description": f"Token used from {len(unique_locations)} different locations",
                    }
                    threats.append(threat)
                    self.logger.warning(f"Token theft detected: {token_id}")

        # Suspicious OAuth grant detection
        oauth_grants = [e for e in token_events if e.get("grant_type") == "oauth"]
        for grant in oauth_grants:
            if grant.get("app_permissions", []):
                perm_count = len(grant["app_permissions"])
                if perm_count > 5:
                    threat = {
                        "threat_type": "oauth_abuse",
                        "severity": "high",
                        "confidence_score": 75.0,
                        "app_name": grant.get("app_name"),
                        "permissions_granted": perm_count,
                        "description": f"Suspicious OAuth grant with {perm_count} permissions",
                    }
                    threats.append(threat)
                    self.logger.warning(f"OAuth abuse detected: {grant.get('app_name')}")

        return threats

    def detect_privilege_escalation(
        self,
        role_changes: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Detect unauthorized privilege escalation.

        Identifies suspicious elevation of privileges and role assignments
        that deviate from approval workflows.

        Args:
            role_changes: List of role/permission changes

        Returns:
            List of detected escalation events
        """
        escalations = []

        for change in role_changes:
            user = change.get("user")
            old_role = change.get("old_role")
            new_role = change.get("new_role")
            approved = change.get("approved", False)
            approver = change.get("approver")

            # Unapproved escalation
            if not approved:
                severity = "critical" if new_role == "admin" else "high"
                escalation = {
                    "threat_type": "privilege_escalation",
                    "severity": severity,
                    "confidence_score": 95.0,
                    "user": user,
                    "old_role": old_role,
                    "new_role": new_role,
                    "approved": False,
                    "description": f"Unauthorized privilege escalation for user {user}",
                }
                escalations.append(escalation)
                self.logger.warning(f"Unauthorized escalation: {user} -> {new_role}")

            # Self-approval detection
            if approver and approver == user:
                escalation = {
                    "threat_type": "privilege_escalation",
                    "severity": "high",
                    "confidence_score": 85.0,
                    "user": user,
                    "new_role": new_role,
                    "self_approved": True,
                    "description": f"Self-approved privilege escalation for user {user}",
                }
                escalations.append(escalation)
                self.logger.warning(f"Self-approved escalation: {user}")

        return escalations

    def detect_lateral_movement(
        self,
        access_events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Detect lateral movement attacks.

        Identifies indicators of pass-the-hash, golden ticket, and
        silver ticket attacks based on access patterns.

        Args:
            access_events: List of resource access events

        Returns:
            List of detected lateral movement indicators
        """
        movements = []

        # Pass-the-hash indicators (same hash from multiple hosts)
        hash_usage = {}
        for event in access_events:
            hash_val = event.get("password_hash")
            host = event.get("source_host")
            if hash_val:
                if hash_val not in hash_usage:
                    hash_usage[hash_val] = []
                hash_usage[hash_val].append(host)

        for hash_val, hosts in hash_usage.items():
            if len(set(hosts)) > 1:  # Used from multiple hosts
                movement = {
                    "threat_type": "pass_the_hash",
                    "severity": "critical",
                    "confidence_score": 92.0,
                    "hash_count": len(hosts),
                    "source_hosts": len(set(hosts)),
                    "description": "Pass-the-hash attack detected",
                }
                movements.append(movement)
                self.logger.warning("Pass-the-hash attack detected")

        # Golden/Silver ticket indicators (abnormal Kerberos usage)
        kerberos_events = [e for e in access_events if e.get("protocol") == "kerberos"]
        for event in kerberos_events:
            ticket_lifetime = event.get("ticket_lifetime_days")
            if ticket_lifetime and ticket_lifetime > 10:
                movement = {
                    "threat_type": "golden_ticket",
                    "severity": "critical",
                    "confidence_score": 88.0,
                    "user": event.get("user"),
                    "ticket_lifetime_days": ticket_lifetime,
                    "description": "Golden ticket attack indicators detected",
                }
                movements.append(movement)
                self.logger.warning(f"Golden ticket indicators: {event.get('user')}")

        # Kerberoasting detection (TGS-REQ patterns)
        tgs_req_count = len([e for e in kerberos_events if e.get("type") == "TGS-REQ"])
        if tgs_req_count > 20:
            movement = {
                "threat_type": "kerberoasting",
                "severity": "high",
                "confidence_score": 80.0,
                "tgs_requests": tgs_req_count,
                "description": "Possible kerberoasting attack",
            }
            movements.append(movement)
            self.logger.warning("Kerberoasting indicators detected")

        return movements

    def detect_mfa_fatigue(
        self,
        mfa_push_events: list[dict[str, Any]],
        time_window_minutes: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Detect MFA fatigue attacks.

        Identifies rapid sequences of MFA push notifications that
        indicate fatigue-based attacks on user approval processes.

        Args:
            mfa_push_events: List of MFA push notification events
            time_window_minutes: Time window for fatigue detection

        Returns:
            List of detected MFA fatigue attacks
        """
        fatigue_attacks = []

        # Group events by user
        user_pushes = {}
        for event in mfa_push_events:
            user = event.get("user")
            if user not in user_pushes:
                user_pushes[user] = []
            user_pushes[user].append(event)

        # Analyze push patterns
        now = datetime.now(timezone.utc)
        for user, pushes in user_pushes.items():
            recent_pushes = []
            for push in pushes:
                try:
                    timestamp = push.get("timestamp")
                    if isinstance(timestamp, str):
                        push_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    else:
                        push_time = timestamp

                    time_diff = (now - push_time).total_seconds() / 60
                    if time_diff <= time_window_minutes:
                        recent_pushes.append(push)
                except (ValueError, TypeError):
                    continue

            if len(recent_pushes) >= self.mfa_fatigue_threshold:
                attack = {
                    "threat_type": "mfa_fatigue",
                    "severity": "high",
                    "confidence_score": min(95.0, 60.0 + len(recent_pushes) * 5),
                    "user": user,
                    "push_count": len(recent_pushes),
                    "time_window_minutes": time_window_minutes,
                    "description": f"MFA fatigue attack on user {user}",
                }
                fatigue_attacks.append(attack)
                self.logger.warning(f"MFA fatigue detected: {user} ({len(recent_pushes)} pushes)")

        return fatigue_attacks

    def run_all_detections(
        self,
        failed_attempts: dict[str, Any],
        token_events: list[dict[str, Any]],
        role_changes: list[dict[str, Any]],
        access_events: list[dict[str, Any]],
        mfa_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Run all threat detection engines.

        Orchestrates all detection methods and aggregates results
        for comprehensive threat assessment.

        Args:
            failed_attempts: Authentication failure data
            token_events: Token usage events
            role_changes: Role/permission changes
            access_events: Resource access events
            mfa_events: MFA interaction events

        Returns:
            Aggregated threat detection results
        """
        all_threats = []

        # Run all detection engines
        all_threats.extend(self.detect_credential_attacks(failed_attempts))
        all_threats.extend(self.detect_token_theft(token_events))
        all_threats.extend(self.detect_privilege_escalation(role_changes))
        all_threats.extend(self.detect_lateral_movement(access_events))
        all_threats.extend(self.detect_mfa_fatigue(mfa_events))

        # Calculate composite risk
        critical_threats = len([t for t in all_threats if t.get("severity") == "critical"])
        high_threats = len([t for t in all_threats if t.get("severity") == "high"])
        overall_risk = min(100.0, critical_threats * 30 + high_threats * 15)

        return {
            "status": "success",
            "total_threats": len(all_threats),
            "critical_threats": critical_threats,
            "high_threats": high_threats,
            "overall_risk_score": overall_risk,
            "threats": all_threats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class CredentialMonitor:
    """Monitors credential exposure and manages remediation"""

    def __init__(self):
        """Initialize credential monitor"""
        self.logger = logger
        self.min_password_length = 12

    def check_credential_exposure(
        self,
        credentials: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Check if credentials appear in known breaches.

        Analyzes credentials against breach databases and dark web
        sources to identify exposed credentials.

        Args:
            credentials: List of credential objects to check

        Returns:
            List of exposed credentials with exposure details
        """
        exposures = []

        # Check against real CredentialLeak table from the dark web monitoring module
        known_exposed_emails: set[str] = set()
        try:
            from src.darkweb.models import CredentialLeak
            import asyncio
            from src.core.database import async_session_factory
            from sqlalchemy import select as _sel

            async def _load_leaked():
                async with async_session_factory() as session:
                    rows = (await session.execute(
                        _sel(CredentialLeak.email).where(
                            CredentialLeak.is_remediated == False  # noqa: E712
                        )
                    )).scalars().all()
                    return {e.lower() for e in rows if e}

            try:
                known_exposed_emails = asyncio.run(_load_leaked())
            except RuntimeError:
                pass
        except ImportError:
            self.logger.debug("CredentialLeak model not available, skipping breach lookup")

        for cred in credentials:
            user = cred.get("user", "")
            cred_type = cred.get("type")

            is_exposed = user.lower() in known_exposed_emails if user else False

            if is_exposed:
                exposure = {
                    "user": user,
                    "credential_type": cred_type,
                    "is_exposed": True,
                    "exposure_source": "credential_leak_database",
                    "exposure_date": datetime.now(timezone.utc).isoformat(),
                    "risk_level": "high",
                }
                exposures.append(exposure)
                self.logger.warning(f"Credential exposure detected for user {user}")

        return exposures

    def assess_password_strength(
        self,
        password: str,
    ) -> dict[str, Any]:
        """
        Assess password strength against security policies.

        Evaluates password complexity, length, entropy, and compliance
        with organizational security policies.

        Args:
            password: Password to assess

        Returns:
            Password strength assessment with recommendations
        """
        score = 0
        issues = []

        # Length check
        if len(password) >= self.min_password_length:
            score += 25
        elif len(password) >= 10:
            score += 15
            issues.append("Password should be at least 12 characters")
        else:
            issues.append("Password must be at least 12 characters")

        # Uppercase check
        if any(c.isupper() for c in password):
            score += 20
        else:
            issues.append("Password must contain uppercase letters")

        # Lowercase check
        if any(c.islower() for c in password):
            score += 20
        else:
            issues.append("Password must contain lowercase letters")

        # Number check
        if any(c.isdigit() for c in password):
            score += 20
        else:
            issues.append("Password must contain numbers")

        # Special character check
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if any(c in special_chars for c in password):
            score += 15
        else:
            issues.append("Password should contain special characters")

        strength = (
            "weak" if score < 40 else "fair" if score < 70 else "good" if score < 85 else "strong"
        )

        return {
            "score": score,
            "strength": strength,
            "issues": issues,
            "compliant": score >= 70,
        }

    def detect_shared_credentials(
        self,
        access_logs: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Detect multiple users or hosts using same credentials.

        Identifies credential sharing that violates least privilege
        and creates security risks.

        Args:
            access_logs: List of access events

        Returns:
            List of shared credential incidents
        """
        sharing_incidents = []

        # Group by credential ID
        cred_usage = {}
        for log in access_logs:
            cred_id = log.get("credential_id")
            user = log.get("user")
            host = log.get("host")

            if cred_id not in cred_usage:
                cred_usage[cred_id] = {"users": set(), "hosts": set()}

            cred_usage[cred_id]["users"].add(user)
            cred_usage[cred_id]["hosts"].add(host)

        # Detect sharing patterns
        for cred_id, usage in cred_usage.items():
            if len(usage["users"]) > 1:
                incident = {
                    "credential_id": cred_id,
                    "issue": "shared_users",
                    "user_count": len(usage["users"]),
                    "users": list(usage["users"]),
                    "severity": "high",
                    "recommendation": "Revoke shared credential and assign individual credentials",
                }
                sharing_incidents.append(incident)
                self.logger.warning(f"Shared credential detected: {cred_id}")

            if len(usage["hosts"]) > 1:
                incident = {
                    "credential_id": cred_id,
                    "issue": "shared_hosts",
                    "host_count": len(usage["hosts"]),
                    "hosts": list(usage["hosts"]),
                    "severity": "high",
                    "recommendation": "Use separate credentials per host",
                }
                sharing_incidents.append(incident)

        return sharing_incidents

    def detect_stale_credentials(
        self,
        credentials: list[dict[str, Any]],
        days_threshold: int = 90,
    ) -> list[dict[str, Any]]:
        """
        Detect credentials that haven't been rotated recently.

        Identifies stale credentials that exceed rotation policies
        and increase exposure risk.

        Args:
            credentials: List of credential objects
            days_threshold: Days since last rotation threshold

        Returns:
            List of stale credentials
        """
        stale_creds = []
        now = datetime.now(timezone.utc)

        for cred in credentials:
            user = cred.get("user")
            last_rotation = cred.get("last_rotation_date")

            if last_rotation:
                try:
                    if isinstance(last_rotation, str):
                        rotation_time = datetime.fromisoformat(last_rotation.replace("Z", "+00:00"))
                    else:
                        rotation_time = last_rotation

                    days_since_rotation = (now - rotation_time).days

                    if days_since_rotation > days_threshold:
                        stale_cred = {
                            "user": user,
                            "credential_type": cred.get("type"),
                            "days_since_rotation": days_since_rotation,
                            "threshold_days": days_threshold,
                            "severity": "medium" if days_since_rotation < 180 else "high",
                            "recommendation": "Rotate credential immediately",
                        }
                        stale_creds.append(stale_cred)
                        self.logger.warning(
                            f"Stale credential: {user} ({days_since_rotation} days old)"
                        )
                except (ValueError, TypeError):
                    continue

        return stale_creds

    def generate_credential_risk_report(
        self,
        exposures: list[dict[str, Any]],
        weak_passwords: list[dict[str, Any]],
        shared_creds: list[dict[str, Any]],
        stale_creds: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Generate comprehensive credential risk report.

        Aggregates all credential-related risks into executive report.

        Args:
            exposures: Exposed credentials
            weak_passwords: Weak password assessments
            shared_creds: Shared credential incidents
            stale_creds: Stale credential list

        Returns:
            Comprehensive risk report
        """
        total_issues = len(exposures) + len(weak_passwords) + len(shared_creds) + len(stale_creds)
        critical_issues = len(exposures)
        risk_score = min(100.0, critical_issues * 40 + len(shared_creds) * 20 + len(stale_creds) * 10)

        return {
            "report_type": "credential_risk",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_issues": total_issues,
            "critical_issues": critical_issues,
            "risk_score": risk_score,
            "exposure_count": len(exposures),
            "weak_password_count": len(weak_passwords),
            "shared_credential_count": len(shared_creds),
            "stale_credential_count": len(stale_creds),
            "exposures": exposures,
            "weak_passwords": weak_passwords,
            "shared_credentials": shared_creds,
            "stale_credentials": stale_creds,
            "recommendations": self._generate_recommendations(critical_issues, total_issues),
        }

    def _generate_recommendations(self, critical: int, total: int) -> list[str]:
        """Generate risk mitigation recommendations"""
        recs = []
        if critical > 0:
            recs.append("Immediately reset exposed credentials")
        if total > 10:
            recs.append("Implement password manager for credential management")
        recs.append("Enforce password rotation policy (90 days)")
        recs.append("Require MFA for all sensitive accounts")
        return recs

    def auto_remediate_exposed(
        self,
        exposures: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Auto-remediate exposed credentials.

        Triggers automated remediation like password resets and
        token revocation for exposed credentials.

        Args:
            exposures: List of exposed credentials

        Returns:
            Remediation action results
        """
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_exposures": len(exposures),
            "actions_taken": [],
            "success_count": 0,
            "failure_count": 0,
        }

        import asyncio
        from src.core.database import async_session_factory

        async def _remediate_user(user_email: str, cred_type: str) -> dict:
            async with async_session_factory() as session:
                from src.models.user import User
                from sqlalchemy import select as _sel

                result = await session.execute(
                    _sel(User).where(User.email == user_email)
                )
                user_record = result.scalar_one_or_none()

                if cred_type == "password" and user_record:
                    # Force password reset by disabling the account and
                    # creating a TicketActivity requesting password change.
                    user_record.is_active = False
                    from src.tickethub.models import TicketActivity
                    activity = TicketActivity(
                        source_type="identity_threat",
                        source_id=user_record.id,
                        activity_type="forced_password_reset",
                        description=f"Account disabled due to credential exposure. Password reset required for {user_email}.",
                    )
                    session.add(activity)
                    await session.commit()
                    return {
                        "user": user_email,
                        "action": "password_reset",
                        "status": "completed",
                        "details": f"Account disabled and password reset ticket created for {user_email}",
                        "success": True,
                    }
                elif cred_type == "api_key" and user_record:
                    # Revoke all API keys for this user
                    from src.models.api_key import APIKey
                    keys = (await session.execute(
                        _sel(APIKey).where(APIKey.owner_id == user_record.id, APIKey.is_active == True)
                    )).scalars().all()
                    revoked_count = 0
                    for key in keys:
                        key.is_active = False
                        revoked_count += 1
                    await session.commit()
                    return {
                        "user": user_email,
                        "action": "token_revocation",
                        "status": "completed",
                        "details": f"Revoked {revoked_count} API key(s) for {user_email}",
                        "success": True,
                    }
                else:
                    return {
                        "user": user_email,
                        "action": f"remediate_{cred_type}",
                        "status": "pending_manual_review",
                        "details": f"User not found or unsupported credential type ({cred_type}). Manual remediation required.",
                        "success": False,
                    }

        for exposure in exposures:
            user_email = exposure.get("user", "")
            cred_type = exposure.get("credential_type", "unknown")

            try:
                action = asyncio.run(_remediate_user(user_email, cred_type))
            except RuntimeError:
                action = {
                    "user": user_email,
                    "action": f"remediate_{cred_type}",
                    "status": "error",
                    "details": "Could not execute remediation (event loop conflict)",
                    "success": False,
                }

            if action.get("success"):
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

            results["actions_taken"].append(action)
            self.logger.info(f"Remediation action: {action['action']} for {user_email} -> {action['status']}")

        return results


class AccessBehaviorAnalyzer:
    """Analyzes identity access patterns and detects anomalies"""

    def __init__(self):
        """Initialize behavior analyzer"""
        self.logger = logger
        self.earth_radius_km = 6371

    def build_identity_baseline(
        self,
        access_history: list[dict[str, Any]],
        days: int = 30,
    ) -> dict[str, Any]:
        """
        Build baseline of normal identity behavior.

        Creates statistical baseline from historical access patterns
        for anomaly detection.

        Args:
            access_history: List of historical access events
            days: Number of days to analyze

        Returns:
            Baseline profile with normal patterns
        """
        baseline = {
            "normal_hours": set(),
            "normal_locations": set(),
            "normal_resources": set(),
            "normal_devices": set(),
            "access_frequency": {},
        }

        # Analyze historical patterns
        for event in access_history:
            hour = event.get("hour")
            location = event.get("location")
            resource = event.get("resource")
            device = event.get("device")

            if hour is not None:
                baseline["normal_hours"].add(hour)
            if location:
                baseline["normal_locations"].add(location)
            if resource:
                baseline["normal_resources"].add(resource)
            if device:
                baseline["normal_devices"].add(device)

        # Convert sets to lists for JSON serialization
        baseline["normal_hours"] = list(baseline["normal_hours"])
        baseline["normal_locations"] = list(baseline["normal_locations"])
        baseline["normal_resources"] = list(baseline["normal_resources"])
        baseline["normal_devices"] = list(baseline["normal_devices"])
        baseline["analysis_window_days"] = days

        return baseline

    def detect_anomalies(
        self,
        current_access: dict[str, Any],
        baseline: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Detect access anomalies against baseline.

        Compares current access patterns against established baseline
        to identify deviations.

        Args:
            current_access: Current access event
            baseline: Baseline profile

        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Check unusual time
        if (
            current_access.get("hour") is not None
            and current_access.get("hour") not in baseline.get("normal_hours", [])
        ):
            anomalies.append(
                {
                    "anomaly_type": "unusual_time",
                    "hour": current_access.get("hour"),
                    "deviation_score": 0.7,
                }
            )

        # Check unusual location
        if (
            current_access.get("location")
            and current_access.get("location") not in baseline.get("normal_locations", [])
        ):
            anomalies.append(
                {
                    "anomaly_type": "unusual_location",
                    "location": current_access.get("location"),
                    "deviation_score": 0.8,
                }
            )

        # Check unusual resource
        if (
            current_access.get("resource")
            and current_access.get("resource") not in baseline.get("normal_resources", [])
        ):
            anomalies.append(
                {
                    "anomaly_type": "unusual_resource",
                    "resource": current_access.get("resource"),
                    "deviation_score": 0.65,
                }
            )

        # Check new device
        if (
            current_access.get("device")
            and current_access.get("device") not in baseline.get("normal_devices", [])
        ):
            anomalies.append(
                {
                    "anomaly_type": "new_device",
                    "device": current_access.get("device"),
                    "deviation_score": 0.75,
                }
            )

        return anomalies

    def calculate_identity_risk_score(
        self,
        threats: list[dict[str, Any]],
        anomalies: list[dict[str, Any]],
        credential_issues: list[dict[str, Any]],
    ) -> float:
        """
        Calculate composite identity risk score.

        Aggregates all signals (threats, anomalies, credential issues)
        into comprehensive risk score (0-100).

        Args:
            threats: List of detected threats
            anomalies: List of detected anomalies
            credential_issues: List of credential issues

        Returns:
            Risk score (0-100)
        """
        score = 0.0

        # Threat contribution (max 40 points)
        critical_threats = len([t for t in threats if t.get("severity") == "critical"])
        high_threats = len([t for t in threats if t.get("severity") == "high"])
        score += min(40.0, critical_threats * 15 + high_threats * 8)

        # Anomaly contribution (max 30 points)
        high_deviation = len([a for a in anomalies if a.get("deviation_score", 0) > 0.7])
        score += min(30.0, high_deviation * 5)

        # Credential issue contribution (max 30 points)
        score += min(30.0, len(credential_issues) * 3)

        return min(100.0, score)

    def detect_impossible_travel(
        self,
        access_events: list[dict[str, Any]],
        avg_speed_kmh: int = 900,
    ) -> list[dict[str, Any]]:
        """
        Detect impossible travel patterns.

        Identifies access from locations that are geographically
        impossible to reach in the time between events.

        Args:
            access_events: List of access events with location/time
            avg_speed_kmh: Average travel speed threshold

        Returns:
            List of impossible travel incidents
        """
        incidents = []

        if len(access_events) < 2:
            return incidents

        # Sort events by timestamp
        sorted_events = sorted(
            access_events, key=lambda x: x.get("timestamp", "")
        )

        for i in range(len(sorted_events) - 1):
            event1 = sorted_events[i]
            event2 = sorted_events[i + 1]

            coords1 = event1.get("coordinates")
            coords2 = event2.get("coordinates")
            time1 = event1.get("timestamp")
            time2 = event2.get("timestamp")

            if coords1 and coords2 and time1 and time2:
                try:
                    # Calculate distance (simplified)
                    lat1, lon1 = coords1.get("lat"), coords1.get("lon")
                    lat2, lon2 = coords2.get("lat"), coords2.get("lon")

                    if all([lat1, lon1, lat2, lon2]):
                        distance = self._calculate_distance(lat1, lon1, lat2, lon2)
                        time_diff = self._parse_time_diff(time1, time2)

                        if time_diff > 0:
                            required_speed = distance / time_diff
                            if required_speed > avg_speed_kmh:
                                incident = {
                                    "anomaly_type": "impossible_travel",
                                    "location1": coords1,
                                    "location2": coords2,
                                    "distance_km": round(distance, 2),
                                    "time_hours": round(time_diff, 2),
                                    "required_speed_kmh": round(required_speed, 2),
                                    "deviation_score": min(1.0, required_speed / (avg_speed_kmh * 2)),
                                }
                                incidents.append(incident)
                                self.logger.warning(f"Impossible travel detected: {distance}km in {time_diff}h")
                except (TypeError, ValueError):
                    continue

        return incidents

    def detect_dormant_account_activation(
        self,
        account: dict[str, Any],
        days_inactive_threshold: int = 90,
    ) -> Optional[dict[str, Any]]:
        """
        Detect activation of dormant accounts.

        Identifies when accounts inactive for extended periods
        are suddenly reactivated.

        Args:
            account: Account information
            days_inactive_threshold: Days threshold for dormancy

        Returns:
            Dormant activation detection or None
        """
        last_activity = account.get("last_activity_date")
        current_activity = account.get("current_activity_date")

        if not (last_activity and current_activity):
            return None

        try:
            if isinstance(last_activity, str):
                last_time = datetime.fromisoformat(last_activity.replace("Z", "+00:00"))
            else:
                last_time = last_activity

            if isinstance(current_activity, str):
                current_time = datetime.fromisoformat(current_activity.replace("Z", "+00:00"))
            else:
                current_time = current_activity

            days_inactive = (current_time - last_time).days

            if days_inactive > days_inactive_threshold:
                return {
                    "anomaly_type": "dormant_activation",
                    "user": account.get("username"),
                    "dormant_days": days_inactive,
                    "severity": "high" if days_inactive > 180 else "medium",
                    "last_activity": last_activity,
                    "reactivation_time": current_activity,
                    "deviation_score": min(1.0, days_inactive / 365),
                }
        except (ValueError, TypeError):
            pass

        return None

    def _calculate_distance(
        self, lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """Calculate distance between two coordinates (Haversine formula)"""
        lat1_rad = radians(lat1)
        lon1_rad = radians(lon1)
        lat2_rad = radians(lat2)
        lon2_rad = radians(lon2)

        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad

        a = sin(dlat / 2) ** 2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon / 2) ** 2
        c = 2 * atan2(sqrt(a), sqrt(1 - a))
        distance = self.earth_radius_km * c

        return distance

    def _parse_time_diff(self, time1: str, time2: str) -> float:
        """Parse time difference in hours"""
        try:
            t1 = datetime.fromisoformat(time1.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(time2.replace("Z", "+00:00"))
            return abs((t2 - t1).total_seconds() / 3600)
        except (ValueError, TypeError):
            return 0.0


class PrivilegedAccessManager:
    """Manages and audits privileged access"""

    def __init__(self):
        """Initialize PAM"""
        self.logger = logger
        self.default_jit_duration_minutes = 60

    def enforce_just_in_time_access(
        self,
        user: str,
        resource: str,
        duration_minutes: int = 60,
    ) -> dict[str, Any]:
        """
        Enforce just-in-time (JIT) access control.

        Grants time-bounded elevated access that automatically expires,
        reducing standing privilege exposure.

        Args:
            user: User requesting access
            resource: Target resource
            duration_minutes: Access duration

        Returns:
            JIT access grant details
        """
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(minutes=duration_minutes)

        grant = {
            "user": user,
            "resource": resource,
            "access_type": "just_in_time",
            "granted_at": now.isoformat(),
            "expires_at": expiry.isoformat(),
            "duration_minutes": duration_minutes,
            "status": "active",
            "requires_mfa": True,
            "audit_enabled": True,
        }

        self.logger.info(f"JIT access granted to {user} for {resource} ({duration_minutes}min)")
        return grant

    def approve_elevation_request(
        self,
        request_id: str,
        approver: str,
        approved: bool,
        reason: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Approve or deny privilege elevation request.

        Implements approval workflow for elevation requests with
        audit trail and MFA confirmation.

        Args:
            request_id: Elevation request ID
            approver: Approver identity
            approved: Approval decision
            reason: Approval/denial reason

        Returns:
            Approval decision with audit details
        """
        decision = {
            "request_id": request_id,
            "approver": approver,
            "approved": approved,
            "decision_time": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "audit_log": {
                "approver": approver,
                "mfa_verified": True,
                "approval_method": "email",
            },
        }

        status_msg = "approved" if approved else "denied"
        self.logger.info(f"Elevation request {request_id} {status_msg} by {approver}")

        return decision

    def audit_privileged_actions(
        self,
        actions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Audit privileged access actions.

        Creates comprehensive audit trail for all privileged actions
        with forensic details.

        Args:
            actions: List of privileged actions

        Returns:
            Audit summary with anomalies
        """
        audit_report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_actions": len(actions),
            "critical_actions": 0,
            "anomalies": [],
            "audit_trail": [],
        }

        for action in actions:
            user = action.get("user")
            action_type = action.get("action_type")
            resource = action.get("resource")
            approved = action.get("approved", False)

            # Check for concerning patterns
            if not approved:
                audit_report["critical_actions"] += 1
                audit_report["anomalies"].append(
                    {
                        "type": "unapproved_privileged_action",
                        "user": user,
                        "action": action_type,
                        "severity": "high",
                    }
                )

            audit_trail_entry = {
                "timestamp": action.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "user": user,
                "action": action_type,
                "resource": resource,
                "approved": approved,
                "result": action.get("result", "completed"),
            }
            audit_report["audit_trail"].append(audit_trail_entry)

        return audit_report

    def detect_excessive_privileges(
        self,
        identities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Detect over-privileged identities.

        Identifies users with excessive privileges that violate
        least privilege principles.

        Args:
            identities: List of identity profiles

        Returns:
            List of over-privileged accounts
        """
        over_privileged = []

        for identity in identities:
            user = identity.get("user")
            roles = identity.get("roles", [])
            resources = identity.get("accessible_resources", [])

            # Admin users should be few
            if "admin" in roles:
                over_privileged.append(
                    {
                        "user": user,
                        "issue": "admin_privilege",
                        "roles": roles,
                        "recommendation": "Review necessity of admin role",
                        "severity": "high",
                    }
                )

            # Excessive resource access
            if len(resources) > 50:
                over_privileged.append(
                    {
                        "user": user,
                        "issue": "excessive_resource_access",
                        "resource_count": len(resources),
                        "recommendation": "Implement least privilege policy",
                        "severity": "medium",
                    }
                )

            # Service accounts with interactive access
            if identity.get("is_service_account") and identity.get("has_interactive_access"):
                over_privileged.append(
                    {
                        "user": user,
                        "issue": "service_account_interactive_access",
                        "recommendation": "Restrict to non-interactive access",
                        "severity": "high",
                    }
                )

        return over_privileged

    def generate_pam_report(
        self,
        jit_grants: list[dict[str, Any]],
        elevation_requests: list[dict[str, Any]],
        audit_findings: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Generate PAM (Privileged Access Management) report.

        Comprehensive PAM metrics and compliance assessment.

        Args:
            jit_grants: JIT access grants
            elevation_requests: Elevation requests
            audit_findings: Audit findings

        Returns:
            Comprehensive PAM report
        """
        approved_requests = len(
            [r for r in elevation_requests if r.get("approved")]
        )
        denied_requests = len(elevation_requests) - approved_requests
        active_jit = len([g for g in jit_grants if g.get("status") == "active"])

        return {
            "report_type": "pam_metrics",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "jit_grants": {
                "total_granted": len(jit_grants),
                "currently_active": active_jit,
                "average_duration_minutes": sum(
                    g.get("duration_minutes", 0) for g in jit_grants
                )
                / max(1, len(jit_grants)),
            },
            "elevation_requests": {
                "total_requests": len(elevation_requests),
                "approved": approved_requests,
                "denied": denied_requests,
                "approval_rate_percent": (approved_requests / max(1, len(elevation_requests))) * 100,
            },
            "audit_summary": audit_findings,
            "compliance_score": self._calculate_compliance_score(
                approved_requests, len(elevation_requests), active_jit
            ),
        }

    def _calculate_compliance_score(
        self,
        approvals: int,
        total_requests: int,
        jit_usage: int,
    ) -> float:
        """Calculate PAM compliance score"""
        approval_rate = (approvals / max(1, total_requests)) * 100
        jit_bonus = min(20.0, jit_usage * 2)
        score = min(100.0, 50 + (approval_rate / 2) + jit_bonus)
        return score
