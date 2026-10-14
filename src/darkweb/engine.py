"""Dark Web Monitoring Engine

The sources a dark-web monitor is checked against. Each fetcher is a real
call through the intel outbound guard (``src/intel/outbound.py`` over
``src/integrations/netguard.py``: vetted and pinned address, timeouts, no
redirects) and raises ``DarkWebSourceError`` on failure; nothing here turns
an error into an empty result.

- Have I Been Pwned: per-account lookups (``HIBP_API_KEY``), per-domain
  breach lookups and the recent breach catalogue (both keyless).
- abuse.ch URLhaus and ThreatFox recent items (``ABUSECH_AUTH_KEY``).
- AlienVault OTX subscribed pulses (``OTX_API_KEY``).
- An operator-configured marketplace feed (``DARKWEB_MARKETPLACE_FEED_URL``).

URLhaus, ThreatFox and OTX are threat-intelligence feeds, not paste sites,
Tor forums or Telegram channels; findings from them are labelled
``threat_intel_feed`` and only recorded when an item mentions one of the
monitor's own terms (see ``src/darkweb/monitor_scan.py``).
"""

import asyncio
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from difflib import SequenceMatcher
from urllib.parse import quote

import httpx

from src.core.config import settings
from src.core.logging import get_logger
from src.intel.outbound import IntelOutboundRefused, guarded_request

logger = get_logger(__name__)

HIBP_API = "https://haveibeenpwned.com/api/v3"
OTX_API = "https://otx.alienvault.com/api/v1"
ABUSECH_URLHAUS = "https://urlhaus-api.abuse.ch/v1"
ABUSECH_THREATFOX = "https://threatfox-api.abuse.ch/api/v1"

USER_AGENT = "PySOAR-DarkWebMonitor"
SOURCE_TIMEOUT = httpx.Timeout(20.0, connect=5.0)

#: Spacing between HIBP account calls (HIBP Pwned 1: 10 requests/minute).
HIBP_REQUEST_SPACING_SECONDS = 1.7
#: Accounts / domains looked up per monitor scan; the rest wait for the next
#: scan and the source status says so.
MAX_EMAILS_PER_SCAN = 50
MAX_DOMAINS_PER_SCAN = 50
#: Items read from each threat feed per scan.
FEED_ITEM_LIMIT = 500


class DarkWebSourceError(Exception):
    """A dark-web source could not be read (HTTP error, refusal, bad body)."""

    def __init__(self, source: str, message: str) -> None:
        self.source = source
        self.message = message
        super().__init__(f"{source}: {message}")


def _env_value(attr: str, env: str) -> Optional[str]:
    value = getattr(settings, attr, None) or os.environ.get(env)
    return value.strip() if isinstance(value, str) and value.strip() else None


def hibp_api_key() -> Optional[str]:
    return _env_value("hibp_api_key", "HIBP_API_KEY")


def abusech_auth_key() -> Optional[str]:
    return _env_value("abusech_auth_key", "ABUSECH_AUTH_KEY")


def otx_api_key() -> Optional[str]:
    return _env_value("otx_api_key", "OTX_API_KEY")


def marketplace_feed_url() -> Optional[str]:
    return _env_value("darkweb_marketplace_feed_url", "DARKWEB_MARKETPLACE_FEED_URL")


def _stable_hash(*parts: Any) -> str:
    return hashlib.sha256("::".join(str(p) for p in parts).encode()).hexdigest()


async def _request_json(
    source: str,
    method: str,
    url: str,
    *,
    ok_statuses: tuple[int, ...] = (200,),
    headers: Optional[dict[str, str]] = None,
    **kwargs: Any,
) -> tuple[int, Any]:
    """One guarded call; ``(status, json body)`` for an accepted status.

    Any other status, a refused target, a transport failure or a non-JSON
    body raises ``DarkWebSourceError`` naming the source. A 404 (when
    accepted) or an empty body answers ``None``.
    """
    merged = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
    try:
        resp = await guarded_request(method, url, headers=merged, timeout=SOURCE_TIMEOUT, **kwargs)
    except IntelOutboundRefused as exc:
        raise DarkWebSourceError(source, f"outbound target refused: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise DarkWebSourceError(source, "timed out") from exc
    except httpx.HTTPError as exc:
        raise DarkWebSourceError(source, f"unreachable: {type(exc).__name__}: {exc}") from exc
    if resp.status_code not in ok_statuses:
        if resp.status_code in (401, 403):
            raise DarkWebSourceError(source, f"rejected the API key (HTTP {resp.status_code})")
        if resp.status_code == 429:
            raise DarkWebSourceError(source, "rate limit reached (HTTP 429)")
        if 300 <= resp.status_code < 400:
            raise DarkWebSourceError(source, f"answered a redirect (HTTP {resp.status_code}); not followed")
        raise DarkWebSourceError(source, f"answered HTTP {resp.status_code}")
    if resp.status_code == 404 or not resp.content:
        return resp.status_code, None
    try:
        return resp.status_code, resp.json()
    except ValueError as exc:
        raise DarkWebSourceError(source, "answered a non-JSON body") from exc


class DarkWebScanner:
    """Fetchers for the sources a dark-web monitor is checked against."""

    def configure_monitors(
        self,
        monitor_type: str,
        search_terms: list[str],
        domains_watched: list[str] = None,
        emails_watched: list[str] = None,
    ) -> dict[str, Any]:
        """Configure monitor with search terms and watch lists"""
        return {
            "monitor_type": monitor_type,
            "search_terms": search_terms,
            "domains_watched": domains_watched or [],
            "emails_watched": emails_watched or [],
            "configured_at": datetime.now(timezone.utc).isoformat(),
        }

    async def search_breach_databases(self) -> list[dict[str, Any]]:
        """HIBP breach catalogue: breaches added in the last 90 days (keyless).

        A catalogue entry is general breach news; the monitor scan keeps only
        the entries that mention a monitor term or watched domain.
        """
        _status, breaches = await _request_json("hibp_breach_catalogue", "GET", f"{HIBP_API}/breaches")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
        findings = []
        for breach in breaches or []:
            if str(breach.get("AddedDate", "")) >= cutoff:
                findings.append({
                    "database": "haveibeenpwned",
                    "breach_name": breach.get("Name", ""),
                    "title": f"Breach: {breach.get('Title') or breach.get('Name', '')}",
                    "affected_count": breach.get("PwnCount", 0),
                    "breach_date": breach.get("BreachDate", ""),
                    "compromised_data": breach.get("DataClasses", []),
                    "domain": breach.get("Domain", ""),
                    "description": (breach.get("Description") or "")[:500],
                    "is_verified": breach.get("IsVerified", False),
                    "content_hash": _stable_hash("hibp_catalogue", breach.get("Name", "")),
                })
        return findings

    async def fetch_urlhaus_recent(self) -> list[dict[str, Any]]:
        """abuse.ch URLhaus: recently reported malicious URLs (``ABUSECH_AUTH_KEY``)."""
        _status, data = await _request_json(
            "urlhaus",
            "GET",
            f"{ABUSECH_URLHAUS}/urls/recent/limit/{FEED_ITEM_LIMIT}/",
            headers={"Auth-Key": abusech_auth_key() or ""},
        )
        items = []
        for entry in (data or {}).get("urls") or []:
            url = entry.get("url", "")
            items.append({
                "url": url,
                "title": f"URLhaus: {entry.get('threat') or 'malicious_url'} URL",
                "description": url,
                "threat_type": entry.get("threat", ""),
                "status": entry.get("url_status", ""),
                "tags": entry.get("tags") or [],
                "host": entry.get("host", ""),
                "posted_date": entry.get("date_added", ""),
                "reference": entry.get("urlhaus_reference", ""),
                "content_hash": _stable_hash("urlhaus", entry.get("id") or url),
            })
        return items

    async def fetch_threatfox_recent(self) -> list[dict[str, Any]]:
        """abuse.ch ThreatFox: IOCs reported in the last 7 days (``ABUSECH_AUTH_KEY``)."""
        _status, data = await _request_json(
            "threatfox",
            "POST",
            f"{ABUSECH_THREATFOX}/",
            headers={"Auth-Key": abusech_auth_key() or ""},
            json={"query": "get_iocs", "days": 7},
        )
        rows = (data or {}).get("data")
        if not isinstance(rows, list):
            # ThreatFox answers {"query_status": "..."} without a data list
            # on errors (for example an unknown key).
            query_status = (data or {}).get("query_status")
            if query_status and query_status not in ("ok", "no_result"):
                raise DarkWebSourceError("threatfox", f"query_status={query_status}")
            rows = []
        items = []
        for ioc in rows[:FEED_ITEM_LIMIT]:
            malware = ioc.get("malware_printable") or ioc.get("malware") or "unknown"
            items.append({
                "title": f"ThreatFox: {ioc.get('threat_type', 'malware')} IOC ({malware})",
                "description": f"IOC: {ioc.get('ioc', '')} ({ioc.get('ioc_type', '')})",
                "ioc_value": ioc.get("ioc", ""),
                "ioc_type": ioc.get("ioc_type", ""),
                "malware": ioc.get("malware", ""),
                "tags": ioc.get("tags") or [],
                "reporter": ioc.get("reporter", ""),
                "timestamp": ioc.get("first_seen", ""),
                "confidence": ioc.get("confidence_level"),
                "content_hash": _stable_hash("threatfox", ioc.get("id") or ioc.get("ioc", "")),
            })
        return items

    async def fetch_otx_pulses(self) -> list[dict[str, Any]]:
        """AlienVault OTX: subscribed pulses modified in the last 7 days (``OTX_API_KEY``)."""
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
        _status, data = await _request_json(
            "otx",
            "GET",
            f"{OTX_API}/pulses/subscribed",
            headers={"X-OTX-API-KEY": otx_api_key() or ""},
            params={"limit": 50, "modified_since": since},
        )
        items = []
        for pulse in (data or {}).get("results") or []:
            indicators = pulse.get("indicators") or []
            items.append({
                "title": f"OTX pulse: {pulse.get('name', '')}",
                "description": (pulse.get("description") or "")[:500],
                "author": pulse.get("author_name", ""),
                "tags": pulse.get("tags") or [],
                "adversary": pulse.get("adversary", ""),
                "targeted_countries": pulse.get("targeted_countries") or [],
                "industries": pulse.get("industries") or [],
                "indicator_values": [str(i.get("indicator", "")) for i in indicators[:200]],
                "indicator_count": len(indicators),
                "tlp": pulse.get("tlp", "white"),
                "timestamp": pulse.get("modified", ""),
                "content_hash": _stable_hash("otx", pulse.get("id", ""), pulse.get("modified", "")),
            })
        return items

    async def fetch_marketplace_feed(self) -> list[dict[str, Any]]:
        """The operator-configured marketplace feed (``DARKWEB_MARKETPLACE_FEED_URL``)."""
        url = marketplace_feed_url()
        if not url:
            raise DarkWebSourceError("marketplace_feed", "DARKWEB_MARKETPLACE_FEED_URL is not set")
        _status, data = await _request_json("marketplace_feed", "GET", url)
        rows = data if isinstance(data, list) else (data or {}).get("results") or []
        items = []
        for item in rows[:FEED_ITEM_LIMIT]:
            if not isinstance(item, dict):
                continue
            items.append({
                "marketplace_name": item.get("marketplace") or item.get("site") or "marketplace",
                "url": item.get("url") or item.get("onion_url") or "",
                "title": item.get("title") or item.get("description") or "marketplace listing",
                "description": item.get("description") or item.get("details") or "",
                "confidence": item.get("confidence"),
                "content_hash": hashlib.sha256(
                    json.dumps(item, sort_keys=True, default=str).encode()
                ).hexdigest(),
            })
        return items

    async def hibp_lookup_emails(self, emails: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
        """Per-account HIBP lookups (``HIBP_API_KEY``).

        For each address: ``/breachedaccount`` (breaches the account is in),
        ``/stealerlogsbyemail`` (infostealer logs; needs an HIBP subscription
        that includes them) and ``/pasteaccount`` (pastes). A 404 means the
        account is not listed. Returns ``(findings, errors)``; a rejected key
        raises ``DarkWebSourceError`` because no further call can succeed.
        """
        key = hibp_api_key()
        if not key:
            raise DarkWebSourceError("hibp_account", "HIBP_API_KEY is not set")
        auth = {"hibp-api-key": key}
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        async def _call(kind: str, url: str, **kwargs: Any) -> Any:
            try:
                status, body = await _request_json(
                    "hibp_account", "GET", url, ok_statuses=(200, 404), headers=auth, **kwargs,
                )
            except DarkWebSourceError as exc:
                if kind == "breachedaccount" and exc.message.startswith("rejected the API key"):
                    raise
                errors.append(f"{kind}: {exc.message}")
                return None
            finally:
                if HIBP_REQUEST_SPACING_SECONDS:
                    await asyncio.sleep(HIBP_REQUEST_SPACING_SECONDS)
            return body if status == 200 else None

        for email in emails:
            email = (email or "").strip()
            if not email or "@" not in email:
                continue
            quoted = quote(email, safe="@")
            breaches = await _call(
                "breachedaccount", f"{HIBP_API}/breachedaccount/{quoted}", params={"truncateResponse": "false"},
            )
            for b in breaches or []:
                findings.append({
                    "source": "hibp_account",
                    "lookup_kind": "breached_account",
                    "email": email,
                    "breach_name": b.get("Name"),
                    "breach_date": b.get("BreachDate"),
                    "affected_count": b.get("PwnCount", 0),
                    "compromised_data": b.get("DataClasses", []),
                    "is_verified": b.get("IsVerified", False),
                    "domain": b.get("Domain"),
                    "description": (b.get("Description") or "")[:300],
                    "content_hash": _stable_hash("hibp_ba", email, b.get("Name")),
                    "title": f"{email} exposed in {b.get('Name')}",
                })
            for site in await _call("stealerlogsbyemail", f"{HIBP_API}/stealerlogsbyemail/{quoted}") or []:
                findings.append({
                    "source": "hibp_stealer",
                    "lookup_kind": "stealer_log",
                    "email": email,
                    "site": site,
                    "content_hash": _stable_hash("hibp_sl", email, site),
                    "title": f"{email} in infostealer log for {site}",
                    "description": f"Credentials for {site} exfiltrated by infostealer malware targeting {email}",
                })
            for p in await _call("pasteaccount", f"{HIBP_API}/pasteaccount/{quoted}") or []:
                findings.append({
                    "source": "hibp_paste",
                    "lookup_kind": "paste",
                    "email": email,
                    "paste_source": p.get("Source"),
                    "paste_id": p.get("Id"),
                    "paste_title": p.get("Title"),
                    "paste_date": p.get("Date"),
                    "email_count": p.get("EmailCount"),
                    "content_hash": _stable_hash("hibp_paste", email, p.get("Source"), p.get("Id")),
                    "title": f"{email} in paste: {p.get('Source')}/{p.get('Id')}",
                    "description": (p.get("Title") or "")[:300],
                })
        return findings, errors

    async def hibp_lookup_domains(self, domains: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
        """Breaches HIBP lists for each watched domain (keyless ``/breaches?domain=``).

        Returns ``(findings, errors)``.
        """
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        for domain in domains:
            domain = (domain or "").strip().lower()
            if not domain:
                continue
            try:
                _status, breaches = await _request_json(
                    "hibp_domain", "GET", f"{HIBP_API}/breaches", params={"domain": domain},
                )
            except DarkWebSourceError as exc:
                errors.append(f"{domain}: {exc.message}")
                continue
            for b in breaches or []:
                findings.append({
                    "source": "hibp_domain",
                    "lookup_kind": "domain_breach",
                    "domain": domain,
                    "breach_name": b.get("Name"),
                    "breach_date": b.get("BreachDate"),
                    "affected_count": b.get("PwnCount", 0),
                    "compromised_data": b.get("DataClasses", []),
                    "is_verified": b.get("IsVerified", False),
                    "description": (b.get("Description") or "")[:300],
                    "content_hash": _stable_hash("hibp_dom", domain, b.get("Name")),
                    "title": f"{domain} in {b.get('Name')}",
                })
        return findings, errors

    async def aggregate_findings(self, results: dict[str, Any]) -> dict[str, Any]:
        """Aggregate and deduplicate findings from multiple sources"""
        all_findings = []
        for source, findings in results.items():
            if source != "timestamp" and isinstance(findings, list):
                for finding in findings:
                    finding["source"] = source
                    all_findings.append(finding)

        # Deduplicate
        deduplicated = await self.deduplicate_results(all_findings)

        return {
            "total_findings": len(deduplicated),
            "findings": deduplicated,
            "timestamp": results.get("timestamp"),
        }

    async def deduplicate_results(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Remove duplicate findings based on content hash"""
        seen_hashes = set()
        deduplicated = []

        for finding in findings:
            # Generate content hash
            content = json.dumps(finding, sort_keys=True, default=str)
            content_hash = hashlib.sha256(content.encode()).hexdigest()

            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                finding["content_hash"] = content_hash
                deduplicated.append(finding)

        logger.info(
            f"Deduplicated findings: {len(findings)} -> {len(deduplicated)}"
        )
        return deduplicated


class CredentialAnalyzer:
    """Credential leak analysis and remediation"""

    def __init__(self):
        """Initialize credential analyzer"""
        self.password_hash_patterns = {
            "md5": r"^[a-f0-9]{32}$",
            "sha1": r"^[a-f0-9]{40}$",
            "sha256": r"^[a-f0-9]{64}$",
            "bcrypt": r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$",
            "argon2": r"^\$argon2",
            "ntlm": r"^[a-f0-9]{32}$",  # Similar to MD5, requires context
        }

    def parse_credential_dumps(self, raw_data: str) -> list[dict[str, str]]:
        """Parse credential dumps from various formats"""
        credentials = []

        # Handle email:password format
        email_password_pattern = r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(.+)"
        matches = re.findall(email_password_pattern, raw_data)
        for email, password in matches:
            credentials.append({"email": email, "password": password})

        # Handle email|password format
        email_password_pipe = r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(.+)"
        matches = re.findall(email_password_pipe, raw_data)
        for email, password in matches:
            credentials.append({"email": email, "password": password})

        # Handle username:password format
        username_password = r"^([a-zA-Z0-9_.-]+):(.+)$"
        for line in raw_data.split("\n"):
            matches = re.findall(username_password, line)
            for username, password in matches:
                credentials.append({"username": username, "password": password})

        return credentials

    def identify_organizational_credentials(
        self,
        credentials: list[dict[str, str]],
        monitored_domains: list[str],
        monitored_emails: list[str],
    ) -> list[dict[str, Any]]:
        """Match credentials against organizational watch lists"""
        organizational_creds = []

        for cred in credentials:
            email = cred.get("email", "")
            username = cred.get("username", "")

            # Check domain matches
            for domain in monitored_domains:
                if domain in email:
                    cred["matched_type"] = "domain"
                    cred["matched_value"] = domain
                    organizational_creds.append(cred)
                    break

            # Check email matches
            if email in monitored_emails:
                cred["matched_type"] = "email"
                cred["matched_value"] = email
                organizational_creds.append(cred)

        return organizational_creds

    def assess_password_risk(self, password_hash: str) -> dict[str, Any]:
        """Assess password hash type and estimated crack time"""
        hash_type = "unknown"
        crack_time_seconds = 0

        for ptype, pattern in self.password_hash_patterns.items():
            if re.match(pattern, password_hash):
                hash_type = ptype
                break

        # Estimate crack times (these are simplified estimates)
        crack_time_map = {
            "plaintext": 0,  # Already cracked
            "md5": 3600,  # ~1 hour
            "sha1": 7200,  # ~2 hours
            "sha256": 86400,  # ~1 day
            "bcrypt": 2592000,  # ~30 days
            "argon2": 31536000,  # ~1 year
            "ntlm": 3600,  # ~1 hour
            "unknown": 604800,  # ~1 week (assumption)
        }

        crack_time_seconds = crack_time_map.get(hash_type, 604800)

        return {
            "hash_type": hash_type,
            "crack_time_seconds": crack_time_seconds,
            "risk_level": self._calculate_risk_level(hash_type),
            "recommendation": self._get_remediation_recommendation(hash_type),
        }

    def _calculate_risk_level(self, hash_type: str) -> str:
        """Calculate risk level based on hash type"""
        high_risk = ["plaintext", "md5", "sha1", "ntlm"]
        medium_risk = ["sha256"]
        low_risk = ["bcrypt", "argon2"]

        if hash_type in high_risk:
            return "critical"
        elif hash_type in medium_risk:
            return "high"
        elif hash_type in low_risk:
            return "medium"
        return "unknown"

    def _get_remediation_recommendation(self, hash_type: str) -> str:
        """Get remediation recommendation based on hash type"""
        if hash_type in ["plaintext", "md5", "sha1", "ntlm"]:
            return "Immediate password reset required"
        elif hash_type == "sha256":
            return "Password reset recommended within 24 hours"
        else:
            return "Monitor for additional exposure"

    async def correlate_with_identity_store(
        self, credentials: list[dict[str, str]], user_database: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Match leaked credentials against known users"""
        matched_users = []

        for cred in credentials:
            for user in user_database:
                if cred.get("email") == user.get("email"):
                    matched_users.append(
                        {
                            "credential": cred,
                            "user": user,
                            "risk_score": 95,
                        }
                    )
                elif cred.get("username") == user.get("username"):
                    matched_users.append(
                        {
                            "credential": cred,
                            "user": user,
                            "risk_score": 85,
                        }
                    )

        return matched_users

    SUPPORTED_REMEDIATION_ACTIONS = frozenset(
        {"password_reset", "account_disabled", "mfa_enforced", "token_revoked"}
    )

    async def auto_remediate(
        self, affected_user_id: str, action: str, db: Optional[Any] = None
    ) -> dict[str, Any]:
        """Apply credential-leak remediation to a matching LOCAL user account.

        Previously returned ``{"status": "initiated", "notification_sent":
        True, "workflow": ...}`` without doing anything — no workflow ran and
        no notification was ever sent. It now either performs a real account
        action against the local User table (same semantics as remediation's
        AccountActionExecutor: flag force_password_change; additionally
        deactivate for account_disabled) when an AsyncSession is provided,
        or honestly reports that nothing was executed.

        Args:
            affected_user_id: Local user id or email of the exposed account
            action: One of SUPPORTED_REMEDIATION_ACTIONS
            db: Optional SQLAlchemy AsyncSession; without it, no remediation
                can be performed and the result says so
        """
        result: dict[str, Any] = {
            "user_id": affected_user_id,
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if action not in self.SUPPORTED_REMEDIATION_ACTIONS:
            result["status"] = "unsupported_action"
            result["detail"] = (
                f"Unsupported action '{action}'; supported: "
                f"{sorted(self.SUPPORTED_REMEDIATION_ACTIONS)}"
            )
            return result

        if db is None:
            result["status"] = "not_executed"
            result["detail"] = (
                "No database session provided; no remediation was performed "
                "and no notification was sent. Pass an AsyncSession to apply "
                "the account action to the local user."
            )
            return result

        from sqlalchemy import or_, select

        from src.models.user import User

        lookup = await db.execute(
            select(User).where(
                or_(User.id == affected_user_id, User.email == affected_user_id)
            )
        )
        user = lookup.scalars().first()
        if user is None:
            result["status"] = "user_not_found"
            result["detail"] = (
                "No local user matches the affected user id/email; "
                "no action was taken."
            )
            return result

        # Same real controls AccountActionExecutor applies: every action
        # forces a credential rotation; disabling also deactivates the login.
        if action == "account_disabled":
            user.is_active = False
        user.force_password_change = True
        await db.flush()

        result["status"] = "applied"
        result["matched_user_id"] = user.id
        result["is_active"] = user.is_active
        result["force_password_change"] = True
        # Honest: nothing here sends an out-of-band notification.
        result["notification_sent"] = False
        return result

    async def generate_exposure_report(
        self, leaks: list[dict[str, Any]], organization_name: str
    ) -> dict[str, Any]:
        """Generate comprehensive credential exposure report"""
        unique_emails = set()
        unique_credentials = 0
        critical_accounts = []
        hash_type_distribution = {}

        for leak in leaks:
            if leak.get("email"):
                unique_emails.add(leak["email"])
            unique_credentials += 1

            hash_type = leak.get("password_type", "unknown")
            hash_type_distribution[hash_type] = (
                hash_type_distribution.get(hash_type, 0) + 1
            )

            if leak.get("is_critical"):
                critical_accounts.append(leak)

        return {
            "organization": organization_name,
            "report_date": datetime.now(timezone.utc).isoformat(),
            "total_credentials_exposed": unique_credentials,
            "unique_accounts": len(unique_emails),
            "critical_accounts": len(critical_accounts),
            "hash_distribution": hash_type_distribution,
            "affected_emails": list(unique_emails),
            "recommended_actions": [
                "Force password reset for all exposed accounts",
                "Enable MFA for all users",
                "Monitor for account takeover attempts",
                "Review access logs for the affected accounts",
            ],
        }


class BrandProtection:
    """Brand threat detection and protection"""

    def __init__(self):
        """Initialize brand protection engine"""
        self.similarity_threshold = 0.75

    def detect_typosquatting(self, legitimate_domain: str) -> list[dict[str, Any]]:
        """Detect typosquatting domains using multiple techniques"""
        detections = []

        # Levenshtein distance (edit distance)
        suspicious_domains = self._generate_typosquats_levenshtein(
            legitimate_domain
        )
        detections.extend(
            [
                {
                    "technique": "levenshtein",
                    "domain": domain,
                    "similarity": score,
                }
                for domain, score in suspicious_domains
            ]
        )

        # Homoglyph detection
        homoglyph_domains = self._generate_homoglyph_variants(legitimate_domain)
        detections.extend(
            [
                {"technique": "homoglyph", "domain": domain, "risk": "high"}
                for domain in homoglyph_domains
            ]
        )

        # TLD substitution
        tld_variants = self._generate_tld_variants(legitimate_domain)
        detections.extend(
            [
                {"technique": "tld_substitution", "domain": domain, "risk": "medium"}
                for domain in tld_variants
            ]
        )

        return detections

    def _generate_typosquats_levenshtein(
        self, domain: str, max_distance: int = 2
    ) -> list[tuple[str, float]]:
        """Generate typosquat variants using Levenshtein distance"""
        base, _, tld = domain.rpartition(".")
        if not base:
            return []

        candidates = []

        # Character substitution variants
        for i in range(len(base)):
            for c in "abcdefghijklmnopqrstuvwxyz0123456789":
                if c != base[i]:
                    variant = base[:i] + c + base[i + 1:] + "." + tld
                    candidates.append(variant)

        # Character insertion
        for i in range(len(base) + 1):
            for c in "abcdefghijklmnopqrstuvwxyz0123456789-":
                variant = base[:i] + c + base[i:] + "." + tld
                candidates.append(variant)

        # Character deletion
        for i in range(len(base)):
            variant = base[:i] + base[i + 1:] + "." + tld
            if variant != "." + tld:
                candidates.append(variant)

        # Adjacent character transposition
        for i in range(len(base) - 1):
            swapped = list(base)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            variant = "".join(swapped) + "." + tld
            candidates.append(variant)

        # Character duplication
        for i in range(len(base)):
            variant = base[:i] + base[i] + base[i:] + "." + tld
            candidates.append(variant)

        # Filter by Levenshtein distance (using SequenceMatcher ratio as proxy)
        results = []
        seen = set()
        for candidate in candidates:
            if candidate == domain or candidate in seen:
                continue
            seen.add(candidate)
            similarity = SequenceMatcher(None, domain, candidate).ratio()
            if similarity >= self.similarity_threshold:
                results.append((candidate, similarity))

        # Sort by similarity descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def _generate_homoglyph_variants(self, domain: str) -> list[str]:
        """Generate homoglyph variants (visually similar characters)"""
        homoglyph_map = {
            "a": ["ɑ", "а"],  # Unicode look-alikes
            "e": ["е"],
            "i": ["і", "ı"],
            "o": ["о", "0"],
            "p": ["р"],
            "s": ["ѕ"],
            "x": ["х"],
        }

        variants = []
        for char, replacements in homoglyph_map.items():
            if char in domain:
                for replacement in replacements:
                    variant = domain.replace(char, replacement)
                    variants.append(variant)

        return variants

    def _generate_tld_variants(self, domain: str) -> list[str]:
        """Generate TLD substitution variants"""
        common_tlds = ["com", "net", "org", "co", "io", "biz", "info"]
        variants = []

        for tld in common_tlds:
            variant = re.sub(r"\.com$|\.net$|\.org$", f".{tld}", domain)
            if variant != domain:
                variants.append(variant)

        return variants

    def detect_lookalike_sites(
        self, legitimate_site_content: str, suspicious_site_content: str
    ) -> dict[str, Any]:
        """Detect lookalike websites using content similarity"""
        similarity = SequenceMatcher(None, legitimate_site_content, suspicious_site_content).ratio()

        return {
            "similarity_score": similarity,
            "risk_level": "critical"
            if similarity > 0.85
            else "high"
            if similarity > 0.70
            else "medium",
            "detected": similarity > 0.70,
            "recommendation": "Initiate takedown if similarity > 0.85",
        }

    def detect_phishing_kits(self, site_content: str) -> dict[str, Any]:
        """Detect phishing kits by analyzing brand asset usage"""
        brand_indicators = {
            "login_form": bool(re.search(r"<form[^>]*>.*password", site_content)),
            "legitimate_logo": bool(
                re.search(r'src="[^"]*logo[^"]*"', site_content)
            ),
            "ssl_certificate": bool(re.search(r"https://", site_content)),
            "obfuscated_js": bool(re.search(r"eval\(|Function\(", site_content)),
        }

        phishing_score = sum(
            [
                1 if brand_indicators.get("login_form") else 0,
                1 if brand_indicators.get("legitimate_logo") else 0,
                -1 if brand_indicators.get("ssl_certificate") else 0,
                2 if brand_indicators.get("obfuscated_js") else 0,
            ]
        )

        return {
            "indicators": brand_indicators,
            "phishing_score": max(0, phishing_score),
            "is_phishing_kit": phishing_score >= 2,
            "confidence": min(100, (phishing_score / 4) * 100),
        }

    async def initiate_takedown_process(
        self, threat_id: str, threat_type: str, provider: str = "auto"
    ) -> dict[str, Any]:
        """Record a takedown request honestly — no provider is integrated.

        Previously fabricated a successful "takedown_requested" response with
        an invented 3-day estimated_resolution. PySOAR has no takedown
        provider integration (no registrar/hoster abuse API), so nothing is
        executed here; the request must be actioned manually.
        """
        return {
            "threat_id": threat_id,
            "threat_type": threat_type,
            "provider": None,
            "status": "no_takedown_provider",
            "detail": (
                "No takedown provider is integrated; the takedown request is "
                "recorded for manual action (registrar/hosting abuse contact) "
                "and is NOT being executed automatically."
            ),
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }

    async def track_takedown_status(self, takedown_id: str) -> dict[str, Any]:
        """Report takedown tracking honestly — no provider is integrated.

        Previously fabricated status "in_progress" with progress=50 and an
        invented 2-day estimated_completion. There is no provider to poll.
        """
        return {
            "takedown_id": takedown_id,
            "status": "no_takedown_provider",
            "detail": (
                "No takedown provider is integrated; there is no external "
                "status to poll. Track manual takedown progress via the "
                "threat's takedown_status field."
            ),
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }


class ThreatIntelCorrelator:
    """Threat intelligence correlation and enrichment"""

    def __init__(self):
        """Initialize threat intelligence correlator"""
        pass

    async def correlate_with_iocs(
        self, finding_data: dict[str, Any], ioc_database: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Correlate findings against IOC database"""
        correlations = []

        for ioc in ioc_database:
            if finding_data.get("domain") == ioc.get("value"):
                correlations.append(
                    {
                        "ioc": ioc,
                        "finding": finding_data,
                        "match_type": "domain",
                        "confidence": 100,
                    }
                )
            elif finding_data.get("email") == ioc.get("value"):
                correlations.append(
                    {
                        "ioc": ioc,
                        "finding": finding_data,
                        "match_type": "email",
                        "confidence": 100,
                    }
                )

        return correlations

    async def correlate_with_incidents(
        self, finding_data: dict[str, Any], incident_database: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Link findings to active incidents"""
        correlations = []

        for incident in incident_database:
            # Check if finding matches incident IOCs
            if finding_data.get("domain") in incident.get("iocs", []):
                correlations.append(
                    {
                        "incident": incident,
                        "finding": finding_data,
                        "relationship": "ioc_match",
                        "confidence": 95,
                    }
                )

        return correlations

    # NOTE: enrich_findings and its helpers (_attribute_actor,
    # _map_campaign, _get_historical_context) were deleted 2026-06-11.
    # They had zero callers and fabricated analysis: campaign mapping
    # always returned "Unattributed", historical context returned
    # hardcoded zeros with now() timestamps, and actor attribution was
    # an 8-entry keyword table presented as intelligence. The real
    # correlation path is correlate_with_iocs / correlate_with_incidents
    # (used by darkweb tasks). Reimplement attribution against stored
    # ThreatActor/ThreatCampaign rows if the feature is wanted.

    async def generate_intelligence_report(
        self, findings: list[dict[str, Any]], organization_name: str
    ) -> dict[str, Any]:
        """Generate comprehensive threat intelligence report"""
        return {
            "organization": organization_name,
            "report_date": datetime.now(timezone.utc).isoformat(),
            "findings_count": len(findings),
            "critical_findings": len(
                [f for f in findings if f.get("severity") == "critical"]
            ),
            "threat_actors": self._extract_threat_actors(findings),
            "campaigns": self._extract_campaigns(findings),
            "recommendations": [
                "Review IOC database for indicator updates",
                "Coordinate with threat intelligence providers",
                "Update detection signatures",
            ],
        }

    def _extract_threat_actors(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Extract unique threat actors from findings"""
        actors = []
        seen = set()

        for finding in findings:
            actor = finding.get("actor")
            if actor and actor not in seen:
                actors.append({"name": actor, "count": 1})
                seen.add(actor)

        return actors

    def _extract_campaigns(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Extract unique campaigns from findings"""
        campaigns = []
        seen = set()

        for finding in findings:
            campaign = finding.get("campaign")
            if campaign and campaign not in seen:
                campaigns.append({"name": campaign, "count": 1})
                seen.add(campaign)

        return campaigns

    async def calculate_risk_score(self, finding: dict[str, Any]) -> int:
        """Calculate overall risk score for finding"""
        score = 0

        # Severity component (0-40)
        severity_map = {
            "critical": 40,
            "high": 30,
            "medium": 20,
            "low": 10,
            "info": 0,
        }
        score += severity_map.get(finding.get("severity", "medium"), 20)

        # Confidence component (0-30)
        confidence = finding.get("confidence_score", 50) / 100 * 30
        score += confidence

        # Impact component (0-30)
        affected_count = finding.get("affected_count", 1)
        impact = min(30, affected_count / 100 * 30)
        score += impact

        return min(100, int(score))
