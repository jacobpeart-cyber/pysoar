"""External IOC enrichment: VirusTotal, AbuseIPDB and AlienVault OTX.

One implementation shared by ``POST /threat-intel/lookup``,
``POST /threat-intel/indicators/{id}/enrich``, ``POST /iocs/{id}/enrich`` and
``IndicatorEnricher`` (the daily refresh task).

Keys, per organisation, first match wins:

1. the organisation's installed integration (``installed_integrations`` row
   for the provider's connector); the credential blob is an ``enc:v1:``
   envelope opened with ``src.core.secrets.decrypt_secret_json``. A blob that
   cannot be opened is reported as ``credentials_unreadable`` for that
   provider, never parsed as JSON and never treated as "not configured";
2. the organisation's Settings > Integrations section
   (``app_settings`` ``integration:<provider>``, secrets opened by
   ``src.services.tenant_settings``);
3. the platform environment (``VIRUSTOTAL_API_KEY``, ``ABUSEIPDB_API_KEY``,
   ``OTX_API_KEY``).

A provider that applies to the indicator type but has no key reports
``not_configured`` with the environment variable that would enable it.
Provider failures (HTTP status, timeout, refused target) are reported per
provider with the reason; they are never turned into an empty result.

Results are cached per (organisation, provider, type, value) for
``CACHE_TTL_SECONDS``; only successful answers are cached.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import re
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.logging import get_logger
from src.core.secrets import SecretUnreadable, decrypt_secret_json
from src.intel.outbound import IntelOutboundRefused, guarded_request

logger = get_logger(__name__)

PROVIDERS: tuple[str, ...] = ("virustotal", "abuseipdb", "otx")

#: Dispatch buckets each provider answers for.
PROVIDER_TYPES: dict[str, frozenset[str]] = {
    "virustotal": frozenset({"ip", "domain", "url", "hash"}),
    "abuseipdb": frozenset({"ip"}),
    "otx": frozenset({"ip", "domain", "url", "hash"}),
}

#: Integration-marketplace connector names per provider.
CONNECTOR_NAMES: dict[str, tuple[str, ...]] = {
    "virustotal": ("virustotal",),
    "abuseipdb": ("abuseipdb",),
    "otx": ("alienvault_otx", "otx"),
}

#: Settings > Integrations section names per provider.
SETTINGS_SECTIONS: dict[str, tuple[str, ...]] = {
    "virustotal": ("integration:virustotal",),
    "abuseipdb": ("integration:abuseipdb",),
    "otx": ("integration:alienvault_otx", "integration:otx"),
}

#: Platform environment variable per provider.
ENV_NAMES: dict[str, str] = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "otx": "OTX_API_KEY",
}

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
OTX_BASE = "https://otx.alienvault.com/api/v1"

CACHE_TTL_SECONDS = 3600
CACHE_MAX_ENTRIES = 5000
_cache: "OrderedDict[tuple[str, ...], tuple[float, dict[str, Any]]]" = OrderedDict()

_KEY_FIELDS = ("api_key", "apikey", "key", "token")


class ProviderError(Exception):
    """A provider answered with an error or could not be reached."""


@dataclass
class ProviderKey:
    provider: str
    api_key: str
    source: str  # "integration" | "tenant_settings" | "platform"


@dataclass
class KeyResolution:
    keys: dict[str, ProviderKey] = field(default_factory=dict)
    #: provider -> reason, for installed credentials that could not be opened.
    unreadable: dict[str, str] = field(default_factory=dict)


@dataclass
class ProviderOutcome:
    """What happened for one provider on one lookup."""

    provider: str
    status: str  # ok | not_configured | credentials_unreadable | unsupported_type | error
    key_source: Optional[str] = None
    cached: bool = False
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    detail: Optional[str] = None

    def summary(self) -> dict[str, Any]:
        """The outcome without the provider payload (for listings)."""
        data = asdict(self)
        data.pop("result", None)
        return data


# --------------------------------------------------------------------------
# Indicator typing
# --------------------------------------------------------------------------


def detect_type(value: str) -> str:
    """Best-effort IOC type detection for ``type='auto'``."""
    v = value.strip()
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if re.fullmatch(r"[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}", v):
        return "domain"
    return "unknown"


def dispatch_bucket(indicator_type: Optional[str]) -> str:
    """Collapse a stored indicator type to the bucket providers dispatch on."""
    t = (indicator_type or "").lower()
    if t in ("ipv4", "ipv6", "ip", "ip-src", "ip-dst"):
        return "ip"
    if t in ("md5", "sha1", "sha256", "sha512", "hash", "file"):
        return "hash"
    if t in ("url", "uri"):
        return "url"
    if t in ("domain", "hostname", "fqdn"):
        return "domain"
    return t or "unknown"


#: Stored ``indicator_type`` values that belong to a UI filter value.
TYPE_VARIANTS: dict[str, tuple[str, ...]] = {
    "ip": ("ip", "ipv4", "ipv6", "cidr"),
    "ipv4": ("ipv4", "ip"),
    "ipv6": ("ipv6", "ip"),
    "hash": ("hash", "md5", "sha1", "sha256", "sha512"),
    "domain": ("domain", "hostname"),
}


def type_variants(indicator_type: str) -> tuple[str, ...]:
    return TYPE_VARIANTS.get(indicator_type.lower(), (indicator_type,))


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------


def _key_from(creds: Any) -> Optional[str]:
    if not isinstance(creds, dict):
        return None
    for name in _KEY_FIELDS:
        value = creds.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def platform_key(provider: str) -> Optional[str]:
    """The platform environment key for ``provider`` (None when unset)."""
    attr = {
        "virustotal": "virustotal_api_key",
        "abuseipdb": "abuseipdb_api_key",
        "otx": "otx_api_key",
    }[provider]
    value = getattr(settings, attr, None) or os.environ.get(ENV_NAMES[provider])
    return value.strip() if isinstance(value, str) and value.strip() else None


async def resolve_provider_keys(
    db: AsyncSession,
    organization_id: Optional[str],
    *,
    platform_keys: Optional[dict[str, Optional[str]]] = None,
) -> KeyResolution:
    """Keys usable by ``organization_id`` (None = platform intel: env keys only).

    ``platform_keys`` overrides the environment lookup (``IndicatorEnricher``
    passes its own availability flags through it).
    """
    from src.integrations.models import InstalledIntegration, IntegrationConnector
    from src.services.tenant_settings import load_tenant_section

    resolution = KeyResolution()

    if organization_id:
        all_names = [n for names in CONNECTOR_NAMES.values() for n in names]
        rows = (
            await db.execute(
                select(InstalledIntegration, IntegrationConnector.name)
                .join(IntegrationConnector, IntegrationConnector.id == InstalledIntegration.connector_id)
                .where(
                    InstalledIntegration.organization_id == organization_id,
                    IntegrationConnector.name.in_(all_names),
                )
                .order_by(InstalledIntegration.created_at.asc()),
            )
        ).all()
        for inst, connector_name in rows:
            provider = next(p for p, names in CONNECTOR_NAMES.items() if connector_name in names)
            if provider in resolution.keys:
                continue
            if (inst.status or "").lower() in ("inactive", "disabled"):
                continue
            blob = inst.auth_credentials_encrypted
            if not blob:
                continue
            try:
                creds = decrypt_secret_json(blob, required=True)
            except SecretUnreadable as exc:
                resolution.unreadable[provider] = exc.reason
                logger.warning(
                    "intel_provider_credentials_unreadable",
                    provider=provider,
                    organization_id=organization_id,
                    reason=exc.reason,
                )
                continue
            key = _key_from(creds)
            if key:
                resolution.keys[provider] = ProviderKey(provider, key, "integration")
                resolution.unreadable.pop(provider, None)

        for provider, sections in SETTINGS_SECTIONS.items():
            if provider in resolution.keys:
                continue
            for section in sections:
                key = _key_from(await load_tenant_section(db, organization_id, section))
                if key:
                    resolution.keys[provider] = ProviderKey(provider, key, "tenant_settings")
                    break

    for provider in PROVIDERS:
        if provider in resolution.keys:
            continue
        if platform_keys is not None:
            key = platform_keys.get(provider)
        else:
            key = platform_key(provider)
        if key is not None:
            resolution.keys[provider] = ProviderKey(provider, key, "platform")
    return resolution


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


def _cache_key(organization_id: Optional[str], provider: str, bucket: str, value: str) -> tuple[str, ...]:
    return (organization_id or "__platform__", provider, bucket, value)


def cache_get(key: tuple[str, ...]) -> Optional[dict[str, Any]]:
    entry = _cache.get(key)
    if entry is None:
        return None
    expires_at, value = entry
    if expires_at < time.time():
        _cache.pop(key, None)
        return None
    return value


def cache_set(key: tuple[str, ...], value: dict[str, Any]) -> None:
    _cache[key] = (time.time() + CACHE_TTL_SECONDS, value)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX_ENTRIES:
        _cache.popitem(last=False)


def cache_clear() -> None:
    _cache.clear()


# --------------------------------------------------------------------------
# Provider calls
# --------------------------------------------------------------------------


def _raise_for_status(provider: str, resp: httpx.Response) -> None:
    if 200 <= resp.status_code < 300:
        return
    if resp.status_code in (401, 403):
        raise ProviderError(f"{provider} rejected the API key (HTTP {resp.status_code})")
    if resp.status_code == 429:
        raise ProviderError(f"{provider} rate limit reached (HTTP 429)")
    if 300 <= resp.status_code < 400:
        raise ProviderError(f"{provider} answered a redirect (HTTP {resp.status_code}); not followed")
    raise ProviderError(f"{provider} answered HTTP {resp.status_code}")


def _json(provider: str, resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError as exc:
        raise ProviderError(f"{provider} answered a non-JSON body") from exc


def vt_verdict(stats: dict[str, Any]) -> tuple[str, int]:
    """Map VT ``last_analysis_stats`` to (verdict, confidence 0-100)."""
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    total = malicious + suspicious + harmless + undetected
    if malicious >= 3:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "suspicious"
    elif total > 0 and harmless > 0:
        verdict = "clean"
    else:
        verdict = "unknown"
    confidence = min(100, int(((malicious + suspicious) / total) * 100)) if total else 0
    return verdict, confidence


async def virustotal_lookup(api_key: str, bucket: str, value: str) -> dict[str, Any]:
    if bucket == "ip":
        endpoint = f"{VT_BASE}/ip_addresses/{quote(value, safe='')}"
    elif bucket == "domain":
        endpoint = f"{VT_BASE}/domains/{quote(value, safe='')}"
    elif bucket == "hash":
        endpoint = f"{VT_BASE}/files/{quote(value, safe='')}"
    elif bucket == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        endpoint = f"{VT_BASE}/urls/{url_id}"
    else:
        raise ProviderError(f"virustotal does not support type '{bucket}'")
    resp = await guarded_request(
        "GET", endpoint, headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    if resp.status_code == 404:
        return {
            "name": "virustotal",
            "verdict": "unknown",
            "confidence": 0,
            "raw": {"not_found": True, "status": 404},
        }
    _raise_for_status("virustotal", resp)
    body = _json("virustotal", resp) or {}
    attributes = (body.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    verdict, confidence = vt_verdict(stats)
    return {
        "name": "virustotal",
        "verdict": verdict,
        "confidence": confidence,
        "raw": {
            "last_analysis_stats": stats,
            "reputation": attributes.get("reputation"),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "asn": attributes.get("asn"),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
        },
    }


async def abuseipdb_lookup(api_key: str, value: str) -> dict[str, Any]:
    resp = await guarded_request(
        "GET",
        ABUSEIPDB_CHECK,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": value, "maxAgeInDays": 90, "verbose": "true"},
    )
    _raise_for_status("abuseipdb", resp)
    data = (_json("abuseipdb", resp) or {}).get("data") or {}
    score = int(data.get("abuseConfidenceScore") or 0)
    if score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    elif score > 0:
        verdict = "low_risk"
    else:
        verdict = "clean"
    return {
        "name": "abuseipdb",
        "verdict": verdict,
        "confidence": score,
        "raw": {
            "abuse_confidence_score": score,
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_public": data.get("isPublic"),
            "is_whitelisted": data.get("isWhitelisted"),
            "last_reported_at": data.get("lastReportedAt"),
        },
    }


def _otx_section(bucket: str, value: str) -> str:
    if bucket == "ip":
        try:
            return "IPv6" if ipaddress.ip_address(value).version == 6 else "IPv4"
        except ValueError as exc:
            raise ProviderError(f"otx: '{value}' is not an IP address") from exc
    return {"domain": "domain", "url": "url", "hash": "file"}[bucket]


def otx_verdict(pulse_count: int, validation: list[Any]) -> tuple[str, int]:
    """Map OTX pulse membership to (verdict, confidence).

    OTX ``validation`` entries mark an indicator as known-good (for example an
    allow-list membership): reported as ``clean``. Otherwise the verdict is
    derived from how many community pulses reference the indicator: none is
    ``unknown`` (absence is not evidence of being clean), one or two is
    ``suspicious``, three or more is ``malicious``. Confidence is 20 per
    pulse, capped at 100. ``raw.pulse_count`` carries the basis.
    """
    if validation:
        return "clean", 0
    if pulse_count <= 0:
        return "unknown", 0
    verdict = "malicious" if pulse_count >= 3 else "suspicious"
    return verdict, min(100, pulse_count * 20)


async def otx_lookup(api_key: str, bucket: str, value: str) -> dict[str, Any]:
    section = _otx_section(bucket, value)
    resp = await guarded_request(
        "GET",
        f"{OTX_BASE}/indicators/{section}/{quote(value, safe='')}/general",
        headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
    )
    if resp.status_code == 404:
        return {"name": "otx", "verdict": "unknown", "confidence": 0, "raw": {"not_found": True, "status": 404}}
    _raise_for_status("otx", resp)
    body = _json("otx", resp) or {}
    pulse_info = body.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    pulse_count = int(pulse_info.get("count") or len(pulses))
    validation = body.get("validation") or []
    verdict, confidence = otx_verdict(pulse_count, validation)
    return {
        "name": "otx",
        "verdict": verdict,
        "confidence": confidence,
        "raw": {
            "pulse_count": pulse_count,
            "pulses": [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "tags": p.get("tags", []),
                    "modified": p.get("modified"),
                    "adversary": p.get("adversary"),
                }
                for p in pulses[:10]
            ],
            "validation": validation,
            "reputation": body.get("reputation"),
            "country": body.get("country_name"),
            "asn": body.get("asn"),
        },
    }


async def _call(provider: str, api_key: str, bucket: str, value: str) -> dict[str, Any]:
    if provider == "virustotal":
        return await virustotal_lookup(api_key, bucket, value)
    if provider == "abuseipdb":
        return await abuseipdb_lookup(api_key, value)
    if provider == "otx":
        return await otx_lookup(api_key, bucket, value)
    raise ProviderError(f"unknown provider {provider}")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


async def enrich_value(
    db: AsyncSession,
    organization_id: Optional[str],
    bucket: str,
    value: str,
    *,
    use_cache: bool = True,
    platform_keys: Optional[dict[str, Optional[str]]] = None,
) -> list[ProviderOutcome]:
    """Run every provider that applies to ``bucket`` for ``value``.

    Always returns one outcome per provider in ``PROVIDERS``: providers that
    do not cover the type report ``unsupported_type``.
    """
    resolution = await resolve_provider_keys(db, organization_id, platform_keys=platform_keys)
    outcomes: dict[str, ProviderOutcome] = {}
    pending: list[tuple[str, ProviderKey]] = []

    for provider in PROVIDERS:
        if bucket not in PROVIDER_TYPES[provider]:
            outcomes[provider] = ProviderOutcome(
                provider, "unsupported_type", detail=f"{provider} does not look up '{bucket}' indicators",
            )
            continue
        key = resolution.keys.get(provider)
        if key is None:
            if provider in resolution.unreadable:
                outcomes[provider] = ProviderOutcome(
                    provider,
                    "credentials_unreadable",
                    error=f"installed {provider} credentials cannot be read ({resolution.unreadable[provider]})",
                )
            else:
                outcomes[provider] = ProviderOutcome(
                    provider,
                    "not_configured",
                    detail=(
                        f"no {provider} API key: install the integration, add the key under "
                        f"Settings > Integrations, or set {ENV_NAMES[provider]} on the platform"
                    ),
                )
            continue
        cache_key = _cache_key(organization_id, provider, bucket, value)
        cached = cache_get(cache_key) if use_cache else None
        if cached is not None:
            outcomes[provider] = ProviderOutcome(provider, "ok", key.source, True, cached)
            continue
        pending.append((provider, key))

    if pending:
        results = await asyncio.gather(
            *(_call(p, k.api_key, bucket, value) for p, k in pending), return_exceptions=True,
        )
        for (provider, key), result in zip(pending, results, strict=True):
            if isinstance(result, BaseException):
                if isinstance(result, (ProviderError, IntelOutboundRefused)):
                    message = str(result)
                elif isinstance(result, httpx.TimeoutException):
                    message = f"{provider} timed out"
                elif isinstance(result, httpx.HTTPError):
                    message = f"{provider} unreachable: {type(result).__name__}: {result}"
                elif isinstance(result, Exception):
                    message = f"{provider} failed: {type(result).__name__}: {result}"
                else:
                    raise result
                logger.warning(
                    "intel_provider_lookup_failed",
                    provider=provider,
                    organization_id=organization_id,
                    error=message[:300],
                )
                outcomes[provider] = ProviderOutcome(provider, "error", key.source, error=message[:500])
                continue
            cache_set(_cache_key(organization_id, provider, bucket, value), result)
            outcomes[provider] = ProviderOutcome(provider, "ok", key.source, False, result)

    return [outcomes[p] for p in PROVIDERS]


def overall_status(outcomes: list[ProviderOutcome]) -> str:
    """One word for a set of outcomes (``external_enrichment`` on the lookup).

    ``ok`` when at least one provider answered; ``enrichment_failed`` when
    every keyed provider failed; ``integration_credentials_unreadable`` when
    nothing ran because installed credentials cannot be opened;
    ``not_configured`` when no applicable provider has a key;
    ``unsupported_indicator_type`` when no provider covers the type.
    """
    applicable = [o for o in outcomes if o.status != "unsupported_type"]
    if not applicable:
        return "unsupported_indicator_type"
    if any(o.status == "ok" for o in applicable):
        return "ok"
    if any(o.status == "error" for o in applicable):
        return "enrichment_failed"
    if any(o.status == "credentials_unreadable" for o in applicable):
        return "integration_credentials_unreadable"
    return "not_configured"
