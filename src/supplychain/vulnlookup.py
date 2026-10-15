"""Component vulnerability lookups against OSV and NVD (wave 4).

``lookup_components`` resolves stored SoftwareComponent rows of one
organisation against:

- OSV (always): ``POST https://api.osv.dev/v1/querybatch`` with a purl or
  (ecosystem, name, version) per component, then ``GET /v1/vulns/{id}`` for
  each advisory's details (severity, aliases, fixed versions);
- NVD (only when ``NVD_API_KEY`` is set and the component has a CPE):
  ``GET https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=...``.

Every request goes through ``PinnedTransport`` (resolve once, refuse internal
addresses, pin the vetted IP). Answers are cached per organisation in
``supplychain_vuln_cache`` (``CACHE_TTL``) and each provider's last outcome is
kept in ``supplychain_provider_status``. Results are written as
``known_vulnerability`` SupplyChainRisk rows deduplicated on
(component, advisory), and the component's ``known_vulnerabilities_count``,
``risk_score`` (highest CVSS base score, 0-10) and ``last_scanned`` are set.
A component whose lookup failed keeps ``last_scanned`` unset, so it reads
``not_scanned`` rather than "0 vulnerabilities".
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import quote

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.integrations.netguard import PinnedTransport
from src.supplychain.models import (
    SBOM,
    SBOMComponent,
    SoftwareComponent,
    SupplyChainProviderStatus,
    SupplyChainRisk,
    SupplyChainVulnCache,
)

logger = get_logger(__name__)

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HTTP_TIMEOUT = 30.0
CACHE_TTL = timedelta(hours=24)
OSV_BATCH_SIZE = 500
MAX_COMPONENTS_PER_LOOKUP = 2_000
MAX_ADVISORY_FETCHES = 300
MAX_NVD_REQUESTS = 40
MAX_ADVISORIES_PER_COMPONENT = 200

#: SoftwareComponent.package_type (or purl type) -> OSV ecosystem.
OSV_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "cargo": "crates.io",
    "go_module": "Go",
    "golang": "Go",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
}


def _inner_transport() -> Optional[httpx.AsyncBaseTransport]:
    """Inner transport under PinnedTransport (None = default). Tests replace it."""
    return None


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=HTTP_TIMEOUT,
        follow_redirects=False,
        transport=PinnedTransport(inner=_inner_transport()),
        headers={"Accept": "application/json", "User-Agent": "PySOAR-supplychain"},
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _naive_utc() -> datetime:
    return datetime.utcnow()


def _key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# CVSS v3.x base score (FIRST specification, section 7.1)
# ---------------------------------------------------------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value: float) -> float:
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """Base score of a ``CVSS:3.x/...`` vector, or None when it is not one."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = metrics["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[metrics["PR"]]
        iss = 1 - (1 - _W["C"][metrics["C"]]) * (1 - _W["I"][metrics["I"]]) * (1 - _W["A"][metrics["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploitability = 8.22 * _W["AV"][metrics["AV"]] * _W["AC"][metrics["AC"]] * pr * _W["UI"][metrics["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(raw, 10.0))


def severity_from_score(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


_LABELS = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


# ---------------------------------------------------------------------------
# Query construction and advisory normalisation
# ---------------------------------------------------------------------------


def osv_query(component: Any) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """(OSV query, None) or (None, reason it cannot be looked up)."""
    version = str(component.version or "").strip()
    if not version or version.lower() in ("unknown", "noassertion", "*", "latest"):
        return None, "component has no concrete version"
    purl = (component.purl or "").strip()
    if purl.startswith("pkg:"):
        base = purl.split("?", 1)[0].split("#", 1)[0]
        if "@" not in base.rsplit("/", 1)[-1]:
            return {"package": {"purl": base}, "version": version}, None
        return {"package": {"purl": base}}, None
    ecosystem = OSV_ECOSYSTEMS.get(str(component.package_type or "").lower())
    if not ecosystem:
        return None, f"no purl and package type {component.package_type!r} has no OSV ecosystem"
    return {"package": {"name": component.name, "ecosystem": ecosystem}, "version": version}, None


def normalise_osv(doc: dict[str, Any]) -> dict[str, Any]:
    """The fields PySOAR stores from one OSV advisory."""
    score: Optional[float] = None
    vector: Optional[str] = None
    for sev in doc.get("severity") or []:
        if isinstance(sev, dict) and str(sev.get("type", "")).startswith("CVSS_V3"):
            s = cvss3_base_score(str(sev.get("score")))
            if s is not None and (score is None or s > score):
                score, vector = s, str(sev.get("score"))
    label = _LABELS.get(str((doc.get("database_specific") or {}).get("severity", "")).lower())
    severity = severity_from_score(score) or label or "unknown"
    fixed: list[str] = []
    for aff in doc.get("affected") or []:
        for rng in (aff or {}).get("ranges") or []:
            for event in (rng or {}).get("events") or []:
                if isinstance(event, dict) and event.get("fixed") and event["fixed"] not in fixed:
                    fixed.append(str(event["fixed"]))
    aliases = [str(a) for a in doc.get("aliases") or []]
    cves = sorted({a for a in [*aliases, str(doc.get("id", ""))] if a.startswith("CVE-")})
    return {
        "id": str(doc.get("id")),
        "source": "osv",
        "summary": str(doc.get("summary") or doc.get("details") or "")[:1000],
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "cves": cves,
        "aliases": aliases,
        "fixed_versions": fixed[:20],
        "published": doc.get("published"),
        "modified": doc.get("modified"),
        "withdrawn": doc.get("withdrawn"),
        "url": f"https://osv.dev/vulnerability/{doc.get('id')}",
    }


def normalise_nvd(item: dict[str, Any]) -> Optional[dict[str, Any]]:
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
    score: Optional[float] = None
    vector: Optional[str] = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key) or []:
            data = (m or {}).get("cvssData") or {}
            s = data.get("baseScore")
            if isinstance(s, (int, float)) and (score is None or s > score):
                score, vector = float(s), data.get("vectorString")
    desc = next((d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    return {
        "id": str(cve_id),
        "source": "nvd",
        "summary": str(desc or "")[:1000],
        "severity": severity_from_score(score) or "unknown",
        "cvss_score": score,
        "cvss_vector": vector,
        "cves": [str(cve_id)],
        "aliases": [],
        "fixed_versions": [],
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "withdrawn": None,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


# ---------------------------------------------------------------------------
# Cache and provider status
# ---------------------------------------------------------------------------


async def _cache_get(db: AsyncSession, org_id: str, provider: str, keys: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    cutoff = _now() - CACHE_TTL
    for i in range(0, len(keys), 500):
        rows = (await db.execute(
            select(SupplyChainVulnCache.query_key, SupplyChainVulnCache.payload, SupplyChainVulnCache.fetched_at)
            .where(
                SupplyChainVulnCache.organization_id == org_id,
                SupplyChainVulnCache.provider == provider,
                SupplyChainVulnCache.query_key.in_(keys[i:i + 500]),
            ),
        )).all()
        for key, payload, fetched_at in rows:
            if fetched_at is not None and fetched_at.tzinfo is None:
                fetched_at = fetched_at.replace(tzinfo=timezone.utc)
            if fetched_at is None or fetched_at < cutoff:
                continue
            try:
                out[key] = json.loads(payload) if payload else None
            except json.JSONDecodeError:
                continue
    return out


async def _cache_put(db: AsyncSession, org_id: str, provider: str, key: str, query: str, payload: Any) -> None:
    row = (await db.execute(
        select(SupplyChainVulnCache).where(
            SupplyChainVulnCache.organization_id == org_id,
            SupplyChainVulnCache.provider == provider,
            SupplyChainVulnCache.query_key == key,
        ),
    )).scalar_one_or_none()
    if row is None:
        row = SupplyChainVulnCache(organization_id=org_id, provider=provider, query_key=key, fetched_at=_now())
        db.add(row)
    row.query = query[:4000]
    row.payload = json.dumps(payload, default=str)
    row.fetched_at = _now()


async def record_provider(
    db: AsyncSession, org_id: str, provider: str, status: str, error: Optional[str] = None, requests: int = 0,
) -> None:
    row = (await db.execute(
        select(SupplyChainProviderStatus).where(
            SupplyChainProviderStatus.organization_id == org_id,
            SupplyChainProviderStatus.provider == provider,
        ),
    )).scalar_one_or_none()
    if row is None:
        row = SupplyChainProviderStatus(organization_id=org_id, provider=provider, status=status, requests_total=0)
        db.add(row)
    row.status = status
    row.requests_total = (row.requests_total or 0) + requests
    if status == "ok":
        row.last_success_at = _now()
    elif status == "error":
        row.last_error_at = _now()
        row.last_error = (error or "")[:2000]


async def provider_status(db: AsyncSession, org_id: str) -> dict[str, Any]:
    """Status of OSV and NVD for ``org_id`` (NVD ``not_configured`` without a key)."""
    rows = {
        r.provider: r
        for r in (await db.execute(
            select(SupplyChainProviderStatus).where(SupplyChainProviderStatus.organization_id == org_id),
        )).scalars()
    }
    out: dict[str, Any] = {}
    for provider in ("osv", "nvd"):
        row = rows.get(provider)
        configured = provider == "osv" or bool(os.getenv("NVD_API_KEY"))
        out[provider] = {
            "configured": configured,
            "status": (row.status if row else "never_used") if configured else "not_configured",
            "last_success_at": row.last_success_at if row else None,
            "last_error_at": row.last_error_at if row else None,
            "last_error": row.last_error if row else None,
            "requests_total": row.requests_total if row else 0,
            "reason": None if configured else "NVD_API_KEY is not set; NVD lookups are skipped",
        }
    cached = (await db.execute(
        select(SupplyChainVulnCache.provider, func.count(SupplyChainVulnCache.id))
        .where(SupplyChainVulnCache.organization_id == org_id)
        .group_by(SupplyChainVulnCache.provider),
    )).all()
    out["cache_entries"] = {p: int(c) for p, c in cached}
    return out


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


@dataclass
class LookupSummary:
    components_checked: int = 0
    components_skipped: list[dict[str, str]] = field(default_factory=list)
    components_failed: int = 0
    advisories_found: int = 0
    risks_new: int = 0
    risks_updated: int = 0
    cache_hits: int = 0
    truncated: bool = False
    providers: dict[str, dict[str, Any]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "components_checked": self.components_checked,
            "components_skipped": self.components_skipped[:200],
            "components_skipped_count": len(self.components_skipped),
            "components_failed": self.components_failed,
            "advisories_found": self.advisories_found,
            "risks_new": self.risks_new,
            "risks_updated": self.risks_updated,
            "cache_hits": self.cache_hits,
            "truncated": self.truncated,
            "providers": self.providers,
        }


async def _osv_batch(client: httpx.AsyncClient, queries: list[dict[str, Any]]) -> list[list[str]]:
    resp = await client.post(OSV_QUERYBATCH_URL, json={"queries": queries})
    if resp.status_code != 200:
        raise httpx.HTTPStatusError(f"OSV querybatch HTTP {resp.status_code}", request=resp.request, response=resp)
    results = (resp.json() or {}).get("results")
    if not isinstance(results, list) or len(results) != len(queries):
        raise ValueError("OSV querybatch answer does not match the queries")
    out: list[list[str]] = []
    for r in results:
        out.append([str(v["id"]) for v in (r or {}).get("vulns") or [] if isinstance(v, dict) and v.get("id")])
    return out


async def lookup_components(
    db: AsyncSession, org_id: str, components: list[SoftwareComponent], *, use_cache: bool = True,
) -> dict[str, Any]:
    """Look ``components`` (all of ``org_id``) up in OSV / NVD and store the results."""
    summary = LookupSummary()
    components = [c for c in components if c.organization_id == org_id]
    if len(components) > MAX_COMPONENTS_PER_LOOKUP:
        components = components[:MAX_COMPONENTS_PER_LOOKUP]
        summary.truncated = True

    queries: dict[str, tuple[dict[str, Any], list[SoftwareComponent]]] = {}
    for comp in components:
        query, reason = osv_query(comp)
        if query is None:
            summary.components_skipped.append({"component_id": comp.id, "name": comp.name, "reason": reason or ""})
            continue
        key = _key(json.dumps(query, sort_keys=True))
        queries.setdefault(key, (query, []))[1].append(comp)

    # 1) OSV querybatch (cached per org per query)
    ids_by_query: dict[str, list[str]] = await _cache_get(db, org_id, "osv", list(queries)) if use_cache else {}
    summary.cache_hits += len(ids_by_query)
    missing = [k for k in queries if k not in ids_by_query]
    osv_error: Optional[str] = None
    osv_requests = 0
    detail_fetches = 0
    advisories: dict[str, dict[str, Any]] = {}
    nvd_by_comp: dict[str, list[dict[str, Any]]] = {}
    nvd_error: Optional[str] = None
    nvd_requests = 0
    nvd_key = os.getenv("NVD_API_KEY")

    async with _client() as client:
        for i in range(0, len(missing), OSV_BATCH_SIZE):
            chunk = missing[i:i + OSV_BATCH_SIZE]
            try:
                osv_requests += 1
                answer = await _osv_batch(client, [queries[k][0] for k in chunk])
            except (httpx.HTTPError, ValueError) as exc:
                osv_error = f"{type(exc).__name__}: {exc}"[:500]
                break
            for k, ids in zip(chunk, answer, strict=True):
                ids_by_query[k] = ids
                await _cache_put(db, org_id, "osv", k, json.dumps(queries[k][0]), ids)

        # 2) advisory details (cached per org per advisory id)
        wanted = sorted({i for ids in ids_by_query.values() for i in (ids or [])})
        cached_docs = await _cache_get(db, org_id, "osv_vuln", [_key(i) for i in wanted]) if use_cache else {}
        for adv_id in wanted:
            doc = cached_docs.get(_key(adv_id))
            if doc is not None:
                summary.cache_hits += 1
                advisories[adv_id] = doc
                continue
            if osv_error:
                continue
            if detail_fetches >= MAX_ADVISORY_FETCHES:
                summary.truncated = True
                continue
            try:
                osv_requests += 1
                detail_fetches += 1
                resp = await client.get(OSV_VULN_URL.format(id=quote(adv_id, safe="")))
                if resp.status_code != 200:
                    raise httpx.HTTPStatusError(f"OSV vuln HTTP {resp.status_code}", request=resp.request, response=resp)
                advisories[adv_id] = normalise_osv(resp.json())
            except (httpx.HTTPError, ValueError) as exc:
                osv_error = f"{type(exc).__name__}: {exc}"[:500]
                continue
            await _cache_put(db, org_id, "osv_vuln", _key(adv_id), adv_id, advisories[adv_id])

        # 3) NVD by CPE, only with an API key
        if nvd_key:
            cpe_comps = [c for c in components if c.cpe]
            cached_nvd = await _cache_get(db, org_id, "nvd", [_key(c.cpe) for c in cpe_comps]) if use_cache else {}
            for comp in cpe_comps:
                ck = _key(comp.cpe)
                if ck in cached_nvd:
                    summary.cache_hits += 1
                    nvd_by_comp[comp.id] = cached_nvd[ck] or []
                    continue
                if nvd_requests >= MAX_NVD_REQUESTS or nvd_error:
                    summary.truncated = summary.truncated or nvd_requests >= MAX_NVD_REQUESTS
                    continue
                try:
                    nvd_requests += 1
                    resp = await client.get(NVD_CVES_URL, params={"cpeName": comp.cpe}, headers={"apiKey": nvd_key})
                    if resp.status_code != 200:
                        raise httpx.HTTPStatusError(f"NVD HTTP {resp.status_code}", request=resp.request, response=resp)
                    items = [normalise_nvd(v) for v in (resp.json() or {}).get("vulnerabilities") or []]
                except (httpx.HTTPError, ValueError) as exc:
                    nvd_error = f"{type(exc).__name__}: {exc}"[:500]
                    continue
                nvd_by_comp[comp.id] = [i for i in items if i]
                await _cache_put(db, org_id, "nvd", ck, comp.cpe, nvd_by_comp[comp.id])

    await record_provider(db, org_id, "osv", "error" if osv_error else "ok", osv_error, osv_requests)
    if nvd_key:
        await record_provider(db, org_id, "nvd", "error" if nvd_error else "ok", nvd_error, nvd_requests)
    summary.providers = {
        "osv": {"status": "error" if osv_error else "ok", "error": osv_error, "requests": osv_requests},
        "nvd": (
            {"status": "error" if nvd_error else "ok", "error": nvd_error, "requests": nvd_requests}
            if nvd_key else {"status": "not_configured", "reason": "NVD_API_KEY is not set"}
        ),
    }

    # 4) write risks per component
    now_naive = _naive_utc()
    touched: list[str] = []
    for key, (_query, comps) in queries.items():
        ids = ids_by_query.get(key)
        for comp in comps:
            if ids is None:
                summary.components_failed += 1  # OSV not reached: stays not_scanned
                continue
            found: list[dict[str, Any]] = []
            complete = True
            for adv_id in ids[:MAX_ADVISORIES_PER_COMPONENT]:
                adv = advisories.get(adv_id)
                if adv is None:
                    complete = False
                    continue
                if not adv.get("withdrawn"):
                    found.append(adv)
            known_cves = {c for a in found for c in a.get("cves", [])}
            for adv in nvd_by_comp.get(comp.id, []):
                if adv["id"] not in known_cves:
                    found.append(adv)
            new, updated = await _store_risks(db, org_id, comp, found, now_naive)
            summary.risks_new += new
            summary.risks_updated += updated
            summary.advisories_found += len(found)
            if not complete:
                # Advisory details missing (cap or provider error): do not
                # claim a finished scan for this component.
                summary.components_failed += 1
                continue
            scores = [a["cvss_score"] for a in found if a.get("cvss_score") is not None]
            comp.known_vulnerabilities_count = len(found)
            comp.risk_score = float(max(scores)) if scores else 0.0
            comp.last_scanned = now_naive
            summary.components_checked += 1
            touched.append(comp.id)
    if touched:
        await _refresh_sbom_scores(db, org_id, touched)
    await db.flush()
    logger.info("supplychain_lookup", org_id=org_id, **{k: v for k, v in summary.as_dict().items()
                                                         if k in ("components_checked", "risks_new", "truncated")})
    return summary.as_dict()


async def _store_risks(
    db: AsyncSession, org_id: str, comp: SoftwareComponent, found: list[dict[str, Any]], now_naive: datetime,
) -> tuple[int, int]:
    existing = {
        r.advisory_id: r
        for r in (await db.execute(
            select(SupplyChainRisk).where(
                SupplyChainRisk.organization_id == org_id,
                SupplyChainRisk.component_id == comp.id,
                SupplyChainRisk.risk_type == "known_vulnerability",
                SupplyChainRisk.advisory_id.is_not(None),
            ),
        )).scalars()
    }
    new = updated = 0
    for adv in found:
        row = existing.get(adv["id"])
        evidence = {
            "source": adv["source"], "advisory_id": adv["id"], "url": adv["url"],
            "cvss_score": adv.get("cvss_score"), "cvss_vector": adv.get("cvss_vector"),
            "fixed_versions": adv.get("fixed_versions"), "aliases": adv.get("aliases"),
            "published": adv.get("published"), "modified": adv.get("modified"),
            "component": f"{comp.name}@{comp.version}",
        }
        fixed = adv.get("fixed_versions") or []
        if row is None:
            row = SupplyChainRisk(
                organization_id=org_id, component_id=comp.id, risk_type="known_vulnerability",
                advisory_id=adv["id"][:100], source=adv["source"], status="open",
                detected_date=now_naive, severity=adv["severity"], description="",
            )
            db.add(row)
            existing[adv["id"]] = row
            new += 1
        else:
            updated += 1
        row.severity = adv["severity"]
        row.description = f"{adv['id']}: {adv.get('summary') or 'no summary'}"[:4000]
        row.cve_ids = json.dumps(adv.get("cves") or [])
        row.evidence = json.dumps(evidence, default=str)
        row.remediation_advice = (
            f"Upgrade {comp.name} to a fixed version: {', '.join(fixed[:5])}" if fixed else None
        )
    return new, updated


async def _refresh_sbom_scores(db: AsyncSession, org_id: str, component_ids: list[str]) -> None:
    """SBOM vulnerability_risk_score = highest CVSS among its looked-up components."""
    sbom_ids: set[str] = set()
    for i in range(0, len(component_ids), 500):
        sbom_ids.update(r[0] for r in (await db.execute(
            select(SBOMComponent.sbom_id).where(
                SBOMComponent.organization_id == org_id,
                SBOMComponent.component_id.in_(component_ids[i:i + 500]),
            ),
        )).all())
    await db.flush()
    for sbom_id in sbom_ids:
        top = (await db.execute(
            select(func.max(SoftwareComponent.risk_score))
            .join(SBOMComponent, SBOMComponent.component_id == SoftwareComponent.id)
            .where(
                SBOMComponent.sbom_id == sbom_id,
                SoftwareComponent.organization_id == org_id,
                SoftwareComponent.last_scanned.is_not(None),
            ),
        )).scalar()
        sbom = (await db.execute(
            select(SBOM).where(SBOM.id == sbom_id, SBOM.organization_id == org_id),
        )).scalar_one_or_none()
        if sbom is not None:
            sbom.vulnerability_risk_score = float(top or 0.0)
