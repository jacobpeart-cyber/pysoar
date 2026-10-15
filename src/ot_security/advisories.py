"""CISA ICS advisories: pinned fetch, platform-wide cache, vendor/product matching.

Replaces the two-entry "simulated" CVE dictionary the OT assessor used to
carry (one entry was a Rocket.Chat CVE labelled as a Siemens PLC, and an empty
vendor matched every entry).

* Source: CISA's public ICS advisories RSS feed (``OT_ICS_ADVISORY_FEED_URL``
  overrides the URL). Fetched through ``netguard.PinnedTransport`` (resolve
  once, refuse internal addresses, pin the vetted IP), no redirects, a size
  cap, and a document with a DOCTYPE / ENTITY declaration is refused before it
  is parsed.
* Cache: ``ot_ics_advisories`` (one row per advisory, shared by every tenant:
  the feed is public and identical for all) and ``ot_advisory_feed_status``
  (last attempt / success / error). A refresh inside ``CACHE_TTL`` is served
  from the cache unless forced; the Celery beat task refreshes it daily.
* Matching: an advisory applies to an asset only when the asset has both a
  vendor and a model, the advisory's vendor matches the asset's vendor and the
  asset's model appears in the advisory's product list or title (normalised,
  word-bounded). The feed does not carry machine-readable affected-version
  ranges, so firmware versions are not evaluated: every match says
  ``affected_versions_evaluated: false`` and links the advisory to review.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET  # noqa: S405 (DOCTYPE/ENTITY refused before parsing)
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from typing import Any, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.integrations.netguard import PinnedTransport
from src.ot_security.models import OTAdvisoryFeedStatus, OTICSAdvisory

logger = get_logger(__name__)

FEED_KEY = "cisa_ics"
DEFAULT_FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
CACHE_TTL = timedelta(hours=6)
HTTP_TIMEOUT = 30.0
MAX_FEED_BYTES = 10 * 1024 * 1024
MAX_ADVISORIES = 5000
MIN_MODEL_LENGTH = 3

_ADVISORY_ID = re.compile(r"ICS[AM]A?-\d{2}-\d{3}-\d{2}[A-Z]?", re.IGNORECASE)
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CVSS = re.compile(r"CVSS\s*v\d(?:\.\d)?\s*(?:base\s*score\s*(?:of\s*)?)?:?\s*(\d{1,2}(?:\.\d)?)", re.IGNORECASE)
_TAG = re.compile(r"<[^>]+>")
_FIELD_STOP = r"(?=\s*(?:Vendor|Equipment|Vulnerabilit(?:y|ies)|ATTENTION|CVSS|Product|$)\s*:?)"
_VENDOR = re.compile(r"Vendor\s*:\s*(.+?)" + _FIELD_STOP, re.IGNORECASE | re.DOTALL)
_EQUIPMENT = re.compile(r"Equipment\s*:\s*(.+?)" + _FIELD_STOP, re.IGNORECASE | re.DOTALL)


class AdvisoryFeedUnavailable(RuntimeError):
    """The advisory feed could not be fetched or parsed."""


def feed_url() -> str:
    return os.environ.get("OT_ICS_ADVISORY_FEED_URL") or DEFAULT_FEED_URL


def _inner_transport() -> Optional[httpx.AsyncBaseTransport]:
    """Inner transport under PinnedTransport (None = default). Tests replace it."""
    return None


def normalize(text: Optional[str]) -> str:
    """Lowercase, non-alphanumerics to single spaces (``S7-1200`` -> ``s7 1200``)."""
    return " ".join(re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).split())


def _contains_words(haystack: str, needle: str) -> bool:
    if not needle or not haystack:
        return False
    return f" {needle} " in f" {haystack} "


def _text(element: Optional[ET.Element]) -> str:
    return (element.text or "").strip() if element is not None else ""


def _plain(html_text: str) -> str:
    return " ".join(unescape(_TAG.sub(" ", html_text or "")).split())


def _split_products(raw: str) -> list[str]:
    parts = re.split(r",|;|\band\b", raw)
    out: list[str] = []
    for part in parts:
        value = part.strip(" .")
        if value and value not in out:
            out.append(value[:255])
    return out[:50]


def parse_feed(body: bytes) -> list[dict[str, Any]]:
    """Parse the CISA ICS advisories RSS document into advisory dicts.

    Raises AdvisoryFeedUnavailable for a document that is not an RSS feed.
    Items without an ICS advisory id are skipped (nothing is invented for them).
    """
    head = body[:4096].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in body.upper():
        raise AdvisoryFeedUnavailable("feed declares a DOCTYPE / ENTITY; refused")
    try:
        root = ET.fromstring(body)  # noqa: S314 (entity declarations refused above)
    except ET.ParseError as exc:
        raise AdvisoryFeedUnavailable(f"feed is not XML: {exc}") from exc
    channel = root.find("channel")
    if root.tag != "rss" or channel is None:
        raise AdvisoryFeedUnavailable("feed is not an RSS document")

    advisories: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in channel.findall("item")[:MAX_ADVISORIES]:
        title = _plain(_text(item.find("title")))
        link = _text(item.find("link"))
        guid = _text(item.find("guid"))
        description = _plain(_text(item.find("description")))
        match = _ADVISORY_ID.search(" ".join((link, guid, title)))
        if not match:
            continue
        advisory_id = match.group(0).upper()
        if advisory_id in seen:
            continue
        seen.add(advisory_id)

        vendor_match = _VENDOR.search(description)
        vendor = vendor_match.group(1).strip(" .")[:255] if vendor_match else None
        equipment = _EQUIPMENT.search(description)
        products = _split_products(equipment.group(1)) if equipment else []
        cves = sorted({c.upper() for c in _CVE.findall(" ".join((title, description)))})
        scores = [float(s) for s in _CVSS.findall(description) if 0 <= float(s) <= 10]
        published = None
        pub = _text(item.find("pubDate"))
        if pub:
            try:
                published = parsedate_to_datetime(pub)
                if published.tzinfo is None:
                    published = published.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                published = None
        advisories.append({
            "advisory_id": advisory_id,
            "title": title[:500] or advisory_id,
            "vendor": vendor or None,
            "products": products,
            "cve_ids": cves,
            "cvss_score": max(scores) if scores else None,
            "url": link[:500] or None,
            "published_at": published,
        })
    return advisories


async def _status_row(db: AsyncSession) -> OTAdvisoryFeedStatus:
    row = (await db.execute(
        select(OTAdvisoryFeedStatus).where(OTAdvisoryFeedStatus.feed == FEED_KEY),
    )).scalar_one_or_none()
    if row is None:
        row = OTAdvisoryFeedStatus(feed=FEED_KEY, url=feed_url(), entries=0)
        db.add(row)
        await db.flush()
    return row


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


async def fetch_feed(url: Optional[str] = None) -> bytes:
    """GET the feed through the pinned transport (no redirects, size-capped)."""
    target = url or feed_url()
    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT,
            follow_redirects=False,
            transport=PinnedTransport(inner=_inner_transport()),
            headers={"Accept": "application/rss+xml, application/xml", "User-Agent": "PySOAR-ot-advisories"},
        ) as client:
            async with client.stream("GET", target) as resp:
                if resp.status_code != 200:
                    raise AdvisoryFeedUnavailable(f"feed returned HTTP {resp.status_code}")
                chunks: list[bytes] = []
                size = 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_FEED_BYTES:
                        raise AdvisoryFeedUnavailable(f"feed larger than {MAX_FEED_BYTES} bytes")
                    chunks.append(chunk)
    except httpx.HTTPError as exc:
        raise AdvisoryFeedUnavailable(f"feed fetch failed: {exc}") from exc
    return b"".join(chunks)


async def refresh_ics_advisories(db: AsyncSession, *, force: bool = False) -> dict[str, Any]:
    """Refresh the advisory cache unless it is fresh (``CACHE_TTL``) and not forced.

    Returns {status: cached|refreshed|unavailable, entries, new, error?}.
    A failed fetch keeps the previous cache and records ``last_error``.
    """
    status = await _status_row(db)
    now = datetime.now(timezone.utc)
    last_success = _aware(status.last_success_at)
    if not force and last_success is not None and now - last_success < CACHE_TTL:
        return {"status": "cached", "entries": status.entries, "new": 0,
                "last_success_at": last_success.isoformat()}

    status.url = feed_url()
    status.last_attempt_at = now
    try:
        advisories = parse_feed(await fetch_feed(status.url))
    except AdvisoryFeedUnavailable as exc:
        status.last_error = str(exc)[:2000]
        await db.flush()
        logger.warning("ot_advisory_feed_unavailable", error=str(exc))
        return {"status": "unavailable", "entries": status.entries, "new": 0, "error": str(exc)}

    existing = {
        row.advisory_id: row
        for row in (await db.execute(
            select(OTICSAdvisory).where(OTICSAdvisory.advisory_id.in_([a["advisory_id"] for a in advisories]))
        )).scalars().all()
    } if advisories else {}
    new = 0
    for adv in advisories:
        row = existing.get(adv["advisory_id"])
        if row is None:
            row = OTICSAdvisory(advisory_id=adv["advisory_id"], title=adv["title"])
            db.add(row)
            new += 1
        for key in ("title", "vendor", "products", "cve_ids", "cvss_score", "url", "published_at"):
            setattr(row, key, adv[key])
        row.fetched_at = now
    status.last_success_at = now
    status.last_error = None
    await db.flush()
    total = len((await db.execute(select(OTICSAdvisory.id))).all())
    status.entries = total
    await db.flush()
    logger.info("ot_advisory_feed_refreshed", parsed=len(advisories), new=new, total=total)
    return {"status": "refreshed", "entries": total, "new": new, "parsed": len(advisories)}


async def feed_state(db: AsyncSession) -> dict[str, Any]:
    """Feed status for API responses (``not_fetched`` until the first success)."""
    row = (await db.execute(
        select(OTAdvisoryFeedStatus).where(OTAdvisoryFeedStatus.feed == FEED_KEY),
    )).scalar_one_or_none()
    if row is None or row.last_success_at is None:
        return {
            "source": "CISA ICS advisories",
            "url": feed_url(),
            "status": "not_fetched",
            "entries": 0,
            "last_success_at": None,
            "last_error": row.last_error if row is not None else None,
        }
    return {
        "source": "CISA ICS advisories",
        "url": row.url,
        "status": "stale" if datetime.now(timezone.utc) - _aware(row.last_success_at) > CACHE_TTL * 8 else "current",
        "entries": row.entries,
        "last_success_at": _aware(row.last_success_at).isoformat(),
        "last_error": row.last_error,
    }


async def load_advisories(db: AsyncSession) -> list[OTICSAdvisory]:
    """Cached advisories that carry a vendor (the only ones that can match)."""
    return list((await db.execute(
        select(OTICSAdvisory)
        .where(OTICSAdvisory.vendor.is_not(None))
        .order_by(OTICSAdvisory.published_at.desc())
        .limit(MAX_ADVISORIES),
    )).scalars().all())


def _vendor_matches(asset_vendor: str, advisory_vendor: str) -> bool:
    a, b = normalize(asset_vendor), normalize(advisory_vendor)
    if not a or not b:
        return False
    return a == b or _contains_words(b, a) or _contains_words(a, b)


def match_asset(asset: Any, advisories: list[Any]) -> list[dict[str, Any]]:
    """Advisories that name this asset's vendor and model.

    ``asset`` is an OTAsset or its ``to_dict()``. An asset without a vendor or
    a model (or a model shorter than ``MIN_MODEL_LENGTH``) matches nothing.
    """

    def _get(name: str) -> Any:
        return asset.get(name) if isinstance(asset, dict) else getattr(asset, name, None)

    vendor = _get("vendor") or ""
    model = normalize(_get("model"))
    if not normalize(vendor) or len(model.replace(" ", "")) < MIN_MODEL_LENGTH:
        return []
    matches: list[dict[str, Any]] = []
    for adv in advisories:
        adv_vendor = adv.get("vendor") if isinstance(adv, dict) else adv.vendor
        if not adv_vendor or not _vendor_matches(vendor, adv_vendor):
            continue
        products = (adv.get("products") if isinstance(adv, dict) else adv.products) or []
        title = adv.get("title") if isinstance(adv, dict) else adv.title
        candidates = [normalize(p) for p in products] + [normalize(title)]
        if not any(_contains_words(c, model) or (len(c) >= MIN_MODEL_LENGTH and _contains_words(model, c))
                   for c in candidates if c):
            continue
        get = adv.get if isinstance(adv, dict) else (lambda k, _a=adv: getattr(_a, k, None))
        published = get("published_at")
        matches.append({
            "advisory_id": get("advisory_id"),
            "title": title,
            "url": get("url"),
            "vendor": adv_vendor,
            "products": products,
            "cve_ids": get("cve_ids") or [],
            "cvss_score": get("cvss_score"),
            "published_at": published.isoformat() if isinstance(published, datetime) else published,
            "match_basis": "vendor+model",
            "affected_versions_evaluated": False,
        })
    return matches
