"""IOC extraction and timeline reconstruction over a case's stored material.

Both functions read only what PySOAR actually holds for the case: the
``forensic_artifacts`` rows and the evidence bytes stored under the evidence
root. Results are persisted (``ForensicArtifact.ioc_extracted``, one
``evidence_ioc_scan`` artifact per scanned evidence file, ``forensic_timeline``
rows tagged with ``artifact_data.derived_from``) so re-running them updates
instead of duplicating.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.dfir.engine import ArtifactAnalyzer
from src.dfir.models import ForensicArtifact, ForensicEvidence, ForensicTimeline
from src.dfir.storage import EvidencePathRefusedError, read_prefix, resolve_tenant_evidence_path

logger = get_logger(__name__)

#: Artifact type of the per-evidence IOC scan record this module writes.
EVIDENCE_SCAN_ARTIFACT = "evidence_ioc_scan"
#: Bytes read from each stored evidence file per scan.
MAX_SCAN_BYTES_PER_FILE = 8 * 1024 * 1024
#: Evidence files / artifacts considered per request.
MAX_EVIDENCE_FILES = 200
MAX_ARTIFACTS = 2000
#: Timeline rows created per reconstruction request.
MAX_TIMELINE_EVENTS = 5000

IOC_KEYS = ("ipv4_addresses", "ipv6_addresses", "domains", "file_hashes", "email_addresses", "urls")
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{6,}")

TIMESTAMP_KEYS = (
    "timestamp", "event_time", "time", "datetime", "created", "modified", "accessed",
    "created_at", "modified_at", "accessed_at", "changed_at", "last_run", "start_time",
    "end_time", "first_seen", "last_seen", "logon_time", "execution_time",
)
RECORD_LIST_KEYS = ("records", "entries", "events", "rows")


def _empty_iocs() -> dict[str, set[str]]:
    return {k: set() for k in IOC_KEYS}


def _merge(into: dict[str, set[str]], iocs: dict[str, Any]) -> None:
    for key in IOC_KEYS:
        values = iocs.get(key) or []
        into[key].update(str(v) for v in values)


def _printable_strings(data: bytes) -> str:
    """``strings``-style extraction: printable ASCII runs of six or more bytes."""
    return "\n".join(m.decode("ascii") for m in _PRINTABLE_RUN_RE.findall(data))


@dataclass
class IOCScanResult:
    iocs: dict[str, list[str]]
    artifacts_scanned: int = 0
    evidence_files_scanned: int = 0
    evidence_files_truncated: int = 0
    evidence_skipped: list[dict[str, str]] = field(default_factory=list)
    scan_artifacts_written: int = 0

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.iocs.values())


async def scan_case_iocs(db: AsyncSession, *, case_id: str, org_id: str, root: str) -> IOCScanResult:
    analyzer = ArtifactAnalyzer()
    aggregated = _empty_iocs()
    now = datetime.now(timezone.utc).isoformat()

    artifacts = list(
        (
            await db.execute(
                select(ForensicArtifact)
                .where(
                    ForensicArtifact.case_id == case_id,
                    ForensicArtifact.organization_id == org_id,
                    ForensicArtifact.artifact_type != EVIDENCE_SCAN_ARTIFACT,
                )
                .order_by(ForensicArtifact.created_at.asc())
                .limit(MAX_ARTIFACTS),
            )
        ).scalars(),
    )
    for artifact in artifacts:
        found = analyzer.extract_iocs(artifact.artifact_data or {}, artifact.artifact_type)
        if found.get("status") != "success":
            continue
        iocs = found.get("iocs", {})
        _merge(aggregated, iocs)
        artifact.ioc_extracted = {**{k: list(iocs.get(k, [])) for k in IOC_KEYS}, "extracted_at": now}

    evidence_rows = list(
        (
            await db.execute(
                select(ForensicEvidence)
                .where(ForensicEvidence.case_id == case_id, ForensicEvidence.organization_id == org_id)
                .order_by(ForensicEvidence.created_at.asc())
                .limit(MAX_EVIDENCE_FILES),
            )
        ).scalars(),
    )
    existing_scans = {
        a.evidence_id: a
        for a in (
            await db.execute(
                select(ForensicArtifact).where(
                    ForensicArtifact.case_id == case_id,
                    ForensicArtifact.organization_id == org_id,
                    ForensicArtifact.artifact_type == EVIDENCE_SCAN_ARTIFACT,
                ),
            )
        ).scalars()
    }

    result = IOCScanResult(iocs={}, artifacts_scanned=len(artifacts))
    for ev in evidence_rows:
        loc = ev.storage_location or ""
        if not loc:
            result.evidence_skipped.append({"evidence_id": ev.id, "reason": "no bytes stored in PySOAR"})
            continue
        if "://" in loc:
            result.evidence_skipped.append({"evidence_id": ev.id, "reason": "remote object; bytes not held locally"})
            continue
        try:
            path = resolve_tenant_evidence_path(root, loc, org_id)
        except EvidencePathRefusedError as exc:
            logger.warning("dfir_evidence_path_refused", evidence_id=ev.id, organization_id=org_id, reason=exc.reason)
            result.evidence_skipped.append({"evidence_id": ev.id, "reason": exc.reason})
            continue
        try:
            data, truncated = read_prefix(path, MAX_SCAN_BYTES_PER_FILE)
        except OSError as exc:
            result.evidence_skipped.append({"evidence_id": ev.id, "reason": f"file unreadable: {exc.strerror or exc}"})
            continue
        found = analyzer.extract_iocs({"strings": _printable_strings(data)}, ev.evidence_type)
        if found.get("status") != "success":
            result.evidence_skipped.append({"evidence_id": ev.id, "reason": found.get("message", "extraction failed")})
            continue
        iocs = {k: list(found["iocs"].get(k, [])) for k in IOC_KEYS}
        _merge(aggregated, iocs)
        result.evidence_files_scanned += 1
        result.evidence_files_truncated += int(truncated)
        scan_data = {
            "source": "stored_evidence_bytes",
            "evidence_sha256": ev.original_hash_sha256,
            "bytes_scanned": len(data),
            "truncated": truncated,
            "scanned_at": now,
        }
        record = existing_scans.get(ev.id)
        if record is None:
            db.add(
                ForensicArtifact(
                    case_id=case_id,
                    evidence_id=ev.id,
                    artifact_type=EVIDENCE_SCAN_ARTIFACT,
                    artifact_data=scan_data,
                    analysis_notes="Indicators extracted from the printable strings of the stored evidence bytes",
                    ioc_extracted={**iocs, "extracted_at": now},
                    risk_score=0.0,
                    organization_id=org_id,
                ),
            )
        else:
            record.artifact_data = scan_data
            record.ioc_extracted = {**iocs, "extracted_at": now}
        result.scan_artifacts_written += 1

    result.iocs = {k: sorted(v) for k, v in aggregated.items()}
    await db.flush()
    logger.info(
        "dfir_ioc_scan",
        case_id=case_id, organization_id=org_id, artifacts=result.artifacts_scanned,
        evidence_files=result.evidence_files_scanned, total=result.total,
    )
    return result


def parse_timestamp(value: Any) -> Optional[str]:
    """ISO-8601 (UTC) for an ISO string or a Unix epoch (s or ms); None otherwise."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000.0 if value > 1e11 else float(value)
        if seconds <= 0:
            return None
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    return None


def _record_events(record: dict[str, Any], key_prefix: str) -> list[tuple[str, str, str]]:
    """(derived_from key, timestamp field, ISO timestamp) for each timestamp field in ``record``."""
    out = []
    for name in TIMESTAMP_KEYS:
        if name in record:
            ts = parse_timestamp(record[name])
            if ts:
                out.append((f"{key_prefix}:{name}", name, ts))
    return out


@dataclass
class TimelineReconstruction:
    created: int = 0
    already_present: int = 0
    from_custody: int = 0
    from_artifacts: int = 0
    truncated: bool = False


async def reconstruct_timeline(db: AsyncSession, *, case_id: str, org_id: str) -> TimelineReconstruction:
    out = TimelineReconstruction()
    existing_keys: set[str] = set()
    for data in (
        await db.execute(
            select(ForensicTimeline.artifact_data).where(
                ForensicTimeline.case_id == case_id, ForensicTimeline.organization_id == org_id,
            ),
        )
    ).scalars():
        if isinstance(data, dict) and data.get("derived_from"):
            existing_keys.add(str(data["derived_from"]))

    def add(key: str, **fields: Any) -> bool:
        if key in existing_keys:
            out.already_present += 1
            return False
        if out.created >= MAX_TIMELINE_EVENTS:
            out.truncated = True
            return False
        existing_keys.add(key)
        artifact_data = dict(fields.pop("artifact_data", {}) or {})
        artifact_data["derived_from"] = key
        db.add(ForensicTimeline(case_id=case_id, organization_id=org_id, artifact_data=artifact_data, **fields))
        out.created += 1
        return True

    evidence_rows = (
        await db.execute(
            select(ForensicEvidence).where(
                ForensicEvidence.case_id == case_id, ForensicEvidence.organization_id == org_id,
            ),
        )
    ).scalars()
    for ev in evidence_rows:
        entries = (ev.chain_of_custody_log or {}).get("entries", []) if isinstance(ev.chain_of_custody_log, dict) else []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            ts = parse_timestamp(entry.get("timestamp"))
            if not ts:
                continue
            action = str(entry.get("action") or "custody_event")[:60]
            if add(
                f"custody:{ev.id}:{index}",
                event_timestamp=ts,
                event_type=f"custody_{action}",
                source="chain_of_custody",
                source_evidence_id=ev.id,
                description=f"{entry.get('actor') or 'unknown actor'}: {action} ({ev.evidence_type} from {ev.source_device})",
                artifact_data={"custody_entry": entry},
            ):
                out.from_custody += 1

    artifacts = (
        await db.execute(
            select(ForensicArtifact)
            .where(
                ForensicArtifact.case_id == case_id,
                ForensicArtifact.organization_id == org_id,
                ForensicArtifact.artifact_type != "evidence_ioc_scan",
            )
            .limit(MAX_ARTIFACTS),
        )
    ).scalars()
    for artifact in artifacts:
        data = artifact.artifact_data or {}
        if not isinstance(data, dict):
            continue
        top_level = {k: v for k, v in data.items() if isinstance(v, (str, int, float, bool)) or v is None}
        candidates: list[tuple[str, str, str, dict[str, Any]]] = [
            (key, name, ts, top_level) for key, name, ts in _record_events(data, f"artifact:{artifact.id}")
        ]
        for list_key in RECORD_LIST_KEYS:
            rows = data.get(list_key)
            if not isinstance(rows, list):
                continue
            for i, row in enumerate(rows[:1000]):
                if isinstance(row, dict):
                    prefix = f"artifact:{artifact.id}:{list_key}[{i}]"
                    candidates.extend((key, name, ts, row) for key, name, ts in _record_events(row, prefix))
        for key, name, ts, summary in candidates:
            if add(
                key,
                event_timestamp=ts,
                event_type=f"{artifact.artifact_type}_{name}"[:100],
                source=f"artifact:{artifact.artifact_type}"[:255],
                source_evidence_id=artifact.evidence_id,
                description=f"{artifact.artifact_type} {name}",
                severity_score=float(artifact.risk_score or 0.0),
                artifact_data={"artifact_id": artifact.id, "record": dict(list(summary.items())[:30])},
            ):
                out.from_artifacts += 1

    await db.flush()
    return out
