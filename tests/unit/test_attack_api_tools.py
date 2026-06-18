"""ATT&CK API endpoints + agent tools."""

import pytest
from sqlalchemy import select

from src.attack.models import AttackSyncState
from tests.unit.test_attack_loader import _bundle


async def _seed(db):
    from src.attack.loader import load_stix_bundle
    await load_stix_bundle(db, _bundle(), domain="enterprise", attack_version="17.1")
    await db.commit()


# --- API ---

@pytest.mark.asyncio
async def test_status_empty_then_loaded(client, auth_headers, db_session):
    r = await client.get("/api/v1/attack/status", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["status"] in ("empty", "loaded")

    await _seed(db_session)
    r = await client.get("/api/v1/attack/status", headers=auth_headers)
    body = r.json()
    assert body["techniques"] == 3
    assert body["attack_version"] == "17.1"


@pytest.mark.asyncio
async def test_get_technique_endpoint(client, auth_headers, db_session):
    await _seed(db_session)
    r = await client.get("/api/v1/attack/techniques/T1110", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["name"] == "Brute Force"

    r = await client.get("/api/v1/attack/techniques/T9999", headers=auth_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_search_and_coverage_endpoints(client, auth_headers, db_session):
    await _seed(db_session)
    r = await client.get("/api/v1/attack/search?q=brute", headers=auth_headers)
    assert any(t["external_id"] == "T1110" for t in r.json()["techniques"])

    r = await client.get("/api/v1/attack/coverage?technique_ids=T1110,T1110.001", headers=auth_headers)
    cov = {c["technique"]: c for c in r.json()["coverage"]}
    assert cov["T1110"]["covered"] is False  # no rules seeded


@pytest.mark.asyncio
async def test_sync_requires_superuser(client, auth_headers, admin_auth_headers):
    # regular user forbidden
    r = await client.post("/api/v1/attack/sync", headers=auth_headers)
    assert r.status_code == 403


# --- Agent tools ---

@pytest.mark.asyncio
async def test_agent_lookup_and_coverage_tools(db_session):
    from src.services.agent_tools import AgentToolRegistry
    await _seed(db_session)
    reg = AgentToolRegistry(db_session)

    out = await reg.execute("lookup_attack_technique", {"technique_id": "t1110"})
    assert out["success"] is True
    assert out["result"]["name"] == "Brute Force"

    out = await reg.execute("get_attack_coverage", {"technique_ids": ["T1110", "T1110.001"]})
    assert out["success"] is True
    assert {c["technique"] for c in out["result"]} == {"T1110", "T1110.001"}

    out = await reg.execute("search_attack", {"query": "mimikatz"})
    assert out["success"] is True
    assert any(s["external_id"] == "S0002" for s in out["result"]["software"])


@pytest.mark.asyncio
async def test_attack_tools_in_investigator_allowlist():
    from src.agentic.investigator import INVESTIGATOR_READONLY_TOOLS
    for t in ("lookup_attack_technique", "search_attack", "get_attack_coverage"):
        assert t in INVESTIGATOR_READONLY_TOOLS
