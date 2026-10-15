"""Wave 4 (W4-B): supply chain made real.

Covers: CycloneDX / SPDX uploads validated (422 with the errors), size-capped
(413) and stored with their components, dependency counts and derived NTIA
compliance, deduplicated per organisation (another tenant never shares a
component row); SBOM generation from stored components only (422 when there
are none); compliance cannot be set by hand; SBOM comparison computed from
stored components; OSV (and NVD with a key) lookups through the pinned
transport with per-organisation caching, provider status reporting and
known_vulnerability risks deduplicated per (component, advisory); a provider
failure leaves components ``not_scanned`` and answers 502; vendor scores
derived from stored questionnaire answers; viewers cannot write. HTTP is
mocked at the transport, DNS at ``netguard._getaddrinfo``.
"""

# ruff: noqa: ARG001  (test double mirrors the netguard resolver signature)
from __future__ import annotations

import json
from typing import Any, Callable, Optional

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.endpoints import supplychain as sc_endpoints
from src.core.database import async_session_factory
from src.integrations import netguard
from src.supplychain import vulnlookup
from src.supplychain.models import SoftwareComponent, SupplyChainRisk, SupplyChainVulnCache
from src.supplychain.tasks import _vulnerability_lookup_sweep_async
from tests.helpers.tenancy import assert_tenant_isolated

BASE = "/api/v1/supplychain"
PUBLIC_IP = "151.101.1.69"


def _dns(monkeypatch: pytest.MonkeyPatch, ip: str = PUBLIC_IP) -> None:
    async def fake(host: str, port: int) -> list[tuple[Any, ...]]:
        return [(2, 1, 6, "", (ip, port))]

    monkeypatch.setattr(netguard, "_getaddrinfo", fake)


def _cdx(components: Optional[list[dict[str, Any]]] = None, *, deps: bool = True) -> dict[str, Any]:
    comps = components if components is not None else [
        {"bom-ref": "req", "type": "library", "name": "requests", "version": "2.19.0",
         "purl": "pkg:pypi/requests@2.19.0", "supplier": {"name": "PSF"},
         "hashes": [{"alg": "SHA-256", "content": "b" * 64}], "licenses": [{"license": {"id": "Apache-2.0"}}]},
        {"bom-ref": "url", "type": "library", "name": "urllib3", "version": "1.24.1",
         "purl": "pkg:pypi/urllib3@1.24.1", "supplier": {"name": "urllib3 team"}},
    ]
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"timestamp": "2026-10-01T00:00:00Z", "tools": [{"name": "syft"}],
                     "component": {"bom-ref": "app", "type": "application", "name": "shop", "version": "3.1"}},
        "components": comps,
    }
    if deps:
        doc["dependencies"] = [{"ref": "app", "dependsOn": ["req"]}, {"ref": "req", "dependsOn": ["url"]}]
    return doc


async def _upload(client: AsyncClient, headers: dict[str, str], doc: Any, name: str = "bom.cdx.json") -> httpx.Response:
    raw = doc if isinstance(doc, (bytes, str)) else json.dumps(doc)
    return await client.post(f"{BASE}/sboms/upload", files={"file": (name, raw, "application/json")}, headers=headers)


# ---------------------------------------------------------------------------
# SBOM upload / import / generate / compliance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cyclonedx_upload_stores_components_graph_and_compliance(
    client: AsyncClient, db_session: AsyncSession, org_a_headers, org_b_headers, org_a, org_b,
):
    resp = await _upload(client, org_a_headers, _cdx())
    assert resp.status_code == 200, resp.text
    sbom = resp.json()
    assert sbom["components_count"] == 2
    assert sbom["direct_dependencies"] == 1 and sbom["transitive_dependencies"] == 1
    assert sbom["compliance_status"] == "compliant"
    assert sbom["application_version"] == "3.1"

    report = (await client.get(f"{BASE}/sboms/{sbom['id']}/compliance", headers=org_a_headers)).json()
    assert report["status"] == "compliant"
    assert report["element_coverage"]["unique_identifier"] == 100.0

    comps = (await client.get(f"{BASE}/components", headers=org_a_headers)).json()["items"]
    assert {c["name"] for c in comps} == {"requests", "urllib3"}
    assert {c["vulnerability_scan_status"] for c in comps} == {"not_scanned"}
    req = next(c for c in comps if c["name"] == "requests")
    assert req["vendor"] == "PSF" and req["package_type"] == "pypi"

    # Org B uploads the same purls: its own rows, never linked to A's.
    resp_b = await _upload(client, org_b_headers, _cdx())
    assert resp_b.status_code == 200
    a_id, b_id = org_a.id, org_b.id
    rows = (await db_session.execute(
        select(SoftwareComponent.organization_id).where(SoftwareComponent.purl == "pkg:pypi/requests@2.19.0"),
    )).scalars().all()
    assert sorted(rows) == sorted([a_id, b_id])
    await assert_tenant_isolated(client, "GET", f"{BASE}/sboms/{sbom['id']}", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{BASE}/sboms/{sbom['id']}/compliance", org_b_headers)

    # Re-uploading does not duplicate components.
    await _upload(client, org_a_headers, _cdx())
    count = (await db_session.execute(
        select(func.count(SoftwareComponent.id)).where(SoftwareComponent.organization_id == a_id),
    )).scalar()
    assert count == 2


@pytest.mark.asyncio
async def test_sbom_without_supplier_or_graph_is_non_compliant(client: AsyncClient, org_a_headers):
    doc = _cdx([{"type": "library", "name": "leftpad", "version": "1.0.0"}], deps=False)
    sbom = (await _upload(client, org_a_headers, doc)).json()
    assert sbom["compliance_status"] == "non_compliant"
    report = (await client.post(f"{BASE}/compliance/validate-sbom", json={"sbom_id": sbom["id"]},
                                headers=org_a_headers)).json()
    missing = set(report["cisa_compliance"]["missing_elements"])
    assert {"supplier", "unique_identifier", "dependency_relationships"} <= missing
    assert report["overall_compliant"] is False

    empty = (await _upload(client, org_a_headers, _cdx([], deps=False))).json()
    assert empty["compliance_status"] == "not_assessed"


@pytest.mark.asyncio
async def test_invalid_and_oversized_sboms_are_rejected(
    client: AsyncClient, org_a_headers, monkeypatch: pytest.MonkeyPatch,
):
    bad = _cdx([{"type": "library", "version": "1"}])
    bad["specVersion"] = "9.9"
    resp = await _upload(client, org_a_headers, bad)
    assert resp.status_code == 422
    errors = resp.json()["detail"]["errors"]
    assert any("specVersion" in e for e in errors) and any("no name" in e for e in errors)

    spdx_bad = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "x"}]}
    resp = await client.post(f"{BASE}/sboms/import", json={"sbom_content": json.dumps(spdx_bad),
                                                           "sbom_format": "spdx_json"}, headers=org_a_headers)
    assert resp.status_code == 422

    assert (await _upload(client, org_a_headers, b"{\"hello\": 1}")).status_code == 400
    monkeypatch.setattr(sc_endpoints, "MAX_SBOM_BYTES", 100)
    big = await _upload(client, org_a_headers, _cdx())
    assert big.status_code == 413


@pytest.mark.asyncio
async def test_spdx_import_reads_external_refs_and_relationships(client: AsyncClient, org_a_headers):
    doc = {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "svc",
        "creationInfo": {"created": "2026-10-01T00:00:00Z", "creators": ["Tool: syft"]},
        "packages": [
            {"SPDXID": "SPDXRef-root", "name": "svc", "versionInfo": "1.0", "supplier": "Organization: Acme",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/svc@1.0"}]},
            {"SPDXID": "SPDXRef-lodash", "name": "lodash", "versionInfo": "4.17.20",
             "supplier": "Organization: OpenJS",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-root", "relationshipType": "DESCRIBES"},
            {"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-lodash", "relationshipType": "DEPENDS_ON"},
        ],
    }
    resp = await client.post(f"{BASE}/sboms/import", json={"sbom_content": json.dumps(doc), "sbom_format": "spdx_json"},
                             headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    sbom = resp.json()
    assert sbom["components_count"] == 2
    assert sbom["direct_dependencies"] == 1
    assert sbom["compliance_status"] == "compliant"
    comps = (await client.get(f"{BASE}/components", params={"search": "lodash"}, headers=org_a_headers)).json()
    assert comps["items"][0]["purl"] == "pkg:npm/lodash@4.17.20"


@pytest.mark.asyncio
async def test_generate_from_stored_components_only(client: AsyncClient, org_a_headers, org_b_headers):
    body = {"name": "gen", "application_name": "shop", "application_version": "1", "sbom_format": "cyclonedx_json"}
    none = await client.post(f"{BASE}/sboms/generate", json=body, headers=org_a_headers)
    assert none.status_code == 422
    assert none.json()["detail"]["error"] == "no_components"

    comp = (await client.post(f"{BASE}/components", json={"name": "flask", "version": "2.0.0", "license": "BSD-3-Clause",
                                                          "package_type": "pypi", "purl": "pkg:pypi/flask@2.0.0"},
                              headers=org_a_headers)).json()
    assert comp["license_spdx_id"] == "BSD-3-Clause"
    dup = await client.post(f"{BASE}/components", json={"name": "flask", "version": "2.0.0",
                                                        "purl": "pkg:pypi/flask@2.0.0"}, headers=org_a_headers)
    assert dup.status_code == 409

    gen = await client.post(f"{BASE}/sboms/generate", json=body, headers=org_a_headers)
    assert gen.status_code == 200, gen.text
    sbom = gen.json()
    assert sbom["components_count"] == 1
    assert sbom["compliance_status"] == "non_compliant"  # no supplier, no dependency graph
    export = await client.post(f"{BASE}/sboms/{sbom['id']}/export", json={"export_format": "cyclonedx_json"},
                               headers=org_a_headers)
    assert "flask" in export.text

    other = await client.post(f"{BASE}/sboms/generate", json={**body, "component_ids": [comp["id"]]},
                              headers=org_b_headers)
    assert other.status_code == 404


@pytest.mark.asyncio
async def test_compliance_status_cannot_be_set_and_rename_works(client: AsyncClient, org_a_headers):
    sbom = (await _upload(client, org_a_headers, _cdx([{"type": "library", "name": "x", "version": "1"}]))).json()
    resp = await client.patch(f"{BASE}/sboms/{sbom['id']}", json={"name": "renamed", "compliance_status": "compliant"},
                              headers=org_a_headers)
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "derived_field"
    ok = await client.patch(f"{BASE}/sboms/{sbom['id']}", json={"name": "renamed"}, headers=org_a_headers)
    assert ok.status_code == 200
    assert ok.json()["name"] == "renamed" and ok.json()["compliance_status"] == "non_compliant"


@pytest.mark.asyncio
async def test_compare_diffs_stored_components(client: AsyncClient, org_a_headers):
    one = (await _upload(client, org_a_headers, _cdx())).json()
    newer = _cdx([
        {"bom-ref": "req", "type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        {"bom-ref": "idna", "type": "library", "name": "idna", "version": "3.4", "purl": "pkg:pypi/idna@3.4"},
    ])
    two = (await _upload(client, org_a_headers, newer)).json()
    diff = (await client.post(f"{BASE}/sboms/compare", json={"sbom_id_1": one["id"], "sbom_id_2": two["id"]},
                              headers=org_a_headers)).json()
    assert [c["name"] for c in diff["components_added"]] == ["idna"]
    assert [c["name"] for c in diff["components_removed"]] == ["urllib3"]
    assert diff["components_updated"][0]["from_version"] == "2.19.0"
    assert diff["components_updated"][0]["to_version"] == "2.31.0"


# ---------------------------------------------------------------------------
# OSV / NVD lookups
# ---------------------------------------------------------------------------

OSV_DOC = {
    "id": "GHSA-x84v-xcm2-53pg",
    "summary": "Insufficiently protected credentials in Requests",
    "aliases": ["CVE-2018-18074"],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
    "database_specific": {"severity": "HIGH"},
}


def _osv(seen: list[httpx.Request], *, fail: bool = False) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if fail:
            return httpx.Response(503)
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            results = []
            for q in queries:
                purl = q["package"].get("purl", "")
                results.append({"vulns": [{"id": OSV_DOC["id"]}]} if "requests" in purl else {})
            return httpx.Response(200, json={"results": results})
        if request.url.path == f"/v1/vulns/{OSV_DOC['id']}":
            return httpx.Response(200, json=OSV_DOC)
        if request.url.path == "/rest/json/cves/2.0":
            return httpx.Response(200, json={"vulnerabilities": [
                {"cve": {"id": "CVE-2018-18074", "metrics": {}, "descriptions": [{"lang": "en", "value": "dup"}]}},
                {"cve": {"id": "CVE-2023-32681", "descriptions": [{"lang": "en", "value": "proxy leak"}],
                         "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 6.1,
                                                                     "vectorString": "CVSS:3.1/AV:N"}}]}}},
            ]})
        return httpx.Response(404)

    return handler


@pytest.mark.asyncio
async def test_osv_lookup_is_pinned_cached_and_deduplicated(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, viewer_headers,
    monkeypatch: pytest.MonkeyPatch,
):
    _dns(monkeypatch)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    seen: list[httpx.Request] = []
    monkeypatch.setattr(vulnlookup, "_inner_transport", lambda: httpx.MockTransport(_osv(seen)))
    await _upload(client, org_a_headers, _cdx())
    org_id = org_a.id

    assert (await client.post(f"{BASE}/components/lookup", json={}, headers=viewer_headers)).status_code == 403
    resp = await client.post(f"{BASE}/components/lookup", json={}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    summary = resp.json()
    assert summary["components_checked"] == 2
    assert summary["risks_new"] == 1
    assert summary["providers"]["osv"]["status"] == "ok"
    assert summary["providers"]["nvd"]["status"] == "not_configured"
    batch = seen[0]
    assert batch.url.host == PUBLIC_IP and batch.headers["host"] == "api.osv.dev"
    assert batch.url.path == "/v1/querybatch"
    sent = json.loads(batch.content)["queries"]
    assert {"package": {"purl": "pkg:pypi/requests@2.19.0"}} in sent

    comps = {c["name"]: c for c in (await client.get(f"{BASE}/components", headers=org_a_headers)).json()["items"]}
    assert comps["requests"]["known_vulnerabilities_count"] == 1
    assert comps["requests"]["risk_score"] == 7.5
    assert comps["requests"]["vulnerability_scan_status"] == "scanned"
    assert comps["urllib3"]["known_vulnerabilities_count"] == 0
    assert comps["urllib3"]["vulnerability_scan_status"] == "scanned"

    risks = (await client.get(f"{BASE}/risks", params={"risk_type": "known_vulnerability"},
                              headers=org_a_headers)).json()["items"]
    assert len(risks) == 1
    risk = risks[0]
    assert risk["advisory_id"] == "GHSA-x84v-xcm2-53pg" and risk["source"] == "osv"
    assert risk["severity"] == "high"
    assert risk["cve_ids"] == ["CVE-2018-18074"]
    assert "2.20.0" in risk["remediation_advice"]
    vulns = (await client.get(f"{BASE}/components/{comps['requests']['id']}/vulnerabilities",
                              headers=org_a_headers)).json()
    assert vulns["highest_severity"] == "high" and vulns["cves"] == ["CVE-2018-18074"]

    # Cached: a second lookup makes no request; a forced one updates, never duplicates.
    seen.clear()
    again = (await client.post(f"{BASE}/components/lookup", json={}, headers=org_a_headers)).json()
    assert seen == [] and again["cache_hits"] >= 2 and again["risks_new"] == 0
    forced = (await client.post(f"{BASE}/components/lookup", json={"use_cache": False}, headers=org_a_headers)).json()
    assert len(seen) >= 2 and forced["risks_new"] == 0 and forced["risks_updated"] == 1
    count = (await db_session.execute(
        select(func.count(SupplyChainRisk.id)).where(SupplyChainRisk.organization_id == org_id),
    )).scalar()
    assert count == 1
    cache_orgs = (await db_session.execute(select(SupplyChainVulnCache.organization_id))).scalars().all()
    assert set(cache_orgs) == {org_id}

    sources = (await client.get(f"{BASE}/vulnerability-sources", headers=org_a_headers)).json()
    assert sources["osv"]["status"] == "ok" and sources["osv"]["requests_total"] >= 2
    assert sources["nvd"]["status"] == "not_configured"
    dash = (await client.get(f"{BASE}/dashboard/overview", headers=org_a_headers)).json()
    assert dash["components_scanned"] == 2 and dash["components_with_vulnerabilities"] == 1
    assert dash["high_risks_open"] == 1
    top = (await client.get(f"{BASE}/dashboard/top-risky-components", headers=org_a_headers)).json()
    assert [t["component_name"] for t in top] == ["requests"]


@pytest.mark.asyncio
async def test_nvd_used_only_with_a_key_and_aliases_not_duplicated(
    client: AsyncClient, org_a_headers, monkeypatch: pytest.MonkeyPatch,
):
    _dns(monkeypatch)
    monkeypatch.setenv("NVD_API_KEY", "nvd-key")
    seen: list[httpx.Request] = []
    monkeypatch.setattr(vulnlookup, "_inner_transport", lambda: httpx.MockTransport(_osv(seen)))
    comp = (await client.post(f"{BASE}/components", json={
        "name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0",
        "cpe": "cpe:2.3:a:python:requests:2.19.0:*:*:*:*:*:*:*",
    }, headers=org_a_headers)).json()
    out = (await client.post(f"{BASE}/components/{comp['id']}/lookup", headers=org_a_headers)).json()
    assert out["providers"]["nvd"]["status"] == "ok"
    nvd = next(r for r in seen if r.url.path == "/rest/json/cves/2.0")
    assert nvd.headers["apikey"] == "nvd-key" and nvd.headers["host"] == "services.nvd.nist.gov"
    assert nvd.url.host == PUBLIC_IP
    risks = (await client.get(f"{BASE}/risks", headers=org_a_headers)).json()["items"]
    assert sorted(r["advisory_id"] for r in risks) == ["CVE-2023-32681", "GHSA-x84v-xcm2-53pg"]


@pytest.mark.asyncio
async def test_provider_failure_leaves_components_not_scanned(
    client: AsyncClient, org_a_headers, monkeypatch: pytest.MonkeyPatch,
):
    _dns(monkeypatch)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    seen: list[httpx.Request] = []
    monkeypatch.setattr(vulnlookup, "_inner_transport", lambda: httpx.MockTransport(_osv(seen, fail=True)))
    await _upload(client, org_a_headers, _cdx())
    resp = await client.post(f"{BASE}/components/lookup", json={}, headers=org_a_headers)
    assert resp.status_code == 502
    assert resp.json()["detail"]["error"] == "provider_unavailable"
    comps = (await client.get(f"{BASE}/components", headers=org_a_headers)).json()["items"]
    assert {c["vulnerability_scan_status"] for c in comps} == {"not_scanned"}
    sources = (await client.get(f"{BASE}/vulnerability-sources", headers=org_a_headers)).json()
    assert sources["osv"]["status"] == "error" and "503" in sources["osv"]["last_error"]


@pytest.mark.asyncio
async def test_lookup_refuses_internal_resolution(client: AsyncClient, org_a_headers, monkeypatch: pytest.MonkeyPatch):
    _dns(monkeypatch, "127.0.0.1")
    seen: list[httpx.Request] = []
    monkeypatch.setattr(vulnlookup, "_inner_transport", lambda: httpx.MockTransport(_osv(seen)))
    await _upload(client, org_a_headers, _cdx())
    resp = await client.post(f"{BASE}/components/lookup", json={}, headers=org_a_headers)
    assert resp.status_code == 502
    assert seen == []


@pytest.mark.asyncio
async def test_lookup_sweep_task(client: AsyncClient, org_a_headers, monkeypatch: pytest.MonkeyPatch):
    _dns(monkeypatch)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    seen: list[httpx.Request] = []
    monkeypatch.setattr(vulnlookup, "_inner_transport", lambda: httpx.MockTransport(_osv(seen)))
    await _upload(client, org_a_headers, _cdx())
    totals = await _vulnerability_lookup_sweep_async(async_session_factory)
    assert totals["components_checked"] == 2 and totals["risks_new"] == 1
    again = await _vulnerability_lookup_sweep_async(async_session_factory)
    assert again["components_checked"] == 0  # fresh components are not looked up again


def test_cvss3_base_scores():
    assert vulnlookup.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert vulnlookup.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert vulnlookup.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N") == 5.4
    assert vulnlookup.cvss3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert vulnlookup.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert vulnlookup.cvss3_base_score("AV:N/AC:L") is None


# ---------------------------------------------------------------------------
# vendors, risks, roles, tenancy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vendor_score_is_derived_from_stored_answers(
    client: AsyncClient, org_a_headers, org_b_headers, viewer_headers,
):
    q = (await client.get(f"{BASE}/vendors/questionnaire", headers=org_a_headers)).json()
    keys = [x["key"] for x in q["questions"]]
    assert "mfa_enforced" in keys

    typed = await client.post(f"{BASE}/vendors", json={"vendor_name": "Acme", "security_score": 99},
                              headers=org_a_headers)
    assert typed.status_code == 422
    blank = (await client.post(f"{BASE}/vendors", json={"vendor_name": "Blank"}, headers=org_a_headers)).json()
    assert blank["assessment_status"] == "not_assessed"

    answers = {"mfa_enforced": "yes", "encryption_at_rest": "no", "security_training": "n/a"}
    vendor = (await client.post(f"{BASE}/vendors", json={"vendor_name": "Acme", "questionnaire_responses": answers},
                                headers=org_a_headers)).json()
    assert vendor["assessment_status"] == "partial"
    assert vendor["security_score"] == 50.0  # weights 3 yes / 3 no; n/a excluded
    assert vendor["answered_questions"] == 3 and vendor["total_questions"] == len(keys)
    assert vendor["questionnaire_responses"]["mfa_enforced"] == "yes"

    bad = await client.patch(f"{BASE}/vendors/{vendor['id']}",
                             json={"questionnaire_responses": {"mfa_enforced": "maybe"}}, headers=org_a_headers)
    assert bad.status_code == 422
    upd = (await client.patch(f"{BASE}/vendors/{vendor['id']}",
                              json={"questionnaire_responses": {**answers, "encryption_at_rest": "yes"}},
                              headers=org_a_headers)).json()
    assert upd["security_score"] == 100.0
    assert (await client.patch(f"{BASE}/vendors/{vendor['id']}", json={"security_score": 10},
                               headers=org_a_headers)).status_code == 422

    scores = {v["vendor_name"]: v for v in (await client.get(f"{BASE}/dashboard/vendor-scores",
                                                             headers=org_a_headers)).json()}
    assert scores["Blank"]["risk_score"] is None and scores["Blank"]["assessment_status"] == "not_assessed"
    assert scores["Acme"]["risk_score"] == 0.0
    dash = (await client.get(f"{BASE}/dashboard/overview", headers=org_a_headers)).json()
    assert dash["vendors_assessed"] == 1 and dash["vendors_not_assessed"] == 1
    assert dash["average_vendor_score"] == 100.0
    assert dash["average_component_risk"] is None

    await assert_tenant_isolated(client, "GET", f"{BASE}/vendors/{vendor['id']}", org_b_headers)
    assert (await client.post(f"{BASE}/vendors", json={"vendor_name": "v"}, headers=viewer_headers)).status_code == 403


@pytest.mark.asyncio
async def test_risk_create_checks_component_tenant(client: AsyncClient, org_a_headers, org_b_headers):
    comp = (await client.post(f"{BASE}/components", json={"name": "a", "version": "1"}, headers=org_a_headers)).json()
    other = await client.post(f"{BASE}/risks", json={"component_id": comp["id"], "risk_type": "license_conflict",
                                                     "severity": "low", "description": "x"}, headers=org_b_headers)
    assert other.status_code == 404
    ok = await client.post(f"{BASE}/risks", json={"component_id": comp["id"], "risk_type": "license_conflict",
                                                  "severity": "low", "description": "x",
                                                  "evidence": {"k": "v"}, "cve_ids": []}, headers=org_a_headers)
    assert ok.status_code == 200, ok.text
    assert ok.json()["evidence"] == {"k": "v"} and ok.json()["source"] == "manual"


@pytest.mark.asyncio
async def test_viewer_cannot_write(client: AsyncClient, org_a_headers, viewer_headers):
    sbom = (await _upload(client, org_a_headers, _cdx())).json()
    for method, path, body in [
        ("POST", f"{BASE}/components", {"name": "x", "version": "1"}),
        ("POST", f"{BASE}/sboms/generate", {"name": "g", "application_name": "a", "application_version": "1"}),
        ("PATCH", f"{BASE}/sboms/{sbom['id']}", {"name": "n"}),
        ("DELETE", f"{BASE}/sboms/{sbom['id']}", None),
        ("POST", f"{BASE}/sboms/compare", {"sbom_id_1": sbom["id"], "sbom_id_2": sbom["id"]}),
    ]:
        resp = await client.request(method, path, json=body, headers=viewer_headers)
        assert resp.status_code == 403, (method, path, resp.status_code)
    up = await _upload(client, viewer_headers, _cdx())
    assert up.status_code == 403
