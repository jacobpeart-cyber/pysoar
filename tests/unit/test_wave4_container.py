"""Wave 4 (W4-B): container security made real.

Covers: image / cluster registration (roles, duplicates, tenancy); image scans
through an installed scanner integration (pinned HTTP, Trivy / Grype report
parsing), through a ``scan_container_image`` endpoint-agent command (result
applied on read and by the reconcile task) or ``awaiting_integration`` with
nothing changed; cluster credentials stored encrypted and never returned; CIS
checks run against a mocked Kubernetes API through the pinned transport with
findings deduplicated per (cluster, image, check) and remediated when the
check passes; without a credential (or with an API server that resolves to an
internal address) every check is ``not_assessed`` and nothing passes;
compliance views read the stored results. HTTP is mocked at the transport,
DNS at ``netguard._getaddrinfo``.
"""

# ruff: noqa: ARG001, ARG005  (test doubles mirror netguard / transport signatures; fixtures used for setup)
from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import AgentCommand, EndpointAgent
from src.agents.service import AgentService
from src.container_security import kube, scanning
from src.container_security.models import (
    ContainerImage,
    ContainerImageScan,
    ImageVulnerability,
    K8sCheckResult,
    K8sSecurityFinding,
    KubernetesCluster,
)
from src.container_security.tasks import reconcile_image_scans_async
from src.core.database import async_session_factory
from src.integrations import netguard
from src.integrations.models import InstalledIntegration, IntegrationConnector
from src.models.audit import AuditLog
from tests.helpers.tenancy import assert_tenant_isolated

BASE = "/api/v1/container-security"
PUBLIC_IP = "93.184.216.34"
API_SERVER = "https://k8s.example.com:6443"
DIGEST = "sha256:" + "a" * 64

TRIVY_REPORT = {
    "SchemaVersion": 2,
    "ArtifactName": "registry.example.com/web/app:1.0",
    "Results": [{
        "Target": "app (debian 12)",
        "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.1",
             "FixedVersion": "3.0.9", "Severity": "CRITICAL", "Title": "openssl overflow",
             "CVSS": {"nvd": {"V3Score": 9.8}}},
            {"VulnerabilityID": "CVE-2024-0002", "PkgName": "zlib", "InstalledVersion": "1.2.11",
             "Severity": "MEDIUM", "Title": "zlib issue"},
            # duplicate row (same CVE / package / version) is stored once
            {"VulnerabilityID": "CVE-2024-0002", "PkgName": "zlib", "InstalledVersion": "1.2.11",
             "Severity": "MEDIUM", "Title": "zlib issue"},
        ],
    }],
}
GRYPE_REPORT = {
    "matches": [
        {"vulnerability": {"id": "GHSA-xxxx-yyyy", "severity": "High", "description": "bad",
                           "fix": {"versions": ["2.0.0"]}, "cvss": [{"metrics": {"baseScore": 7.5}}]},
         "artifact": {"name": "requests", "version": "1.0.0"}},
    ],
}


def _dns(monkeypatch: pytest.MonkeyPatch, ip: str = PUBLIC_IP) -> None:
    async def fake(host: str, port: int) -> list[tuple[Any, ...]]:
        return [(2, 1, 6, "", (ip, port))]

    monkeypatch.setattr(netguard, "_getaddrinfo", fake)


def _detail(resp: httpx.Response) -> Any:
    return resp.json().get("detail")


async def _image(client: AsyncClient, headers: dict[str, str], tag: str = "1.0") -> dict[str, Any]:
    resp = await client.post(f"{BASE}/images", json={
        "registry": "registry.example.com", "repository": "web/app", "tag": tag, "digest_sha256": DIGEST,
    }, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _cluster(client: AsyncClient, headers: dict[str, str], name: str = "prod") -> dict[str, Any]:
    resp = await client.post(f"{BASE}/clusters", json={
        "name": name, "version": "v1.29", "provider": "eks", "endpoint": API_SERVER,
    }, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_image_registration_is_unscanned_scoped_and_role_gated(
    client: AsyncClient, org_a_headers, org_b_headers, viewer_headers,
):
    img = await _image(client, org_a_headers)
    assert img["scan_status"] == "not_scanned"
    assert img["scanned_at"] is None
    assert img["compliance_status"] == "not_scanned"
    assert img["digest_sha256"] == DIGEST

    dup = await client.post(f"{BASE}/images", json={
        "registry": "registry.example.com", "repository": "web/app", "tag": "1.0",
    }, headers=org_a_headers)
    assert dup.status_code == 409
    bad = await client.post(f"{BASE}/images", json={
        "registry": "r", "repository": "x", "tag": "1", "digest_sha256": "nothex",
    }, headers=org_a_headers)
    assert bad.status_code == 422
    denied = await client.post(f"{BASE}/images", json={
        "registry": "r", "repository": "x", "tag": "1",
    }, headers=viewer_headers)
    assert denied.status_code == 403

    await assert_tenant_isolated(client, "GET", f"{BASE}/images/{img['id']}", org_b_headers)
    await assert_tenant_isolated(client, "POST", f"{BASE}/images/{img['id']}/scan", org_b_headers)
    listed = await client.get(f"{BASE}/images", headers=org_b_headers)
    assert img["id"] not in {i["id"] for i in listed.json()}
    # Another tenant may register the same reference.
    other = await client.post(f"{BASE}/images", json={
        "registry": "registry.example.com", "repository": "web/app", "tag": "1.0",
    }, headers=org_b_headers)
    assert other.status_code == 201


@pytest.mark.asyncio
async def test_cluster_registration_and_names_unique_per_org(
    client: AsyncClient, org_a_admin_headers, org_a_headers, org_b_headers,
):
    cl = await _cluster(client, org_a_admin_headers)
    assert cl["assessment_status"] == "not_assessed"
    assert cl["compliance_status"] == "not_assessed"
    assert cl["has_credential"] is False
    assert (await client.post(f"{BASE}/clusters", json={
        "name": "prod", "version": "v1", "endpoint": API_SERVER,
    }, headers=org_a_admin_headers)).status_code == 409
    assert (await client.post(f"{BASE}/clusters", json={
        "name": "x", "version": "v1", "endpoint": "http://k8s.example.com",
    }, headers=org_a_admin_headers)).status_code == 422
    # analysts cannot register clusters
    assert (await client.post(f"{BASE}/clusters", json={
        "name": "y", "version": "v1", "endpoint": API_SERVER,
    }, headers=org_a_headers)).status_code == 403
    await assert_tenant_isolated(client, "GET", f"{BASE}/clusters/{cl['id']}", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{BASE}/clusters/{cl['id']}/checks", org_b_headers)


@pytest.mark.asyncio
async def test_orgless_superuser_is_refused(client: AsyncClient, superuser_headers):
    resp = await client.get(f"{BASE}/images", headers=superuser_headers)
    assert resp.status_code == 403
    assert "organization_required" in json.dumps(resp.json())


# ---------------------------------------------------------------------------
# image scans
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_without_scanner_is_awaiting_integration_and_changes_nothing(
    client: AsyncClient, org_a_headers, org_a_admin_headers,
):
    img = await _image(client, org_a_headers)
    avail = await client.get(f"{BASE}/scanners", headers=org_a_headers)
    assert avail.json()["status"] == "awaiting_integration"

    resp = await client.post(f"{BASE}/images/{img['id']}/scan", headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "awaiting_integration"
    assert "Trivy" in body["detail"]
    assert body["compliance_status"] == "not_scanned"
    assert body["scan_id"] is None
    after = (await client.get(f"{BASE}/images/{img['id']}", headers=org_a_headers)).json()
    assert after["scan_status"] == "awaiting_integration"
    assert after["scanned_at"] is None
    assert after["compliance_status"] == "not_scanned"
    assert after["risk_score"] == 0
    risk = (await client.get(f"{BASE}/images/{img['id']}/risk-assessment", headers=org_a_headers)).json()
    assert risk["risk_score"] is None
    assert risk["recommendation"].startswith("Not scanned")
    # analysts cannot trigger scans (admin: pulls images on live hosts)
    assert (await client.post(f"{BASE}/images/{img['id']}/scan", headers=org_a_headers)).status_code == 403


@pytest.mark.asyncio
async def test_agent_scan_applies_trivy_report_and_deduplicates(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, org_a_admin_headers,
):
    org_id = org_a.id
    agent = EndpointAgent(hostname="scanner-1", status="active", capabilities=["container_scan"],
                          organization_id=org_id)
    db_session.add(agent)
    await db_session.commit()
    agent_id = agent.id
    img = await _image(client, org_a_headers)

    resp = await client.post(f"{BASE}/images/{img['id']}/scan", headers=org_a_admin_headers)
    body = resp.json()
    assert body["status"] == "pending", body
    assert body["method"] == "agent"
    scan_id = body["scan_id"]
    scan = (await db_session.execute(select(ContainerImageScan).where(ContainerImageScan.id == scan_id))).scalar_one()
    cmd = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == scan.command_id))).scalar_one()
    assert cmd.action == "scan_container_image"
    assert cmd.payload["image_ref"] == f"registry.example.com/web/app:1.0@{DIGEST}"
    assert cmd.payload["scanner"] == "trivy"
    cmd_id = cmd.id

    # Agent reports the Trivy JSON on stdout.
    agent_row = (await db_session.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))).scalar_one()
    cmd.status = "dispatched"
    await AgentService(db_session).ingest_result(
        agent=agent_row, command_id=cmd_id, status="success", exit_code=0, stdout=json.dumps(TRIVY_REPORT),
    )
    await db_session.commit()

    got = (await client.get(f"{BASE}/images/{img['id']}", headers=org_a_headers)).json()
    assert got["scan_status"] == "completed"
    assert got["vulnerability_count_critical"] == 1
    assert got["vulnerability_count_medium"] == 1
    assert got["compliance_status"] == "non_compliant"
    assert got["scanned_at"] is not None
    assert got["risk_score"] > 0
    vulns = (await client.get(f"{BASE}/images/{img['id']}/vulnerabilities", headers=org_a_headers)).json()
    assert sorted(v["cve_id"] for v in vulns) == ["CVE-2024-0001", "CVE-2024-0002"]
    crit = next(v for v in vulns if v["cve_id"] == "CVE-2024-0001")
    assert crit["fixed_version"] == "3.0.9" and crit["cvss_score"] == 9.8
    scans = (await client.get(f"{BASE}/images/{img['id']}/scans", headers=org_a_headers)).json()
    assert scans[0]["status"] == "completed" and scans[0]["vulnerabilities_total"] == 2

    # A clean re-scan through the reconcile task removes the stale rows.
    resp = await client.post(f"{BASE}/images/{img['id']}/scan", headers=org_a_admin_headers)
    scan2 = (await db_session.execute(
        select(ContainerImageScan).where(ContainerImageScan.id == resp.json()["scan_id"]),
    )).scalar_one()
    cmd2 = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == scan2.command_id))).scalar_one()
    cmd2.status = "dispatched"
    agent_row = (await db_session.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))).scalar_one()
    await AgentService(db_session).ingest_result(
        agent=agent_row, command_id=cmd2.id, status="success",
        stdout=json.dumps({"SchemaVersion": 2, "Results": [{"Target": "app", "Vulnerabilities": []}]}),
    )
    await db_session.commit()
    totals = await reconcile_image_scans_async(async_session_factory)
    assert totals["changed"] == 1
    db_session.expire_all()
    count = (await db_session.execute(
        select(func.count(ImageVulnerability.id)).where(ImageVulnerability.image_id == img["id"]),
    )).scalar()
    assert count == 0
    image = (await db_session.execute(select(ContainerImage).where(ContainerImage.id == img["id"]))).scalar_one()
    assert image.compliance_status == "compliant"  # a real scanner reported zero
    assert image.vulnerability_count_critical == 0
    audit = (await db_session.execute(
        select(func.count(AuditLog.id)).where(AuditLog.action == "container_image_scan"),
    )).scalar()
    assert audit == 2


@pytest.mark.asyncio
async def test_agent_failure_and_garbage_output_fail_the_scan(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, org_a_admin_headers,
):
    agent = EndpointAgent(hostname="scanner-2", status="active", capabilities=["container_scan"],
                          organization_id=org_a.id)
    db_session.add(agent)
    await db_session.commit()
    agent_id = agent.id
    img = await _image(client, org_a_headers)
    resp = await client.post(f"{BASE}/images/{img['id']}/scan", headers=org_a_admin_headers)
    scan_id = resp.json()["scan_id"]
    scan = (await db_session.execute(select(ContainerImageScan).where(ContainerImageScan.id == scan_id))).scalar_one()
    cmd = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == scan.command_id))).scalar_one()
    cmd.status = "dispatched"
    agent_row = (await db_session.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))).scalar_one()
    await AgentService(db_session).ingest_result(agent=agent_row, command_id=cmd.id, status="success",
                                                 stdout="trivy: command not found")
    await db_session.commit()
    got = (await client.get(f"{BASE}/scans/{scan_id}", headers=org_a_headers)).json()
    assert got["status"] == "failed"
    assert "not a scanner report" in got["error"]
    image = (await client.get(f"{BASE}/images/{img['id']}", headers=org_a_headers)).json()
    assert image["scan_status"] == "failed"
    assert image["compliance_status"] == "not_scanned"


async def _scanner_integration(db: AsyncSession, org_id: str, name: str = "trivy") -> str:
    connector = (await db.execute(select(IntegrationConnector).where(IntegrationConnector.name == name))).scalar_one_or_none()
    if connector is None:
        connector = IntegrationConnector(
            name=name, display_name=name, category="container_security", supported_actions="[]",
            supported_triggers="[]", auth_type="api_key", config_schema="{}",
        )
        db.add(connector)
        await db.flush()
    integ = InstalledIntegration(
        organization_id=org_id, connector_id=connector.id, display_name=f"{name} gateway",
        config_encrypted=json.dumps({"base_url": "https://scanner.example.com", "scan_path": "/v1/scan"}),
        auth_credentials_encrypted="__plaintext__:" + json.dumps({"api_key": "scan-token"}),
        status="active", health_status="healthy",
    )
    db.add(integ)
    await db.commit()
    return integ.id


@pytest.mark.asyncio
async def test_integration_scan_is_pinned_and_parses_grype(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, org_a_admin_headers,
    monkeypatch: pytest.MonkeyPatch,
):
    _dns(monkeypatch)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=GRYPE_REPORT)

    monkeypatch.setattr(scanning, "_inner_transport", lambda: httpx.MockTransport(handler))
    await _scanner_integration(db_session, org_a.id)
    img = await _image(client, org_a_headers)
    resp = await client.post(f"{BASE}/images/{img['id']}/scan", headers=org_a_admin_headers)
    body = resp.json()
    assert body["status"] == "completed", body
    assert body["method"] == "integration"
    assert body["vulnerabilities"] == 1
    assert body["compliance_status"] == "non_compliant"
    req = seen[0]
    assert req.url.host == PUBLIC_IP
    assert req.headers["host"] == "scanner.example.com"
    assert req.url.path == "/v1/scan"
    assert req.headers["authorization"] == "Bearer scan-token"
    assert json.loads(req.content)["image"].startswith("registry.example.com/web/app:1.0")
    vulns = (await client.get(f"{BASE}/images/{img['id']}/vulnerabilities", headers=org_a_headers)).json()
    assert vulns[0]["cve_id"] == "GHSA-xxxx-yyyy" and vulns[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_integration_resolving_internal_fails_honestly(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, org_a_admin_headers,
    monkeypatch: pytest.MonkeyPatch,
):
    _dns(monkeypatch, "10.0.0.7")
    monkeypatch.setattr(scanning, "_inner_transport", lambda: httpx.MockTransport(lambda r: httpx.Response(200)))
    await _scanner_integration(db_session, org_a.id)
    img = await _image(client, org_a_headers)
    body = (await client.post(f"{BASE}/images/{img['id']}/scan", headers=org_a_admin_headers)).json()
    assert body["status"] == "failed"
    assert body["compliance_status"] == "not_scanned"


# ---------------------------------------------------------------------------
# credentials and CIS checks
# ---------------------------------------------------------------------------


def _pod(ns: str, name: str, image: str, *, privileged: bool = False, host_network: bool = False) -> dict[str, Any]:
    sc: dict[str, Any] = {"allowPrivilegeEscalation": False, "runAsNonRoot": True,
                          "capabilities": {"drop": ["ALL"]}}
    if privileged:
        sc["privileged"] = True
    return {
        "metadata": {"namespace": ns, "name": name},
        "spec": {"hostNetwork": host_network, "containers": [{"name": "c", "image": image, "securityContext": sc}]},
    }


def _api(state: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        path = request.url.path
        if path == "/version":
            return httpx.Response(200, json={"gitVersion": "v1.29.3"})
        lists = {
            "/api/v1/nodes": [{"metadata": {"name": "n1"}}, {"metadata": {"name": "n2"}}],
            "/api/v1/namespaces": [
                {"metadata": {"name": "web", "labels": {"pod-security.kubernetes.io/enforce": "baseline"}}},
                {"metadata": {"name": "kube-system"}},
            ],
            "/api/v1/pods": state["pods"],
            "/api/v1/serviceaccounts": [
                {"metadata": {"namespace": "web", "name": "default"}, "automountServiceAccountToken": False},
            ],
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": [
                {"metadata": {"name": "cluster-admin"}, "roleRef": {"name": "cluster-admin"},
                 "subjects": [{"kind": "Group", "name": "system:masters"}]},
            ],
            "/apis/rbac.authorization.k8s.io/v1/clusterroles": [],
            "/apis/rbac.authorization.k8s.io/v1/roles": [],
            "/apis/networking.k8s.io/v1/networkpolicies": [{"metadata": {"namespace": "web", "name": "deny"}}],
        }
        if path in lists:
            return httpx.Response(200, json={"items": lists[path], "metadata": {}})
        if path == "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations":
            return httpx.Response(403, json={"message": "forbidden"})
        return httpx.Response(404)

    return handler


@pytest.mark.asyncio
async def test_audit_without_credential_marks_every_check_not_assessed(
    client: AsyncClient, db_session: AsyncSession, org_a_admin_headers, org_a_headers,
):
    cl = await _cluster(client, org_a_admin_headers)
    resp = await client.post(f"{BASE}/clusters/{cl['id']}/audit", json={}, headers=org_a_admin_headers)
    body = resp.json()
    assert body["status"] == "not_assessed"
    assert body["cis_compliance"] is None
    assert body["checks"]["pass"] == 0 and body["checks"]["fail"] == 0
    assert body["checks"]["not_assessed"] == len(kube.CIS_CHECKS)
    checks = (await client.get(f"{BASE}/clusters/{cl['id']}/checks", headers=org_a_headers)).json()
    assert {c["status"] for c in checks} == {"not_assessed"}
    assert all("credential" in c["reason"] for c in checks)
    matrix = (await client.get(f"{BASE}/dashboard/compliance-matrix", headers=org_a_headers)).json()
    assert matrix[0]["status"] == "not_assessed" and matrix[0]["cis_score"] is None
    assert matrix[0]["nsa_cisa_score"] is None
    dash = (await client.get(f"{BASE}/dashboard/overview", headers=org_a_headers)).json()
    assert dash["non_compliant_clusters"] == 0
    assert dash["cluster_compliance"][0]["status"] == "not_assessed"
    comp = (await client.get(f"{BASE}/clusters/{cl['id']}/compliance-check", headers=org_a_headers)).json()
    assert comp["status"] == "not_assessed" and comp["compliance_score"] is None


@pytest.mark.asyncio
async def test_credential_is_encrypted_never_returned_and_admin_only(
    client: AsyncClient, db_session: AsyncSession, org_a_admin_headers, org_a_headers, viewer_headers,
):
    cl = await _cluster(client, org_a_admin_headers)
    url = f"{BASE}/clusters/{cl['id']}/credential"
    assert (await client.put(url, json={"token": "t0p"}, headers=org_a_headers)).status_code == 403
    assert (await client.put(url, json={"token": "t0p"}, headers=viewer_headers)).status_code == 403
    resp = await client.put(url, json={"token": "s3cr3t-token"}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["has_credential"] is True
    assert "s3cr3t-token" not in resp.text
    row = (await db_session.execute(select(KubernetesCluster).where(KubernetesCluster.id == cl["id"]))).scalar_one()
    assert row.credential_encrypted.startswith("enc:v1:")
    assert "s3cr3t-token" not in row.credential_encrypted
    listed = await client.get(f"{BASE}/clusters", headers=org_a_headers)
    assert "s3cr3t" not in listed.text and "credential_encrypted" not in listed.text

    exec_cfg = """
apiVersion: v1
kind: Config
current-context: c
contexts: [{name: c, context: {cluster: k, user: u}}]
clusters: [{name: k, cluster: {server: "https://k8s.example.com"}}]
users: [{name: u, user: {exec: {command: aws}}}]
"""
    bad = await client.put(url, json={"kubeconfig": exec_cfg}, headers=org_a_admin_headers)
    assert bad.status_code == 422
    assert _detail(bad)["error"] == "invalid_credential"
    both = await client.put(url, json={"kubeconfig": exec_cfg, "token": "x"}, headers=org_a_admin_headers)
    assert both.status_code == 422


@pytest.mark.asyncio
async def test_cis_audit_reads_the_api_pinned_and_dedupes_findings(
    client: AsyncClient, db_session: AsyncSession, org_a_admin_headers, org_a_headers, org_b_headers,
    monkeypatch: pytest.MonkeyPatch,
):
    _dns(monkeypatch)
    state: dict[str, Any] = {
        "requests": [],
        "pods": [
            _pod("web", "api-1", "nginx:1.25", privileged=True),
            _pod("web", "api-2", "nginx:1.25", privileged=True),
            _pod("web", "worker", "busybox:1", host_network=True),
            _pod("kube-system", "cni", "calico:3", privileged=True),  # system namespace excluded
        ],
    }
    monkeypatch.setattr(kube, "transport_factory", lambda ctx: httpx.MockTransport(_api(state)))
    kubeconfig = """
apiVersion: v1
kind: Config
current-context: prod
contexts: [{name: prod, context: {cluster: prod, user: auditor}}]
clusters: [{name: prod, cluster: {server: "https://k8s.example.com:6443"}}]
users: [{name: auditor, user: {token: "kube-token"}}]
"""
    cl = await _cluster(client, org_a_admin_headers)
    cid = cl["id"]
    assert (await client.put(f"{BASE}/clusters/{cid}/credential", json={"kubeconfig": kubeconfig},
                             headers=org_a_admin_headers)).status_code == 200

    body = (await client.post(f"{BASE}/clusters/{cid}/audit", json={}, headers=org_a_admin_headers)).json()
    assert body["status"] == "assessed", body
    req = state["requests"][0]
    assert req.url.host == PUBLIC_IP
    assert req.headers["host"] == "k8s.example.com:6443"
    assert req.headers["authorization"] == "Bearer kube-token"

    checks = {c["check_id"]: c for c in (await client.get(f"{BASE}/clusters/{cid}/checks", headers=org_a_headers)).json()}
    assert checks["5.2.2"]["status"] == "fail"
    assert checks["5.2.5"]["status"] == "fail"
    assert checks["5.2.3"]["status"] == "pass"
    assert checks["5.1.1"]["status"] == "pass"
    assert checks["5.3.2"]["status"] == "pass"
    assert checks["1.2.1"]["status"] == "not_assessed"  # apiserver not visible
    assert checks["5.2.1"]["status"] == "not_assessed"  # webhooks not readable (403)
    assert "403" in checks["5.2.1"]["reason"]

    cluster = (await client.get(f"{BASE}/clusters/{cid}", headers=org_a_headers)).json()
    assert cluster["node_count"] == 2 and cluster["pod_count"] == 4
    assert cluster["version"] == "v1.29.3"
    assert cluster["assessment_status"] == "assessed"
    assert cluster["compliance_status"] in ("compliant", "partial", "non_compliant")

    findings = (await client.get(f"{BASE}/clusters/{cid}/findings", headers=org_a_headers)).json()
    privileged = [f for f in findings if f["check_id"] == "5.2.2"]
    assert len(privileged) == 1  # two pods, one image -> one finding
    assert privileged[0]["image_ref"] == "nginx:1.25"
    assert "web/api-1" in privileged[0]["description"] and "web/api-2" in privileged[0]["description"]
    assert all("calico" not in (f["image_ref"] or "") for f in findings)
    total = len(findings)

    again = (await client.post(f"{BASE}/clusters/{cid}/audit", json={}, headers=org_a_admin_headers)).json()
    assert again["findings_new"] == 0
    assert len((await client.get(f"{BASE}/clusters/{cid}/findings", headers=org_a_headers)).json()) == total
    keys = (await db_session.execute(
        select(K8sSecurityFinding.dedupe_key).where(K8sSecurityFinding.cluster_id == cid),
    )).scalars().all()
    assert len(keys) == len(set(keys))

    # The privileged pods are fixed: the next audit remediates that finding.
    state["pods"] = [_pod("web", "api-1", "nginx:1.25"), _pod("web", "worker", "busybox:1", host_network=True)]
    third = (await client.post(f"{BASE}/clusters/{cid}/audit", json={}, headers=org_a_admin_headers)).json()
    assert third["findings_resolved"] >= 1
    db_session.expire_all()
    fixed = (await db_session.execute(
        select(K8sSecurityFinding).where(K8sSecurityFinding.cluster_id == cid, K8sSecurityFinding.check_id == "5.2.2"),
    )).scalar_one()
    assert fixed.status == "remediated"

    # Tenancy on the results.
    other = await client.get(f"{BASE}/findings", headers=org_b_headers)
    assert other.json() == []
    await assert_tenant_isolated(client, "POST", f"{BASE}/clusters/{cid}/audit", org_b_headers, json={})


@pytest.mark.asyncio
async def test_api_server_resolving_internal_is_refused_and_not_assessed(
    client: AsyncClient, db_session: AsyncSession, org_a_admin_headers, org_a_headers,
    monkeypatch: pytest.MonkeyPatch,
):
    _dns(monkeypatch, "10.0.0.5")
    called: list[httpx.Request] = []
    monkeypatch.setattr(kube, "transport_factory",
                        lambda ctx: httpx.MockTransport(lambda r: called.append(r) or httpx.Response(200, json={})))
    cl = await _cluster(client, org_a_admin_headers)
    await client.put(f"{BASE}/clusters/{cl['id']}/credential", json={"token": "tok"}, headers=org_a_admin_headers)
    body = (await client.post(f"{BASE}/clusters/{cl['id']}/audit", json={}, headers=org_a_admin_headers)).json()
    assert body["status"] == "failed"
    assert "outbound_refused" in body["reason"]
    assert called == []
    statuses = (await db_session.execute(
        select(K8sCheckResult.status).where(K8sCheckResult.cluster_id == cl["id"]),
    )).scalars().all()
    assert set(statuses) == {"not_assessed"}
    audit = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "k8s_cluster_cis_audit"),
    )).scalars().all()
    assert audit and audit[-1].success is False


@pytest.mark.asyncio
async def test_write_routes_refuse_viewers(client: AsyncClient, org_a_headers, org_a_admin_headers, viewer_headers):
    img = await _image(client, org_a_headers)
    cl = await _cluster(client, org_a_admin_headers)
    for method, path, body in [
        ("POST", f"{BASE}/images/{img['id']}/scan", None),
        ("DELETE", f"{BASE}/images/{img['id']}", None),
        ("PATCH", f"{BASE}/images/{img['id']}", {"labels": {}}),
        ("POST", f"{BASE}/clusters/{cl['id']}/audit", {}),
        ("PUT", f"{BASE}/clusters/{cl['id']}/credential", {"token": "x"}),
        ("DELETE", f"{BASE}/clusters/{cl['id']}/credential", None),
        ("DELETE", f"{BASE}/clusters/{cl['id']}", None),
    ]:
        resp = await client.request(method, path, json=body, headers=viewer_headers)
        assert resp.status_code == 403, (method, path, resp.status_code)


@pytest.mark.asyncio
async def test_delete_cluster_removes_its_rows(
    client: AsyncClient, db_session: AsyncSession, org_a_admin_headers,
):
    cl = await _cluster(client, org_a_admin_headers)
    await client.post(f"{BASE}/clusters/{cl['id']}/audit", json={}, headers=org_a_admin_headers)
    assert (await client.delete(f"{BASE}/clusters/{cl['id']}", headers=org_a_admin_headers)).status_code == 204
    left = (await db_session.execute(
        select(func.count(K8sCheckResult.id)).where(K8sCheckResult.cluster_id == cl["id"]),
    )).scalar()
    assert left == 0


def test_report_parsers_reject_non_reports():
    with pytest.raises(scanning.ReportError):
        scanning.parse_report({"hello": "world"})
    with pytest.raises(scanning.ReportError):
        scanning.parse_report("not json")
    used, vulns = scanning.parse_report(json.dumps(TRIVY_REPORT))
    assert used == "trivy" and len(vulns) == 3


def test_scan_action_is_capability_gated():
    from src.agents.capabilities import capability_allows, requires_approval

    assert capability_allows(["container_scan"], "scan_container_image")
    assert not capability_allows(["ir"], "scan_container_image")
    assert not requires_approval("scan_container_image")


def test_image_reference_grammar_refuses_option_and_shell_strings() -> None:
    """The reference is handed to an agent that runs trivy/grype on it."""
    from src.container_security.scanning import validate_image_reference

    for good in ("nginx", "library/nginx:1.25", "registry.example.com:5000/web/app:1.0",
                 "ghcr.io/org/app@sha256:" + "a" * 64, "r.io/a/b:1.0@sha256:" + "0" * 64):
        assert validate_image_reference(good) == good
    for bad in ("--db-repository=evil/x", "nginx; rm -rf /", "nginx && curl x", "web app:1", "",
                "registry.example.com/web/app:1.0 --quiet", "a/b:tag with space", "$(id)"):
        with pytest.raises(ValueError):
            validate_image_reference(bad)


async def test_image_registration_refuses_malformed_references(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    bad = await client.post(f"{BASE}/images", json={
        "registry": "registry.example.com", "repository": "web/app; rm -rf /", "tag": "1.0",
    }, headers=org_a_headers)
    assert bad.status_code == 422, bad.text
    assert bad.json()["detail"]["error"] == "invalid_image_reference"
    opt = await client.post(f"{BASE}/images", json={
        "registry": "", "repository": "--db-repository=evil", "tag": "latest",
    }, headers=org_a_headers)
    assert opt.status_code == 422, opt.text


def test_policy_control_check_does_not_pass_on_a_webhook_name_alone() -> None:
    from src.container_security.kube import ClusterSnapshot, _check_policy_control

    snap = ClusterSnapshot(version="v1.30", data={
        "validatingwebhooks": [{"metadata": {"name": "gatekeeper-validating-webhook-configuration"}}],
        "namespaces": [{"metadata": {"name": "payments", "labels": {}}}],
    })
    outcome = _check_policy_control(snap)
    assert outcome.status == "not_assessed"
    assert "not verifiable" in outcome.reason
    enforced = ClusterSnapshot(version="v1.30", data={
        "validatingwebhooks": [],
        "namespaces": [{"metadata": {"name": "payments", "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}}],
    })
    assert _check_policy_control(enforced).status == "pass"
