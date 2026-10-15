"""Kubernetes API access and CIS checks for registered clusters (wave 4).

A cluster gets a credential (a kubeconfig or a bearer token) through
``PUT /container-security/clusters/{id}/credential``. It is stored as an
``enc:v1:`` envelope (``src.core.secrets.encrypt_secret_json``) and never
returned. ``run_cis_audit`` then reads the cluster through its Kubernetes API
and evaluates the CIS Kubernetes Benchmark (v1.8) checks that can be decided
from API objects. Every request goes through ``PinnedTransport``: the API
server's host is resolved once, refused when it resolves to an internal
address, and the connection is pinned to the vetted IP with the hostname kept
for TLS. TLS is verified against the CA in the kubeconfig, else
``PYSOAR_KUBE_CA_BUNDLE``, else the system store; ``PYSOAR_KUBE_VERIFY_TLS=false``
is the explicit, logged opt-out.

Honesty rules: without a credential, or when the API cannot be read, every
check is ``not_assessed`` with the reason; a check is ``pass`` only after it
was evaluated on data read from the API, and never on a truncated listing.
Checks that need control-plane or node file access are ``not_assessed`` unless
the kube-apiserver runs as a visible pod whose flags can be read.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import ssl
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

import httpx
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.container_security.models import K8sCheckResult, K8sSecurityFinding, KubernetesCluster
from src.core.logging import get_logger
from src.core.secrets import SecretUnreadable, decrypt_secret_json, encrypt_secret_json
from src.integrations.netguard import OutboundTargetRefused, PinnedTransport, resolve_and_vet

logger = get_logger(__name__)

HTTP_TIMEOUT = 20.0
#: Items read per list call and the cap per resource kind. A listing that
#: hits the cap is marked truncated: checks then never report ``pass`` on it.
PAGE_LIMIT = 500
MAX_ITEMS_PER_KIND = 10_000
MAX_OFFENDERS_IN_DESCRIPTION = 20
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
CIS_BENCHMARK = "CIS Kubernetes Benchmark v1.8"


class KubeCredentialError(ValueError):
    """The submitted credential cannot be used (shape or unsupported auth)."""


class KubeAccessError(Exception):
    """The Kubernetes API could not be read."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def _b64_pem(value: Any, what: str) -> str:
    try:
        return base64.b64decode(str(value), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise KubeCredentialError(f"{what} is not valid base64 PEM") from exc


def _named(items: Any, name: str) -> dict[str, Any]:
    for item in items or []:
        if isinstance(item, dict) and item.get("name") == name:
            return item
    raise KubeCredentialError(f"kubeconfig has no entry named {name!r}")


def parse_kubeconfig(text: str, context: Optional[str] = None) -> dict[str, Any]:
    """Normalise a kubeconfig to ``{server, token | client cert/key, ca_pem}``.

    Supported user auth: ``token`` and ``client-certificate-data`` /
    ``client-key-data``. ``exec`` / ``auth-provider`` plugins and file
    references are refused: PySOAR cannot run plugins or read local files.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise KubeCredentialError(f"kubeconfig is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("kind") not in (None, "Config"):
        raise KubeCredentialError("kubeconfig must be a kind: Config document")
    ctx_name = context or doc.get("current-context")
    if not ctx_name:
        raise KubeCredentialError("kubeconfig has no current-context; name one with 'context'")
    ctx = _named(doc.get("contexts"), ctx_name).get("context") or {}
    cluster = _named(doc.get("clusters"), ctx.get("cluster")).get("cluster") or {}
    user = _named(doc.get("users"), ctx.get("user")).get("user") or {}

    server = cluster.get("server")
    if not server:
        raise KubeCredentialError("kubeconfig cluster has no server")
    out: dict[str, Any] = {"server": str(server)}
    if cluster.get("certificate-authority-data"):
        out["ca_pem"] = _b64_pem(cluster["certificate-authority-data"], "certificate-authority-data")
    elif cluster.get("certificate-authority"):
        raise KubeCredentialError(
            "certificate-authority file paths are not supported; inline it as certificate-authority-data",
        )
    if user.get("exec") or user.get("auth-provider"):
        raise KubeCredentialError(
            "exec / auth-provider credential plugins are not supported; use a service-account token "
            "or client-certificate-data",
        )
    if user.get("token"):
        out["token"] = str(user["token"])
    elif user.get("client-certificate-data") and user.get("client-key-data"):
        out["client_cert_pem"] = _b64_pem(user["client-certificate-data"], "client-certificate-data")
        out["client_key_pem"] = _b64_pem(user["client-key-data"], "client-key-data")
    else:
        raise KubeCredentialError(
            "kubeconfig user has no token or inline client certificate (file paths are not supported)",
        )
    return out


def normalise_credential(
    *,
    kubeconfig: Optional[str],
    token: Optional[str],
    ca_data: Optional[str],
    context: Optional[str],
    endpoint: str,
) -> tuple[str, dict[str, Any]]:
    """Return ``(credential_type, normalised credential)`` from the request body."""
    if bool(kubeconfig) == bool(token):
        raise KubeCredentialError("provide exactly one of 'kubeconfig' or 'token'")
    if kubeconfig:
        cred = parse_kubeconfig(kubeconfig, context)
        ctype = "kubeconfig"
    else:
        cred = {"server": endpoint, "token": str(token).strip()}
        if ca_data:
            cred["ca_pem"] = _b64_pem(ca_data, "ca_data")
        ctype = "token"
    parts = urlsplit(cred["server"])
    if parts.scheme != "https" or not parts.hostname:
        raise KubeCredentialError("the Kubernetes API server must be an https:// URL")
    return ctype, cred


def store_credential(cluster: KubernetesCluster, ctype: str, cred: dict[str, Any]) -> None:
    cluster.credential_encrypted = encrypt_secret_json(cred)
    cluster.credential_type = ctype
    cluster.credential_set_at = datetime.now(timezone.utc)
    cluster.endpoint = cred["server"][:255]


def load_credential(cluster: KubernetesCluster) -> dict[str, Any]:
    """Decrypt the stored credential; raises SecretUnreadable (never falls back)."""
    cred = decrypt_secret_json(cluster.credential_encrypted, required=True)
    if not isinstance(cred, dict) or not cred.get("server"):
        raise SecretUnreadable("invalid_json", "stored credential has no server")
    return cred


# ---------------------------------------------------------------------------
# Pinned, TLS-verified client
# ---------------------------------------------------------------------------


def _ssl_context(cred: dict[str, Any]) -> ssl.SSLContext:
    if os.getenv("PYSOAR_KUBE_VERIFY_TLS", "true").strip().lower() == "false":
        logger.warning("kube_tls_verification_disabled", server=cred.get("server"))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif cred.get("ca_pem"):
        ctx = ssl.create_default_context(cadata=cred["ca_pem"])
    elif os.getenv("PYSOAR_KUBE_CA_BUNDLE"):
        ctx = ssl.create_default_context(cafile=os.environ["PYSOAR_KUBE_CA_BUNDLE"])
    else:
        ctx = ssl.create_default_context()
    if cred.get("client_cert_pem") and cred.get("client_key_pem"):
        # ssl only loads a client certificate from files: write both to a
        # private temporary directory, load them, and remove them at once.
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = os.path.join(tmp, "client.crt")
            key_path = os.path.join(tmp, "client.key")
            with open(cert_path, "w", encoding="utf-8") as fh:
                fh.write(cred["client_cert_pem"])
            with open(key_path, "w", encoding="utf-8") as fh:
                fh.write(cred["client_key_pem"])
            os.chmod(key_path, 0o600)
            ctx.load_cert_chain(cert_path, key_path)
    return ctx


def _default_transport(ctx: ssl.SSLContext) -> httpx.AsyncBaseTransport:
    return httpx.AsyncHTTPTransport(verify=ctx)


#: Builds the inner transport under PinnedTransport. Tests replace it with an
#: ``httpx.MockTransport``; the pinning layer stays in place.
transport_factory: Callable[[ssl.SSLContext], httpx.AsyncBaseTransport] = _default_transport


class KubeClient:
    """Read-only Kubernetes API client: pinned, TLS-verified, paginated."""

    def __init__(self, cred: dict[str, Any]) -> None:
        self.cred = cred
        self.server = cred["server"].rstrip("/")
        self.http: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "KubeClient":
        try:
            await resolve_and_vet(self.server)
        except OutboundTargetRefused as exc:
            raise KubeAccessError("outbound_refused", str(exc)) from exc
        try:
            ctx = _ssl_context(self.cred)
        except (ssl.SSLError, OSError, ValueError) as exc:
            raise KubeAccessError("tls_setup_failed", str(exc)) from exc
        headers = {"Accept": "application/json"}
        if self.cred.get("token"):
            headers["Authorization"] = f"Bearer {self.cred['token']}"
        self.http = httpx.AsyncClient(
            base_url=self.server,
            headers=headers,
            timeout=HTTP_TIMEOUT,
            follow_redirects=False,
            transport=PinnedTransport(inner=transport_factory(ctx)),
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self.http is not None:
            await self.http.aclose()

    async def get_json(self, path: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        assert self.http is not None
        try:
            resp = await self.http.get(path, params=params)
        except httpx.HTTPError as exc:
            raise KubeAccessError("unreachable", f"GET {path}: {type(exc).__name__}: {exc}") from exc
        if resp.status_code in (401, 403):
            raise KubeAccessError("forbidden", f"GET {path}: HTTP {resp.status_code}")
        if resp.status_code != 200:
            raise KubeAccessError("http_error", f"GET {path}: HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise KubeAccessError("invalid_response", f"GET {path}: not JSON") from exc
        if not isinstance(body, dict):
            raise KubeAccessError("invalid_response", f"GET {path}: not a JSON object")
        return body

    async def list_all(self, path: str) -> tuple[list[dict[str, Any]], bool]:
        """All items of a list endpoint, following ``continue``; (items, truncated)."""
        items: list[dict[str, Any]] = []
        token: Optional[str] = None
        while True:
            params: dict[str, Any] = {"limit": PAGE_LIMIT}
            if token:
                params["continue"] = token
            body = await self.get_json(path, params)
            batch = [i for i in (body.get("items") or []) if isinstance(i, dict)]
            items.extend(batch)
            token = (body.get("metadata") or {}).get("continue")
            if len(items) >= MAX_ITEMS_PER_KIND:
                return items[:MAX_ITEMS_PER_KIND], bool(token) or len(items) > MAX_ITEMS_PER_KIND
            if not token:
                return items, False


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

RESOURCES: dict[str, str] = {
    "nodes": "/api/v1/nodes",
    "namespaces": "/api/v1/namespaces",
    "pods": "/api/v1/pods",
    "serviceaccounts": "/api/v1/serviceaccounts",
    "clusterrolebindings": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
    "clusterroles": "/apis/rbac.authorization.k8s.io/v1/clusterroles",
    "roles": "/apis/rbac.authorization.k8s.io/v1/roles",
    "networkpolicies": "/apis/networking.k8s.io/v1/networkpolicies",
    "validatingwebhooks": "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
}


@dataclass
class ClusterSnapshot:
    version: Optional[str]
    data: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    truncated: set[str] = field(default_factory=set)
    errors: dict[str, str] = field(default_factory=dict)


async def collect_snapshot(client: KubeClient) -> ClusterSnapshot:
    """Read every resource the checks need. ``/version`` failing aborts the run."""
    version_doc = await client.get_json("/version")
    snap = ClusterSnapshot(version=str(version_doc.get("gitVersion") or "") or None)
    for kind, path in RESOURCES.items():
        try:
            items, truncated = await client.list_all(path)
        except KubeAccessError as exc:
            if exc.reason in ("unreachable",):
                raise
            snap.errors[kind] = str(exc)
            continue
        snap.data[kind] = items
        if truncated:
            snap.truncated.add(kind)
    return snap


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@dataclass
class CheckOutcome:
    status: str  # pass | fail | not_assessed
    reason: str
    # image ref (or None for cluster-wide) -> offending resources
    offenders: dict[Optional[str], list[str]] = field(default_factory=dict)
    resource_type: str = "Cluster"


def _meta(obj: dict[str, Any]) -> dict[str, Any]:
    return obj.get("metadata") or {}


def _workload_pods(pods: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [p for p in pods if _meta(p).get("namespace") not in SYSTEM_NAMESPACES]


def _containers(pod: dict[str, Any]) -> list[dict[str, Any]]:
    spec = pod.get("spec") or {}
    return [c for c in (spec.get("containers") or []) + (spec.get("initContainers") or []) if isinstance(c, dict)]


def _sc(container: dict[str, Any]) -> dict[str, Any]:
    return container.get("securityContext") or {}


def _caps(container: dict[str, Any]) -> dict[str, Any]:
    return _sc(container).get("capabilities") or {}


def _pod_check(pred: Callable[[dict[str, Any], dict[str, Any]], bool]) -> Callable[[ClusterSnapshot], CheckOutcome]:
    """A workload check: ``pred(pod, container)`` True means the container offends."""

    def run(snap: ClusterSnapshot) -> CheckOutcome:
        offenders: dict[Optional[str], list[str]] = {}
        for pod in _workload_pods(snap.data["pods"]):
            meta = _meta(pod)
            for c in _containers(pod):
                if pred(pod, c):
                    offenders.setdefault(str(c.get("image") or "unknown"), []).append(
                        f"{meta.get('namespace')}/{meta.get('name')}:{c.get('name')}",
                    )
        return CheckOutcome(
            "fail" if offenders else "pass",
            "offending containers found" if offenders else "no workload container offends",
            offenders,
            "Pod",
        )

    return run


def _pod_spec_flag(flag: str) -> Callable[[dict[str, Any], dict[str, Any]], bool]:
    return lambda pod, _c: bool((pod.get("spec") or {}).get(flag))


def _runs_as_root(pod: dict[str, Any], c: dict[str, Any]) -> bool:
    pod_sc = (pod.get("spec") or {}).get("securityContext") or {}
    non_root = _sc(c).get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
    uid = _sc(c).get("runAsUser", pod_sc.get("runAsUser"))
    return not (non_root is True or (isinstance(uid, int) and uid > 0))


def _keeps_net_raw(_pod: dict[str, Any], c: dict[str, Any]) -> bool:
    drop = {str(x).upper() for x in (_caps(c).get("drop") or [])}
    return not ({"ALL", "NET_RAW"} & drop)


def _uses_host_path(pod: dict[str, Any], _c: dict[str, Any]) -> bool:
    return any(isinstance(v, dict) and v.get("hostPath") for v in (pod.get("spec") or {}).get("volumes") or [])


def _uses_host_port(_pod: dict[str, Any], c: dict[str, Any]) -> bool:
    return any(isinstance(p, dict) and p.get("hostPort") for p in c.get("ports") or [])


def _secret_env(_pod: dict[str, Any], c: dict[str, Any]) -> bool:
    for env in c.get("env") or []:
        if isinstance(env, dict) and ((env.get("valueFrom") or {}).get("secretKeyRef")):
            return True
    return any(isinstance(e, dict) and e.get("secretRef") for e in c.get("envFrom") or [])


def _check_cluster_admin(snap: ClusterSnapshot) -> CheckOutcome:
    bad: list[str] = []
    for crb in snap.data["clusterrolebindings"]:
        if (crb.get("roleRef") or {}).get("name") != "cluster-admin":
            continue
        name = str(_meta(crb).get("name"))
        if name.startswith("system:"):
            continue
        subjects = [
            f"{s.get('kind')}:{s.get('name')}"
            for s in crb.get("subjects") or []
            if isinstance(s, dict) and not str(s.get("name", "")).startswith("system:")
        ]
        if subjects:
            bad.append(f"{name} -> {', '.join(subjects)}")
    return CheckOutcome(
        "fail" if bad else "pass",
        "non-system subjects are bound to cluster-admin" if bad else "only system subjects hold cluster-admin",
        {None: bad} if bad else {},
        "ClusterRoleBinding",
    )


def _check_wildcards(snap: ClusterSnapshot) -> CheckOutcome:
    bad: list[str] = []
    for kind in ("clusterroles", "roles"):
        for role in snap.data[kind]:
            meta = _meta(role)
            name = str(meta.get("name"))
            if name.startswith("system:") or name == "cluster-admin":
                continue
            for rule in role.get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                if any("*" in (rule.get(k) or []) for k in ("verbs", "resources", "apiGroups")):
                    ns = meta.get("namespace")
                    bad.append(f"{kind[:-1]} {ns + '/' if ns else ''}{name}")
                    break
    return CheckOutcome(
        "fail" if bad else "pass",
        "roles grant wildcard verbs, resources or apiGroups" if bad else "no non-system role uses wildcards",
        {None: bad} if bad else {},
        "Role",
    )


def _check_default_sa(snap: ClusterSnapshot) -> CheckOutcome:
    bad = [
        f"{_meta(sa).get('namespace')}/default"
        for sa in snap.data["serviceaccounts"]
        if _meta(sa).get("name") == "default"
        and _meta(sa).get("namespace") not in SYSTEM_NAMESPACES
        and sa.get("automountServiceAccountToken") is not False
    ]
    return CheckOutcome(
        "fail" if bad else "pass",
        "default service accounts mount their token" if bad else "default service accounts set automountServiceAccountToken: false",
        {None: bad} if bad else {},
        "ServiceAccount",
    )


def _check_policy_control(snap: ClusterSnapshot) -> CheckOutcome:
    hooks = [
        str(_meta(h).get("name"))
        for h in snap.data["validatingwebhooks"]
        if any(k in str(_meta(h).get("name", "")).lower() for k in ("gatekeeper", "kyverno"))
    ]
    unlabelled = [
        str(_meta(ns).get("name"))
        for ns in snap.data["namespaces"]
        if _meta(ns).get("name") not in SYSTEM_NAMESPACES
        and "pod-security.kubernetes.io/enforce" not in (_meta(ns).get("labels") or {})
    ]
    if hooks:
        return CheckOutcome("pass", f"policy engine admission webhooks present: {', '.join(hooks[:5])}")
    if not unlabelled:
        return CheckOutcome("pass", "every workload namespace enforces a Pod Security Admission level")
    return CheckOutcome(
        "fail",
        "no Gatekeeper/Kyverno webhook and namespaces without a pod-security.kubernetes.io/enforce label",
        {None: unlabelled},
        "Namespace",
    )


def _check_network_policies(snap: ClusterSnapshot) -> CheckOutcome:
    covered = {_meta(p).get("namespace") for p in snap.data["networkpolicies"]}
    bad = [
        str(_meta(ns).get("name"))
        for ns in snap.data["namespaces"]
        if _meta(ns).get("name") not in SYSTEM_NAMESPACES and _meta(ns).get("name") not in covered
    ]
    return CheckOutcome(
        "fail" if bad else "pass",
        "namespaces without any NetworkPolicy" if bad else "every workload namespace has a NetworkPolicy",
        {None: bad} if bad else {},
        "Namespace",
    )


def _check_default_namespace(snap: ClusterSnapshot) -> CheckOutcome:
    offenders: dict[Optional[str], list[str]] = {}
    for pod in snap.data["pods"]:
        meta = _meta(pod)
        if meta.get("namespace") != "default":
            continue
        for c in _containers(pod):
            offenders.setdefault(str(c.get("image") or "unknown"), []).append(f"default/{meta.get('name')}:{c.get('name')}")
    return CheckOutcome(
        "fail" if offenders else "pass",
        "workloads run in the default namespace" if offenders else "no pod runs in the default namespace",
        offenders,
        "Pod",
    )


def _apiserver_flag_check(evaluate: Callable[[dict[str, str]], Optional[bool]], what: str) -> Callable[[ClusterSnapshot], CheckOutcome]:
    """Evaluate a kube-apiserver flag read from its static pod, when visible."""

    def run(snap: ClusterSnapshot) -> CheckOutcome:
        apiservers = [
            p for p in snap.data["pods"]
            if _meta(p).get("namespace") == "kube-system"
            and ((_meta(p).get("labels") or {}).get("component") == "kube-apiserver")
        ]
        if not apiservers:
            return CheckOutcome(
                "not_assessed",
                "kube-apiserver is not visible as a pod (managed control plane); its flags cannot be read through the API",
            )
        bad: list[str] = []
        for pod in apiservers:
            for c in _containers(pod):
                flags: dict[str, str] = {}
                for arg in (c.get("command") or []) + (c.get("args") or []):
                    text = str(arg)
                    if text.startswith("--"):
                        key, _, value = text[2:].partition("=")
                        flags[key] = value
                verdict = evaluate(flags)
                if verdict is False:
                    bad.append(f"kube-system/{_meta(pod).get('name')}")
        return CheckOutcome(
            "fail" if bad else "pass",
            f"kube-apiserver {what}" + (" is not satisfied" if bad else " is satisfied"),
            {None: bad} if bad else {},
            "Pod",
        )

    return run


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    title: str
    severity: str
    needs: tuple[str, ...]
    run: Callable[[ClusterSnapshot], CheckOutcome]

    @property
    def slug(self) -> str:
        return "cis_" + self.check_id.replace(".", "_")


CIS_CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec("1.2.1", "Ensure that the --anonymous-auth argument is set to false", "critical", ("pods",),
              _apiserver_flag_check(lambda f: f.get("anonymous-auth") == "false", "--anonymous-auth=false")),
    CheckSpec("1.2.6", "Ensure that the --authorization-mode argument is not set to AlwaysAllow", "critical", ("pods",),
              _apiserver_flag_check(lambda f: "AlwaysAllow" not in f.get("authorization-mode", "AlwaysAllow").split(","),
                                    "--authorization-mode without AlwaysAllow")),
    CheckSpec("1.2.8", "Ensure that the --authorization-mode argument includes RBAC", "high", ("pods",),
              _apiserver_flag_check(lambda f: "RBAC" in f.get("authorization-mode", "").split(","),
                                    "--authorization-mode including RBAC")),
    CheckSpec("5.1.1", "Ensure that the cluster-admin role is only used where required", "high",
              ("clusterrolebindings",), _check_cluster_admin),
    CheckSpec("5.1.3", "Minimize wildcard use in Roles and ClusterRoles", "medium",
              ("clusterroles", "roles"), _check_wildcards),
    CheckSpec("5.1.5", "Ensure that default service accounts are not actively used", "medium",
              ("serviceaccounts",), _check_default_sa),
    CheckSpec("5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place", "high",
              ("namespaces", "validatingwebhooks"), _check_policy_control),
    CheckSpec("5.2.2", "Minimize the admission of privileged containers", "critical", ("pods",),
              _pod_check(lambda _p, c: bool(_sc(c).get("privileged")))),
    CheckSpec("5.2.3", "Minimize the admission of containers wishing to share the host process ID namespace", "high",
              ("pods",), _pod_check(_pod_spec_flag("hostPID"))),
    CheckSpec("5.2.4", "Minimize the admission of containers wishing to share the host IPC namespace", "high",
              ("pods",), _pod_check(_pod_spec_flag("hostIPC"))),
    CheckSpec("5.2.5", "Minimize the admission of containers wishing to share the host network namespace", "high",
              ("pods",), _pod_check(_pod_spec_flag("hostNetwork"))),
    CheckSpec("5.2.6", "Minimize the admission of containers with allowPrivilegeEscalation", "medium", ("pods",),
              _pod_check(lambda _p, c: _sc(c).get("allowPrivilegeEscalation") is not False)),
    CheckSpec("5.2.7", "Minimize the admission of root containers", "medium", ("pods",), _pod_check(_runs_as_root)),
    CheckSpec("5.2.8", "Minimize the admission of containers with the NET_RAW capability", "medium", ("pods",),
              _pod_check(_keeps_net_raw)),
    CheckSpec("5.2.9", "Minimize the admission of containers with added capabilities", "medium", ("pods",),
              _pod_check(lambda _p, c: bool(_caps(c).get("add")))),
    CheckSpec("5.2.12", "Minimize the admission of HostPath volumes", "high", ("pods",), _pod_check(_uses_host_path)),
    CheckSpec("5.2.13", "Minimize the admission of containers which use HostPorts", "medium", ("pods",),
              _pod_check(_uses_host_port)),
    CheckSpec("5.3.2", "Ensure that all Namespaces have NetworkPolicies defined", "high",
              ("namespaces", "networkpolicies"), _check_network_policies),
    CheckSpec("5.4.1", "Prefer using secrets as files over secrets as environment variables", "medium", ("pods",),
              _pod_check(_secret_env)),
    CheckSpec("5.7.4", "The default namespace should not be used", "low", ("pods",), _check_default_namespace),
)

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def evaluate_checks(snap: Optional[ClusterSnapshot], unavailable_reason: Optional[str]) -> list[tuple[CheckSpec, CheckOutcome]]:
    """Run every check. With no snapshot every check is not_assessed with the reason."""
    out: list[tuple[CheckSpec, CheckOutcome]] = []
    for spec in CIS_CHECKS:
        if snap is None:
            out.append((spec, CheckOutcome("not_assessed", unavailable_reason or "not assessed")))
            continue
        missing = [k for k in spec.needs if k not in snap.data]
        if missing:
            reasons = "; ".join(snap.errors.get(k, f"{k} not read") for k in missing)
            out.append((spec, CheckOutcome("not_assessed", f"cannot read {', '.join(missing)}: {reasons}")))
            continue
        outcome = spec.run(snap)
        truncated = [k for k in spec.needs if k in snap.truncated]
        if outcome.status == "pass" and truncated:
            outcome = CheckOutcome(
                "not_assessed",
                f"listing of {', '.join(truncated)} was truncated at {MAX_ITEMS_PER_KIND} items; "
                "a pass cannot be asserted on partial data",
            )
        out.append((spec, outcome))
    return out


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def finding_dedupe_key(cluster_id: str, image_ref: Optional[str], check_id: str) -> str:
    return hashlib.sha256(f"{cluster_id}|{image_ref or ''}|{check_id}".encode("utf-8")).hexdigest()


def _describe(spec: CheckSpec, outcome: CheckOutcome, image_ref: Optional[str], resources: list[str]) -> str:
    shown = ", ".join(resources[:MAX_OFFENDERS_IN_DESCRIPTION])
    more = len(resources) - MAX_OFFENDERS_IN_DESCRIPTION
    tail = f" (+{more} more)" if more > 0 else ""
    subject = f" for image {image_ref}" if image_ref else ""
    return f"CIS {spec.check_id} {spec.title}: {outcome.reason}{subject}. Affected: {shown}{tail}"


async def persist_results(
    db: AsyncSession,
    cluster: KubernetesCluster,
    results: list[tuple[CheckSpec, CheckOutcome]],
    *,
    now: datetime,
) -> dict[str, int]:
    """Upsert check results and (cluster, image, check)-deduplicated findings."""
    org_id = cluster.organization_id
    stored = {
        r.check_id: r
        for r in (await db.execute(
            select(K8sCheckResult).where(
                K8sCheckResult.cluster_id == cluster.id,
                K8sCheckResult.organization_id == org_id,
            ),
        )).scalars()
    }
    existing = {
        f.dedupe_key: f
        for f in (await db.execute(
            select(K8sSecurityFinding).where(
                K8sSecurityFinding.cluster_id == cluster.id,
                K8sSecurityFinding.organization_id == org_id,
                K8sSecurityFinding.dedupe_key.is_not(None),
            ),
        )).scalars()
    }
    counts = {"pass": 0, "fail": 0, "not_assessed": 0, "findings_new": 0, "findings_updated": 0, "findings_resolved": 0}
    for spec, outcome in results:
        counts[outcome.status] = counts.get(outcome.status, 0) + 1
        row = stored.get(spec.check_id)
        evidence = {
            "offender_count": sum(len(v) for v in outcome.offenders.values()),
            "images": sorted(k for k in outcome.offenders if k)[:50],
            "benchmark": CIS_BENCHMARK,
        }
        if row is None:
            row = K8sCheckResult(
                cluster_id=cluster.id, check_id=spec.check_id, organization_id=org_id,
                title=spec.title, status=outcome.status,
            )
            db.add(row)
        row.title = spec.title
        row.status = outcome.status
        row.reason = outcome.reason[:4000]
        row.evidence = evidence
        row.evaluated_at = now
        if outcome.status == "not_assessed":
            continue  # findings for an unassessed check are left untouched

        failing_keys: set[str] = set()
        for image_ref, resources in outcome.offenders.items():
            key = finding_dedupe_key(cluster.id, image_ref, spec.check_id)
            failing_keys.add(key)
            namespaces = {r.split("/", 1)[0] for r in resources if "/" in r}
            finding = existing.get(key)
            if finding is None:
                finding = K8sSecurityFinding(
                    cluster_id=cluster.id,
                    organization_id=org_id,
                    finding_type=spec.slug,
                    check_id=spec.check_id,
                    image_ref=(image_ref or None) and image_ref[:512],
                    dedupe_key=key,
                    status="open",
                    detected_at=now,
                    severity=spec.severity,
                    resource_type=outcome.resource_type,
                    resource_name=(resources[0] if resources else cluster.name)[:255],
                    description="",
                )
                db.add(finding)
                existing[key] = finding
                counts["findings_new"] += 1
            else:
                counts["findings_updated"] += 1
                if finding.status == "remediated":
                    finding.status = "open"  # failing again
            finding.severity = spec.severity
            finding.namespace = next(iter(namespaces)) if len(namespaces) == 1 else None
            finding.resource_name = (resources[0] if resources else cluster.name)[:255]
            finding.description = _describe(spec, outcome, image_ref, resources)
            finding.cis_benchmark_id = spec.check_id
            finding.last_seen_at = now
        for key, finding in existing.items():
            if finding.check_id == spec.check_id and key not in failing_keys and finding.status == "open":
                finding.status = "remediated"
                finding.remediation = (
                    f"CIS {spec.check_id} no longer fails for this resource "
                    f"(observed on {now.date().isoformat()} through the Kubernetes API)"
                )
                counts["findings_resolved"] += 1
    await db.flush()
    return counts


async def run_cis_audit(db: AsyncSession, cluster: KubernetesCluster) -> dict[str, Any]:
    """Assess ``cluster`` against the Kubernetes API and store the results.

    Returns a summary; never raises for an unreachable cluster (the failure is
    recorded on the cluster and every check is not_assessed).
    """
    now = datetime.now(timezone.utc)
    snap: Optional[ClusterSnapshot] = None
    reason: Optional[str] = None
    if not cluster.credential_encrypted:
        reason = (
            "no Kubernetes API credential is installed for this cluster "
            "(PUT /container-security/clusters/{id}/credential)"
        )
        cluster.assessment_status = "not_assessed"
        cluster.assessment_error = reason
    else:
        try:
            cred = load_credential(cluster)
            async with KubeClient(cred) as client:
                snap = await collect_snapshot(client)
        except SecretUnreadable as exc:
            reason = f"stored credential cannot be read: {exc.reason}"
        except KubeAccessError as exc:
            reason = f"Kubernetes API not readable ({exc.reason}): {exc.detail}"[:2000]
        if snap is None:
            cluster.assessment_status = "failed"
            cluster.assessment_error = reason
            logger.warning("k8s_cis_audit_failed", cluster_id=cluster.id, reason=reason)

    results = evaluate_checks(snap, reason)
    counts = await persist_results(db, cluster, results, now=now)
    assessed = counts["pass"] + counts["fail"]
    cis_pct: Optional[float] = round(counts["pass"] / assessed * 100, 1) if assessed else None
    if snap is not None:
        cluster.assessment_status = "assessed"
        cluster.assessment_error = (
            "; ".join(f"{k}: {v}" for k, v in snap.errors.items())[:2000] or None
        )
        cluster.last_audit = now
        if snap.version:
            cluster.version = snap.version[:50]
        if "nodes" in snap.data and "nodes" not in snap.truncated:
            cluster.node_count = len(snap.data["nodes"])
        if "namespaces" in snap.data and "namespaces" not in snap.truncated:
            cluster.namespace_count = len(snap.data["namespaces"])
        if "pods" in snap.data and "pods" not in snap.truncated:
            cluster.pod_count = len(snap.data["pods"])
        cluster.compliance_score = round(cis_pct) if cis_pct is not None else 0
        cluster.risk_score = min(
            100, sum(SEVERITY_WEIGHT.get(spec.severity, 0) for spec, o in results if o.status == "fail"),
        )
    await db.flush()
    return {
        "assessment_status": cluster.assessment_status,
        "reason": reason,
        "checks": {k: counts[k] for k in ("pass", "fail", "not_assessed")},
        "findings_new": counts["findings_new"],
        "findings_updated": counts["findings_updated"],
        "findings_resolved": counts["findings_resolved"],
        "cis_compliance": cis_pct,
        "benchmark": CIS_BENCHMARK,
    }

