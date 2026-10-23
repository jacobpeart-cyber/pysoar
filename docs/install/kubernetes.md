# Installing PySOAR on Kubernetes

**Status: the Helm chart is render-validated, not yet applied to a cluster.**
`helm lint`, `helm template` and `kubeconform` pass (in
`.github/workflows/helm.yml`, and again on 2026-10-17 for this guide); no
install, upgrade or rollback has been run on a real cluster. Treat a first
install as a test.

The chart is `deploy/helm/pysoar`. Its full reference (every resource, the
security settings, the migration hook, what was checked with Docker, the
differences from docker compose) is
[deploy/kubernetes/README.md](../../deploy/kubernetes/README.md). This page is
the operator sequence. Environment variables: [environment.md](environment.md).

## Prerequisites

- Kubernetes 1.26 or later (`kubeVersion: ">=1.26.0-0"` in `Chart.yaml`),
  Helm 3, an ingress controller, and a ReadWriteMany storage class (or an
  existing claim) writable by UID/GID 999.
- PostgreSQL 15 and Redis 7 outside the chart (managed services). The chart's
  in-cluster Postgres and Redis (`devDependencies.enabled`) are for
  development only: no backups, no TLS, no HA.
- The images. The chart defaults to `ghcr.io/jacobpeart-cyber/pysoar-backend`
  and `ghcr.io/jacobpeart-cyber/pysoar-frontend` tagged with the chart's
  `appVersion` (`0.9.0`). They exist only after a release has been cut
  ([RELEASING.md](../releases/RELEASING.md)); until then build and push your
  own and set `image.backend` / `image.frontend`.

## 1. Namespace and Secret

The chart never creates secret values. Create one Secret holding every
secret setting; each key becomes an environment variable of the api, worker,
scheduler and migration containers. The required keys and a complete
`kubectl create secret generic` command are in the chart README,
["The Secret"](../../deploy/kubernetes/README.md#the-secret):
`DATABASE_URL`, `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`,
`SECRET_KEY`, `JWT_SECRET_KEY`, `ENCRYPTION_MASTER_KEY`,
`FIRST_ADMIN_PASSWORD`. Optional secret keys are the rows marked Secret = yes
in [environment.md](environment.md).

Database TLS: `config.databaseSslMode` (default `require`) becomes
`DATABASE_SSL_MODE`, which `src/core/database.py` passes to asyncpg as its
`ssl` argument unless `DATABASE_URL` already carries `ssl=` or `sslmode=`.
(The chart README and a comment in `values.yaml` still say the setting is not
applied to the engine; that was true before commit 00a0d45 and is no longer.)

Private ghcr.io packages also need an image pull Secret
(`kubectl create secret docker-registry`, shown in the chart README) listed
in `imagePullSecrets`.

## 2. Values

Start from `deploy/helm/pysoar/values-example-production.yaml` (its hosts,
CIDRs and storage class are placeholders). The chart refuses to render
without `secret.existingSecret`, `publicUrl`, `config.firstAdminEmail` and,
with the ingress enabled, `ingress.host`. Non-secret settings go under
`config` (or `config.extra` as `NAME: "value"` using the names in
[environment.md](environment.md)); they are rendered into the
`<release>-config` ConfigMap.

An on-premises SIEM or other integration on a private network (Splunk,
Elasticsearch, QRadar, an internal IdP) is refused until its network is in
`config.outboundPrivateAllowlist` (a list of CIDRs, default empty, rendered
as the JSON list `OUTBOUND_PRIVATE_ALLOWLIST`; not through `config.extra`,
which the chart refuses for this key). With `networkPolicy.egress.enabled`
the same network also needs an `extraEgress` rule. Details:
["Private integration targets"](../../deploy/kubernetes/README.md#private-integration-targets-configoutboundprivateallowlist).
This value was checked by rendering only (2026-10-22: `helm lint --strict`,
`helm template` with the example values and with
`--set-json 'config.outboundPrivateAllowlist=["10.20.0.0/24","fd12:3456::/48"]'`,
`kubeconform -strict` on that render: 19 valid); it has not been applied to a
cluster.

Check the render before installing:

```sh
helm lint deploy/helm/pysoar --strict -f my-values.yaml
helm template pysoar deploy/helm/pysoar -n pysoar -f my-values.yaml > rendered.yaml
```

## 3. Install

```sh
helm upgrade --install pysoar deploy/helm/pysoar -n pysoar -f my-values.yaml --wait --timeout 15m
```

The `pysoar-migrate` Job runs before any pod starts (Helm
`pre-install,pre-upgrade` hook). On an empty database it runs
`alembic upgrade head`, which builds the schema from the models and stamps
head; on a database with `alembic_version` it applies pending revisions; on
a database with tables but no `alembic_version` it fails without changing
anything. A failed Job is kept for its logs:

```sh
kubectl -n pysoar logs job/pysoar-migrate
```

## 4. Check it

```sh
kubectl -n pysoar get pods -l app.kubernetes.io/instance=pysoar
kubectl -n pysoar port-forward svc/pysoar-api 8000:8000
curl -s http://127.0.0.1:8000/api/v1/health
```

`healthy` with the expected `version` and `commit` means the api reaches
Postgres and Redis; `degraded` means it does not (readiness stays green in
that state, see the chart README). Then sign in through the ingress host as
`config.firstAdminEmail` with `FIRST_ADMIN_PASSWORD`.

## Upgrades and backups

See [upgrade.md](../operations/upgrade.md#kubernetes) and
[backup-restore.md](../operations/backup-restore.md#kubernetes).
`deploy/backup-db.sh` and `deploy/restore-db.sh` drive a docker compose
stack and do not apply here.

## What was validated for this page (2026-10-17)

- `helm lint deploy/helm/pysoar --strict -f deploy/helm/pysoar/values-example-production.yaml`:
  1 chart linted, 0 failed (Helm v3.17.3).
- `helm template` with the example production values: 19 resources
  (5 Deployments, 3 Services, 3 PodDisruptionBudgets, 2 ConfigMaps, 1 each of
  HorizontalPodAutoscaler, Ingress, Job, NetworkPolicy,
  PersistentVolumeClaim, ServiceAccount); `helm template` with no values
  fails, as documented, on the first required value.
- `kubeconform -strict -kubernetes-version 1.29.0` on that render: 19 valid,
  0 invalid.
- Not run: any cluster install, the migration hook ordering, the ingress, the
  storage class, the HPA, a `helm rollback`.
