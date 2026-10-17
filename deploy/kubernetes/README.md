# PySOAR on Kubernetes

The supported way to run PySOAR on Kubernetes is the Helm chart in
[`deploy/helm/pysoar`](../helm/pysoar).

**Status: render-validated, not yet applied to a cluster.** On every change,
`.github/workflows/helm.yml` runs `helm lint`, `helm template` (default values
and `values-example-production.yaml`, plus the in-cluster development and
Cilium variants) and `kubeconform -strict` against the Kubernetes 1.26 and
1.29 API schemas. That proves the manifests are well-formed and schema-valid.
It does not prove the release installs, upgrades or serves traffic on a real
cluster: no cluster install has been done yet. Separately, the container
settings the chart relies on were exercised with Docker on 2026-10-17 (see
"What was checked outside the chart" below).

Production today runs on docker compose (see `docker-compose.yml`); the chart
is the Kubernetes packaging of the same services.

## What the chart deploys

| Component | Kind | Image and command |
|---|---|---|
| api | Deployment, Service (`<release>-api`, 8000), HPA, PDB | backend image, its CMD (`uvicorn src.main:app --host 0.0.0.0 --port 8000`) |
| worker | Deployment (optional PDB) | backend image, `celery -A src.workers.celery_app worker --loglevel=info --concurrency=2 --max-memory-per-child=300000 --max-tasks-per-child=50` (as in `docker-compose.yml`), `PYSOAR_DB_POOL=null`, memory limit 1536Mi |
| worker-investigations | Deployment, off by default | backend image, the same worker with `-Q investigations --max-memory-per-child=400000` (the dedicated worker described in `src/workers/celery_app.py`) |
| scheduler | Deployment, 1 replica, `Recreate` | backend image, `celery -A src.workers.celery_app beat --loglevel=info --schedule=/tmp/celerybeat-schedule`, `PYSOAR_DB_POOL=null` |
| frontend | Deployment, Service (`<release>-frontend`, 80), PDB | frontend image (nginx serving the dist baked in by `frontend/Dockerfile`) with a chart ConfigMap replacing `/etc/nginx/conf.d/default.conf` |
| migrate | Job, Helm `pre-install,pre-upgrade` hook | backend image, see "Migrations" |
| ingress | Ingress | `/api` to the api Service, `/` to the frontend Service, TLS from a named Secret, class configurable |
| syslog | Service, off by default | UDP and TCP `SIEM_SYSLOG_PORT` (5514) on the api pods |
| data | PersistentVolumeClaim (RWX, kept on uninstall) | mounted on api and worker at `/app/uploads`, `/app/data`, `/app/backups`, `/app/archives` |
| config | ConfigMap `<release>-config` | non-secret settings (below) |
| egress policy | NetworkPolicy or CiliumNetworkPolicy, off by default | api, worker, scheduler and migrate pods |
| dev Postgres and Redis | StatefulSets and Services, off by default | **development and evaluation only, not for production** |

Not in the chart: Flower, Prometheus, Grafana and the simulation agent from
`docker-compose.yml`, and the edge nginx of `nginx/nginx.conf` (the ingress
controller takes its place; see "Differences from docker compose").

The base manifests that lived in `deploy/kubernetes/base/` (HPA, PDB, LLM
egress NetworkPolicy) are folded into the chart as `templates/hpa.yaml`,
`templates/pdb.yaml` and `templates/networkpolicy-egress.yaml`, behind
`api.autoscaling`, `api.pdb` and `networkPolicy.egress`. The files in
`base/` are no longer the maintained copy.

## Before you install

1. **Images.** The chart defaults to `ghcr.io/jacobpeart-cyber/pysoar-backend`
   and `ghcr.io/jacobpeart-cyber/pysoar-frontend`, tag = the chart's
   `appVersion` (the repository `VERSION` file, currently 0.9.0). These images
   are pushed by `.github/workflows/release.yml` when a `v*` tag is cut; until
   a release exists they are not in the registry, so build and push your own
   and set `image.*.repository` / `tag` (or `digest`). Private packages need
   `imagePullSecrets`.
2. **Postgres 15 and Redis 7**, reachable from the cluster (managed services
   in production).
3. **A namespace and the Secret.** The chart never creates or templates
   secret values; `secret.existingSecret` names a Secret you create. Every key
   in it becomes an environment variable of the api, worker, scheduler and
   migrate containers. Do not put ConfigMap keys in it.
4. **A TLS certificate** for the ingress host, in a `kubernetes.io/tls`
   Secret named by `ingress.tls.secretName` (default `<release>-tls`), or a
   cert-manager issuer annotation that fills it.
5. **Storage.** A ReadWriteMany storage class for the data claim (several api
   pods on different nodes mount it), or `persistence.existingClaim`. The
   volume must be writable by UID/GID 999 (the `pysoar` user of the backend
   image); the pods set `fsGroup: 999`, but some network filesystems (NFS,
   EFS access points) ignore fsGroup and need their ownership set on the
   storage side. With `persistence.enabled=false` the paths are `emptyDir`
   and uploads, evidence and STIG content are lost when a pod restarts.

### The Secret

Required keys (names from `src/core/config.py`; the api refuses to start in
production without a strong `SECRET_KEY` / `JWT_SECRET_KEY` and a set
`ENCRYPTION_MASTER_KEY`, see `src/main.py`):

| Key | Content |
|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://USER:PASSWORD@HOST:5432/DB`. TLS goes in the URL (`?ssl=require`): `DATABASE_SSL_MODE` is validated but not applied to the engine. |
| `REDIS_URL` | Redis database 0 |
| `CELERY_BROKER_URL` | Redis database 1 |
| `CELERY_RESULT_BACKEND` | Redis database 2 |
| `SECRET_KEY` | random, e.g. `secrets.token_urlsafe(64)` |
| `JWT_SECRET_KEY` | random, different from `SECRET_KEY` |
| `ENCRYPTION_MASTER_KEY` | base64 of exactly 32 random bytes (`openssl rand -base64 32`); it encrypts stored credentials, so losing it loses them |
| `FIRST_ADMIN_PASSWORD` | initial password of `config.firstAdminEmail`, created when the users table is empty; the account must change it at first login |

Optional keys: any other secret setting in `src/core/config.py`, for example
`SMTP_USER`, `SMTP_PASSWORD`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`,
`SHODAN_API_KEY`, `GREYNOISE_API_KEY`, `URLSCAN_API_KEY`, `HIBP_API_KEY`,
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`,
`ELASTICSEARCH_API_KEY`, `SPLUNK_TOKEN`, `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`.

```bash
kubectl create namespace pysoar

kubectl -n pysoar create secret generic pysoar-env \
  --from-literal=DATABASE_URL='postgresql+asyncpg://pysoar:DB_PASSWORD@DB_HOST:5432/pysoar?ssl=require' \
  --from-literal=REDIS_URL='redis://:REDIS_PASSWORD@REDIS_HOST:6379/0' \
  --from-literal=CELERY_BROKER_URL='redis://:REDIS_PASSWORD@REDIS_HOST:6379/1' \
  --from-literal=CELERY_RESULT_BACKEND='redis://:REDIS_PASSWORD@REDIS_HOST:6379/2' \
  --from-literal=SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')" \
  --from-literal=JWT_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')" \
  --from-literal=ENCRYPTION_MASTER_KEY="$(openssl rand -base64 32)" \
  --from-literal=FIRST_ADMIN_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
```

Replace the upper-case placeholders. Store the generated values in your
password manager before you lose the shell; `kubectl get secret` is the only
other copy. A TLS Redis uses `rediss://` (Celery requires an `ssl_cert_reqs`
query parameter on `rediss://` URLs).

If the ghcr.io packages are private:

```bash
kubectl -n pysoar create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=GITHUB_USER --docker-password=GITHUB_TOKEN_WITH_READ_PACKAGES
```

## Values a deployer must set

The chart refuses to render without these:

| Value | Meaning |
|---|---|
| `secret.existingSecret` | the Secret above |
| `publicUrl` | external URL (`PYSOAR_PUBLIC_URL`, used for links in notifications and phishing-simulation tracking; the code's fallback is the PySOAR project's own host) |
| `config.firstAdminEmail` | `FIRST_ADMIN_EMAIL` |
| `ingress.host` | when `ingress.enabled` (default true) |

It also refuses `config.databaseSslMode` values other than `require`,
`verify-full` or `disable` while `config.appEnv` is `production` (the same
rule as `validate_database_ssl_mode` in `src/core/config.py`; the backend
image sets `APP_ENV=production`).

Usually also set: `ingress.className`, `ingress.annotations`,
`ingress.tls.secretName`, `imagePullSecrets`, `image.*.tag` or `digest`,
`persistence.storageClass`, `api.forwardedAllowIps` (the ingress controller
pod CIDR, so uvicorn trusts its `X-Forwarded-For` and rate limits and audit
rows see client addresses; uvicorn reads it as `FORWARDED_ALLOW_IPS`), and
`config.*` (log level, CORS origins, LLM defaults, OT discovery CIDRs,
syslog). Anything else non-secret goes in `config.extra` as `NAME: "value"`.

`values-example-production.yaml` shows a complete production override; its
hostnames, CIDRs and storage class are placeholders.

## Install and upgrade

```bash
helm upgrade --install pysoar deploy/helm/pysoar -n pysoar \
  -f my-values.yaml --wait --timeout 15m
```

### Migrations

The `migrate` Job runs as a `pre-install,pre-upgrade` hook, so new pods never
start against an older schema (an unmigrated database crash-loops the api at
`create_first_admin`). It inspects the database first:

* `alembic_version` table present: `alembic upgrade head`.
* No tables at all (first install): also `alembic upgrade head`. On a
  database with no tables (or only an empty `alembic_version`),
  `alembic/env.py` creates the schema from the models it imports (the same
  tables, columns, indexes and foreign keys as the api's boot-time
  `init_db()` create_all) and stamps head, in one transaction on PostgreSQL;
  the revision chain is not replayed, because revisions 001-006 created
  placeholder tables the later revisions never matched (it stopped at 007,
  `column "ioc_type" does not exist`). It refuses if any model module failed
  to import. `alembic upgrade <rev>` other than head, and `alembic stamp`,
  do not take this path.
* Tables but no `alembic_version`: the Job fails and changes nothing. Stamp
  the revision that matches the schema by hand (`alembic stamp <rev>`) and
  upgrade again.

A failed Job is kept for `kubectl -n pysoar logs job/pysoar-migrate`; a
successful one is deleted. The hook uses the namespace's `default`
ServiceAccount without a token (the chart's own ServiceAccount does not exist
yet during a pre-install hook). When `networkPolicy.egress` is enabled, the
migrate pod is covered by it on upgrades, so the database must be reachable
through `extraEgress`.

Back up the database before every upgrade (`deploy/backup-db.sh` covers the
compose stack; on Kubernetes use your managed database's snapshots).

## Security settings

* Backend pods run as UID/GID 999 (`pysoar`), frontend pods as 101 (`nginx`);
  `runAsNonRoot`, `seccompProfile: RuntimeDefault`,
  `allowPrivilegeEscalation: false`, all capabilities dropped, read-only root
  filesystem. Writable paths are `emptyDir` (`/tmp`, `/app/logs`; for nginx
  `/var/cache/nginx`, `/run`, `/tmp`) or the data claim.
* The frontend nginx listens on 8080 (non-root cannot bind 80) and proxies
  `/api/` and `/api/v1/ws` to `<release>-api.<namespace>.svc`. Its config is
  the hardened `nginx/default.conf` (dotfile and backup-file blocks, CSP,
  `/api/` with a trailing slash so `/api-keys` stays a SPA route), not the
  `frontend/nginx.conf` baked into the image.
* No ServiceAccount token is mounted in any pod; PySOAR does not call the
  Kubernetes API of the cluster it runs in (the container-security scanner
  uses stored per-cluster credentials).
* The chart creates no Secret.
* `networkPolicy.egress` (SC-7, SC-7(5)) is deny-by-default egress for the
  backend pods: cluster DNS, TCP/443 to public address space only (metadata
  service, link-local, loopback, multicast, CGNAT and RFC1918 excluded) and
  whatever you add in `extraEgress`. A managed Postgres or Redis in a private
  subnet, an SMTP relay or an internal SIEM must be listed there, or the pods
  cannot reach them. `flavor: cilium` renders a CiliumNetworkPolicy that pins
  TCP/443 to `llmHosts` by FQDN instead (requires Cilium's DNS proxy); its
  `extraEgress` entries use Cilium's rule format. Integrations that call
  other public HTTPS hosts (VirusTotal, Shodan, ...) are blocked under the
  Cilium flavor unless you add them.
* Ingress-side protections from `nginx/nginx.conf` (per-IP request rate
  limits, 50 MB body size, long WebSocket timeouts, HSTS on API responses)
  are not configured by the chart; set them through `ingress.annotations`
  for your controller (the example file shows the ingress-nginx annotations
  for body size and timeouts). The api's own in-process limiter
  (600 requests per minute per client IP, per pod) still applies.

## In-cluster Postgres and Redis (development only)

`devDependencies.enabled=true` adds single-replica Postgres 15 and Redis 7
StatefulSets, labelled `pysoar.io/not-for-production: "true"`. **Not for
production**: no backups, no TLS, no high availability. The Secret must also
hold `POSTGRES_PASSWORD` and `REDIS_PASSWORD`, `DATABASE_URL` must point at
`<release>-postgres:5432` (user and database `pysoar` by default) and the
Redis URLs at `<release>-redis:6379` with the password. In this mode the
migrate hook is not rendered (it would run before the in-cluster database
exists); the same migration script runs as an init container of the api pod,
so the chart requires `api.autoscaling.enabled=false` and `api.replicas=1`.

## Differences from docker compose

* Migrations run in a hook Job, not by hand after the containers start.
* The frontend serves the dist baked into its image; there is no
  `./frontend/dist` bind mount and no `docker compose restart frontend` step.
  A new frontend is a new image tag.
* Celery beat keeps its schedule file in `/tmp` (`--schedule`) because the
  root filesystem is read-only; it is rebuilt from the code's schedule on
  restart.
* The worker liveness probe pings this pod's own Celery node
  (`-d celery@$HOSTNAME`); compose's check is a broadcast ping.
* `/api/v1/health` returns 200 with `status: degraded` when Postgres or Redis
  is down, so readiness tracks the api process, not its dependencies.

## What was checked outside the chart (Docker, 2026-10-17)

Against a throwaway `postgres:15-alpine` and `redis:7-alpine`, with a backend
image built from the working tree and the local frontend image:

* The rendered migration script, run as UID 999 with a read-only root
  filesystem and all capabilities dropped (the earlier version of the script,
  which bootstrapped an empty database with `init_db()` plus
  `alembic stamp head`): empty database bootstrapped (211 tables, stamped
  `038`); a second run upgrades as a no-op; a database one revision behind
  upgrades `037 -> 038`; tables without `alembic_version` exit 1.
* The current script (empty databases go through `alembic upgrade head`),
  extracted from `helm template` with the production values and run with the
  working tree's Python against throwaway `postgres:15` databases, not in the
  container: empty database built (210 tables plus `alembic_version`,
  stamped `038`) with the same tables, columns, types, nullability, indexes
  and foreign keys as a second database built by the api's `init_db()`; a
  second run is a no-op; a database with one stray table and no
  `alembic_version` exits 1 and is left unchanged.
* The api under the same settings with the chart's mounts: started,
  `GET /api/v1/health` returned `healthy`; the syslog receiver bound 5514 as
  non-root. With root-owned data volumes the simulation-agent token write to
  `/app/data/agent` failed with permission denied, which is why the data
  volume must be writable by GID 999.
* The worker and beat commands under the same settings; both chart liveness
  probe commands succeeded.
* The frontend image as UID 101, read-only, with the chart's nginx config:
  serves `/` and `/api-keys` (SPA), drops `/.env`, and proxies
  `/api/v1/health` to the api by its Service-style name.
* `?ssl=require` in `DATABASE_URL` is honoured (a non-TLS server is refused).
* The dev Postgres (UID 70) and Redis (UID 999) images start read-only and
  non-root with the chart's mounts.

None of this was a Kubernetes run: no kubelet, scheduler, CNI, ingress
controller, storage driver, HPA or Helm hook ordering was exercised.

## Validate locally

```bash
helm lint deploy/helm/pysoar --strict -f deploy/helm/pysoar/values-example-production.yaml
helm template pysoar deploy/helm/pysoar -n pysoar \
  -f deploy/helm/pysoar/values-example-production.yaml > rendered.yaml
kubeconform -strict -summary -kubernetes-version 1.29.0 \
  -schema-location default \
  -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
  rendered.yaml
```

No OPA Gatekeeper or other admission policies exist in this repository, so
none are evaluated against the rendered manifests.
