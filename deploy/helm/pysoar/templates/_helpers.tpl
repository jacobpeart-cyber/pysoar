{{/* Chart name, truncated to the DNS label limit. */}}
{{- define "pysoar.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Release fullname. */}}
{{- define "pysoar.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "pysoar.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "pysoar.labels" -}}
helm.sh/chart: {{ include "pysoar.chart" . }}
app.kubernetes.io/name: {{ include "pysoar.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: pysoar
{{- end -}}

{{/* Selector labels for one component: include "pysoar.selectorLabels" (dict "ctx" $ "component" "api") */}}
{{- define "pysoar.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pysoar.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "pysoar.componentLabels" -}}
{{ include "pysoar.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "pysoar.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "pysoar.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image reference: include "pysoar.image" (dict "ctx" $ "image" .Values.image.backend) */}}
{{- define "pysoar.image" -}}
{{- $tag := default .ctx.Chart.AppVersion .image.tag -}}
{{- if .image.digest -}}
{{- printf "%s@%s" .image.repository .image.digest -}}
{{- else -}}
{{- printf "%s:%s" .image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "pysoar.secretName" -}}
{{- required "secret.existingSecret is required: the name of an existing Secret holding DATABASE_URL, REDIS_URL, CELERY_BROKER_URL, CELERY_RESULT_BACKEND, SECRET_KEY, JWT_SECRET_KEY, ENCRYPTION_MASTER_KEY and FIRST_ADMIN_PASSWORD (see deploy/kubernetes/README.md)" .Values.secret.existingSecret -}}
{{- end -}}

{{- define "pysoar.apiServiceName" -}}
{{- printf "%s-api" (include "pysoar.fullname" .) -}}
{{- end -}}

{{- define "pysoar.tlsSecretName" -}}
{{- default (printf "%s-tls" (include "pysoar.fullname" .)) .Values.ingress.tls.secretName -}}
{{- end -}}

{{/* Fails rendering when a required value is missing or inconsistent. */}}
{{- define "pysoar.validate" -}}
{{- $_ := include "pysoar.secretName" . -}}
{{- $_ := required "publicUrl is required: the external URL users reach PySOAR on (PYSOAR_PUBLIC_URL)" .Values.publicUrl -}}
{{- $_ := required "config.firstAdminEmail is required (FIRST_ADMIN_EMAIL)" .Values.config.firstAdminEmail -}}
{{- if .Values.ingress.enabled -}}
{{- $_ := required "ingress.host is required when ingress.enabled is true" .Values.ingress.host -}}
{{- end -}}
{{- if eq .Values.config.appEnv "production" -}}
{{- if not (has .Values.config.databaseSslMode (list "require" "verify-full" "disable")) -}}
{{- fail "config.databaseSslMode must be require, verify-full or disable when config.appEnv is production (src/core/config.py validate_database_ssl_mode)" -}}
{{- end -}}
{{- end -}}
{{- if .Values.devDependencies.enabled -}}
{{- if or .Values.api.autoscaling.enabled (gt (int .Values.api.replicas) 1) -}}
{{- fail "devDependencies.enabled runs migrations in the api pod's init container, so it needs exactly one api pod: set api.autoscaling.enabled=false and api.replicas=1" -}}
{{- end -}}
{{- end -}}
{{- if not (has .Values.networkPolicy.egress.flavor (list "kubernetes" "cilium")) -}}
{{- fail "networkPolicy.egress.flavor must be kubernetes or cilium" -}}
{{- end -}}
{{- end -}}

{{/*
Non-secret environment, shared by the ConfigMap and the migration hook Job
(a pre-install hook runs before the chart's ConfigMap exists, so the Job
carries the same pairs inline). Output: one "KEY: value" pair per line.
*/}}
{{- define "pysoar.configData" -}}
APP_ENV: {{ .Values.config.appEnv | quote }}
DEBUG: "false"
DATABASE_SSL_MODE: {{ .Values.config.databaseSslMode | quote }}
LOG_LEVEL: {{ .Values.config.logLevel | quote }}
LOG_FORMAT: {{ .Values.config.logFormat | quote }}
CORS_ORIGINS: {{ .Values.config.corsOrigins | toJson | quote }}
FIRST_ADMIN_EMAIL: {{ .Values.config.firstAdminEmail | quote }}
PYSOAR_PUBLIC_URL: {{ .Values.publicUrl | quote }}
LLM_PROVIDER: {{ .Values.config.llmProvider | quote }}
{{- with .Values.config.llmModel }}
LLM_MODEL: {{ . | quote }}
{{- end }}
{{- with .Values.config.ollamaBaseUrl }}
OLLAMA_BASE_URL: {{ . | quote }}
{{- end }}
{{- with .Values.config.openaiBaseUrl }}
OPENAI_BASE_URL: {{ . | quote }}
{{- end }}
OT_DISCOVERY_ALLOWED_CIDRS: {{ .Values.config.otDiscoveryAllowedCidrs | toJson | quote }}
SIEM_SYSLOG_ENABLED: {{ .Values.config.siemSyslogEnabled | toString | quote }}
SIEM_SYSLOG_PORT: {{ .Values.config.siemSyslogPort | toString | quote }}
{{- range $k, $v := .Values.config.extra }}
{{ $k }}: {{ $v | toString | quote }}
{{- end }}
{{- end -}}

{{/* envFrom for backend containers: ConfigMap first, then the Secret (later sources win). */}}
{{- define "pysoar.backendEnvFrom" -}}
- configMapRef:
    name: {{ include "pysoar.fullname" . }}-config
- secretRef:
    name: {{ include "pysoar.secretName" . }}
{{- end -}}

{{/* Writable mounts for the read-only backend root filesystem. */}}
{{- define "pysoar.backendVolumeMounts" -}}
- name: tmp
  mountPath: /tmp
- name: logs
  mountPath: /app/logs
- name: app-data
  mountPath: /app/uploads
  subPath: uploads
- name: app-data
  mountPath: /app/data
  subPath: data
- name: app-data
  mountPath: /app/backups
  subPath: backups
- name: app-data
  mountPath: /app/archives
  subPath: archives
{{- end -}}

{{- define "pysoar.backendVolumes" -}}
- name: tmp
  emptyDir: {}
- name: logs
  emptyDir: {}
- name: app-data
{{- if .Values.persistence.enabled }}
  persistentVolumeClaim:
    claimName: {{ default (printf "%s-data" (include "pysoar.fullname" .)) .Values.persistence.existingClaim }}
{{- else }}
  emptyDir: {}
{{- end }}
{{- end -}}

{{/*
Migration script: upgrade an alembic-managed database, bootstrap an empty
one (create_all + stamp head), refuse anything else.
*/}}
{{- define "pysoar.migrateScript" -}}
set -eu
python - <<'PY'
import asyncio
from sqlalchemy import inspect
from src.core.database import engine

async def main():
    async with engine.connect() as conn:
        names = await conn.run_sync(lambda c: inspect(c).get_table_names())
    await engine.dispose()
    if "alembic_version" in names:
        state = "managed"
    elif not names:
        state = "empty"
    else:
        state = "unmanaged"
    with open("/tmp/pysoar-db-state", "w") as fh:
        fh.write(state)

asyncio.run(main())
PY
state="$(cat /tmp/pysoar-db-state)"
echo "pysoar-migrate: database state: ${state}"
case "${state}" in
  managed)
    alembic upgrade head
    ;;
  empty)
    # The same create_all the api runs at boot, after importing src.main so
    # every model the application registers is in the metadata.
    python -c "import asyncio, src.main; from src.core.database import init_db; asyncio.run(init_db())"
    alembic stamp head
    ;;
  *)
    echo "pysoar-migrate: tables exist but there is no alembic_version table; refusing to guess. Stamp the matching revision by hand (alembic stamp <rev>) and re-run." >&2
    exit 1
    ;;
esac
alembic current
{{- end -}}
