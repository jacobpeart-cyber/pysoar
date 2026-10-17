# PySOAR Dockerfile
# Multi-stage build for optimized production image

# Stage 1: Build stage
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Production stage
FROM python:3.11-slim AS production

WORKDIR /app

# Install runtime dependencies only.
# postgresql-client-15 gives the api pg_dump for POST /api/v1/backup/create.
# It must not be older than the server (the bundled postgres service is
# postgres:15), and its major version should match the server's so the dump
# reloads with psql there (pg_dump 17 writes settings a 15 server rejects).
# The Debian release under python:3.11-slim ships only its own major version,
# so it comes from the PostgreSQL project's apt repository; the signing key's
# fingerprint is checked before the repository is trusted.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    ca-certificates \
    gpg \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
       https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && gpg --show-keys --with-colons /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
       | grep -qx "fpr:::::::::B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8:" \
    && . /etc/os-release \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-15 \
    && apt-get purge -y --auto-remove gpg \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r pysoar && useradd -r -g pysoar pysoar

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=pysoar:pysoar . .

# Create necessary directories (/app/backups: BACKUP_DIR of the backup routes;
# docker-compose.yml mounts ./backups over it)
RUN mkdir -p /app/logs /app/uploads /app/tmp /app/backups && \
    chown -R pysoar:pysoar /app

# Switch to non-root user
USER pysoar

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production

# Build identity. PYSOAR_COMMIT is reported by GET /api/v1/health as
# "commit" (src/core/version.py); without the build argument it stays
# "unknown". The version itself comes from the VERSION file copied above.
# These sit after the code COPY so a new commit does not invalidate the
# dependency layers. The release workflow also sets the OCI labels itself;
# these give a local build the same keys.
ARG PYSOAR_COMMIT=unknown
ARG PYSOAR_VERSION=unknown
ARG PYSOAR_BUILD_DATE=unknown
ENV PYSOAR_COMMIT=${PYSOAR_COMMIT}
LABEL org.opencontainers.image.title="pysoar-backend" \
      org.opencontainers.image.description="PySOAR API, Celery worker and scheduler image" \
      org.opencontainers.image.source="https://github.com/jacobpeart-cyber/pysoar" \
      org.opencontainers.image.revision="${PYSOAR_COMMIT}" \
      org.opencontainers.image.version="${PYSOAR_VERSION}" \
      org.opencontainers.image.created="${PYSOAR_BUILD_DATE}"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Expose port
EXPOSE 8000

# Default command
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
