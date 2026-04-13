"""Normalize legacy indicator_type values (ip -> ipv4, unknown -> best-effort).

Revision ID: 008
Revises: 007
Create Date: 2026-04-11

After the 007 iocs -> threat_indicators unification, some pre-existing
threat_indicators rows still used the legacy ``ip`` type string. Also
some rows had an ``unknown`` indicator_type. This migration:

  1. Renames ``indicator_type = 'ip'`` to ``'ipv4'`` (safe — all rows in
     that category were IPv4 addresses).
  2. For ``indicator_type = 'unknown'`` rows, attempts to re-detect the
     type from ``value`` format (regex on IPv4/domain/URL/hash). Rows
     that still can't be classified are left as-is for manual review.
"""

import re

import sqlalchemy as sa
from alembic import op


revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _detect(value: str) -> str | None:
    v = (value or "").strip()
    if not v:
        return None
    if v.startswith(("http://", "https://", "ftp://")):
        return "url"
    if _IPV4_RE.match(v):
        return "ipv4"
    if _SHA256_RE.match(v):
        return "sha256"
    if _SHA1_RE.match(v):
        return "sha1"
    if _MD5_RE.match(v):
        return "md5"
    if _DOMAIN_RE.match(v):
        return "domain"
    return None


def upgrade() -> None:
    bind = op.get_bind()

    # 1. Rename legacy 'ip' to 'ipv4'
    bind.execute(
        sa.text("UPDATE threat_indicators SET indicator_type = 'ipv4' WHERE indicator_type = 'ip'")
    )

    # 2. Re-detect unknown types
    rows = list(
        bind.execute(
            sa.text("SELECT id, value FROM threat_indicators WHERE indicator_type = 'unknown'")
        )
    )
    for row in rows:
        detected = _detect(row._mapping["value"])
        if detected:
            bind.execute(
                sa.text("UPDATE threat_indicators SET indicator_type = :t WHERE id = :id"),
                {"t": detected, "id": row._mapping["id"]},
            )

    print(f"[migration 008] normalized indicator_type for {len(rows)} unknown rows")


def downgrade() -> None:
    # Best-effort reverse: put things back into 'ip' / 'unknown' is destructive;
    # we leave the normalized data as-is.
    pass
