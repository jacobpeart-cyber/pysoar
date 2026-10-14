"""Evidence byte storage for DFIR.

Every evidence file PySOAR holds lives under the evidence root
(``DFIR_UPLOAD_ROOT``, default ``/app/uploads/dfir``) at
``<root>/<organization_id>/<case_id>/<uuid>_<sanitised name>``. Hashes are
computed over the bytes as they are written; nothing here ever rewrites a
stored file or its recorded hash.
"""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from dataclasses import dataclass
from typing import Optional

DEFAULT_EVIDENCE_ROOT = "/app/uploads/dfir"

_FILENAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def evidence_root() -> str:
    """The configured evidence root (read from the environment each call)."""
    return os.environ.get("DFIR_UPLOAD_ROOT", DEFAULT_EVIDENCE_ROOT)


def sanitize_filename(filename: Optional[str]) -> str:
    """A safe basename: no directory part, unsafe characters collapsed, 200 chars max."""
    base = os.path.basename(filename or "").strip() or "evidence.bin"
    base = _FILENAME_SANITIZE_RE.sub("_", base).strip("._") or "evidence.bin"
    return base[:200]


class EvidencePathRefusedError(Exception):
    """A stored local evidence location that must not be read.

    ``reason`` is ``evidence_path_outside_storage_root`` (not under the
    evidence root at all) or ``evidence_path_outside_tenant_root`` (under the
    root but in another organisation's subtree, e.g. a legacy row).
    """

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _within(real: str, real_dir: str) -> bool:
    return real == real_dir or real.startswith(real_dir + os.sep)


def resolve_tenant_evidence_path(root: str, location: str, org_id: Optional[str]) -> str:
    """The real path for a stored local evidence location, confined to the tenant.

    New rows store the location relative to the evidence root
    (``<org>/<case>/<file>``); older rows store an absolute path. Either way
    the resolved path (symlinks followed) must be inside
    ``<root>/<org_id>``. ``org_id=None`` checks the root only and exists for
    root-level housekeeping; every request path passes the caller's org.
    Raises ``EvidencePathRefusedError``.
    """
    real_root = os.path.realpath(root)
    candidate = location if os.path.isabs(location) else os.path.join(root, location)
    real = os.path.realpath(candidate)
    if not _within(real, real_root) or real == real_root:
        raise EvidencePathRefusedError(
            "evidence_path_outside_storage_root",
            "this evidence item points outside the evidence storage root and cannot be served",
        )
    if org_id is not None:
        tenant_root = os.path.realpath(os.path.join(root, str(org_id)))
        if not _within(real, tenant_root) or real == tenant_root:
            raise EvidencePathRefusedError(
                "evidence_path_outside_tenant_root",
                "this evidence item points outside the organisation's evidence directory and cannot be read",
            )
    return real


def relative_location(root: str, path: str) -> str:
    """``path`` relative to the evidence root, with forward slashes (what new rows store)."""
    return os.path.relpath(path, root).replace(os.sep, "/")


@dataclass
class StoredEvidence:
    path: str
    sha256: str
    md5: str
    sha512: str
    size: int


def store_evidence_bytes(root: str, org_id: str, case_id: str, filename: str, data: bytes) -> StoredEvidence:
    """Write ``data`` under the org/case directory and hash it on the way in.

    The file is written to a temporary name and renamed into place, so a
    reader never sees a partial file. Raises ``OSError`` on any IO failure
    (and removes the temporary file).
    """
    target_dir = os.path.join(root, str(org_id), str(case_id))
    os.makedirs(target_dir, exist_ok=True)
    final_path = os.path.join(target_dir, f"{uuid.uuid4().hex}_{sanitize_filename(filename)}")
    tmp_path = final_path + ".part"
    sha256, md5, sha512 = hashlib.sha256(), hashlib.md5(usedforsecurity=False), hashlib.sha512()
    try:
        with open(tmp_path, "wb") as fh:
            view = memoryview(data)
            step = 1024 * 1024
            for offset in range(0, len(view), step):
                chunk = view[offset : offset + step]
                sha256.update(chunk)
                md5.update(chunk)
                sha512.update(chunk)
                fh.write(chunk)
        os.replace(tmp_path, final_path)
    except OSError:
        remove_quietly(tmp_path)
        raise
    return StoredEvidence(
        path=final_path, sha256=sha256.hexdigest(), md5=md5.hexdigest(), sha512=sha512.hexdigest(), size=len(data),
    )


def hash_file(path: str, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_prefix(path: str, limit: int) -> tuple[bytes, bool]:
    """The first ``limit`` bytes of ``path`` and whether the file was longer."""
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    return data[:limit], len(data) > limit


def remove_quietly(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
