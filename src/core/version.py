"""The release version and build commit of this PySOAR build.

The ``VERSION`` file at the repository root is the single source of truth for
the version (semantic versioning, ``MAJOR.MINOR.PATCH``). The release workflow
(.github/workflows/release.yml) refuses a tag that is not ``v`` + that file's
contents, so the version an image reports is the version it was released as.

The commit comes from the ``PYSOAR_COMMIT`` environment variable, which the
Dockerfile sets from the build argument of the same name. A build that was not
given one (a plain ``docker build`` or a source checkout) reports ``unknown``:
the value is never guessed, and anything that is not a hexadecimal git object
name is reported as ``unknown`` rather than echoed back.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

#: Repository root: src/core/version.py -> src/core -> src -> root. In the
#: image this is /app, where the Dockerfile's ``COPY . .`` places VERSION.
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

#: Semantic Versioning 2.0.0 (https://semver.org), including optional
#: pre-release and build metadata.
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")

UNKNOWN = "unknown"


def read_version(path: Path = VERSION_FILE) -> str:
    """Return the version in ``path``; raise if it is missing or not semver.

    A missing or malformed VERSION file is a packaging defect, so it fails
    loudly at import instead of reporting a made-up version.
    """
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise RuntimeError(f"VERSION file not found at {path}") from exc
    if not SEMVER_RE.match(value):
        raise RuntimeError(f"VERSION file {path} does not hold a semantic version: {value!r}")
    return value


def get_commit() -> str:
    """The build commit from ``PYSOAR_COMMIT``, or ``unknown`` when absent or malformed."""
    value = os.environ.get("PYSOAR_COMMIT", "").strip().lower()
    return value if _COMMIT_RE.match(value) else UNKNOWN


__version__ = read_version()
