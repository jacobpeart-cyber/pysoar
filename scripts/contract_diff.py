"""Exact frontend<->backend API contract diff for PySOAR.

Backend: every route the FastAPI app actually serves (method + path).
Frontend: every path string passed to api.get/post/put/patch/delete (or
fetch/axios) anywhere under frontend/src, resolved against the client's base
("/api/v1").  Path parameters are normalised to {x} on both sides.

Backend routes the frontend never calls are split using
``docs/api/api-only-routes.md``:

* KEEP-API: documented API-only routes (integrations, agents, probes,
  automation). Reported separately, not as "never called".
* Called dynamically: routes a page calls through a path built at runtime
  (the regex cannot see them). Reported separately too.
* EXPOSE: real routes the UI should call. Still reported as never called
  until a page calls them.
* Pending retirement: routes slated for deletion by another change. Also
  still reported as never called.
* anything else is "unclassified" and is listed route by route.

The functions are importable (tests/unit/test_route_inventory.py uses them);
running the file prints the report and writes a JSON copy (``--json PATH``).
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
API_ONLY_DOC = ROOT / "docs" / "api" / "api-only-routes.md"
FRONTEND_SRC = ROOT / "frontend" / "src"
BASE = "/api/v1"

_PARAM_RE = re.compile(r"\{[^}/]+\}")
_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


def normalise(path: str) -> str:
    """Replace every path parameter with ``{x}``."""
    return _PARAM_RE.sub("{x}", path)


# ---------------------------------------------------------------- backend
def backend_routes(app: Any) -> dict[tuple[str, str], str]:
    """Every (METHOD, normalised path) the app serves, mapped to a handler name.

    Walks the router tree (including routers FastAPI keeps lazy as
    ``_IncludedRouter``, and routes hidden from the schema) and adds the
    OpenAPI document's paths.
    """
    found: dict[tuple[str, str], str] = {}

    def walk(routes: Iterable[Any], prefix: str = "") -> None:
        for r in routes:
            ctx = getattr(r, "include_context", None)
            original = getattr(r, "original_router", None)
            if ctx is not None and original is not None:
                walk(original.routes, prefix + (getattr(ctx, "prefix", "") or ""))
                continue
            sub = getattr(r, "routes", None)
            methods = getattr(r, "methods", None)
            if sub is not None and not methods:
                walk(sub, prefix + getattr(r, "path", ""))
                continue
            path = getattr(r, "path", None)
            if not path or not methods:
                continue
            for m in methods:
                if m in ("HEAD", "OPTIONS"):
                    continue
                found[(m, normalise(prefix + path))] = getattr(r, "name", "")

    walk(app.routes)
    for path, ops in app.openapi().get("paths", {}).items():
        for method, op in ops.items():
            if method.upper() in ("HEAD", "OPTIONS", "PARAMETERS"):
                continue
            key = (method.upper(), normalise(path))
            found.setdefault(key, op.get("operationId", "") if isinstance(op, dict) else "")
    return found


# --------------------------------------------------------------- frontend
_CALL_RE = re.compile(
    r"""(?:api|apiClient|client|axios)\.(get|post|put|patch|delete)\s*(?:<[^>]*>)?\s*\(\s*(`[^`]*`|'[^']*'|"[^"]*")""",
    re.S,
)
_FETCH_RE = re.compile(r"""fetch\s*\(\s*(`[^`]*`|'[^']*'|"[^"]*")""")


def _norm_fe(raw: str) -> str | None:
    s = raw[1:-1]
    s = re.sub(r"\$\{[^}]*\}", "{x}", s)          # template params
    s = s.split("?")[0]
    if s.startswith("http") or not s.startswith("/"):
        return None
    if not s.startswith("/api/"):
        s = BASE + s
    return s.rstrip("/") or "/"


def frontend_calls(src: Path = FRONTEND_SRC) -> tuple[dict[tuple[str, str], set[str]], list[tuple[str, str]]]:
    """Parsed frontend calls ``{(METHOD, path): {files}}`` and the unparsed call sites."""
    calls: dict[tuple[str, str], set[str]] = defaultdict(set)
    unparsed: list[tuple[str, str]] = []
    for f in sorted(src.rglob("*.ts*")):
        if "node_modules" in f.parts:
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        rel = str(f.relative_to(ROOT))
        for m in _CALL_RE.finditer(text):
            method, raw = m.group(1).upper(), m.group(2)
            p = _norm_fe(raw)
            if p is None:
                unparsed.append((rel, raw[:80]))
                continue
            calls[(method, p)].add(rel)
        for m in _FETCH_RE.finditer(text):
            p = _norm_fe(m.group(1))
            if p is not None:
                calls[("GET", p)].add(rel + " (fetch)")
    return calls, unparsed


# ------------------------------------------------------- API-only allowlist
_ROW_RE = re.compile(r"^\|\s*(GET|POST|PUT|PATCH|DELETE)\s*\|\s*`?(/[^|`\s]*)`?\s*\|")


def api_only_routes(doc: Path = API_ONLY_DOC) -> dict[str, dict[tuple[str, str], int]]:
    """Routes listed in the API-only file, by section.

    Returns ``{"keep": {...}, "dynamic": {...}, "expose": {...}, "pending": {...}}`` mapping
    (METHOD, normalised /api/v1 path) to the line number in the file. A row
    is a markdown table row whose first two cells are the method and the
    path; the section is the nearest ``## `` heading (KEEP-API, Called
    dynamically, EXPOSE or Pending retirement).
    """
    sections: dict[str, dict[tuple[str, str], int]] = {"keep": {}, "dynamic": {}, "expose": {}, "pending": {}}
    if not doc.exists():
        return sections
    current: str | None = None
    for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith("## "):
            head = line.lower()
            current = (
                "keep" if "keep-api" in head
                else "dynamic" if "dynamic" in head
                else "expose" if "expose" in head
                else "pending" if "pending" in head
                else None
            )
            continue
        m = _ROW_RE.match(line)
        if m and current:
            path = m.group(2)
            if not path.startswith(BASE):
                path = BASE + path
            sections[current][(m.group(1), normalise(path))] = lineno
    return sections


# ------------------------------------------------------------------ diff
def _segments_match(route: str, path: str) -> bool:
    rs, ps = route.strip("/").split("/"), path.strip("/").split("/")
    if len(rs) != len(ps):
        return False
    return all(a == b or a == "{x}" for a, b in zip(rs, ps, strict=True))


def matches(backend_key: tuple[str, str], call: tuple[str, str]) -> bool:
    (bm, bp), (fm, fp) = backend_key, call
    return bm == fm and (bp == fp or bp == fp + "/" or _segments_match(bp, fp))


def diff(backend: dict[tuple[str, str], str],
         frontend: dict[tuple[str, str], set[str]],
         api_only: dict[str, dict[tuple[str, str], int]]) -> dict[str, Any]:
    """Compute the contract report."""
    missing = sorted(
        (k, sorted(v)) for k, v in frontend.items()
        if not any(matches(b, k) for b in backend)
    )
    matched: set[tuple[str, str]] = {b for b in backend for c in frontend if matches(b, c)}
    v1 = {k for k in backend if k[1].startswith(BASE)}
    uncalled = sorted(k for k in v1 if k not in matched)
    keep, dynamic = api_only["keep"], api_only["dynamic"]
    expose, pending = api_only["expose"], api_only["pending"]
    documented_keep = [k for k in uncalled if k in keep]
    dynamic_calls = [k for k in uncalled if k in dynamic]
    still_uncalled = [k for k in uncalled if k not in keep and k not in dynamic]
    return {
        "backend_routes": len(v1),
        "frontend_calls": len(frontend),
        "missing": missing,
        "called": sorted(v1 & matched),
        "api_only": documented_keep,
        "dynamic": dynamic_calls,
        "never_called": still_uncalled,
        "expose": [k for k in still_uncalled if k in expose],
        "pending": [k for k in still_uncalled if k in pending],
        "unclassified": [k for k in still_uncalled if k not in expose and k not in pending],
        # Documented routes the app no longer serves, and KEEP-API rows the UI now calls.
        "stale_documented": sorted(
            k for sec in (keep, dynamic, expose, pending) for k in sec if k not in backend
        ),
        "documented_but_called": sorted(k for k in {**keep, **dynamic} if k in matched),
    }


def _by_prefix(keys: Iterable[tuple[str, str]]) -> list[tuple[str, int]]:
    counts: dict[str, int] = defaultdict(int)
    for _m, p in keys:
        parts = p.split("/")
        counts[parts[3] if len(parts) > 3 else p] += 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def main(argv: list[str]) -> int:
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    os.environ.setdefault("APP_ENV", "development")
    from src.main import app  # imported after the path setup above

    backend = backend_routes(app)
    frontend, unparsed = frontend_calls()
    api_only = api_only_routes()
    rep = diff(backend, frontend, api_only)

    print(f"backend /api/v1 routes: {rep['backend_routes']}")
    print(f"frontend distinct calls: {rep['frontend_calls']}")
    print(f"frontend calls with NO backend route: {len(rep['missing'])}")
    for (m, p), files in rep["missing"]:
        print(f"  {m:6} {p}   <- {', '.join(files)[:120]}")
    print(f"backend routes called by the frontend: {len(rep['called'])}")
    print(f"documented API-only routes (KEEP-API, {API_ONLY_DOC.relative_to(ROOT)}): {len(rep['api_only'])}")
    for prefix, n in _by_prefix(rep["api_only"]):
        print(f"  {n:4}  /api/v1/{prefix}")
    print(f"routes the frontend calls through a runtime-built path (documented): {len(rep['dynamic'])}")
    print(f"backend routes never called by frontend: {len(rep['never_called'])} "
          f"(EXPOSE {len(rep['expose'])}, pending retirement {len(rep['pending'])}, "
          f"unclassified {len(rep['unclassified'])})")
    for label, keys in (("EXPOSE", rep["expose"]), ("pending retirement", rep["pending"]),
                        ("unclassified", rep["unclassified"])):
        for m, p in keys:
            print(f"  {label:18} {m:6} {p}")
    if rep["stale_documented"]:
        print(f"documented routes the app does not serve: {len(rep['stale_documented'])}")
        for m, p in rep["stale_documented"]:
            print(f"  {m:6} {p}")
    if rep["documented_but_called"]:
        print(f"KEEP-API / dynamic routes the frontend now calls literally (move them out of the file): "
              f"{len(rep['documented_but_called'])}")
        for m, p in rep["documented_but_called"]:
            print(f"  {m:6} {p}")
    print(f"unparsed dynamic call sites: {len(unparsed)}")

    out_path = None
    if "--json" in argv:
        out_path = Path(argv[argv.index("--json") + 1])
    else:
        out_path = Path(tempfile.gettempdir()) / "contract_diff.json"
    out = {
        "backend_routes": rep["backend_routes"],
        "frontend_calls": rep["frontend_calls"],
        "frontend_calls_with_no_backend_route": [
            {"method": m, "path": p, "files": files} for (m, p), files in rep["missing"]
        ],
        "backend_routes_documented_api_only": [
            {"method": m, "path": p, "handler": backend[(m, p)]} for (m, p) in rep["api_only"]
        ],
        "backend_routes_called_dynamically": [
            {"method": m, "path": p, "handler": backend[(m, p)]} for (m, p) in rep["dynamic"]
        ],
        "backend_routes_never_called_by_frontend": [
            {"method": m, "path": p, "handler": backend[(m, p)],
             "classification": ("expose" if (m, p) in api_only["expose"]
                                else "pending" if (m, p) in api_only["pending"]
                                else "unclassified")}
            for (m, p) in rep["never_called"]
        ],
        "documented_routes_not_served": [{"method": m, "path": p} for (m, p) in rep["stale_documented"]],
        "unparsed_dynamic_calls": unparsed[:40],
    }
    out_path.write_text(json.dumps(out, indent=2))
    print(f"json: {out_path}")
    return 1 if rep["missing"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
