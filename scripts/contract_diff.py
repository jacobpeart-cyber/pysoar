"""Exact frontend<->backend API contract diff for PySOAR.

Backend: every route the FastAPI app actually serves (method + path).
Frontend: every path string passed to api.get/post/put/patch/delete (or
fetch/axios) anywhere under frontend/src, resolved against the client's base
("/api/v1").  Path parameters are normalised to {x} on both sides.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(r"C:\Users\jacob\pysoar")
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
os.environ.setdefault("APP_ENV", "development")

# ---------------------------------------------------------------- backend
from src.main import app  # noqa: E402

backend: dict[tuple[str, str], str] = {}


def walk(routes, prefix: str = "") -> None:
    for r in routes:
        sub = getattr(r, "routes", None)
        if sub is not None and not getattr(r, "methods", None):
            walk(sub, prefix + getattr(r, "path", ""))
            continue
        path = getattr(r, "path", None)
        methods = getattr(r, "methods", None)
        if not path or not methods:
            continue
        norm = re.sub(r"\{[^}/]+\}", "{x}", prefix + path)
        for m in methods:
            if m in ("HEAD", "OPTIONS"):
                continue
            backend[(m, norm)] = getattr(r, "name", "")


walk(app.routes)
# Newer FastAPI keeps included routers lazy in app.routes; the OpenAPI document
# is the authoritative list of what is served.
for path, ops in app.openapi().get("paths", {}).items():
    norm = re.sub(r"\{[^}/]+\}", "{x}", path)
    for method, op in ops.items():
        if method.upper() in ("HEAD", "OPTIONS", "PARAMETERS"):
            continue
        backend[(method.upper(), norm)] = op.get("operationId", "") if isinstance(op, dict) else ""

# --------------------------------------------------------------- frontend
BASE = "/api/v1"
call_re = re.compile(
    r"""(?:api|apiClient|client|axios)\.(get|post|put|patch|delete)\s*(?:<[^>]*>)?\s*\(\s*(`[^`]*`|'[^']*'|"[^"]*")""",
    re.S,
)
fetch_re = re.compile(r"""fetch\s*\(\s*(`[^`]*`|'[^']*'|"[^"]*")""")

frontend: dict[tuple[str, str], set[str]] = defaultdict(set)
unparsed: list[tuple[str, str]] = []


def norm_fe(raw: str) -> str | None:
    s = raw[1:-1]
    s = re.sub(r"\$\{[^}]*\}", "{x}", s)          # template params
    s = s.split("?")[0]
    if s.startswith("http"):
        return None
    if not s.startswith("/"):
        return None
    if not s.startswith("/api/"):
        s = BASE + s
    s = re.sub(r"/\{x\}", "/{x}", s)
    return s.rstrip("/") or "/"


for f in Path("frontend/src").rglob("*.ts*"):
    if "node_modules" in f.parts:
        continue
    text = f.read_text(encoding="utf-8", errors="replace")
    for m in call_re.finditer(text):
        method, raw = m.group(1).upper(), m.group(2)
        p = norm_fe(raw)
        if p is None:
            unparsed.append((str(f), raw[:80]))
            continue
        frontend[(method, p)].add(str(f))
    for m in fetch_re.finditer(text):
        p = norm_fe(m.group(1))
        if p is None:
            continue
        frontend[("GET", p)].add(str(f) + " (fetch)")

# ------------------------------------------------------------------ diff
def _segments_match(route: str, path: str) -> bool:
    rs, ps = route.strip("/").split("/"), path.strip("/").split("/")
    if len(rs) != len(ps):
        return False
    return all(a == b or a == "{x}" for a, b in zip(rs, ps))


def backend_has(method: str, path: str) -> bool:
    if (method, path) in backend or (method, path + "/") in backend:
        return True
    # a literal frontend segment may fill a backend path parameter
    return any(m == method and _segments_match(r, path) for (m, r) in backend)


missing = sorted((k, sorted(v)) for k, v in frontend.items() if not backend_has(*k))
matched_backend: set[tuple[str, str]] = set()
for (fm, fp) in frontend:
    for (bm, bp) in backend:
        if bm == fm and (bp == fp or bp == fp + "/" or _segments_match(bp, fp)):
            matched_backend.add((bm, bp))
uncalled = sorted(k for k in backend if k not in matched_backend and k[1].startswith("/api/v1"))
by_prefix: dict[str, int] = defaultdict(int)
for (_m, p) in uncalled:
    parts = p.split("/")
    by_prefix[parts[3] if len(parts) > 3 else p] += 1

out = {
    "backend_routes": len([k for k in backend if k[1].startswith("/api/v1")]),
    "frontend_calls": len(frontend),
    "frontend_calls_with_no_backend_route": [{"method": m, "path": p, "files": files} for (m, p), files in missing],
    "backend_routes_never_called_by_frontend": [{"method": m, "path": p, "handler": backend[(m, p)]} for (m, p) in uncalled],
    "unparsed_dynamic_calls": unparsed[:40],
}
Path(r"C:\Users\jacob\AppData\Local\Temp\claude\c--Users-jacob-pysoar\24d58a32-1d51-4604-afeb-d7dce6c4b51d\scratchpad\contract_diff.json").write_text(json.dumps(out, indent=2))
print(f"backend /api/v1 routes: {out['backend_routes']}")
print(f"frontend distinct calls: {out['frontend_calls']}")
print(f"frontend calls with NO backend route: {len(missing)}")
for (m, p), files in missing:
    print(f"  {m:6} {p}   <- {', '.join(files)[:120]}")
print(f"backend routes never called by frontend: {len(uncalled)}")
for prefix, n in sorted(by_prefix.items(), key=lambda kv: -kv[1]):
    print(f"  {n:4}  /api/v1/{prefix}")
print(f"unparsed dynamic call sites: {len(unparsed)}")
