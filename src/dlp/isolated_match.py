"""Run tenant-authored regular expressions in a killable child process.

Custom DLP patterns are matched over every tenant's stored content inside the
shared Celery worker (and, for the policy "test" route, inside the API
process). Python's ``re`` has no timeout and a thread running a catastrophic
pattern cannot be interrupted, so the matching runs in a separate interpreter
started with ``-I`` that reads the patterns and records from stdin and writes
one JSON line per record as it finishes. If the child exceeds its budget it is
killed; the records that were reported before the kill are scanned, the rest
are returned as unscanned so the caller can record them instead of silently
passing them. The static check in :mod:`src.dlp.scanner` is a first filter;
this is the guarantee.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Iterable

#: Default budget for one policy over one window of records.
DEFAULT_BUDGET_SECONDS = 10.0

_CHILD = r"""
import json, re, sys
payload = json.loads(sys.stdin.read())
patterns = {name: re.compile(expr) for name, expr in payload["patterns"].items()}
for rec in payload["records"]:
    hits = []
    text = rec["text"]
    for name, pat in patterns.items():
        for m in pat.finditer(text):
            if m.group(0):
                hits.append([name, m.start(), m.end()])
    sys.stdout.write(json.dumps({"id": rec["id"], "hits": hits}) + "\n")
    sys.stdout.flush()
"""


def match_custom_patterns(
    patterns: dict[str, str],
    records: Iterable[tuple[str, str]],
    budget_seconds: float = DEFAULT_BUDGET_SECONDS,
) -> tuple[dict[str, list[tuple[str, int, int]]], list[str], bool]:
    """Match ``patterns`` (name -> expression) over ``records`` (id, text).

    Returns ``(hits_by_record_id, unscanned_record_ids, timed_out)``. Records
    the child reported before a kill are complete; the others are unscanned.
    """
    record_list = [(str(rid), text or "") for rid, text in records]
    if not patterns or not record_list:
        return {}, [], False
    payload = json.dumps({"patterns": patterns, "records": [{"id": rid, "text": text} for rid, text in record_list]})
    proc = subprocess.Popen(  # noqa: S603 - fixed interpreter and program, data only on stdin
        [sys.executable, "-I", "-c", _CHILD],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    timed_out = False
    try:
        out, _ = proc.communicate(payload, timeout=budget_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        out, _ = proc.communicate()
    hits: dict[str, list[tuple[str, int, int]]] = {}
    for line in (out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        hits[str(row["id"])] = [(str(h[0]), int(h[1]), int(h[2])) for h in row.get("hits", [])]
    unscanned = [rid for rid, _ in record_list if rid not in hits]
    if proc.returncode not in (0, None) and not timed_out and unscanned:
        # the child crashed (e.g. a pattern that re rejects at run time): nothing is silently passed
        timed_out = True
    return hits, unscanned, timed_out
