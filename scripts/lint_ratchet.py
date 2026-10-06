"""Lint and type-check debt ratchet.

The tree carries lint and typing debt that is far too large to clear in one
change (October 2026: ~7,000 findings against the ruff style profile in
pyproject.toml, ~6,800 strict-mypy errors). A gate the tree cannot pass is not
a gate, and silently ignoring the debt lets it grow. This ratchet is the honest
middle: CI fails when any debt count is HIGHER than the committed baseline, and
the baseline is lowered as debt is paid down. It never allows the count to go
up, and it never pretends the count is zero.

Usage:
    python scripts/lint_ratchet.py            # compare against .lint-baseline.json, exit 1 on growth
    python scripts/lint_ratchet.py --update   # rewrite the baseline from the current counts
    python scripts/lint_ratchet.py --json     # print the current counts as JSON

Counters:
    ruff_style   findings from `ruff check src/ tests/` with the full pyproject
                 profile (the runtime-defect subset is a hard gate elsewhere)
    mypy         errors from `mypy --ignore-missing-imports src/` (pyproject strict config)

The frontend eslint warning count is ratcheted separately in CI with
`eslint --max-warnings`, read from the same baseline file (key `eslint_warnings`).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE = ROOT / ".lint-baseline.json"

_RUFF_FOUND = re.compile(r"Found (\d+) error")
_MYPY_FOUND = re.compile(r"Found (\d+) error")


def _run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
    return (proc.stdout or "") + (proc.stderr or "")


def count_ruff_style() -> int:
    out = _run([sys.executable, "-m", "ruff", "check", "src/", "tests/", "--statistics", "--exit-zero"])
    match = _RUFF_FOUND.search(out)
    if match:
        return int(match.group(1))
    if "All checks passed" in out:
        return 0
    raise RuntimeError(f"could not parse ruff output:\n{out[-800:]}")


def count_mypy() -> int:
    out = _run([sys.executable, "-m", "mypy", "--ignore-missing-imports", "src/"])
    match = _MYPY_FOUND.search(out)
    if match:
        return int(match.group(1))
    if "Success: no issues found" in out:
        return 0
    raise RuntimeError(f"could not parse mypy output:\n{out[-800:]}")


def current_counts(include_mypy: bool = True) -> dict[str, int]:
    counts = {"ruff_style": count_ruff_style()}
    if include_mypy:
        counts["mypy"] = count_mypy()
    return counts


def load_baseline() -> dict[str, int]:
    if not BASELINE.exists():
        raise SystemExit(f"{BASELINE.name} is missing; run `python scripts/lint_ratchet.py --update` once")
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    return {k: int(v) for k, v in data.items() if not k.startswith("_")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true", help="rewrite the baseline from current counts")
    parser.add_argument("--json", action="store_true", help="print current counts as JSON and exit")
    parser.add_argument("--skip-mypy", action="store_true", help="only measure ruff (faster local check)")
    args = parser.parse_args(argv)

    counts = current_counts(include_mypy=not args.skip_mypy)

    if args.json:
        print(json.dumps(counts, indent=2))
        return 0

    if args.update:
        existing: dict[str, object] = {}
        if BASELINE.exists():
            existing = json.loads(BASELINE.read_text(encoding="utf-8"))
        existing.update(counts)
        existing["_comment"] = (
            "Debt counts the ratchet compares against. Lower them as debt is paid down; "
            "never raise them to make CI green. eslint_warnings is applied via --max-warnings in CI."
        )
        BASELINE.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"baseline written: {counts}")
        return 0

    baseline = load_baseline()
    failed = False
    for key, value in counts.items():
        allowed = baseline.get(key)
        if allowed is None:
            print(f"{key}: {value} (no baseline entry; add it with --update)")
            failed = True
        elif value > allowed:
            print(f"{key}: {value} > baseline {allowed}  FAIL (new debt introduced)")
            failed = True
        elif value < allowed:
            print(f"{key}: {value} < baseline {allowed}  (improved; lower the baseline with --update)")
        else:
            print(f"{key}: {value} == baseline {allowed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
