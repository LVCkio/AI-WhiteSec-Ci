#!/usr/bin/env python3
"""Security Gate — evaluates combined findings and fails CI on blocking issues.

Exit codes:
  0  — gate passed (no blocking findings, or only warnings)
  1  — gate FAILED (AGREEMENT findings at critical/high severity detected)
  2  — invalid arguments or could not read results file

Usage (in GitHub Actions):
    python scripts/security_gate.py artifacts/pipeline-result.json \\
        --block-on AGREEMENT \\
        --max-severity high
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Severity order: higher index = more severe
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def evaluate(
    findings: list[dict],
    block_statuses: set[str],
    max_severity: str,
) -> tuple[bool, list[dict]]:
    """Return (should_block, blocking_findings)."""
    threshold = SEVERITY_RANK.get(max_severity.lower(), 3)
    blocking = [
        f
        for f in findings
        if f.get("combination_status") in block_statuses
        and SEVERITY_RANK.get((f.get("severity") or "medium").lower(), 0) >= threshold
    ]
    return bool(blocking), blocking


def main() -> None:
    parser = argparse.ArgumentParser(description="AI WhiteSec Security Gate")
    parser.add_argument("results_file", type=Path, help="Path to pipeline-result.json")
    parser.add_argument(
        "--block-on",
        nargs="+",
        default=["AGREEMENT"],
        metavar="STATUS",
        help="Combination statuses that trigger a gate failure (default: AGREEMENT)",
    )
    parser.add_argument(
        "--max-severity",
        default="high",
        choices=list(SEVERITY_RANK),
        help="Minimum severity that triggers a block (default: high)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a short summary even when gate passes",
    )
    args = parser.parse_args()

    if not args.results_file.exists():
        print(f"[gate] ERROR: results file not found: {args.results_file}", file=sys.stderr)
        sys.exit(2)

    try:
        data: dict = json.loads(args.results_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[gate] ERROR: could not parse results file: {exc}", file=sys.stderr)
        sys.exit(2)

    combined: list[dict] = data.get("combined_findings", [])
    run_id = data.get("run_id", "unknown")
    counts = data.get("counts", {})

    print(f"[gate] run_id={run_id}")
    print(
        f"[gate] findings — code_units={counts.get('code_units', '?')}  "
        f"ai={counts.get('ai', '?')}  checkmarx={counts.get('checkmarx', '?')}  "
        f"combined={counts.get('combined', '?')}"
    )

    block_statuses = set(s.upper() for s in args.block_on)
    should_block, blocking = evaluate(combined, block_statuses, args.max_severity)

    if args.summary or should_block:
        by_status: dict[str, int] = {}
        for f in combined:
            key = f.get("combination_status") or "UNKNOWN"
            by_status[key] = by_status.get(key, 0) + 1
        print("[gate] combined findings by status:", json.dumps(by_status))

    if should_block:
        print(
            f"[gate] FAILED — {len(blocking)} blocking finding(s) "
            f"(status in {sorted(block_statuses)}, severity >= {args.max_severity})"
        )
        for i, f in enumerate(blocking, 1):
            print(
                f"  [{i}] {f.get('combination_status')} | {f.get('severity', '?').upper()} | "
                f"{f.get('cwe', '?')} | {f.get('file_path', '?')}:{f.get('start_line', '?')} "
                f"— {f.get('title', '')}"
            )
        sys.exit(1)

    print(
        f"[gate] PASSED — no {sorted(block_statuses)} findings at "
        f"{args.max_severity}+ severity."
    )


if __name__ == "__main__":
    main()
