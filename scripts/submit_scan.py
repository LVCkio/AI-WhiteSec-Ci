"""Deliver the Checkmarx branch to an already started parallel run.

Exit 0 requires a real Gateway Security Gate PASS that permits deployment.
This script does not run Checkmarx or infer scanner completion from an empty report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.contracts import (CheckmarxScan, FinalDecision, RunIdentity, RunView,
                           SourceFile, source_manifest_digest)


def git_bytes(source: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(source), *args], stderr=subprocess.PIPE)


def snapshot_sources(source: Path, commit: str, excludes: list[str]) -> tuple[str, list[SourceFile]]:
    resolved = git_bytes(source, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
    if commit != resolved:
        raise ValueError("--commit must be the complete immutable commit SHA")
    listing = git_bytes(source, "ls-tree", "-rz", "--full-tree", resolved).split(b"\x00")
    sources = []
    for entry in listing:
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, _ = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8")
        if not path.endswith(".py") or any(
            path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/")
            for prefix in excludes
        ):
            continue
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"Unsupported source entry (symlink/submodule): {path}")
        content_bytes = git_bytes(source, "show", f"{resolved}:{path}")
        content = content_bytes.decode("utf-8")
        sources.append(SourceFile(path=path, content=content,
                                  sha256=hashlib.sha256(content_bytes).hexdigest()))
    if not sources:
        raise ValueError("No tracked Python files in the requested snapshot/scope")
    return resolved, sources


def deployment_exit_code(decision: FinalDecision) -> int:
    if decision.decision == "PASS" and decision.mode == "real" and decision.allow_deploy:
        return 0
    return {"BLOCK": 2, "REVIEW": 3, "ERROR": 4, "PASS": 3}[decision.decision]


def validate_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and
        parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
        raise ValueError("Remote Gateway URLs must use HTTPS")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--sarif", type=Path, required=True)
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--scan-status", choices=["completed", "error", "incomplete"], required=True)
    parser.add_argument("--scan-preset", required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--exclude", action="append", default=[], help="Repository-relative directory; repeat as needed")
    parser.add_argument("--output", type=Path, default=Path("decision.json"))
    parser.add_argument("--wait-seconds", type=float, default=150)
    args = parser.parse_args(argv)
    key = os.getenv("GATEWAY_API_KEY", "")
    try:
        if not key.strip():
            raise ValueError("GATEWAY_API_KEY is not set")
        validate_url(args.url)
        if not 0 < args.wait_seconds <= 3600:
            raise ValueError("--wait-seconds must be in (0, 3600]")
        commit, sources = snapshot_sources(args.source, args.commit, args.exclude)
        report = json.loads(args.sarif.read_text(encoding="utf-8-sig"))
        identity = RunIdentity(run_id=args.run_id, repository=args.repository,
                               commit_sha=commit, artifact_digest=args.artifact_digest)
        manifest = source_manifest_digest(sources)
        scan = CheckmarxScan(scan_id=args.scan_id, status=args.scan_status, mode="real",
                             preset=args.scan_preset, commit_sha=commit,
                             source_manifest_sha256=manifest, sarif=report)
        import httpx
        with httpx.Client(timeout=150, trust_env=False, follow_redirects=False) as client:
            run_url = args.url.rstrip("/") + "/v1/runs/" + args.run_id
            headers = {"X-API-Key": key}
            existing_response = client.get(run_url, headers=headers)
            existing_response.raise_for_status()
            existing = RunView.model_validate(existing_response.json())
            if existing.identity != identity or existing.source_manifest_sha256 != manifest:
                raise ValueError("The locked parallel run uses a different identity or source scope")
            response = client.post(run_url + "/checkmarx", json=scan.model_dump(), headers=headers)
            response.raise_for_status()
            state = RunView.model_validate(response.json())
            deadline = time.monotonic() + args.wait_seconds
            while state.decision is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError("A detector branch is still pending")
                time.sleep(1)
                response = client.get(run_url, headers=headers)
                response.raise_for_status()
                state = RunView.model_validate(response.json())
        decision = state.decision
        if decision.identity != identity or decision.scan_id != args.scan_id:
            raise ValueError("Gateway response identity does not match this build")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(decision.model_dump_json(indent=2) + "\n", encoding="utf-8")
        print(f"Gateway Security Gate: {decision.decision}; mode={decision.mode}; allow_deploy={decision.allow_deploy}")
        print(f"Decision saved to {args.output.resolve()}")
        return deployment_exit_code(decision)
    except Exception as error:
        # Avoid printing upstream bodies or credentials/source code on CI failure.
        print(f"Submission failed ({type(error).__name__}); deployment remains blocked.", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
