"""Start the CodeBERT branch, then run Checkmarx concurrently in CI."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.contracts import RunIdentity, RunStart, RunView, source_manifest_digest
from scripts.submit_scan import snapshot_sources, validate_url


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--output", type=Path, default=Path("run-receipt.json"))
    args = parser.parse_args(argv)
    try:
        key = os.getenv("GATEWAY_API_KEY", "")
        if not key.strip():
            raise ValueError("GATEWAY_API_KEY is missing")
        validate_url(args.url)
        commit, sources = snapshot_sources(args.source, args.commit, args.exclude)
        request = RunStart(identity=RunIdentity(run_id=args.run_id, repository=args.repository,
                           commit_sha=commit, artifact_digest=args.artifact_digest), sources=sources)
        import httpx
        with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as client:
            response = client.post(args.url.rstrip("/") + "/v1/runs", json=request.model_dump(),
                                   headers={"X-API-Key": key})
            response.raise_for_status()
        state = RunView.model_validate(response.json())
        if state.identity != request.identity or state.source_manifest_sha256 != source_manifest_digest(sources):
            raise ValueError("Gateway returned another run")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(state.model_dump_json(indent=2) + "\n", encoding="utf-8")
        print(f"Run {args.run_id} accepted; CodeBERT starts independently. Start Checkmarx now on the same snapshot.")
        print("This receipt does not authorize deployment; both detector results are still required.")
        return 0
    except Exception as error:
        print(f"Run creation failed ({type(error).__name__}); no deployment permission.", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
