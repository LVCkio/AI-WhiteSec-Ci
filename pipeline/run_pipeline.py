from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from urllib import request

from extract_python import extract_repository
from sarif_adapter import adapt_sarif


def http_json(method: str, url: str, payload: dict | None = None, api_key: str = "") -> dict | list:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("X-API-Key", api_key)
    try:
        with request.urlopen(req, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))
    except request.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")[:400]
        raise RuntimeError(
            f"HTTP {exc.code} {exc.reason} from {method} {url}\n"
            f"Response body: {body_text}"
        ) from exc
    except TimeoutError as exc:
        raise RuntimeError(f"Timeout after 120s calling {method} {url}") from exc
    except OSError as exc:
        raise RuntimeError(f"Connection error calling {method} {url}: {exc}") from exc


def ai_findings(units: list[dict], inference_url: str, threshold: float) -> tuple[list[dict], str]:
    if not units:
        model = http_json("GET", f"{inference_url}/v1/model")
        return [], str(model["model_version"])
    findings: list[dict] = []
    model_version = "unknown"
    for offset in range(0, len(units), 200):
        batch = units[offset : offset + 200]
        payload = {
            "samples": [
                {
                    "code": unit["code"],
                    "file_path": unit["file_path"],
                    "function_name": unit.get("function_name"),
                    "start_line": unit.get("start_line"),
                }
                for unit in batch
            ]
        }
        response = http_json("POST", f"{inference_url}/v1/predict/batch", payload)
        model_version = str(response["model_version"])
        for unit, prediction in zip(batch, response["predictions"], strict=True):
            if not prediction["risk_detected"] or prediction["confidence"] < threshold:
                continue
            findings.append(
                {
                    "source": "ai",
                    "file_path": unit["file_path"],
                    "function_name": unit.get("function_name"),
                    "start_line": unit.get("start_line"),
                    "end_line": unit.get("end_line"),
                    "cwe": prediction["cwe"],
                    "severity": "high" if prediction["confidence"] >= 0.9 else "medium",
                    "confidence": prediction["confidence"],
                    "title": f"AI prediction: {prediction['cwe']}",
                    "description": prediction["explanation"],
                    "evidence": {
                        "model_version": prediction["model_version"],
                        "model_mode": prediction["model_mode"],
                        "scores": prediction["scores"],
                        "source_type": unit["source_type"],
                    },
                }
            )
    return findings, model_version


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AI WhiteSec integration pipeline")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--files", nargs="*")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--project", default="AI WhiteSec Project")
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--sarif", type=Path)
    parser.add_argument("--backend", default="http://localhost:8000")
    parser.add_argument("--inference", default="http://localhost:8001")
    parser.add_argument("--threshold", type=float, default=0.70)
    parser.add_argument("--output", type=Path, default=Path("artifacts/pipeline-result.json"))
    # API key for backend authentication; also read from BACKEND_API_KEY env var.
    parser.add_argument("--api-key", default=os.getenv("BACKEND_API_KEY", ""), dest="api_key")
    args = parser.parse_args()

    started = time.perf_counter()
    units = extract_repository(args.root, args.files)
    ai, model_version = ai_findings(units, args.inference.rstrip("/"), args.threshold)
    sast = adapt_sarif(args.sarif) if args.sarif and args.sarif.exists() else []

    # Convenience shortcut: pass api_key to every backend call.
    def backend(method: str, path: str, payload: dict | None = None) -> dict | list:
        return http_json(method, f"{args.backend.rstrip('/')}{path}", payload, api_key=args.api_key)

    # Create the run record first so we can mark it failed on error.
    run = backend(
        "POST",
        "/api/v1/runs",
        {
            "project": args.project,
            "repository": args.repository,
            "commit_sha": args.commit_sha,
            "branch": args.branch,
            "trigger": "pipeline",
            "model_version": model_version,
            "checkmarx_config": "sarif-import" if sast else None,
        },
    )
    run_id = run["id"]
    combined: list = []

    try:
        if ai or sast:
            backend(
                "POST",
                f"/api/v1/runs/{run_id}/findings",
                {"findings": [*ai, *sast]},
            )
        combined = backend("POST", f"/api/v1/runs/{run_id}/correlate", {})
        elapsed = round(time.perf_counter() - started, 4)
        backend(
            "PATCH",
            f"/api/v1/runs/{run_id}",
            {
                "status": "completed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": elapsed,
            },
        )
    except Exception as exc:
        # Mark the run as failed so the dashboard reflects the real outcome.
        elapsed = round(time.perf_counter() - started, 4)
        try:
            backend(
                "PATCH",
                f"/api/v1/runs/{run_id}",
                {
                    "status": "failed",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "duration_seconds": elapsed,
                },
            )
        except Exception:
            pass  # Best-effort; original error takes priority.
        print(f"[pipeline] FAILED: {exc}", file=sys.stderr)
        sys.exit(1)

    report = {
        "run_id": run_id,
        "repository": args.repository,
        "commit_sha": args.commit_sha,
        "model_version": model_version,
        "counts": {"code_units": len(units), "ai": len(ai), "checkmarx": len(sast), "combined": len(combined)},
        "duration_seconds": elapsed,
        "combined_findings": combined,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
