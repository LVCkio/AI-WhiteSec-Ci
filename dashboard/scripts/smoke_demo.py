"""Verify independent CodeBERT execution and the Gateway's two-branch join."""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.contracts import CheckmarxScan, RunStart, SourceFile, source_manifest_digest


def demo_payload(vulnerable: bool, run_id: str | None = None) -> tuple[RunStart, CheckmarxScan]:
    content = "# demo: SQL_INJECTION\ndef lookup(name):\n    return name\n" if vulnerable else "def hello():\n    return 'hello'\n"
    source = SourceFile(path="sample.py", content=content,
                        sha256=hashlib.sha256(content.encode()).hexdigest())
    start = RunStart.model_validate({"identity": {
        "run_id": run_id or "parallel-demo-" + uuid.uuid4().hex, "repository": "local/demo-fixture",
        "commit_sha": "a" * 40, "artifact_digest": "sha256:" + "b" * 64},
        "sources": [source.model_dump()]})
    results = [{"ruleId": "SQL_Injection", "level": "error", "message": {"text": "Synthetic demo finding"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "sample.py"},
                                                        "region": {"startLine": 2}}}]}] if vulnerable else []
    scan = CheckmarxScan(scan_id="demo-checkmarx-fixture", status="completed", mode="demo",
                        preset="demo-sast", commit_sha=start.identity.commit_sha,
                        source_manifest_sha256=source_manifest_digest([source]),
                        sarif={"version": "2.1.0", "runs": [{
                            "tool": {"driver": {"name": "Checkmarx SAST (demo)", "rules": [{
                                "id": "SQL_Injection", "properties": {"cwe": "CWE-89", "severity": "high"}}]}},
                            "invocations": [{"executionSuccessful": True}], "results": results}]})
    return start, scan


def exercise(client, headers):
    for vulnerable, expected in [(True, "BLOCK"), (False, "PASS")]:
        start, scan = demo_payload(vulnerable)
        response = client.post("/v1/runs", json=start.model_dump(), headers=headers)
        response.raise_for_status()
        run_url = "/v1/runs/" + start.identity.run_id
        deadline = time.monotonic() + 15
        while True:
            response = client.get(run_url, headers=headers)
            response.raise_for_status()
            state = response.json()
            if state["codebert_status"] != "pending":
                break
            if time.monotonic() > deadline:
                raise TimeoutError("CodeBERT branch did not finish")
            time.sleep(0.05)
        assert state["checkmarx_status"] == "pending" and state["decision"] is None, state
        assert state["codebert_status"] == "completed", state
        print("CodeBERT completed independently; Checkmarx pending; no final decision")
        response = client.post(run_url + "/checkmarx", json=scan.model_dump(), headers=headers)
        response.raise_for_status()
        result = response.json()["decision"]
        assert result["authority"] == "gateway-security-gate", result
        assert result["decision"] == expected, result
        assert result["mode"] == "demo" and result["allow_deploy"] is False, result
        print(f"{expected}: authority=gateway-security-gate, mode=demo, allow_deploy=false")


def offline():
    from fastapi.testclient import TestClient
    from app.codebert import create_app as create_codebert
    from app.gateway import create_app as create_gateway
    from app.store import AuditStore
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
        "MODEL_MODE": "demo", "SERVICE_API_KEY": "offline-service-key", "GATEWAY_API_KEY": "offline-gateway-key",
    }):
        with TestClient(create_codebert()) as model_client:
            async def forward(request):
                response = model_client.post("/v1/inferences", json=request.model_dump(),
                                             headers={"X-Service-Key": "offline-service-key"})
                response.raise_for_status()
                return response.json()
            gateway = create_gateway(store=AuditStore("sqlite:///" + str(Path(directory) / "audit.sqlite3")),
                                     forward=forward, api_key="offline-gateway-key")
            with TestClient(gateway) as client:
                exercise(client, {"X-API-Key": "offline-gateway-key"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    if args.offline:
        offline()
        return
    import httpx
    with httpx.Client(base_url=args.url.rstrip("/"), timeout=150, trust_env=False) as client:
        exercise(client, {"X-API-Key": os.environ["GATEWAY_API_KEY"]})


if __name__ == "__main__":
    main()
