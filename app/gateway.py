"""Parallel detector coordination and the authoritative Gateway Security Gate."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.contracts import (CheckmarxScan, FinalDecision, GateEvidence, InferenceRequest,
                           InferenceResult, NormalizedScan, RunIdentity, RunStart,
                           RunView, UnitReference, source_manifest_digest)
from app.gate import evaluate
from app.dashboard import create_router
from app.inference import Policy, load_policy
from app.normalize import ReportError, normalize, prepare_sources
from app.store import AuditStore, RunConflict


class DashboardAssets(StaticFiles):
    """Buildless modules must update together after a local code change."""

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response


def canonical_hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")).hexdigest()


def view(record: dict) -> RunView:
    if record.get("schema_version") != "2.0":
        raise HTTPException(409, "Historical sequential run; create a new run_id for the parallel workflow")
    return RunView(identity=RunIdentity.model_validate(record["identity"]),
                   status="decided" if record.get("decision") else "pending",
                   checkmarx_status=record["checkmarx"]["scan_status"] if record.get("checkmarx") else "pending",
                   codebert_status=record["codebert"]["status"] if record.get("codebert") else "pending",
                   source_manifest_sha256=record["source_manifest_sha256"],
                   decision=FinalDecision.model_validate(record["decision"]) if record.get("decision") else None)


def create_app(*, store: AuditStore | None = None, forward: Callable | None = None,
               api_key: str | None = None, policy: Policy | None = None) -> FastAPI:
    expected_key = api_key if api_key is not None else os.getenv("GATEWAY_API_KEY", "")

    @asynccontextmanager
    async def lifespan(instance):
        if not expected_key.strip():
            raise RuntimeError("GATEWAY_API_KEY must be configured")
        if forward is None and not os.getenv("SERVICE_API_KEY", "").strip():
            raise RuntimeError("SERVICE_API_KEY must be configured")
        instance.state.store = store or AuditStore(os.getenv(
            "DATABASE_URL", "sqlite:///" + str(Path("data/audit.sqlite3").resolve())))
        try:
            instance.state.policy = policy or load_policy(Path(os.getenv("POLICY_PATH", "config/final-policy.json")))
        except Exception:
            instance.state.policy = None
        yield

    api = FastAPI(title="AI WhiteSec Gateway and Security Gate", version="2.0.0", lifespan=lifespan)

    @api.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        return JSONResponse(status_code=422, content={"detail": [
            {key: item[key] for key in ("loc", "type", "msg") if key in item}
            for item in error.errors()]})

    def authorize(x_api_key: str = Header(default="")):
        if not expected_key.strip() or not hmac.compare_digest(x_api_key.encode(), expected_key.encode()):
            raise HTTPException(401, "Invalid API key")

    api.include_router(create_router(authorize))
    dashboard_directory = Path(__file__).resolve().parent / "static" / "dashboard"
    api.mount("/dashboard-assets", DashboardAssets(directory=str(dashboard_directory), check_dir=False), name="dashboard-assets")

    @api.get("/", include_in_schema=False)
    @api.get("/dashboard", include_in_schema=False)
    def dashboard_page():
        return FileResponse(dashboard_directory / "index.html", media_type="text/html",
                            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                     "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"})

    def finish_join(record: dict) -> dict:
        if record.get("decision") or not record.get("codebert") or not record.get("checkmarx"):
            return record
        scan = NormalizedScan.model_validate(record["checkmarx"])
        evidence = GateEvidence(identity=RunIdentity.model_validate(record["identity"]),
                                scan_id=scan.scan_id, scan_status=scan.scan_status, scan_mode=scan.scan_mode,
                                findings=scan.findings,
                                coverage_issues=record["coverage_issues"] + scan.coverage_issues,
                                source_manifest_sha256=record["source_manifest_sha256"],
                                units=[UnitReference.model_validate(unit) for unit in record["units"]],
                                inference=InferenceResult.model_validate(record["codebert"]))
        frozen_policy = record.get("policy")
        locked_policy = Policy(frozen_policy["version"], frozen_policy["release_approved"],
                               frozenset(frozen_policy["block_checkmarx_severities"]),
                               frozen_policy["review_score_margin"]) if frozen_policy else None
        record["decision"] = evaluate(evidence, locked_policy).model_dump()
        return record

    async def run_inference(request: InferenceRequest):
        try:
            if forward is not None:
                result = await forward(request)
            else:
                async with httpx.AsyncClient(timeout=120, trust_env=False) as client:
                    response = await client.post(
                        os.getenv("CODEBERT_URL", "http://127.0.0.1:8001").rstrip("/") + "/v1/inferences",
                        json=request.model_dump(), headers={"X-Service-Key": os.getenv("SERVICE_API_KEY", "")},
                    )
                    response.raise_for_status()
                    result = response.json()
            inference = result if isinstance(result, InferenceResult) else InferenceResult.model_validate(result)
            if inference.identity != request.identity or inference.source_manifest_sha256 != request.source_manifest_sha256:
                raise ValueError("Inference returned a different snapshot")
        except Exception as error:
            inference = InferenceResult(identity=request.identity, source_manifest_sha256=request.source_manifest_sha256,
                                        status="error", mode="real", reasons=[f"CodeBERT transport/inference failed ({type(error).__name__})"])

        def merge(record):
            if record.get("codebert"):
                # A stale worker/retry cannot overwrite the first committed result.
                return record
            record["codebert"] = inference.model_dump()
            return finish_join(record)
        api.state.store.update(request.identity.run_id, merge)

    @api.get("/health/live")
    def live():
        return {"status": "alive", "service": "gateway-security-gate"}

    @api.get("/health/ready")
    async def ready():
        try:
            api.state.store.ready()
            if api.state.policy is None:
                raise ValueError("Policy is unavailable")
            if forward is None:
                async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
                    response = await client.get(os.getenv("CODEBERT_URL", "http://127.0.0.1:8001").rstrip("/") + "/health/live")
                    response.raise_for_status()
        except Exception:
            raise HTTPException(503, "Gateway dependencies are unavailable")
        return {"status": "ready", "security_decision_authority": "gateway-security-gate"}

    @api.post("/v1/runs", response_model=RunView, status_code=202, dependencies=[Depends(authorize)])
    async def start(request: RunStart, background: BackgroundTasks):
        try:
            units, issues = prepare_sources(request.sources)
        except ReportError as error:
            raise HTTPException(422, str(error))
        manifest = source_manifest_digest(request.sources)
        gate_policy = api.state.policy
        frozen_policy = {"version": gate_policy.version, "release_approved": gate_policy.release_approved,
                         "block_checkmarx_severities": sorted(gate_policy.block_checkmarx_severities),
                         "review_score_margin": gate_policy.review_score_margin} if gate_policy else None
        record = {"schema_version": "2.0", "identity": request.identity.model_dump(),
                  "source_manifest_sha256": manifest, "coverage_issues": issues,
                  "units": [unit.model_dump(exclude={"code"}) for unit in units],
                  "workflow": {"parallel": ["checkmarx", "codebert"], "join": "gateway", "final": "security-gate"},
                  "policy": frozen_policy, "created_at": time.time(), "inference_requested_at": time.time(),
                  "codebert": None, "checkmarx": None, "decision": None}
        try:
            prior = api.state.store.reserve(request.identity.run_id, canonical_hash(request.model_dump()), record)
        except RunConflict as error:
            raise HTTPException(409, str(error))
        if prior:
            current = prior["record"]
            view(current)
            if not current.get("codebert") and time.time() - current.get("inference_requested_at", 0) > 150:
                claimed = False
                def claim(record):
                    nonlocal claimed
                    if not record.get("codebert") and time.time() - record.get("inference_requested_at", 0) > 150:
                        record["inference_requested_at"] = time.time()
                        claimed = True
                    return record
                current = api.state.store.update(request.identity.run_id, claim)
                if claimed:
                    background.add_task(run_inference, InferenceRequest(identity=request.identity,
                                        source_manifest_sha256=manifest, units=units, coverage_issues=issues))
            return view(current)
        background.add_task(run_inference, InferenceRequest(identity=request.identity,
                            source_manifest_sha256=manifest, units=units, coverage_issues=issues))
        return view(record)

    @api.post("/v1/runs/{run_id}/checkmarx", response_model=RunView, dependencies=[Depends(authorize)])
    async def receive_checkmarx(run_id: str, scan: CheckmarxScan):
        saved = api.state.store.get(run_id)
        if not saved:
            raise HTTPException(404, "Start the source run before delivering Checkmarx results")
        record = saved["record"]
        view(record)
        try:
            normalized = normalize(scan, RunIdentity.model_validate(record["identity"]),
                                   record["source_manifest_sha256"],
                                   [UnitReference.model_validate(unit) for unit in record["units"]])
        except (ReportError, ValueError, TypeError, AttributeError, KeyError) as error:
            raise HTTPException(422, str(error))
        fingerprint = canonical_hash(scan.model_dump())

        def merge(current):
            if current.get("checkmarx"):
                if current["checkmarx_fingerprint"] != fingerprint:
                    raise RunConflict("Checkmarx result is immutable for this run")
                return current
            current["checkmarx"] = normalized.model_dump()
            current["checkmarx_fingerprint"] = fingerprint
            return finish_join(current)
        try:
            return view(api.state.store.update(run_id, merge))
        except RunConflict as error:
            raise HTTPException(409, str(error))

    @api.get("/v1/runs/{run_id}", response_model=RunView, dependencies=[Depends(authorize)])
    def get_run(run_id: str):
        saved = api.state.store.get(run_id)
        if not saved:
            raise HTTPException(404, "Run not found")
        return view(saved["record"])

    @api.post("/v1/scans", dependencies=[Depends(authorize)])
    def obsolete_sequential_endpoint():
        raise HTTPException(410, "Use POST /v1/runs before scanning and then /v1/runs/{run_id}/checkmarx")

    return api


app = create_app()
