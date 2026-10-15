"""Independent CodeBERT inference branch; Gateway owns the Security Gate.

The service needs a source snapshot, not a Checkmarx report. It returns bound
model evidence and coverage information without issuing deployment decisions.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.contracts import GROUPS, InferenceRequest, InferenceResult, Prediction, safe_path
from app.inference import ContextTooLong, build_engine


@dataclass
class Runtime:
    mode: str
    engine: Any = None
    startup_error: str | None = None


@asynccontextmanager
async def lifespan(application: FastAPI):
    configured_mode = os.getenv("MODEL_MODE", "real")
    runtime = Runtime(mode=configured_mode if configured_mode in {"real", "demo"} else "real")
    application.state.runtime = runtime
    try:
        runtime.engine = build_engine(configured_mode, Path(os.getenv("MODEL_DIR", "models/current")))
        _engine_metadata(runtime)
    except Exception as exc:
        # Keep checkpoint paths, source, and exception details out of the API.
        runtime.engine = None
        runtime.startup_error = f"Startup validation failed ({type(exc).__name__})"
    yield
    application.state.runtime = None


def authenticate(service_key: str | None) -> None:
    expected = os.getenv("SERVICE_API_KEY", "")
    if not expected.strip():
        raise HTTPException(status_code=503, detail="Service authentication is not configured")
    if service_key is None or not service_key.strip() or not hmac.compare_digest(
        service_key.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="Invalid service credentials")


def _engine_metadata(runtime: Runtime) -> tuple[str, dict[str, float]]:
    engine = runtime.engine
    if engine is None or runtime.startup_error:
        raise ValueError("Inference engine is unavailable")
    if runtime.mode not in {"real", "demo"} or getattr(engine, "mode", None) != runtime.mode:
        raise ValueError("Inference engine mode is inconsistent")
    version = getattr(engine, "model_version", None)
    if not isinstance(version, str) or not version.strip():
        raise ValueError("Inference needs a model version")
    thresholds = getattr(engine, "thresholds", None)
    if not isinstance(thresholds, dict) or set(thresholds) != set(GROUPS):
        raise ValueError("Inference needs six calibrated thresholds")
    if any(type(value) not in {float, int} or not math.isfinite(value) or not 0 < value < 1
           for value in thresholds.values()):
        raise ValueError("Inference thresholds are invalid")
    return version, dict(thresholds)


def evaluate(request: InferenceRequest, runtime: Runtime) -> InferenceResult:
    """Classify independently, preserving the exact run and source binding."""
    common = dict(identity=request.identity, source_manifest_sha256=request.source_manifest_sha256,
                  mode="demo" if runtime.mode == "demo" else "real")
    coverage_issues = list(request.coverage_issues)
    predictions: list[Prediction] = []
    model_version = None
    thresholds: dict[str, float] = {}

    def result(status: str, reasons: list[str]) -> InferenceResult:
        return InferenceResult(**common, status=status, model_version=model_version,
                               thresholds=thresholds, predictions=predictions,
                               coverage_issues=coverage_issues, reasons=reasons)

    unit_ids = {unit.unit_id for unit in request.units}
    if len(unit_ids) != len(request.units) or any(not unit_id.strip() for unit_id in unit_ids):
        return result("error", ["Source unit identifiers must be nonblank and unique"])
    for unit in request.units:
        try:
            safe_path(unit.path)
        except ValueError:
            return result("error", ["Source unit path is invalid"])
        line_count = max(1, len(unit.code.splitlines()))
        if (unit.end_line < unit.start_line or unit.end_line - unit.start_line + 1 != line_count
                or hashlib.sha256(unit.code.encode("utf-8")).hexdigest() != unit.sha256):
            return result("error", ["Source unit digest or line range is invalid"])

    try:
        model_version, thresholds = _engine_metadata(runtime)
    except Exception:
        return result("error", ["Validated CodeBERT inference engine is unavailable"])

    for unit in request.units:
        if not unit.code.strip():
            coverage_issues.append(f"Source unit {unit.unit_id} has no code to classify")
            continue
        try:
            prediction = runtime.engine.predict(unit)
        except ContextTooLong as exc:
            coverage_issues.append(
                f"Source unit {unit.unit_id} exceeds model coverage "
                f"({exc.token_count} > {exc.max_tokens} tokens)"
            )
            continue
        except Exception:
            return result("error", ["CodeBERT inference failed"])
        if not isinstance(prediction, Prediction) or prediction.unit_id != unit.unit_id:
            coverage_issues.append(f"Missing valid prediction for source unit {unit.unit_id}")
            continue
        try:
            # Revalidate even if a custom engine bypassed Pydantic construction.
            prediction = Prediction.model_validate(prediction.model_dump())
        except Exception:
            return result("error", ["CodeBERT inference produced invalid probabilities"])
        predictions.append(prediction)

    if coverage_issues or len(predictions) != len(request.units):
        return result("incomplete", ["CodeBERT did not completely cover the submitted source snapshot"])
    reasons = ["CodeBERT produced probabilities for every submitted source unit"]
    if runtime.mode == "demo":
        reasons.append("Demo fixture probabilities are for workflow validation")
    return result("completed", reasons)


def create_app() -> FastAPI:
    """Construct an inference service with runtime state isolated per instance."""
    application = FastAPI(title="CodeBERT Inference", version="2.0.0", lifespan=lifespan)

    @application.exception_handler(RequestValidationError)
    async def invalid_request(_request, error: RequestValidationError):
        # FastAPI's default validation errors include the submitted input. A
        # rejected source snippet must not be copied into logs or API errors.
        details = [{"loc": list(item["loc"]), "type": item["type"], "msg": item["msg"]}
                   for item in error.errors()]
        return JSONResponse(status_code=422, content={"detail": details})

    @application.get("/health/live")
    def health_live():
        return {"status": "alive"}

    @application.get("/health/ready")
    def health_ready():
        runtime = getattr(application.state, "runtime", None)
        try:
            version, _ = _engine_metadata(runtime)
        except Exception:
            return JSONResponse(status_code=503, content={"status": "unavailable",
                                                         "authority": "codebert-inference"})
        return {"status": "ready", "mode": runtime.mode, "authority": "codebert-inference",
                "model_version": version}

    @application.post("/v1/inferences", response_model=InferenceResult)
    def inference(request: InferenceRequest, x_service_key: str | None = Header(default=None)):
        authenticate(x_service_key)
        runtime = getattr(application.state, "runtime", None) or Runtime(
            mode="real", startup_error="Not initialized"
        )
        return evaluate(request, runtime)

    return application


app = create_app()
