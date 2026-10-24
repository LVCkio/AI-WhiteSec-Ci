"""Authenticated, read-only dashboard projections of the parallel audit log."""
from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.contracts import (GROUPS, FinalDecision, InferenceResult, NormalizedScan,
                           RunIdentity, UnitReference, safe_path)
from app.normalize import CWE_GROUPS

LIMIT = 1000
DECISIONS = ("PASS", "BLOCK", "REVIEW", "ERROR")
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
LOCAL_TIMEZONE = timezone(timedelta(hours=7))
WORKFLOW = {"parallel": ["checkmarx", "codebert"], "join": "gateway",
            "final": "security-gate", "authority": "gateway-security-gate"}


def _fields(value: dict, model) -> dict:
    if not isinstance(value, dict):
        raise ValueError("Audit component is not an object")
    return {name: value[name] for name in model.model_fields if name in value}


def _timestamp(value) -> str | None:
    try:
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
        elif type(value) in {int, float} and math.isfinite(value) and value > 0:
            parsed = datetime.fromtimestamp(value, tz=timezone.utc)
        else:
            return None
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _project(run_id: str, record: dict) -> dict:
    """Whitelist fields; source snippets, scanner messages and keys stay out."""
    if not isinstance(record, dict) or record.get("schema_version") != "2.0":
        raise ValueError("Only parallel audit records are supported")
    identity = RunIdentity.model_validate(_fields(record.get("identity"), RunIdentity))
    if identity.run_id != run_id:
        raise ValueError("Audit identity differs from its row")
    manifest = record.get("source_manifest_sha256")
    if not isinstance(manifest, str) or re.fullmatch(r"[0-9a-f]{64}", manifest) is None:
        raise ValueError("Audit source manifest is invalid")
    raw_units = record.get("units")
    if not isinstance(raw_units, list) or not raw_units:
        raise ValueError("Audit needs source references")
    units = [UnitReference.model_validate(_fields(unit, UnitReference)) for unit in raw_units]
    if len({unit.unit_id for unit in units}) != len(units):
        raise ValueError("Audit source unit identifiers are duplicated")
    for unit in units:
        safe_path(unit.path)
        if not unit.unit_id.strip() or unit.end_line < unit.start_line:
            raise ValueError("Audit source unit reference is invalid")
    inference = (InferenceResult.model_validate(_fields(record["codebert"], InferenceResult))
                 if record.get("codebert") else None)
    if inference and (inference.identity != identity or inference.source_manifest_sha256 != manifest):
        raise ValueError("Audit inference belongs to a different snapshot")
    if inference and (len({item.unit_id for item in inference.predictions}) != len(inference.predictions)
                      or {item.unit_id for item in inference.predictions} - {unit.unit_id for unit in units}):
        raise ValueError("Audit predictions do not match source references")
    scan = (NormalizedScan.model_validate(_fields(record["checkmarx"], NormalizedScan))
            if record.get("checkmarx") else None)
    if scan and scan.source_manifest_sha256 != manifest:
        raise ValueError("Audit scanner belongs to a different snapshot")
    decision = (FinalDecision.model_validate(_fields(record["decision"], FinalDecision))
                if record.get("decision") else None)
    if decision and (decision.identity != identity or scan is None or inference is None
                     or decision.scan_id != scan.scan_id):
        raise ValueError("Audit decision is missing its bound detector evidence")
    observed_mode = ("demo" if (inference and inference.mode == "demo") or (scan and scan.scan_mode == "demo")
                     else "real" if inference or scan else "unknown")
    if decision and decision.mode != observed_mode:
        raise ValueError("Audit decision and detector modes disagree")
    coverage = record.get("coverage_issues", [])
    if not isinstance(coverage, list) or any(not isinstance(item, str) for item in coverage):
        raise ValueError("Audit coverage issues are invalid")
    created = (_timestamp(record.get("created_at")) or _timestamp(record.get("inference_requested_at"))
               or (_timestamp(decision.created_at) if decision else None))
    findings = [finding.model_dump(exclude={"message"}) for finding in scan.findings] if scan else []
    predictions = [prediction.model_dump() for prediction in inference.predictions] if inference else []
    maximum = max((score for prediction in predictions for score in prediction["scores"].values()), default=None)
    brief = {"run_id": run_id, "repository": identity.repository, "commit_sha": identity.commit_sha,
             "created_at": created, "status": "decided" if decision else "pending",
             "decision": decision.decision if decision else None, "mode": observed_mode,
             "allow_deploy": bool(decision and decision.allow_deploy and observed_mode == "real"),
             "checkmarx_status": scan.scan_status if scan else "pending",
             "codebert_status": inference.status if inference else "pending",
             "findings_count": len(findings), "units_count": len(units), "max_score": maximum}
    policy = record.get("policy")
    safe_policy = ({name: policy[name] for name in ("version", "release_approved", "block_checkmarx_severities",
                                                  "review_score_margin") if name in policy}
                   if isinstance(policy, dict) else None)
    return {"schema_version": "1.0", "run": brief, "identity": identity.model_dump(),
            "source_manifest_sha256": manifest, "units": [unit.model_dump() for unit in units],
            "coverage_issues": coverage, "workflow": dict(WORKFLOW), "policy": safe_policy,
            "checkmarx": ({"scan_id": scan.scan_id, "status": scan.scan_status, "mode": scan.scan_mode,
                           "preset": scan.scan_preset, "raw_report_sha256": scan.raw_report_sha256,
                           "source_manifest_sha256": scan.source_manifest_sha256,
                           "coverage_issues": list(scan.coverage_issues), "findings": findings} if scan else None),
            "codebert": ({"status": inference.status, "mode": inference.mode, "authority": inference.authority,
                          "model_version": inference.model_version, "thresholds": dict(inference.thresholds),
                          "predictions": predictions, "coverage_issues": list(inference.coverage_issues),
                          "reasons": list(inference.reasons)} if inference else None),
            "final_decision": decision.model_dump(exclude={"predictions"}) if decision else None}


def _overview(store) -> tuple[dict, list[dict]]:
    window = store.list_records(LIMIT)
    details = []
    legacy = invalid = 0
    for item in window["records"]:
        record = item["record"]
        if isinstance(record, dict) and record.get("schema_version") == "1.0":
            legacy += 1
            continue
        try:
            details.append(_project(item["run_id"], record))
        except (ValueError, TypeError, KeyError, AttributeError):
            invalid += 1
    details.sort(key=lambda item: (item["run"]["created_at"] or "", item["run"]["run_id"]), reverse=True)
    runs = [item["run"] for item in details]
    findings = [{"run_id": item["run"]["run_id"], "source": "checkmarx", **finding}
                for item in details if item["checkmarx"] for finding in item["checkmarx"]["findings"]]
    scores = [{"run_id": item["run"]["run_id"], **prediction}
              for item in details if item["codebert"] for prediction in item["codebert"]["predictions"]]
    decision_counts = Counter(run["decision"] for run in runs if run["decision"])
    mode_counts = Counter(run["mode"] for run in runs)
    severity_counts = Counter(finding["severity"] for finding in findings)
    categories = []
    for group in GROUPS:
        threshold_hits = 0
        for item in details:
            model = item["codebert"]
            if model and group in model["thresholds"]:
                threshold = model["thresholds"][group]
                if math.isfinite(threshold) and 0 < threshold < 1:
                    threshold_hits += sum(prediction["scores"][group] >= threshold for prediction in model["predictions"])
        categories.append({"group": group, "cwes": sorted(cwe for cwe, mapped in CWE_GROUPS.items() if mapped == group),
                           "checkmarx_findings": sum(group in finding["groups"] for finding in findings),
                           "ai_threshold_hits": threshold_hits})
    trend = {}
    undated = 0
    for run in runs:
        if not run["created_at"]:
            undated += 1
            continue
        date = datetime.fromisoformat(run["created_at"]).astimezone(LOCAL_TIMEZONE).date().isoformat()
        bucket = trend.setdefault(date, {"date": date, "runs": 0, **{key: 0 for key in DECISIONS}, "pending": 0})
        bucket["runs"] += 1
        bucket[run["decision"] or "pending"] += 1
    observed = next((item for item in details if item["codebert"]
                     and item["codebert"]["status"] == "completed"), None)
    model = {"status": "unavailable", "mode": None, "model_version": None, "thresholds": {},
             "observed_run_id": None, "performance": None,
             "performance_note": "No labelled validation metrics are stored in this audit window",
             "readiness": "not_checked"}
    if observed:
        actual = observed["codebert"]
        model.update(status="demo" if actual["mode"] == "demo" else "observed-real",
                     mode=actual["mode"], model_version=actual["model_version"], thresholds=actual["thresholds"],
                     observed_run_id=observed["run"]["run_id"])
    warnings = []
    if window["truncated"]:
        warnings.append(f"Audit window is capped at {LIMIT} rows selected by run_id; aggregates apply to included runs only")
    if legacy:
        warnings.append(f"Skipped {legacy} historical sequential records")
    if invalid:
        warnings.append(f"Skipped {invalid} invalid audit records")
    if undated:
        warnings.append(f"{undated} included runs have no audited timestamp and are omitted from the trend")
    payload = {"schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(),
               "window": {"limit": LIMIT, "total_records": window["total_records"], "included_runs": len(runs),
                          "legacy_skipped": legacy, "invalid_skipped": invalid,
                          "truncated": window["truncated"], "selection": window["selection"]},
               "summary": {"total_runs": len(runs), "pending_runs": sum(run["status"] == "pending" for run in runs),
                           "decided_runs": sum(run["status"] == "decided" for run in runs),
                           "decisions": {key: decision_counts[key] for key in DECISIONS},
                           "modes": {key: mode_counts[key] for key in ("real", "demo", "unknown")},
                           "release_allowed_runs": sum(run["allow_deploy"] for run in runs),
                           "demo_pass_runs": sum(run["decision"] == "PASS" and run["mode"] == "demo" for run in runs),
                           "findings_count": len(findings), "severities": {key: severity_counts[key] for key in SEVERITIES}},
               "runs": runs, "findings": findings, "scores": scores, "categories": categories,
               "trend": [trend[date] for date in sorted(trend)], "trend_timezone": "Asia/Saigon",
               "model": model, "warnings": warnings, "workflow": dict(WORKFLOW)}
    return payload, details


def create_router(authorizer: Callable) -> APIRouter:
    """Reuse Gateway's configured authorization, including factory test keys."""
    router = APIRouter(prefix="/v1/dashboard", tags=["dashboard"], dependencies=[Depends(authorizer)])

    @router.get("")
    def overview(request: Request):
        payload, _ = _overview(request.app.state.store)
        return JSONResponse(payload, headers={"Cache-Control": "no-store"})

    @router.get("/export")
    def export(request: Request):
        payload, details = _overview(request.app.state.store)
        payload["details"] = details
        return JSONResponse(payload, headers={"Cache-Control": "no-store",
                                              "Content-Disposition": 'attachment; filename="ai-whitesec-audit.json"'})

    @router.get("/runs/{run_id}")
    def detail(run_id: str, request: Request):
        saved = request.app.state.store.get(run_id)
        if saved is None:
            raise HTTPException(404, "Run not found")
        record = saved["record"]
        if not isinstance(record, dict) or record.get("schema_version") != "2.0":
            raise HTTPException(409, "Historical sequential run is not available in the parallel dashboard")
        try:
            payload = _project(run_id, record)
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(409, "Audit record is invalid")
        return JSONResponse(payload, headers={"Cache-Control": "no-store"})

    return router
