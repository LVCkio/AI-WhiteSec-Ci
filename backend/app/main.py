from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, selectinload

from .api_extra import lifespan, router as extra_router
from .config import get_settings
from .database import Base, engine, get_db
from .logging_config import get_logger, setup_logging
from .middleware import APIKeyMiddleware, TraceMiddleware
from .models import Finding, ScanRun
from .schemas import (
    FindingBatchCreate,
    FindingCreate,
    FindingRead,
    ScanRunCreate,
    ScanRunDetail,
    ScanRunRead,
    ScanRunUpdate,
)
from .services.correlation import correlate_findings, make_fingerprint
from .services.remediation import remediation_for


settings = get_settings()
setup_logging(level=settings.log_level)
logger = get_logger(__name__)

app = FastAPI(
    title="AI WhiteSec CI API",
    version="0.1.0",
    description="Integration API for CodeBERT and Checkmarx security findings.",
    lifespan=lifespan,
)
# Middleware is applied in reverse registration order (last added = outermost).
# Order here: CORS → APIKey → Trace (Trace is the first to run on incoming).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(APIKeyMiddleware)
app.add_middleware(TraceMiddleware)

app.include_router(extra_router)

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")
DbSession = Annotated[Session, Depends(get_db)]



@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "backend", "version": app.version}


@app.post("/api/v1/runs", response_model=ScanRunRead, status_code=201)
def create_run(payload: ScanRunCreate, db: DbSession) -> ScanRun:
    run = ScanRun(**payload.model_dump())
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@app.get("/api/v1/runs", response_model=list[ScanRunRead])
def list_runs(
    db: DbSession,
    limit: int = Query(default=25, ge=1, le=200),
) -> list[ScanRun]:
    return list(db.scalars(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit)))


@app.get("/api/v1/runs/{run_id}", response_model=ScanRunDetail)
def get_run(run_id: str, db: DbSession) -> ScanRun:
    run = db.scalar(
        select(ScanRun).options(selectinload(ScanRun.findings)).where(ScanRun.id == run_id)
    )
    if run is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return run


@app.patch("/api/v1/runs/{run_id}", response_model=ScanRunRead)
def update_run(run_id: str, payload: ScanRunUpdate, db: DbSession) -> ScanRun:
    run = db.get(ScanRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(run, key, value)
    if run.status == "completed" and run.completed_at is None:
        run.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(run)
    return run


def finding_from_payload(run_id: str, payload: FindingCreate) -> Finding:
    data = payload.model_dump()
    data["remediation"] = data.get("remediation") or remediation_for(data.get("cwe"))
    data["fingerprint"] = data.get("fingerprint") or make_fingerprint(data)
    return Finding(run_id=run_id, **data)


@app.post("/api/v1/runs/{run_id}/findings", response_model=list[FindingRead], status_code=201)
def add_findings(run_id: str, payload: FindingBatchCreate, db: DbSession) -> list[Finding]:
    if db.get(ScanRun, run_id) is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    if any(item.source == "combined" for item in payload.findings):
        raise HTTPException(status_code=400, detail="Combined findings must be created by the correlator")
    findings = [finding_from_payload(run_id, item) for item in payload.findings]
    db.add_all(findings)
    db.commit()
    for item in findings:
        db.refresh(item)
    return findings


@app.post("/api/v1/runs/{run_id}/correlate", response_model=list[FindingRead])
def correlate_run(run_id: str, db: DbSession) -> list[Finding]:
    if db.get(ScanRun, run_id) is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    raw = list(
        db.scalars(
            select(Finding).where(Finding.run_id == run_id, Finding.source.in_(["ai", "checkmarx"]))
        )
    )
    raw_dicts = [FindingRead.model_validate(item).model_dump() for item in raw]
    correlated = correlate_findings(raw_dicts)
    db.execute(delete(Finding).where(Finding.run_id == run_id, Finding.source == "combined"))
    combined_rows = [Finding(run_id=run_id, **item) for item in correlated]
    db.add_all(combined_rows)
    db.commit()
    for item in combined_rows:
        db.refresh(item)
    return combined_rows


@app.get("/api/v1/dashboard/summary")
def dashboard_summary(db: DbSession) -> dict:
    total_runs = db.scalar(select(func.count()).select_from(ScanRun)) or 0
    completed_runs = db.scalar(
        select(func.count()).select_from(ScanRun).where(ScanRun.status == "completed")
    ) or 0
    combined_total = db.scalar(
        select(func.count()).select_from(Finding).where(Finding.source == "combined")
    ) or 0
    by_status = dict(
        db.execute(
            select(Finding.combination_status, func.count())
            .where(Finding.source == "combined")
            .group_by(Finding.combination_status)
        ).all()
    )
    by_cwe = dict(
        db.execute(
            select(Finding.cwe, func.count())
            .where(Finding.source == "combined")
            .group_by(Finding.cwe)
            .order_by(func.count().desc())
        ).all()
    )
    return {
        "runs": {"total": total_runs, "completed": completed_runs},
        "combined_findings": combined_total,
        "by_combination_status": by_status,
        "by_cwe": by_cwe,
    }


@app.post("/api/v1/demo/seed", response_model=ScanRunDetail, status_code=201)
def seed_demo(db: DbSession) -> ScanRun:
    commit = sha256(datetime.now(timezone.utc).isoformat().encode()).hexdigest()[:12]
    run = ScanRun(
        project="AI WhiteSec Demo",
        repository="demo/vulnerable-python-app",
        commit_sha=commit,
        branch="main",
        trigger="demo",
        status="completed",
        model_version="mock-codebert-5cwe-v1",
        checkmarx_config="demo-sast",
        completed_at=datetime.now(timezone.utc),
        duration_seconds=37.4,
    )
    db.add(run)
    db.flush()
    samples = [
        FindingCreate(
            source="ai",
            file_path="app/users.py",
            function_name="find_user",
            start_line=41,
            end_line=48,
            cwe="CWE-89",
            severity="high",
            confidence=0.93,
            title="Possible SQL injection",
            evidence={"model_version": "mock-codebert-5cwe-v1", "mock": True},
        ),
        FindingCreate(
            source="checkmarx",
            file_path="app/users.py",
            function_name="find_user",
            start_line=44,
            end_line=44,
            cwe="CWE-89",
            severity="high",
            title="SQL query built from untrusted input",
            evidence={"rule_id": "Cx.Python.SQL_Injection"},
        ),
        FindingCreate(
            source="checkmarx",
            file_path="app/files.py",
            function_name="download",
            start_line=19,
            end_line=24,
            cwe="CWE-22",
            severity="medium",
            title="User-controlled file path",
            evidence={"rule_id": "Cx.Python.Path_Traversal"},
        ),
        FindingCreate(
            source="ai",
            file_path="app/templates.py",
            function_name="preview",
            start_line=8,
            end_line=13,
            cwe="CWE-79",
            severity="medium",
            confidence=0.81,
            title="Possible cross-site scripting",
            evidence={"model_version": "mock-codebert-5cwe-v1", "mock": True},
        ),
    ]
    raw_rows = [finding_from_payload(run.id, item) for item in samples]
    db.add_all(raw_rows)
    db.flush()
    raw_dicts = [FindingRead.model_validate(item).model_dump() for item in raw_rows]
    db.add_all([Finding(run_id=run.id, **item) for item in correlate_findings(raw_dicts)])
    db.commit()
    return db.scalar(
        select(ScanRun).options(selectinload(ScanRun.findings)).where(ScanRun.id == run.id)
    )

