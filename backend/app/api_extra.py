"""Additional endpoints: global findings list, project summary, and lifespan startup.

Added:
  GET /api/v1/findings          — paginated global findings list with filters
  GET /api/v1/projects          — project-level aggregation from scan_runs
  GET /api/v1/stats/live        — live KPI for the dashboard overview screen
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .logging_config import get_logger
from .models import Finding, ScanRun
from .schemas import FindingRead

logger = get_logger(__name__)
DbSession = Annotated[Session, Depends(get_db)]

router = APIRouter()


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app):
    """Create tables and log startup (Alembic handles schema in Docker)."""
    Base.metadata.create_all(bind=engine)
    logger.info("startup", extra={"event": "tables_ensured"})
    yield
    logger.info("shutdown")


# ── Global findings list ──────────────────────────────────────────────────────

@router.get("/api/v1/findings", response_model=list[FindingRead])
def list_findings(
    db: DbSession,
    source: str | None = Query(default=None, description="Filter by source: ai | checkmarx | combined"),
    severity: str | None = Query(default=None, description="Filter by severity: critical | high | medium | low | info"),
    cwe: str | None = Query(default=None, description="Filter by CWE, e.g. CWE-89"),
    combination_status: str | None = Query(default=None, description="AGREEMENT | AI_ONLY | SAST_ONLY"),
    project: str | None = Query(default=None, description="Filter by project name (partial match)"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[Finding]:
    """Return findings across all runs with optional filters."""
    stmt = (
        select(Finding)
        .join(ScanRun, Finding.run_id == ScanRun.id)
        .order_by(Finding.created_at.desc())
    )
    if source:
        stmt = stmt.where(Finding.source == source)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if cwe:
        stmt = stmt.where(Finding.cwe == cwe)
    if combination_status:
        stmt = stmt.where(Finding.combination_status == combination_status)
    if project:
        stmt = stmt.where(ScanRun.project.ilike(f"%{project}%"))
    stmt = stmt.limit(limit).offset(offset)
    return list(db.scalars(stmt))


# ── Project aggregation ───────────────────────────────────────────────────────

@router.get("/api/v1/projects")
def list_projects(db: DbSession) -> list[dict]:
    """Aggregate project-level statistics from scan_runs."""
    # All distinct project names
    project_names = db.scalars(select(distinct(ScanRun.project))).all()
    result = []
    for name in sorted(project_names):
        runs_q = select(ScanRun).where(ScanRun.project == name)
        runs = list(db.scalars(runs_q))
        total = len(runs)
        completed = sum(1 for r in runs if r.status == "completed")
        failed = sum(1 for r in runs if r.status == "failed")
        running = sum(1 for r in runs if r.status == "running")

        # Latest run
        latest = db.scalar(
            select(ScanRun)
            .where(ScanRun.project == name)
            .order_by(ScanRun.started_at.desc())
            .limit(1)
        )

        # Combined findings count for this project
        combined_count = db.scalar(
            select(func.count())
            .select_from(Finding)
            .join(ScanRun, Finding.run_id == ScanRun.id)
            .where(ScanRun.project == name, Finding.source == "combined")
        ) or 0

        # High/critical combined findings
        high_count = db.scalar(
            select(func.count())
            .select_from(Finding)
            .join(ScanRun, Finding.run_id == ScanRun.id)
            .where(
                ScanRun.project == name,
                Finding.source == "combined",
                Finding.severity.in_(["high", "critical"]),
            )
        ) or 0

        result.append({
            "project": name,
            "repository": latest.repository if latest else None,
            "runs": {"total": total, "completed": completed, "failed": failed, "running": running},
            "latest_run": {
                "id": latest.id,
                "status": latest.status,
                "commit_sha": latest.commit_sha,
                "branch": latest.branch,
                "started_at": latest.started_at.isoformat() if latest.started_at else None,
                "model_version": latest.model_version,
            } if latest else None,
            "findings": {"combined": combined_count, "high_critical": high_count},
        })
    return result


# ── Live KPI for dashboard ────────────────────────────────────────────────────

@router.get("/api/v1/stats/live")
def live_stats(db: DbSession) -> dict:
    """Live KPI numbers consumed by the dashboard overview screen."""
    total_runs = db.scalar(select(func.count()).select_from(ScanRun)) or 0
    completed = db.scalar(select(func.count()).select_from(ScanRun).where(ScanRun.status == "completed")) or 0
    failed = db.scalar(select(func.count()).select_from(ScanRun).where(ScanRun.status == "failed")) or 0
    running = db.scalar(select(func.count()).select_from(ScanRun).where(ScanRun.status == "running")) or 0

    combined_total = db.scalar(select(func.count()).select_from(Finding).where(Finding.source == "combined")) or 0
    agreement = db.scalar(select(func.count()).select_from(Finding).where(Finding.combination_status == "AGREEMENT")) or 0
    ai_only = db.scalar(select(func.count()).select_from(Finding).where(Finding.combination_status == "AI_ONLY")) or 0
    sast_only = db.scalar(select(func.count()).select_from(Finding).where(Finding.combination_status == "SAST_ONLY")) or 0

    high_crit = db.scalar(
        select(func.count()).select_from(Finding).where(
            Finding.source == "combined",
            Finding.severity.in_(["high", "critical"]),
        )
    ) or 0

    by_cwe = dict(
        db.execute(
            select(Finding.cwe, func.count())
            .where(Finding.source == "combined", Finding.cwe.isnot(None))
            .group_by(Finding.cwe)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
    )

    distinct_projects = db.scalar(select(func.count(distinct(ScanRun.project)))) or 0

    return {
        "projects": distinct_projects,
        "runs": {"total": total_runs, "completed": completed, "failed": failed, "running": running},
        "findings": {
            "combined": combined_total,
            "agreement": agreement,
            "ai_only": ai_only,
            "sast_only": sast_only,
            "high_critical": high_crit,
        },
        "by_cwe": by_cwe,
    }
