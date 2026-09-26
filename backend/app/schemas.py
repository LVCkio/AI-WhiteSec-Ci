from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


FindingSource = Literal["ai", "checkmarx", "combined"]
Severity = Literal["critical", "high", "medium", "low", "info"]


class ScanRunCreate(BaseModel):
    project: str = Field(min_length=1, max_length=200)
    repository: str = Field(min_length=1, max_length=300)
    commit_sha: str = Field(min_length=1, max_length=64)
    branch: str | None = None
    trigger: str = "manual"
    model_version: str | None = None
    checkmarx_config: str | None = None


class ScanRunUpdate(BaseModel):
    status: Literal["running", "completed", "failed"] | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = Field(default=None, ge=0)


class ScanRunRead(ScanRunCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    started_at: datetime
    completed_at: datetime | None
    duration_seconds: float | None


class FindingCreate(BaseModel):
    source: FindingSource
    file_path: str = Field(min_length=1, max_length=500)
    function_name: str | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    cwe: str | None = None
    severity: Severity = "medium"
    confidence: float | None = Field(default=None, ge=0, le=1)
    title: str = Field(min_length=1, max_length=500)
    description: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str | None = None
    combination_status: str | None = None
    remediation: str | None = None


class FindingBatchCreate(BaseModel):
    findings: list[FindingCreate]


class FindingRead(FindingCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    fingerprint: str
    created_at: datetime


class ScanRunDetail(ScanRunRead):
    findings: list[FindingRead]

