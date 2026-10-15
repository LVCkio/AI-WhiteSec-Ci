"""Versioned boundary shared by Gateway and the final CodeBERT service."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

GROUPS = (
    "PATH_TRAVERSAL", "XSS", "OS_COMMAND_INJECTION", "SQL_INJECTION",
    "INSECURE_AUTHENTICATION", "HARDCODED_CREDENTIALS",
)
SHA256 = r"^[0-9a-f]{64}$"


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunIdentity(Contract):
    run_id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    repository: str = Field(min_length=1, max_length=500)
    commit_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


def safe_path(value: str) -> str:
    if "\\" in value or "\x00" in value or ":" in value:
        raise ValueError("Source paths must be repository-relative POSIX paths")
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("Source path is not canonical or escapes the repository")
    return value


class SourceFile(Contract):
    path: str = Field(max_length=1000)
    content: str = Field(max_length=200_000)
    sha256: str = Field(pattern=SHA256)

    _path = field_validator("path")(safe_path)

    @model_validator(mode="after")
    def check_digest(self):
        if hashlib.sha256(self.content.encode("utf-8")).hexdigest() != self.sha256:
            raise ValueError("Source SHA-256 does not match content")
        return self


def source_manifest_digest(sources: list[SourceFile]) -> str:
    entries = [{"path": source.path, "sha256": source.sha256}
               for source in sorted(sources, key=lambda source: source.path)]
    return hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


class CheckmarxScan(Contract):
    scan_id: str = Field(min_length=1, max_length=200)
    status: Literal["completed", "error", "incomplete"]
    mode: Literal["real", "demo"] = "real"
    preset: str = Field(min_length=1, max_length=200)
    commit_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    source_manifest_sha256: str = Field(pattern=SHA256)
    sarif: dict


class RunStart(Contract):
    schema_version: Literal["2.0"] = "2.0"
    identity: RunIdentity
    sources: list[SourceFile] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def unique_sources(self):
        if len({source.path for source in self.sources}) != len(self.sources):
            raise ValueError("Duplicate source path")
        return self


class Finding(Contract):
    finding_id: str
    rule_id: str
    path: str | None = None
    start_line: int | None = Field(default=None, ge=1)
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"]
    cwes: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    message: str
    unit_ids: list[str] = Field(default_factory=list)


class CodeUnit(Contract):
    unit_id: str
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    code: str = Field(max_length=200_000)
    sha256: str = Field(pattern=SHA256)


class UnitReference(Contract):
    unit_id: str
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    sha256: str = Field(pattern=SHA256)


class InferenceRequest(Contract):
    schema_version: Literal["2.0"] = "2.0"
    identity: RunIdentity
    source_manifest_sha256: str = Field(pattern=SHA256)
    units: list[CodeUnit] = Field(min_length=1)
    coverage_issues: list[str] = Field(default_factory=list)


class Prediction(Contract):
    unit_id: str
    token_count: int = Field(ge=0)
    scores: dict[str, float]

    @field_validator("scores")
    @classmethod
    def check_scores(cls, scores):
        if set(scores) != set(GROUPS) or any(
            not isinstance(score, (int, float)) or not 0 <= score <= 1
            for score in scores.values()
        ):
            raise ValueError("Exactly six finite probabilities are required")
        return scores


class InferenceResult(Contract):
    schema_version: Literal["2.0"] = "2.0"
    authority: Literal["codebert-inference"] = "codebert-inference"
    identity: RunIdentity
    source_manifest_sha256: str = Field(pattern=SHA256)
    status: Literal["completed", "incomplete", "error"]
    mode: Literal["real", "demo"]
    model_version: str | None = None
    thresholds: dict[str, float] = Field(default_factory=dict)
    predictions: list[Prediction] = Field(default_factory=list)
    coverage_issues: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def complete_model_evidence(self):
        if self.status == "completed":
            if not self.model_version or not self.model_version.strip():
                raise ValueError("Completed inference needs a model version")
            if set(self.thresholds) != set(GROUPS) or any(
                not 0 < threshold < 1 for threshold in self.thresholds.values()
            ):
                raise ValueError("Completed inference needs six finite calibrated thresholds")
        return self


class GateEvidence(Contract):
    identity: RunIdentity
    scan_id: str
    scan_status: Literal["completed", "error", "incomplete"]
    scan_mode: Literal["real", "demo"]
    findings: list[Finding]
    coverage_issues: list[str]
    source_manifest_sha256: str = Field(pattern=SHA256)
    units: list[UnitReference] = Field(min_length=1)
    inference: InferenceResult


class NormalizedScan(Contract):
    scan_id: str
    scan_status: Literal["completed", "error", "incomplete"]
    scan_mode: Literal["real", "demo"]
    scan_preset: str
    raw_report_sha256: str = Field(pattern=SHA256)
    source_manifest_sha256: str = Field(pattern=SHA256)
    findings: list[Finding]
    coverage_issues: list[str]


class FinalDecision(Contract):
    schema_version: Literal["2.0"] = "2.0"
    identity: RunIdentity
    scan_id: str
    authority: Literal["gateway-security-gate"] = "gateway-security-gate"
    decision: Literal["PASS", "BLOCK", "REVIEW", "ERROR"]
    allow_deploy: bool
    mode: Literal["real", "demo"]
    model_version: str | None = None
    policy_version: str
    reasons: list[str] = Field(min_length=1)
    predictions: list[Prediction] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @model_validator(mode="after")
    def no_bypass(self):
        if self.allow_deploy and (self.decision != "PASS" or self.mode != "real"):
            raise ValueError("Only a real Security Gate PASS may permit deployment")
        return self


class RunView(Contract):
    schema_version: Literal["2.0"] = "2.0"
    identity: RunIdentity
    status: Literal["pending", "decided"]
    checkmarx_status: Literal["pending", "completed", "incomplete", "error"]
    codebert_status: Literal["pending", "completed", "incomplete", "error"]
    source_manifest_sha256: str
    decision: FinalDecision | None = None
