from __future__ import annotations

from hashlib import sha256
from typing import Any

from .remediation import remediation_for


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./").lower()


def lines_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool:
    values = (left.get("start_line"), left.get("end_line"), right.get("start_line"), right.get("end_line"))
    if any(value is None for value in values):
        return False
    left_start, left_end, right_start, right_end = (int(value) for value in values)
    return max(left_start, right_start) <= min(left_end, right_end)


def findings_match(ai: dict[str, Any], sast: dict[str, Any]) -> bool:
    if normalize_path(ai["file_path"]) != normalize_path(sast["file_path"]):
        return False
    if not ai.get("cwe") or ai.get("cwe") != sast.get("cwe"):
        return False
    ai_function = (ai.get("function_name") or "").strip().lower()
    sast_function = (sast.get("function_name") or "").strip().lower()
    return bool(ai_function and sast_function and ai_function == sast_function) or lines_overlap(ai, sast)


def stronger_severity(*values: str | None) -> str:
    present = [value for value in values if value in SEVERITY_RANK]
    return max(present or ["medium"], key=lambda value: SEVERITY_RANK[value])


def make_fingerprint(item: dict[str, Any]) -> str:
    stable = "|".join(
        [
            normalize_path(item["file_path"]),
            (item.get("function_name") or "").strip().lower(),
            item.get("cwe") or "unknown",
            item.get("combination_status") or item.get("source") or "unknown",
        ]
    )
    return sha256(stable.encode("utf-8")).hexdigest()


def correlate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ai_findings = [item for item in findings if item.get("source") == "ai"]
    sast_findings = [item for item in findings if item.get("source") == "checkmarx"]
    matched_ai_ids: set[str] = set()
    combined: list[dict[str, Any]] = []

    for sast in sast_findings:
        matches = [ai for ai in ai_findings if findings_match(ai, sast)]
        if matches:
            matched_ai_ids.update(str(item["id"]) for item in matches)
            best_ai = max(matches, key=lambda item: item.get("confidence") or 0)
            result = {
                "source": "combined",
                "file_path": sast["file_path"],
                "function_name": sast.get("function_name") or best_ai.get("function_name"),
                "start_line": sast.get("start_line") or best_ai.get("start_line"),
                "end_line": sast.get("end_line") or best_ai.get("end_line"),
                "cwe": sast.get("cwe"),
                "severity": stronger_severity(sast.get("severity"), best_ai.get("severity")),
                "confidence": best_ai.get("confidence"),
                "title": f"Agreement: {sast.get('title') or sast.get('cwe')}",
                "description": "CodeBERT and Checkmarx reported the same CWE in the same code unit.",
                "evidence": {
                    "checkmarx_finding_ids": [str(sast["id"])],
                    "ai_finding_ids": [str(item["id"]) for item in matches],
                },
                "combination_status": "AGREEMENT",
                "remediation": remediation_for(sast.get("cwe")),
            }
        else:
            result = {
                **{key: value for key, value in sast.items() if key not in {"id", "run_id", "created_at"}},
                "source": "combined",
                "title": f"SAST only: {sast.get('title') or sast.get('cwe')}",
                "evidence": {"checkmarx_finding_ids": [str(sast["id"])]},
                "combination_status": "SAST_ONLY",
                "remediation": remediation_for(sast.get("cwe")),
            }
        result["fingerprint"] = make_fingerprint(result)
        combined.append(result)

    for ai in ai_findings:
        if str(ai["id"]) in matched_ai_ids:
            continue
        result = {
            **{key: value for key, value in ai.items() if key not in {"id", "run_id", "created_at"}},
            "source": "combined",
            "title": f"AI only: {ai.get('title') or ai.get('cwe')}",
            "evidence": {"ai_finding_ids": [str(ai["id"])]},
            "combination_status": "AI_ONLY",
            "remediation": remediation_for(ai.get("cwe")),
        }
        result["fingerprint"] = make_fingerprint(result)
        combined.append(result)

    return combined

