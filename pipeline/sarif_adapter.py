from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def severity_of(result: dict[str, Any]) -> str:
    properties = result.get("properties") or {}
    candidate = str(properties.get("severity") or properties.get("level") or result.get("level") or "warning").lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "error": "high",
        "medium": "medium",
        "warning": "medium",
        "low": "low",
        "note": "low",
        "none": "info",
    }
    return mapping.get(candidate, "medium")


def cwe_of(result: dict[str, Any], rule: dict[str, Any]) -> str | None:
    haystack = json.dumps({"result": result, "rule": rule})
    match = re.search(r"CWE[-_ ]?(\d+)", haystack, re.I)
    return f"CWE-{match.group(1)}" if match else None


def message_text(message: Any) -> str:
    if isinstance(message, dict):
        return str(message.get("text") or message.get("markdown") or "Checkmarx finding")
    return str(message or "Checkmarx finding")


def adapt_sarif(path: Path) -> list[dict]:
    document = json.loads(path.read_text(encoding="utf-8"))
    findings: list[dict] = []
    for run in document.get("runs", []):
        rules = {
            str(rule.get("id")): rule
            for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = str(result.get("ruleId") or "unknown-rule")
            rule = rules.get(rule_id, {})
            location = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            artifact = location.get("artifactLocation") or {}
            region = location.get("region") or {}
            file_path = str(artifact.get("uri") or "unknown.py").replace("\\", "/")
            title = str(rule.get("name") or rule.get("shortDescription", {}).get("text") or rule_id)
            findings.append(
                {
                    "source": "checkmarx",
                    "file_path": file_path,
                    "function_name": (result.get("properties") or {}).get("functionName"),
                    "start_line": region.get("startLine"),
                    "end_line": region.get("endLine") or region.get("startLine"),
                    "cwe": cwe_of(result, rule),
                    "severity": severity_of(result),
                    "confidence": None,
                    "title": title,
                    "description": message_text(result.get("message")),
                    "evidence": {
                        "rule_id": rule_id,
                        "sarif_partial_fingerprints": result.get("partialFingerprints") or {},
                    },
                }
            )
    return findings

