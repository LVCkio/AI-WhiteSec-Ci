"""Checkmarx SARIF adapter. It prepares evidence and never issues a decision."""
from __future__ import annotations

import ast
import hashlib
import json
import re
from urllib.parse import unquote, urlparse

from app.contracts import (CheckmarxScan, CodeUnit, Finding, NormalizedScan,
                           RunIdentity, SourceFile, UnitReference, safe_path)

CWE_GROUPS = {
    "CWE-22": "PATH_TRAVERSAL", "CWE-23": "PATH_TRAVERSAL", "CWE-36": "PATH_TRAVERSAL",
    "CWE-79": "XSS", "CWE-78": "OS_COMMAND_INJECTION", "CWE-89": "SQL_INJECTION",
    "CWE-287": "INSECURE_AUTHENTICATION", "CWE-306": "INSECURE_AUTHENTICATION",
    "CWE-307": "INSECURE_AUTHENTICATION", "CWE-798": "HARDCODED_CREDENTIALS",
    "CWE-259": "HARDCODED_CREDENTIALS", "CWE-321": "HARDCODED_CREDENTIALS",
}


class ReportError(ValueError):
    pass


def _properties(value: dict) -> dict:
    result = value.get("properties", {})
    if not isinstance(result, dict):
        raise ReportError("SARIF properties must be an object")
    return result


def _cwes(rule: dict, result: dict) -> list[str]:
    values = []
    for item in (rule, result):
        for key, value in _properties(item).items():
            if key.lower() in {"cwe", "cweid", "cwe-id", "cwe_id", "cwes"}:
                for candidate in value if isinstance(value, list) else [value]:
                    if str(candidate).isdigit():
                        values.append("CWE-" + str(candidate))
                    else:
                        values.extend("CWE-" + number for number in
                                      re.findall(r"CWE[-/ :]*(\d+)", str(candidate), re.I))
            elif key.lower() == "tags" and isinstance(value, list):
                for tag in value:
                    values.extend("CWE-" + number for number in
                                  re.findall(r"CWE[-/ :]*(\d+)", str(tag), re.I))
    return sorted(set(values))


def _severity(rule: dict, result: dict) -> str:
    for item in (result, rule):
        props = _properties(item)
        severity = str(props.get("severity", "")).lower()
        if severity in {"critical", "high", "medium", "low", "info"}:
            return severity
        if "security-severity" in props:
            try:
                score = float(props["security-severity"])
                if not 0 <= score <= 10:
                    return "unknown"
                return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
            except (TypeError, ValueError):
                return "unknown"
    level = result.get("level", rule.get("defaultConfiguration", {}).get("level"))
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "unknown")


def prepare_sources(sources: list[SourceFile]) -> tuple[list[CodeUnit], list[str]]:
    """Prepare the independent AI branch before any scanner result exists."""
    issues: list[str] = []
    units: list[CodeUnit] = []
    for source in sources:
        if not source.path.endswith(".py"):
            issues.append(f"unsupported_language:{source.path}")
            continue
        try:
            ast.parse(source.content, filename=source.path)
        except (SyntaxError, ValueError):
            issues.append(f"python_parse_failed:{source.path}")
        # Full modules preserve imports, globals and inter-function context.
        # The final gate must REVIEW oversized input rather than truncate it.
        line_count = max(1, len(source.content.splitlines()))
        units.append(CodeUnit(unit_id=f"{source.path}:1-{line_count}", path=source.path,
                              start_line=1, end_line=line_count, code=source.content,
                              sha256=source.sha256))
    if not units:
        raise ReportError("No Python source exists in the submitted pilot scope")
    return units, issues


def normalize(scan: CheckmarxScan, identity: RunIdentity, manifest: str,
              units: list[UnitReference]) -> NormalizedScan:
    """Normalize independently arriving scanner evidence against the locked run."""
    if scan.commit_sha != identity.commit_sha:
        raise ReportError("Checkmarx scan does not match the locked commit")
    if scan.source_manifest_sha256 != manifest:
        raise ReportError("Checkmarx scope manifest does not match the locked source")
    if not scan.scan_id.strip() or not scan.preset.strip():
        raise ReportError("Checkmarx scan ID and preset must be nonblank")
    report = scan.sarif
    if scan.status != "completed":
        digest = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False).encode("utf-8")).hexdigest()
        return NormalizedScan(scan_id=scan.scan_id, scan_status=scan.status, scan_mode=scan.mode,
                              scan_preset=scan.preset, raw_report_sha256=digest,
                              source_manifest_sha256=manifest, findings=[],
                              coverage_issues=["Scanner did not complete; its report is not treated as clean"])
    if report.get("version") != "2.1.0":
        raise ReportError("Only SARIF 2.1.0 is supported")
    runs = report.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ReportError("SARIF runs must be a nonempty array")
    issues: list[str] = []
    by_path = {unit.path: unit for unit in units}
    findings = []
    scan_status = scan.status
    for run_number, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ReportError("Each SARIF run must be an object")
        tool = run.get("tool", {})
        if not isinstance(tool, dict) or not isinstance(tool.get("driver"), dict):
            raise ReportError("SARIF tool.driver must be an object")
        driver = tool["driver"]
        if "checkmarx" not in str(driver.get("name", "")).lower():
            raise ReportError("SARIF tool driver must identify Checkmarx")
        provenance = run.get("versionControlProvenance", [])
        if not isinstance(provenance, list) or any(not isinstance(item, dict) for item in provenance):
            raise ReportError("SARIF versionControlProvenance must be an array of objects")
        revisions = [item.get("revisionId") for item in provenance if item.get("revisionId")]
        if any(revision != identity.commit_sha for revision in revisions):
            raise ReportError("SARIF scanner revision does not match the submitted commit")
        if scan.mode == "real" and not revisions:
            issues.append("scanner_snapshot_provenance_missing")
        artifacts = run.get("artifacts", [])
        if not isinstance(artifacts, list) or any(not isinstance(item, dict) for item in artifacts):
            raise ReportError("SARIF artifacts must be an array of objects")
        targets = set()
        for artifact in artifacts:
            roles = artifact.get("roles", [])
            if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
                raise ReportError("SARIF artifact roles must be an array of strings")
            if "analysisTarget" not in roles:
                continue
            try:
                uri = artifact["location"]["uri"]
                if not isinstance(uri, str) or urlparse(uri).scheme:
                    raise ValueError("Invalid analysis target URI")
                target = safe_path(unquote(uri).replace("\\", "/"))
                targets.add(target)
                if target not in by_path:
                    issues.append(f"scanner_target_not_covered:{target}")
            except (ValueError, KeyError, TypeError):
                issues.append("scanner_target_location_unmapped")
        if targets:
            for path in by_path:
                if path not in targets:
                    issues.append(f"model_source_not_in_scanner_scope:{path}")
        elif scan.mode == "real":
            issues.append("scanner_scope_provenance_missing")
        rules = driver.get("rules", [])
        if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
            raise ReportError("SARIF rules must be an array of objects")
        rule_by_id = {rule["id"]: rule for rule in rules if "id" in rule}
        results = run.get("results")
        if not isinstance(results, list):
            raise ReportError("SARIF results must be present, including for a clean scan")
        invocations = run.get("invocations", [])
        if not isinstance(invocations, list):
            raise ReportError("SARIF invocations must be an array")
        for invocation in invocations:
            if not isinstance(invocation, dict):
                raise ReportError("Invalid SARIF invocation")
            if "executionSuccessful" in invocation and type(invocation["executionSuccessful"]) is not bool:
                raise ReportError("SARIF executionSuccessful must be a boolean")
            if invocation.get("executionSuccessful") is False:
                scan_status = "error"
            notifications = invocation.get("toolExecutionNotifications", [])
            if not isinstance(notifications, list) or any(not isinstance(item, dict) for item in notifications):
                raise ReportError("SARIF toolExecutionNotifications must be an array of objects")
            for notification in notifications:
                if notification.get("level", "warning") not in {"error", "warning", "note", "none"}:
                    raise ReportError("Invalid SARIF notification level")
                if notification.get("level") == "error":
                    scan_status = "error"
        for result_number, result in enumerate(results):
            if not isinstance(result, dict):
                raise ReportError("Each SARIF result must be an object")
            rule_id = result.get("ruleId")
            rule = rule_by_id.get(rule_id, {})
            if "ruleIndex" in result:
                index = result["ruleIndex"]
                if not isinstance(index, int) or not 0 <= index < len(rules):
                    raise ReportError("SARIF ruleIndex is invalid")
                indexed = rules[index]
                if rule_id and indexed.get("id") != rule_id:
                    raise ReportError("SARIF ruleId/ruleIndex disagree")
                rule = indexed
                rule_id = indexed.get("id")
            if not isinstance(rule_id, str) or not rule_id:
                raise ReportError("SARIF finding has no rule identifier")
            message = result.get("message", {})
            if not isinstance(message, dict):
                raise ReportError("SARIF message must be an object")
            text = message.get("text", message.get("markdown", ""))
            if not isinstance(text, str):
                raise ReportError("SARIF message text must be a string")
            cwes = _cwes(rule, result)
            groups = sorted({CWE_GROUPS[cwe] for cwe in cwes if cwe in CWE_GROUPS})
            for cwe in cwes:
                if cwe not in CWE_GROUPS:
                    issues.append(f"unmapped_cwe:{run_number}:{result_number}:{cwe}")
            location_list = result.get("locations", [])
            if not isinstance(location_list, list):
                raise ReportError("SARIF locations must be an array")
            if not location_list:
                location_list = [{}]
            for location_number, location in enumerate(location_list):
                path = None
                line = None
                mapped = []
                try:
                    physical = location.get("physicalLocation", {})
                    artifact = physical.get("artifactLocation", {})
                    if "index" in artifact and "uri" not in artifact:
                        artifact = run.get("artifacts", [])[artifact["index"]]["location"]
                    uri = artifact.get("uri", "")
                    if not isinstance(uri, str) or urlparse(uri).scheme:
                        raise ValueError("URI is absolute")
                    path = safe_path(unquote(uri).replace("\\", "/"))
                    line = physical.get("region", {}).get("startLine")
                    if not isinstance(line, int) or line < 1:
                        raise ValueError("Line missing")
                    unit = by_path.get(path)
                    if unit and line <= unit.end_line:
                        mapped = [unit.unit_id]
                    else:
                        issues.append(f"unmatched_finding:{run_number}:{result_number}:{location_number}")
                except (ValueError, TypeError, KeyError, IndexError, AttributeError):
                    path = None
                    line = None
                    issues.append(f"unmapped_location:{run_number}:{result_number}:{location_number}")
                findings.append(Finding(
                    finding_id=f"cx:{run_number}:{result_number}:{location_number}", rule_id=rule_id,
                    path=path, start_line=line, severity=_severity(rule, result), cwes=cwes,
                    groups=groups, message=text[:10_000], unit_ids=mapped,
                ))
            if result.get("suppressions"):
                issues.append(f"suppressed_finding_requires_review:{run_number}:{result_number}")
    raw_digest = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":"),
                                           ensure_ascii=False).encode("utf-8")).hexdigest()
    return NormalizedScan(scan_id=scan.scan_id, scan_status=scan_status, scan_mode=scan.mode,
                          scan_preset=scan.preset, raw_report_sha256=raw_digest,
                          source_manifest_sha256=scan.source_manifest_sha256,
                          findings=findings, coverage_issues=sorted(set(issues)))
