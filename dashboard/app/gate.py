"""Gateway Security Gate joins two independent detector results."""
from __future__ import annotations

from app.contracts import FinalDecision, GateEvidence, GROUPS
from app.inference import Policy


def evaluate(evidence: GateEvidence, policy: Policy | None) -> FinalDecision:
    inference = evidence.inference
    mode = "demo" if inference.mode == "demo" or evidence.scan_mode == "demo" else "real"
    common = dict(identity=evidence.identity, scan_id=evidence.scan_id, mode=mode,
                  model_version=inference.model_version,
                  policy_version=policy.version if policy else "unavailable")

    def result(decision, reasons):
        return FinalDecision(**common, decision=decision,
                             allow_deploy=(decision == "PASS" and mode == "real" and
                                           policy is not None and policy.release_approved),
                             reasons=reasons, predictions=inference.predictions)

    if inference.identity != evidence.identity or inference.source_manifest_sha256 != evidence.source_manifest_sha256:
        return result("ERROR", ["Detector identity or source manifest does not match the locked run"])
    if policy is None:
        return result("ERROR", ["Validated Security Gate policy is unavailable"])
    if evidence.scan_status != "completed" or inference.status == "error":
        return result("ERROR", [f"Detector failure: Checkmarx={evidence.scan_status}, CodeBERT={inference.status}"])
    reviews = list(evidence.coverage_issues) + list(inference.coverage_issues)
    blocks = []
    units = {unit.unit_id: unit for unit in evidence.units}
    if not units or len(units) != len(evidence.units) or any(not key.strip() for key in units):
        return result("ERROR", ["Source unit identifiers must be nonblank and unique"])
    if any(unit.end_line < unit.start_line for unit in evidence.units):
        return result("ERROR", ["Source unit line ranges are invalid"])
    predictions = {prediction.unit_id: prediction for prediction in inference.predictions}
    if len(predictions) != len(inference.predictions) or set(predictions) - set(units):
        return result("ERROR", ["CodeBERT prediction identifiers are duplicated or outside this snapshot"])
    if set(predictions) != set(units) or inference.status != "completed":
        reviews.append("CodeBERT did not cover every source unit")
    for finding in evidence.findings:
        if finding.severity in policy.block_checkmarx_severities:
            blocks.append(f"Checkmarx {finding.finding_id}: {finding.severity} severity")
        else:
            reviews.append(f"Unresolved Checkmarx finding {finding.finding_id} ({finding.severity})")
        if not finding.groups or any(group not in GROUPS for group in finding.groups):
            reviews.append(f"Unmapped Checkmarx finding {finding.finding_id}")
        if not finding.unit_ids or any(unit_id not in units for unit_id in finding.unit_ids):
            reviews.append(f"Finding {finding.finding_id} lacks complete source mapping")
    for prediction in inference.predictions:
        if set(inference.thresholds) != set(GROUPS):
            reviews.append("Calibrated model thresholds are unavailable")
            break
        for label in GROUPS:
            threshold = inference.thresholds[label]
            score = prediction.scores[label]
            if score >= threshold:
                blocks.append(f"CodeBERT {label} in {prediction.unit_id} ({score:.4f} >= {threshold:.4f})")
            elif score >= max(0, threshold - policy.review_score_margin):
                reviews.append(f"CodeBERT {label} in {prediction.unit_id} is near its threshold")
    if blocks:
        return result("BLOCK", blocks + reviews)
    if mode == "real" and not policy.release_approved:
        reviews.append("Security Gate release policy has not been approved")
    if reviews:
        return result("REVIEW", reviews)
    reasons = ["Gateway joined both completed detector results for the same commit and source scope"]
    if mode == "demo":
        reasons.append("Demo results cannot authorize deployment")
    return result("PASS", reasons)
