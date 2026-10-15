import unittest

from app.contracts import GateEvidence, Finding, UnitReference, InferenceRequest
from app.gate import evaluate
from app.inference import Policy
from app.normalize import prepare_sources
from scripts.smoke_demo import demo_payload
from app.contracts import source_manifest_digest
from test_gateway import prediction_result


class SecurityGateTests(unittest.TestCase):
    def setUp(self):
        start, scan = demo_payload(False)
        units, _ = prepare_sources(start.sources)
        request = InferenceRequest(identity=start.identity, units=units,
                                   source_manifest_sha256=source_manifest_digest(start.sources))
        self.evidence = GateEvidence(identity=start.identity, scan_id=scan.scan_id,
            scan_status="completed", scan_mode="real", findings=[], coverage_issues=[],
            source_manifest_sha256=request.source_manifest_sha256,
            units=[UnitReference.model_validate(unit.model_dump(exclude={"code"})) for unit in units],
            inference=prediction_result(request, mode="real"))
        self.policy = Policy("approved-test-v1", True, frozenset({"high", "critical"}), 0.15)

    def gate(self):
        return evaluate(self.evidence, self.policy)

    def test_complete_approved_real_evidence_allows_deploy(self):
        result = self.gate()
        self.assertEqual("gateway-security-gate", result.authority)
        self.assertEqual("PASS", result.decision)
        self.assertTrue(result.allow_deploy)

    def test_unapproved_policy_requires_review(self):
        self.policy = Policy("draft", False, frozenset({"high", "critical"}), 0.15)
        self.assertEqual("REVIEW", self.gate().decision)
        self.assertFalse(self.gate().allow_deploy)

    def test_demo_in_either_branch_never_authorizes(self):
        self.evidence.scan_mode = "demo"
        self.assertFalse(self.gate().allow_deploy)
        self.evidence.scan_mode = "real"
        self.evidence.inference.mode = "demo"
        self.assertFalse(self.gate().allow_deploy)

    def test_failed_model_or_scanner_is_error(self):
        self.evidence.inference.status = "error"
        self.assertEqual("ERROR", self.gate().decision)
        self.evidence.inference.status = "completed"
        self.evidence.scan_status = "error"
        self.assertEqual("ERROR", self.gate().decision)

    def test_model_positive_blocks_clean_scanner(self):
        self.evidence.inference.predictions[0].scores["SQL_INJECTION"] = 0.9
        self.assertEqual("BLOCK", self.gate().decision)

    def test_high_scanner_finding_blocks_low_model_score(self):
        self.evidence.findings = [Finding(finding_id="cx-high", rule_id="sql", severity="high", message="risk",
            path="sample.py", start_line=1, groups=["SQL_INJECTION"], unit_ids=[self.evidence.units[0].unit_id])]
        self.assertEqual("BLOCK", self.gate().decision)

    def test_lower_scanner_disagreement_and_unmapped_findings_review(self):
        self.evidence.findings = [Finding(finding_id="cx-medium", rule_id="unknown", severity="medium", message="risk")]
        self.assertEqual("REVIEW", self.gate().decision)

    def test_incomplete_coverage_and_near_threshold_review(self):
        self.evidence.inference.status = "incomplete"
        self.evidence.inference.coverage_issues = ["long context"]
        self.assertEqual("REVIEW", self.gate().decision)
        self.evidence.inference.status = "completed"
        self.evidence.inference.coverage_issues = []
        self.evidence.inference.predictions[0].scores["XSS"] = 0.7
        self.assertEqual("REVIEW", self.gate().decision)

    def test_missing_duplicate_or_foreign_predictions_cannot_pass(self):
        prediction = self.evidence.inference.predictions[0]
        self.evidence.inference.predictions = []
        self.assertEqual("REVIEW", self.gate().decision)
        self.evidence.inference.predictions = [prediction, prediction]
        self.assertEqual("ERROR", self.gate().decision)
        self.evidence.inference.predictions = [prediction.model_copy(update={"unit_id": "other"})]
        self.assertEqual("ERROR", self.gate().decision)

    def test_identity_mismatch_or_missing_policy_errors(self):
        self.evidence.inference.source_manifest_sha256 = "f" * 64
        self.assertEqual("ERROR", self.gate().decision)
        self.assertEqual("ERROR", evaluate(self.evidence, None).decision)

    def test_no_source_or_duplicate_source_units_errors(self):
        self.evidence.units.append(self.evidence.units[0])
        self.assertEqual("ERROR", self.gate().decision)
        self.evidence.units = []
        self.assertEqual("ERROR", self.gate().decision)


if __name__ == "__main__":
    unittest.main()
