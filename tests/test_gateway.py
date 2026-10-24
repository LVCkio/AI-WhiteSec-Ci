import asyncio
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient

from app.contracts import (FinalDecision, InferenceResult, Prediction, GROUPS,
                           GateEvidence, UnitReference)
from app.gateway import create_app
from app.gate import evaluate
from app.inference import Policy
from app.normalize import normalize, prepare_sources
from app.store import AuditStore
from scripts.smoke_demo import demo_payload
from scripts.submit_scan import deployment_exit_code


def prediction_result(request, mode="demo", **updates):
    data = dict(identity=request.identity, source_manifest_sha256=request.source_manifest_sha256,
                status="completed", mode=mode, model_version="demo-fixture-v1" if mode == "demo" else "reviewed-model-v1",
                thresholds={label: 0.8 for label in GROUPS},
                predictions=[Prediction(unit_id=unit.unit_id, token_count=20,
                                        scores={label: 0.02 for label in GROUPS}) for unit in request.units],
                reasons=["complete"])
    data.update(updates)
    return InferenceResult(**data)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = AuditStore("sqlite:///" + str(Path(self.temp.name) / "audit.sqlite3"))
        self.forwarded = []
        async def forward(request):
            self.forwarded.append(request)
            return prediction_result(request)
        self.client = self.enterContext(TestClient(create_app(store=self.store, forward=forward, api_key="test-key")))
        self.headers = {"X-API-Key": "test-key"}
        self.start, self.scan = demo_payload(False, "parallel-test")
        self.url = "/v1/runs/parallel-test"

    def start_run(self, body=None):
        return self.client.post("/v1/runs", json=body or self.start.model_dump(), headers=self.headers)

    def deliver(self, body=None):
        return self.client.post(self.url + "/checkmarx", json=body or self.scan.model_dump(), headers=self.headers)

    def test_model_starts_without_any_checkmarx_report_and_gate_waits(self):
        self.assertEqual(202, self.start_run().status_code)
        self.assertEqual(1, len(self.forwarded))
        state = self.client.get(self.url, headers=self.headers).json()
        self.assertEqual("completed", state["codebert_status"])
        self.assertEqual("pending", state["checkmarx_status"])
        self.assertEqual("pending", state["status"])
        self.assertIsNone(state["decision"])

    def test_only_gateway_gate_issues_final_decision_after_both(self):
        self.start_run()
        state = self.deliver().json()
        self.assertEqual("decided", state["status"])
        self.assertEqual("gateway-security-gate", state["decision"]["authority"])
        self.assertEqual("PASS", state["decision"]["decision"])
        self.assertFalse(state["decision"]["allow_deploy"])

    def test_scanner_may_finish_first_while_model_is_running(self):
        entered = threading.Event()
        release = threading.Event()
        async def delayed(request):
            entered.set()
            while not release.is_set():
                await asyncio.sleep(0.01)
            return prediction_result(request)
        with TestClient(create_app(store=self.store, forward=delayed, api_key="test-key")) as client:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(client.post, "/v1/runs", json=self.start.model_dump(), headers=self.headers)
                try:
                    self.assertTrue(entered.wait(3))
                    response = client.post(self.url + "/checkmarx", json=self.scan.model_dump(), headers=self.headers)
                    self.assertEqual("completed", response.json()["checkmarx_status"])
                    self.assertEqual("pending", response.json()["codebert_status"])
                    self.assertIsNone(response.json()["decision"])
                finally:
                    release.set()
                future.result(timeout=3)
            state = client.get(self.url, headers=self.headers).json()
            self.assertEqual("PASS", state["decision"]["decision"])

    def test_duplicate_run_and_branch_are_idempotent(self):
        self.start_run()
        self.start_run()
        self.assertEqual(1, len(self.forwarded))
        first = self.deliver().json()
        self.assertEqual(first, self.deliver().json())
        body = self.scan.model_dump()
        body["sarif"] = dict(reversed(list(body["sarif"].items())))
        self.assertEqual(first, self.deliver(body).json())

    def test_changed_source_or_scan_cannot_reuse_same_run(self):
        self.start_run()
        body = self.start.model_dump()
        body["identity"]["artifact_digest"] = "sha256:" + "f" * 64
        self.assertEqual(409, self.start_run(body).status_code)
        self.deliver()
        body = self.scan.model_dump()
        body["scan_id"] = "different"
        self.assertEqual(409, self.deliver(body).status_code)

    def test_mismatched_scanner_commit_or_manifest_rejected(self):
        self.start_run()
        for key, value in [("commit_sha", "f" * 40), ("source_manifest_sha256", "f" * 64)]:
            body = self.scan.model_dump()
            body[key] = value
            self.assertEqual(422, self.deliver(body).status_code)
        self.assertIsNone(self.client.get(self.url, headers=self.headers).json()["decision"])

    def test_model_transport_failure_is_error_when_scanner_arrives(self):
        async def broken(request):
            raise ValueError("failed")
        with TestClient(create_app(store=self.store, forward=broken, api_key="test-key")) as client:
            client.post("/v1/runs", json=self.start.model_dump(), headers=self.headers)
            pending = client.get(self.url, headers=self.headers).json()
            self.assertEqual("error", pending["codebert_status"])
            self.assertIsNone(pending["decision"])
            result = client.post(self.url + "/checkmarx", json=self.scan.model_dump(), headers=self.headers).json()
            self.assertEqual("ERROR", result["decision"]["decision"])
            self.assertFalse(result["decision"]["allow_deploy"])

    def test_foreign_inference_identity_cannot_pass(self):
        async def foreign(request):
            result = prediction_result(request).model_dump()
            result["identity"]["commit_sha"] = "f" * 40
            return result
        with TestClient(create_app(store=self.store, forward=foreign, api_key="test-key")) as client:
            client.post("/v1/runs", json=self.start.model_dump(), headers=self.headers)
            result = client.post(self.url + "/checkmarx", json=self.scan.model_dump(), headers=self.headers).json()
            self.assertEqual("ERROR", result["decision"]["decision"])

    def test_scanner_failure_without_sarif_is_terminal_error(self):
        self.start_run()
        body = self.scan.model_dump()
        body.update(status="error", sarif={})
        result = self.deliver(body).json()
        self.assertEqual("error", result["checkmarx_status"])
        self.assertEqual("ERROR", result["decision"]["decision"])

    def test_failed_sarif_invocation_is_not_empty_clean_success(self):
        self.start_run()
        body = self.scan.model_dump()
        body["sarif"]["runs"][0]["invocations"][0]["executionSuccessful"] = False
        self.assertEqual("ERROR", self.deliver(body).json()["decision"]["decision"])

    def test_malformed_boolean_and_notifications_are_rejected(self):
        self.start_run()
        for value in ["false", None, 0]:
            body = self.scan.model_dump()
            body["sarif"]["runs"][0]["invocations"][0]["executionSuccessful"] = value
            self.assertEqual(422, self.deliver(body).status_code)
        body = self.scan.model_dump()
        body["sarif"]["runs"][0]["invocations"][0]["toolExecutionNotifications"] = {"error": {"level": "error"}}
        self.assertEqual(422, self.deliver(body).status_code)

    def test_wrong_report_revision_rejected(self):
        self.start_run()
        body = self.scan.model_dump()
        body["sarif"]["runs"][0]["versionControlProvenance"] = [{"revisionId": "f" * 40}]
        self.assertEqual(422, self.deliver(body).status_code)

    def test_scanner_target_outside_model_scope_requires_review(self):
        self.start_run()
        body = self.scan.model_dump()
        body["sarif"]["runs"][0]["artifacts"] = [{"roles": ["analysisTarget"], "location": {"uri": "missing.py"}}]
        self.assertEqual("REVIEW", self.deliver(body).json()["decision"]["decision"])

    def test_missing_real_provenance_requires_review(self):
        self.start_run()
        body = self.scan.model_dump()
        body["mode"] = "real"
        self.assertEqual("REVIEW", self.deliver(body).json()["decision"]["decision"])

    def test_source_hash_failure_does_not_echo_source(self):
        body = self.start.model_dump()
        body["sources"][0]["content"] += "# private-source-marker"
        response = self.start_run(body)
        self.assertEqual(422, response.status_code)
        self.assertNotIn("private-source-marker", response.text)
        self.assertEqual([], self.forwarded)

    def test_authentication_and_run_creation_required(self):
        self.assertEqual(401, self.client.post("/v1/runs", json=self.start.model_dump()).status_code)
        self.assertEqual(404, self.deliver().status_code)

    def test_audit_contains_both_branches_and_no_source_code(self):
        self.start_run()
        self.deliver()
        record = self.store.get("parallel-test")["record"]
        self.assertEqual(["checkmarx", "codebert"], record["workflow"]["parallel"])
        self.assertIsNotNone(record["codebert"])
        self.assertIsNotNone(record["checkmarx"])
        self.assertNotIn("code", record["units"][0])

    def test_expired_inference_lease_can_recover_same_immutable_run(self):
        self.start_run()
        def simulate_interruption(record):
            record["codebert"] = None
            record["inference_requested_at"] = 0
            return record
        self.store.update("parallel-test", simulate_interruption)
        self.start_run()
        self.assertEqual(2, len(self.forwarded))
        self.assertEqual("completed", self.client.get(self.url, headers=self.headers).json()["codebert_status"])

    def test_policy_is_locked_when_run_starts(self):
        self.start_run()
        record = self.store.get("parallel-test")["record"]
        self.assertFalse(record["policy"]["release_approved"])

    def test_old_sequential_endpoint_is_retired(self):
        self.assertEqual(410, self.client.post("/v1/scans", headers=self.headers).status_code)

    def test_cli_deploy_exit_zero_requires_real_gate_permission(self):
        for decision, mode, allowed, expected in [("PASS", "demo", False, 3), ("PASS", "real", False, 3),
            ("PASS", "real", True, 0), ("BLOCK", "real", False, 2), ("REVIEW", "real", False, 3), ("ERROR", "real", False, 4)]:
            result = FinalDecision(identity=self.start.identity, scan_id="test", decision=decision,
                                   allow_deploy=allowed, mode=mode, policy_version="test", reasons=["test"])
            self.assertEqual(expected, deployment_exit_code(result))


if __name__ == "__main__":
    unittest.main()
