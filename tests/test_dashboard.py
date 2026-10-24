"""Authenticated dashboard uses actual audit evidence without source leakage."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from fastapi.testclient import TestClient

from app.contracts import GROUPS, InferenceResult, Prediction
from app.gateway import create_app
from app.inference import Policy
from app.store import AuditStore
from scripts.smoke_demo import demo_payload


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = AuditStore("sqlite:///" + str(Path(self.temp.name) / "audit.sqlite3"))
        self.mode = "demo"
        self.inference_status = "completed"
        self.score = 0.02

        async def forward(request):
            return InferenceResult(identity=request.identity,
                source_manifest_sha256=request.source_manifest_sha256,
                status=self.inference_status, mode=self.mode,
                model_version="demo-fixture-v1" if self.mode == "demo" else "reviewed-test-model",
                thresholds={group: 0.8 for group in GROUPS},
                predictions=[Prediction(unit_id=unit.unit_id, token_count=20,
                    scores={group: self.score for group in GROUPS}) for unit in request.units],
                reasons=["Audited test inference"])

        app = create_app(store=self.store, forward=forward, api_key="dashboard-factory-key",
                         policy=Policy("dashboard-test-policy", True, frozenset({"high", "critical"}), 0.15))
        self.client = self.enterContext(TestClient(app))
        self.headers = {"X-API-Key": "dashboard-factory-key"}

    def create_run(self, run_id, *, mode="demo", vulnerable=False, deliver=True,
                   inference_status="completed", score=0.02):
        self.mode, self.inference_status, self.score = mode, inference_status, score
        start, scan = demo_payload(vulnerable, run_id)
        scan.mode = mode
        if mode == "real":
            sarif_run = scan.sarif["runs"][0]
            sarif_run["versionControlProvenance"] = [{"revisionId": start.identity.commit_sha}]
            sarif_run["artifacts"] = [{"roles": ["analysisTarget"], "location": {"uri": "sample.py"}}]
        response = self.client.post("/v1/runs", json=start.model_dump(), headers=self.headers)
        self.assertEqual(response.status_code, 202, response.text)
        if deliver:
            response = self.client.post(f"/v1/runs/{run_id}/checkmarx", json=scan.model_dump(), headers=self.headers)
            self.assertEqual(response.status_code, 200, response.text)
        return start, scan

    def dashboard(self):
        response = self.client.get("/v1/dashboard", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_all_dashboard_routes_require_the_factory_gateway_key(self):
        for path in ("/v1/dashboard", "/v1/dashboard/export", "/v1/dashboard/runs/missing"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)
                self.assertEqual(self.client.get(path, headers={"X-API-Key": "wrong"}).status_code, 401)
        self.assertEqual(self.client.get("/v1/dashboard", headers=self.headers).status_code, 200)

    def test_public_dashboard_shell_has_local_asset_policy_and_never_embeds_api_key(self):
        for path in ("/", "/dashboard"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.headers["content-type"].startswith("text/html"))
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertEqual(response.headers["x-content-type-options"], "nosniff")
                policy = response.headers["content-security-policy"]
                self.assertIn("script-src 'self'", policy)
                self.assertIn("connect-src 'self'", policy)
                self.assertIn("frame-ancestors 'none'", policy)
                self.assertNotIn("dashboard-factory-key", response.text)
                self.assertNotIn("SERVICE_API_KEY", response.text)
                self.assertIn("/dashboard-assets/", response.text)

    def test_static_mount_serves_assets_without_exposing_backend_or_environment_paths(self):
        for path, media_type in (("/dashboard-assets/favicon.svg", "image/svg+xml"),
                                 ("/dashboard-assets/adapter.js", "javascript"),
                                 ("/dashboard-assets/app.css", "text/css")):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(media_type, response.headers["content-type"])
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        for path in ("/dashboard-assets/%2e%2e/%2e%2e/gateway.py",
                     "/dashboard-assets/%2e%2e/%2e%2e/%2e%2e/.env",
                     "/dashboard-assets/.env", "/dashboard-assets/store.py"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_empty_dashboard_has_no_fabricated_model_or_performance_metrics(self):
        data = self.dashboard()
        self.assertEqual(data["summary"]["total_runs"], 0)
        self.assertEqual(data["summary"]["decisions"], {key: 0 for key in ("PASS", "BLOCK", "REVIEW", "ERROR")})
        self.assertEqual(data["runs"], [])
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["scores"], [])
        self.assertEqual(data["trend"], [])
        self.assertEqual(data["model"]["status"], "unavailable")
        self.assertIsNone(data["model"]["model_version"])
        self.assertIsNone(data["model"]["performance"])
        self.assertEqual(data["model"]["readiness"], "not_checked")

    def test_failed_model_observation_remains_nullable_and_does_not_claim_current_readiness(self):
        self.create_run("failed-model-only", mode="real", inference_status="error")
        data = self.dashboard()
        self.assertEqual(data["model"]["status"], "unavailable")
        self.assertIsNone(data["model"]["model_version"])
        self.assertIsNone(data["model"]["observed_run_id"])
        self.assertIsNone(data["model"]["performance"])
        self.assertEqual(data["model"]["readiness"], "not_checked")
        self.assertEqual(data["summary"]["decisions"]["ERROR"], 1)

    def test_completed_model_with_pending_scanner_is_never_counted_as_pass(self):
        self.create_run("awaiting-checkmarx", deliver=False)
        data = self.dashboard()
        self.assertEqual(data["summary"]["pending_runs"], 1)
        self.assertEqual(data["summary"]["decided_runs"], 0)
        self.assertEqual(data["summary"]["decisions"]["PASS"], 0)
        self.assertEqual(data["summary"]["release_allowed_runs"], 0)
        self.assertEqual(data["runs"][0]["status"], "pending")
        self.assertEqual(data["runs"][0]["codebert_status"], "completed")
        self.assertEqual(data["runs"][0]["checkmarx_status"], "pending")
        self.assertIsNone(data["runs"][0]["decision"])

    def test_demo_pass_is_distinct_from_real_release_permission(self):
        self.create_run("demo-pass")
        data = self.dashboard()
        self.assertEqual(data["summary"]["decisions"]["PASS"], 1)
        self.assertEqual(data["summary"]["demo_pass_runs"], 1)
        self.assertEqual(data["summary"]["release_allowed_runs"], 0)
        self.assertEqual(data["summary"]["modes"]["demo"], 1)
        self.assertFalse(data["runs"][0]["allow_deploy"])
        self.assertEqual(data["model"]["status"], "demo")

    def test_real_audit_counts_keep_pass_block_review_error_and_pending_distinct(self):
        self.create_run("real-pass", mode="real")
        self.create_run("real-block", mode="real", vulnerable=True)
        self.create_run("real-review", mode="real", score=0.7)
        self.create_run("real-error", mode="real", inference_status="error")
        self.create_run("real-pending", mode="real", deliver=False)
        data = self.dashboard()
        self.assertEqual(data["summary"]["total_runs"], 5)
        self.assertEqual(data["summary"]["decisions"], {key: 1 for key in ("PASS", "BLOCK", "REVIEW", "ERROR")})
        self.assertEqual(data["summary"]["pending_runs"], 1)
        self.assertEqual(data["summary"]["decided_runs"], 4)
        self.assertEqual(data["summary"]["release_allowed_runs"], 1)
        self.assertEqual(data["summary"]["modes"]["real"], 5)
        self.assertEqual(data["summary"]["findings_count"], 1)
        self.assertEqual(data["summary"]["severities"]["high"], 1)

    def test_detail_preserves_bound_evidence_thresholds_and_final_reasons(self):
        start, scan = self.create_run("details-real", mode="real", vulnerable=True)
        response = self.client.get("/v1/dashboard/runs/details-real", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["identity"], start.identity.model_dump())
        self.assertEqual(data["source_manifest_sha256"], scan.source_manifest_sha256)
        self.assertEqual(data["checkmarx"]["scan_id"], scan.scan_id)
        self.assertEqual(data["checkmarx"]["mode"], "real")
        self.assertEqual(data["checkmarx"]["findings"][0]["groups"], ["SQL_INJECTION"])
        self.assertEqual(data["codebert"]["thresholds"], {group: 0.8 for group in GROUPS})
        self.assertEqual(data["codebert"]["predictions"][0]["scores"]["SQL_INJECTION"], 0.02)
        self.assertEqual(data["final_decision"]["decision"], "BLOCK")
        self.assertTrue(data["final_decision"]["reasons"])
        self.assertEqual(data["units"][0]["sha256"], start.sources[0].sha256)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_dashboard_and_export_whitelist_fields_without_source_or_service_keys(self):
        self.create_run("safe-export", vulnerable=True)
        secret = "hidden-source-and-key-marker"

        def inject(record):
            record["SERVICE_API_KEY"] = secret
            record["sources"] = [{"content": secret}]
            record["units"][0]["code"] = secret
            record["policy"]["SERVICE_API_KEY"] = secret
            record["checkmarx"]["sarif"] = {"source": secret}
            record["checkmarx"]["findings"][0]["message"] = secret
            return record

        self.store.update("safe-export", inject)
        for path in ("/v1/dashboard", "/v1/dashboard/export", "/v1/dashboard/runs/safe-export"):
            response = self.client.get(path, headers=self.headers)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(secret, response.text)
            self.assertNotIn("SERVICE_API_KEY", response.text)
            self.assertNotIn('"content"', response.text)
            self.assertNotIn('"code"', response.text)
            self.assertNotIn('"sarif"', response.text)

    def test_export_is_a_json_attachment_of_existing_audit_records(self):
        self.create_run("download-demo")
        count = self.store.list_records()["total_records"]
        response = self.client.get("/v1/dashboard/export", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.headers["content-disposition"], 'attachment; filename="ai-whitesec-audit.json"')
        data = json.loads(response.content)
        self.assertEqual(data["details"][0]["identity"]["run_id"], "download-demo")
        self.assertEqual(self.store.list_records()["total_records"], count)

    def test_legacy_and_invalid_records_are_skipped_with_traceable_counts(self):
        self.create_run("current-demo")
        self.store.reserve("legacy-1", "old-fingerprint", {"schema_version": "1.0", "sources": [{"code": "legacy-secret"}]})
        self.store.reserve("invalid-1", "bad-fingerprint", {"schema_version": "2.0", "identity": {}})
        data = self.dashboard()
        self.assertEqual(data["window"]["total_records"], 3)
        self.assertEqual(data["window"]["included_runs"], 1)
        self.assertEqual(data["window"]["legacy_skipped"], 1)
        self.assertEqual(data["window"]["invalid_skipped"], 1)
        self.assertEqual(len(data["warnings"]), 2)
        self.assertEqual(self.client.get("/v1/dashboard/runs/legacy-1", headers=self.headers).status_code, 409)
        self.assertEqual(self.client.get("/v1/dashboard/runs/invalid-1", headers=self.headers).status_code, 409)
        self.assertEqual(self.client.get("/v1/dashboard/runs/missing", headers=self.headers).status_code, 404)
        self.assertNotIn("legacy-secret", json.dumps(data))

    def test_store_reader_caps_parameterized_window_and_reports_truncation(self):
        for run_id in ("z-run", "a-run", "m-run"):
            self.create_run(run_id)
        window = self.store.list_records(2)
        self.assertEqual([row["run_id"] for row in window["records"]], ["z-run", "m-run"])
        self.assertEqual(window["total_records"], 3)
        self.assertTrue(window["truncated"])
        for invalid in (0, 1001, "1", True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.store.list_records(invalid)
        self.store.list_records = Mock(return_value={**window, "total_records": 2001, "limit": 1000})
        data = self.dashboard()
        self.assertEqual(data["window"]["total_records"], 2001)
        self.assertEqual(data["summary"]["total_runs"], 2)
        self.assertTrue(data["window"]["truncated"])
        self.assertTrue(any("aggregates apply to included runs" in warning for warning in data["warnings"]))

    def test_trend_and_model_metadata_come_from_latest_observed_run(self):
        self.create_run("old-demo")
        self.create_run("new-real", mode="real")

        def timestamp(value):
            def change(record):
                record["created_at"] = value
                return record
            return change

        self.store.update("old-demo", timestamp("2026-10-11T20:00:00+00:00"))
        self.store.update("new-real", timestamp("2026-10-12T20:00:00+00:00"))
        data = self.dashboard()
        self.assertEqual(data["runs"][0]["run_id"], "new-real")
        self.assertEqual(data["model"]["observed_run_id"], "new-real")
        self.assertEqual(data["model"]["status"], "observed-real")
        self.assertEqual(data["model"]["model_version"], "reviewed-test-model")
        self.assertIsNone(data["model"]["performance"])
        self.assertEqual([bucket["date"] for bucket in data["trend"]], ["2026-10-12", "2026-10-13"])
        self.assertEqual(data["trend_timezone"], "Asia/Saigon")

    def test_group_counts_use_actual_findings_and_calibrated_threshold_hits(self):
        self.create_run("category-hit", vulnerable=True, score=0.95)
        data = self.dashboard()
        categories = {category["group"]: category for category in data["categories"]}
        self.assertEqual(categories["SQL_INJECTION"]["checkmarx_findings"], 1)
        self.assertEqual(categories["SQL_INJECTION"]["ai_threshold_hits"], 1)
        self.assertIn("CWE-89", categories["SQL_INJECTION"]["cwes"])
        self.assertEqual(categories["XSS"]["checkmarx_findings"], 0)
        self.assertEqual(categories["XSS"]["ai_threshold_hits"], 1)


if __name__ == "__main__":
    unittest.main()
