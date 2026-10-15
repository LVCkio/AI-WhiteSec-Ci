"""Independent inference branch and local checkpoint safety tests."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.codebert import Runtime, create_app, evaluate
from app.contracts import GROUPS, CodeUnit, InferenceRequest, Prediction, RunIdentity
from app.inference import (
    ContextTooLong, DemoEngine, EngineUnavailable, RealEngine,
    load_manifest, validate_checkpoint_config, validate_loading_info,
)


def request(code="def answer():\n    return 42\n", **updates):
    unit = CodeUnit(unit_id="src/app.py:1", path="src/app.py", start_line=1,
                    end_line=max(1, len(code.splitlines())), code=code,
                    sha256=hashlib.sha256(code.encode()).hexdigest())
    base = dict(identity=RunIdentity(run_id="test-1", repository="local/thesis", commit_sha="a" * 40,
                                    artifact_digest="sha256:" + "b" * 64),
                source_manifest_sha256="d" * 64, units=[unit])
    base.update(updates)
    return InferenceRequest(**base)


class FakeRealEngine:
    mode = "real"
    model_version = "reviewed-test-checkpoint"
    max_tokens = 512
    thresholds = {label: 0.8 for label in GROUPS}

    def __init__(self, scores=None):
        self.scores = {label: 0.02 for label in GROUPS}
        self.scores.update(scores or {})

    def predict(self, unit):
        return Prediction(unit_id=unit.unit_id, token_count=20, scores=self.scores)


def manifest():
    return dict(model_version="reviewed-v1", tokenizer_version="tok-v1", dataset_version="data-v1",
                validation_report="validation-v1", approved_for_inference=True,
                task="multi_label_classification", max_tokens=512,
                label_mapping={label: index for index, label in enumerate(GROUPS)},
                thresholds={label: 0.8 for label in GROUPS})


def checkpoint_config():
    return dict(model_type="roberta", architectures=["RobertaForSequenceClassification"],
                problem_type="multi_label_classification", num_labels=6,
                label2id={label: index for index, label in enumerate(GROUPS)},
                id2label={str(index): label for index, label in enumerate(GROUPS)})


class InferenceTests(unittest.TestCase):
    def runtime(self, engine=None):
        return Runtime(mode="real", engine=engine or FakeRealEngine())

    def assert_bound(self, result, payload):
        self.assertEqual(result.identity, payload.identity)
        self.assertEqual(result.source_manifest_sha256, payload.source_manifest_sha256)
        serialized = result.model_dump()
        self.assertNotIn("decision", serialized)
        self.assertNotIn("allow_deploy", serialized)
        self.assertEqual(result.authority, "codebert-inference")

    def test_inference_starts_without_any_checkmarx_report(self):
        payload = request()
        result = evaluate(payload, self.runtime())
        self.assert_bound(result, payload)
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.predictions), 1)
        self.assertEqual(result.model_version, "reviewed-test-checkpoint")
        self.assertEqual(result.thresholds, {label: 0.8 for label in GROUPS})
        self.assertNotIn("scan_id", payload.model_dump())
        self.assertNotIn("checkmarx", payload.model_dump())

    def test_high_score_is_model_evidence_without_a_security_decision(self):
        payload = request()
        result = evaluate(payload, self.runtime(FakeRealEngine({"XSS": 0.95})))
        self.assert_bound(result, payload)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.predictions[0].scores["XSS"], 0.95)

    def test_unavailable_engine_preserves_identity_and_manifest(self):
        payload = request()
        for runtime in (Runtime(mode="real"),
                        Runtime(mode="real", engine=FakeRealEngine(), startup_error="private-path")):
            with self.subTest(runtime=runtime):
                result = evaluate(payload, runtime)
                self.assert_bound(result, payload)
                self.assertEqual(result.status, "error")
                self.assertEqual(result.predictions, [])
                self.assertNotIn("private-path", result.model_dump_json())

    def test_engine_metadata_failure_cannot_complete_inference(self):
        for field, value in (("model_version", " "), ("thresholds", {"XSS": 0.8}),
                             ("thresholds", {label: float("nan") for label in GROUPS}),
                             ("mode", "demo")):
            with self.subTest(field=field, value=value):
                engine = FakeRealEngine()
                setattr(engine, field, value)
                self.assertEqual(evaluate(request(), self.runtime(engine)).status, "error")

    def test_coverage_issue_or_empty_source_makes_inference_incomplete(self):
        for payload in (request(coverage_issues=["Unsupported Java source"]), request("")):
            with self.subTest(payload=payload):
                result = evaluate(payload, self.runtime())
                self.assert_bound(result, payload)
                self.assertEqual(result.status, "incomplete")
                self.assertTrue(result.coverage_issues)

    def test_missing_or_misbound_prediction_makes_inference_incomplete(self):
        for prediction in (None, Prediction(unit_id="other-unit", token_count=20,
                                            scores={label: 0.02 for label in GROUPS})):
            with self.subTest(prediction=prediction):
                engine = FakeRealEngine()
                engine.predict = Mock(return_value=prediction)
                result = evaluate(request(), self.runtime(engine))
                self.assertEqual(result.status, "incomplete")
                self.assertEqual(result.predictions, [])

    def test_inference_exception_is_bound_error_without_source_or_exception_detail(self):
        secret = "secret-original-source"
        payload = request(f"# {secret}\npass\n")
        engine = FakeRealEngine()
        engine.predict = Mock(side_effect=RuntimeError(f"Failed on {secret}"))
        result = evaluate(payload, self.runtime(engine))
        self.assert_bound(result, payload)
        self.assertEqual(result.status, "error")
        self.assertNotIn(secret, result.model_dump_json())

    def test_long_context_is_incomplete_and_keeps_other_valid_predictions(self):
        long_payload = request("word " * 600)
        payload = request()
        long_payload.units[0].unit_id = "src/long.py:1"
        long_payload.units[0].path = "src/long.py"
        payload.units.extend(long_payload.units)
        result = evaluate(payload, Runtime(mode="demo", engine=DemoEngine()))
        self.assert_bound(result, payload)
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(len(result.predictions), 1)
        self.assertTrue(any("exceeds model coverage" in issue for issue in result.coverage_issues))

    def test_demo_marker_reports_each_canonical_group_as_probability(self):
        for group in GROUPS:
            with self.subTest(group=group):
                payload = request(f"# demo: {group}\npass\n")
                result = evaluate(payload, Runtime(mode="demo", engine=DemoEngine()))
                self.assert_bound(result, payload)
                self.assertEqual(result.status, "completed")
                self.assertEqual(result.mode, "demo")
                self.assertEqual(result.model_version, "demo-fixture-v1")
                self.assertEqual(result.predictions[0].scores[group], 0.95)

    def test_tampered_unit_digest_duplicate_id_or_invalid_range_is_error(self):
        mutations = [lambda payload: setattr(payload.units[0], "sha256", "0" * 64),
                     lambda payload: payload.units.append(payload.units[0]),
                     lambda payload: setattr(payload.units[0], "unit_id", " "),
                     lambda payload: setattr(payload.units[0], "path", "../private.py"),
                     lambda payload: setattr(payload.units[0], "end_line", 100),
                     lambda payload: setattr(payload.units[0], "start_line", 3)]
        for mutate in mutations:
            payload = request()
            mutate(payload)
            with self.subTest(payload=payload):
                result = evaluate(payload, self.runtime())
                self.assert_bound(result, payload)
                self.assertEqual(result.status, "error")

    def test_unit_slice_may_start_after_line_one_with_consistent_range(self):
        payload = request()
        payload.units[0].start_line = 20
        payload.units[0].end_line = 21
        self.assertEqual(evaluate(payload, self.runtime()).status, "completed")


class CheckpointTests(unittest.TestCase):
    def write_manifest(self, directory, data):
        (Path(directory) / "manifest.json").write_text(json.dumps(data), encoding="utf-8")

    def test_reviewed_canonical_manifest_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write_manifest(directory, manifest())
            loaded = load_manifest(directory)
            self.assertEqual(loaded.max_tokens, 512)
            self.assertEqual(set(loaded.thresholds), set(GROUPS))

    def test_bad_or_unapproved_manifest_fails_before_model_import(self):
        mutations = [dict(approved_for_inference=False), dict(task="single_label_classification"),
                     dict(tokenizer_version=" "), dict(dataset_version=""), dict(validation_report=""),
                     dict(model_version=""), dict(max_tokens=513), dict(max_tokens=True),
                     dict(label_mapping={label: 5 - index for index, label in enumerate(GROUPS)}),
                     dict(thresholds={label: float("nan") for label in GROUPS}),
                     dict(thresholds={label: 1 for label in GROUPS}),
                     dict(thresholds={label: True for label in GROUPS})]
        with tempfile.TemporaryDirectory() as directory:
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    data = manifest()
                    data.update(mutation)
                    self.write_manifest(directory, data)
                    with self.assertRaises(ValueError):
                        RealEngine(directory)

    def test_base_checkpoint_or_label_mismatch_is_rejected(self):
        mutations = [dict(architectures=["RobertaModel"]), dict(problem_type="single_label_classification"),
                     dict(num_labels=2), dict(id2label={"0": "LABEL_0"}),
                     dict(label2id={label: 5 - index for index, label in enumerate(GROUPS)})]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                data = checkpoint_config()
                data.update(mutation)
                with self.assertRaises(ValueError):
                    validate_checkpoint_config(data)

    def test_hf_missing_or_mismatched_classification_head_fails_closed(self):
        for name in ("missing_keys", "mismatched_keys", "unexpected_keys", "error_msgs"):
            with self.subTest(field=name), self.assertRaises(EngineUnavailable):
                validate_loading_info({name: ["classifier.out_proj.weight"]})

    def test_checkpoint_loader_requires_local_safetensors_and_rejects_missing_head(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write_manifest(directory, manifest())
            (Path(directory) / "config.json").write_text(json.dumps(checkpoint_config()), encoding="utf-8")
            with self.assertRaises(EngineUnavailable):
                RealEngine(directory)
            (Path(directory) / "model.safetensors").write_bytes(b"test-only")
            tokenizer_loader = Mock(return_value=object())
            model_loader = Mock(return_value=(object(), {"missing_keys": ["classifier.out_proj.weight"]}))
            transformer_module = types.ModuleType("transformers")
            transformer_module.AutoTokenizer = types.SimpleNamespace(from_pretrained=tokenizer_loader)
            transformer_module.AutoModelForSequenceClassification = types.SimpleNamespace(from_pretrained=model_loader)
            with patch.dict(sys.modules, {"torch": types.ModuleType("torch"), "transformers": transformer_module}):
                with self.assertRaises(EngineUnavailable):
                    RealEngine(directory)
            self.assertTrue(model_loader.call_args.kwargs["local_files_only"])
            self.assertTrue(model_loader.call_args.kwargs["use_safetensors"])
            self.assertFalse(model_loader.call_args.kwargs["trust_remote_code"])
            self.assertFalse(tokenizer_loader.call_args.kwargs["trust_remote_code"])

    def test_real_tokenization_counts_full_context_before_model_forward(self):
        engine = RealEngine.__new__(RealEngine)
        engine.max_tokens = 512
        engine.tokenizer = Mock(return_value={"input_ids": list(range(700)), "attention_mask": [1] * 700})
        engine.model = Mock()
        with self.assertRaises(ContextTooLong) as raised:
            engine.predict(request("word " * 700).units[0])
        self.assertEqual(raised.exception.token_count, 700)
        self.assertFalse(engine.tokenizer.call_args.kwargs["truncation"])
        self.assertTrue(engine.tokenizer.call_args.kwargs["add_special_tokens"])
        engine.model.assert_not_called()


class ServiceTests(unittest.TestCase):
    def environment(self, directory, **updates):
        return dict(MODEL_MODE="demo", POLICY_PATH=str(Path(directory) / "absent-policy.json"),
                    MODEL_DIR=str(Path(directory) / "missing-model"), SERVICE_API_KEY="test-service-key", **updates)

    def test_authentication_requires_nonblank_configured_key(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, self.environment(directory)), TestClient(create_app()) as client:
                self.assertEqual(client.get("/health/live").status_code, 200)
                self.assertEqual(client.get("/health/ready").status_code, 200)
                for key in (None, "", "wrong-key"):
                    headers = {"X-Service-Key": key} if key is not None else {}
                    self.assertEqual(client.post("/v1/inferences", json=request().model_dump(),
                                                 headers=headers).status_code, 401)
                with patch.dict(os.environ, {"SERVICE_API_KEY": " "}):
                    self.assertEqual(client.post("/v1/inferences", json=request().model_dump(),
                                                 headers={"X-Service-Key": " "}).status_code, 503)

    def test_api_starts_branch_before_checkmarx_and_cannot_issue_decisions(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, self.environment(directory)), TestClient(create_app()) as client:
                payload = request()
                response = client.post("/v1/inferences", json=payload.model_dump(),
                                       headers={"X-Service-Key": "test-service-key"})
                self.assertEqual(response.status_code, 200)
                result = response.json()
                self.assertEqual(result["authority"], "codebert-inference")
                self.assertEqual(result["identity"], payload.identity.model_dump())
                self.assertEqual(result["source_manifest_sha256"], payload.source_manifest_sha256)
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["mode"], "demo")
                self.assertNotIn("decision", result)
                self.assertNotIn("allow_deploy", result)
                self.assertEqual(client.post("/v1/decisions", json=payload.model_dump()).status_code, 404)

    def test_real_mode_missing_model_remains_live_but_not_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(directory)
            env["MODEL_MODE"] = "real"
            with patch.dict(os.environ, env), TestClient(create_app()) as client:
                self.assertEqual(client.get("/health/live").status_code, 200)
                self.assertEqual(client.get("/health/ready").status_code, 503)
                payload = request()
                response = client.post("/v1/inferences", json=payload.model_dump(),
                                       headers={"X-Service-Key": "test-service-key"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["status"], "error")
                self.assertEqual(response.json()["identity"], payload.identity.model_dump())
                self.assertEqual(response.json()["source_manifest_sha256"], payload.source_manifest_sha256)

    def test_invalid_request_never_echoes_source_in_validation_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, self.environment(directory)), TestClient(create_app()) as client:
                payload = request().model_dump()
                secret = "private-source-marker"
                payload["units"][0]["code"] = secret * 11000
                response = client.post("/v1/inferences", json=payload,
                                       headers={"X-Service-Key": "test-service-key"})
                self.assertEqual(response.status_code, 422)
                self.assertNotIn(secret, response.text)
                self.assertNotIn("input", response.json()["detail"][0])

    def test_invalid_mode_fails_readiness_and_policy_does_not_affect_inference(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.environment(directory)
            Path(env["POLICY_PATH"]).write_text("invalid policy", encoding="utf-8")
            with patch.dict(os.environ, env), TestClient(create_app()) as client:
                self.assertEqual(client.get("/health/ready").status_code, 200)
            env["MODEL_MODE"] = "unsupported"
            with patch.dict(os.environ, env), TestClient(create_app()) as client:
                self.assertEqual(client.get("/health/live").status_code, 200)
                self.assertEqual(client.get("/health/ready").status_code, 503)

    def test_app_factory_instances_have_independent_runtime_state(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = create_app(), create_app()
            with patch.dict(os.environ, self.environment(directory)), TestClient(first) as first_client:
                with patch.dict(os.environ, {"MODEL_MODE": "real"}), TestClient(second) as second_client:
                    self.assertEqual(first_client.get("/health/ready").status_code, 200)
                    self.assertEqual(second_client.get("/health/ready").status_code, 503)
                    self.assertEqual(first.state.runtime.mode, "demo")
                    self.assertEqual(second.state.runtime.mode, "real")


if __name__ == "__main__":
    unittest.main()
