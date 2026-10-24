"""Kiem thu dashboard local (dashboard/collect.py, dashboard/server.py) tren du lieu gia lap; khong can torch."""
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard"))
import collect  # noqa: E402
import server  # noqa: E402

POLICY = {"agree": "BLOCK", "sast_only": {"high": "BLOCK", "audit": "REVIEW"}, "codebert_only": "REVIEW",
          "conflict": "REVIEW", "pass": "PASS"}


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")


def scan_doc(repo, ruleset="4.2.0", tools=("semgrep",)):
    finding = {"tool": "semgrep", "rule_id": "D.nX.main.security-config.semgrep.team.sql-injection", "cwes": ["89"],
               "classes": ["SQL_INJECTION"], "line": 3, "message": "SQL", "confidence": "high"}
    return {
        "tool": {"name": "AI-WhiteSec-CI", "version": "0.2.0"}, "repo": str(repo), "commit": None,
        "architecture": "parallel", "mode": "parallel", "degraded_reason": None, "verdict": "BLOCK",
        "pipeline": {"model_dir": "models\\c03_v51"}, "sast_tools": list(tools),
        "gate_config": {"version": "1.1", "policy": POLICY,
                        "verifier": {"enabled": True, "model": "models\\verifier_codebert_v51", "kind": "codebert", "threshold": 0.594}},
        "ruleset": {"ruleset_version": ruleset, "ruleset_sha256": "ab" * 32, "regression_passed": True},
        "a01_verification": "codebert:models\\verifier_codebert_v51", "device": "cpu",
        "summary": {"files": 1, "units": 2, "decisions": {"BLOCK": 1, "REVIEW": 0, "PASS": 1},
                    "compare_states": {"agree": 0, "sast_only": 1, "codebert_only": 0, "conflict": 0, "pass": 1}, "model_calls": 2},
        "timing_seconds": {"extract_s": 0.01, "sast_s": 1.0, "codebert_s": 2.0, "parallel_wall_s": 2.0, "total_s": 2.1},
        "results": [{"file": "db.py", "function": "find", "language": "Python", "lines": [1, 4], "status": "FINDING",
                     "decision": "BLOCK", "compare_state": "sast_only", "reported_by": ["sast"], "vuln_class": "SQL_INJECTION",
                     "related_classes": ["SQL_INJECTION"], "sast_classes": ["SQL_INJECTION"],
                     "codebert": {"class": "SQL_INJECTION", "prob": 0.9, "p_vulnerable": 0.2, "flagged": False, "flag_source": "verifier"},
                     "probabilities": {"SQL_INJECTION": 0.9}, "p_vulnerable": 0.2,
                     "metadata": {"cwe": "CWE-89", "severity": "critical", "priority": {"score": 100, "level": "P1"}},
                     "findings": [finding]}],
        "all_units": [{"file": "db.py", "function": "find", "decision": "BLOCK", "compare_state": "sast_only",
                       "sast_classes": ["SQL_INJECTION"], "codebert_class": "SQL_INJECTION", "p_vulnerable": 0.2},
                      {"file": "db.py", "function": "safe", "decision": "PASS", "compare_state": "pass",
                       "sast_classes": [], "codebert_class": "XSS", "p_vulnerable": float("nan")}],
    }


def make_root(tmp):
    root = Path(tmp)
    src = root / "targets" / "flask_vuln_app" / "scan_src"
    write(src / "db.py", "import sqlite3\n\ndef find(q):\n    cur.execute('SELECT %s' % q)\n\ndef safe():\n    return 1\n")
    write(root / "targets" / "flask_vuln_app" / "ground_truth.json",
          {"n": 1, "vulnerabilities": [{"id": "SQLI-1", "file": "app/db.py", "function": "find", "class": "SQL_INJECTION"}]})
    write(root / "reports" / "targets" / "flask_vuln_app_scan_v42.json", json.dumps(scan_doc(src)).replace("NaN", "NaN"))
    write(root / "reports" / "targets" / "flask_vuln_app_scan_old.json", scan_doc(src, "4.1.0", ("semgrep", "bandit")))
    write(root / "reports" / "targets" / "flask_vuln_app_scan.json", {"verdict": "BLOCK", "results": []})  # ban cu, bo qua
    write(root / "reports" / "targets" / "flask_vuln_app_eval_v42.json", {
        "n_vulnerabilities": 1, "n_vulnerable_units": 1, "n_units": 2, "verifier_threshold": 0.594,
        "results": [{"method": "Gate_BLOCK", "per_class": [{"class": "SQL_INJECTION", "gt": 1, "detected": 1, "predicted": 1}],
                     "n_predictions": 1, "detected_any_class": 1.0, "flagged_safe_functions": 0, "safe_functions": 1,
                     "wrong_class_on_vulnerable": 0}]})
    write(root / "models" / "pipeline_config.json", {"model_dir": "models\\c03_v51"})
    write(root / "models" / "gate_config.json", {"version": "1.1", "policy": POLICY,
          "verifier": {"enabled": True, "model": "models\\verifier_codebert_v51", "kind": "codebert", "threshold": 0.594}})
    write(root / "models" / "c03_v51" / "run_info.json", {"model": "microsoft/codebert-base", "val": {"macro_f1": 0.7, "accuracy": 0.8,
          "macro_f1_Python": 0.6, "n_Python": 10, "confusion_matrix": [[1, 0], [0, 1]]},
          "log_history": [{"epoch": 1.0, "eval_macro_f1": 0.5}, {"epoch": 2.0, "eval_macro_f1": 0.7}]})
    write(root / "security-config" / "semgrep" / "tools" / "ruleset.py", 'RULESET_VERSION = "4.2.0"\n')
    write(root / "security-config" / "semgrep" / "semgrep.yml", "rules:\n  - id: a\n  - id: b\n")
    write(root / "reports" / "gate_eval_val_x.json", {"verifier": "models\\verifier_codebert_v51", "selected_threshold": 0.638,
          "sweep": {"0.594": {"flag_vuln": 0.8, "block_vuln": 0.2}, "0.638": {"flag_vuln": 0.7, "block_vuln": 0.19}},
          "comparison": {"Gate: BLOCK": {"all": {"flag_vuln": 0.2, "flag_patched": 0.07}}}})
    return root


class CollectTests(unittest.TestCase):
    def test_build_from_scan_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = collect.build(make_root(tmp))
        self.assertEqual(data["schema"], collect.SCHEMA)
        self.assertEqual(sorted(r["id"] for r in data["runs"]), ["flask_vuln_app:old", "flask_vuln_app:v42"])  # ban cu bi bo
        cur = [c for c in data["configs"] if c["current"]]
        self.assertEqual(len(cur), 1)
        self.assertEqual(cur[0]["runs"], ["flask_vuln_app:v42"])
        self.assertEqual(data["configs"][0]["id"], cur[0]["id"])  # cau hinh hien tai dung dau
        self.assertEqual(data["project"]["current_config"], cur[0]["id"])
        self.assertEqual(data["project"]["ruleset"], {"version": "4.2.0", "n_rules": 2})
        run = next(r for r in data["runs"] if r["id"] == "flask_vuln_app:v42")
        units = {u["function"]: u for u in run["units"]}
        self.assertEqual(units["find"]["gt"]["status"], "vulnerable")       # 'app/db.py' -> 'db.py'
        self.assertTrue(units["find"]["gt"]["class_match"])
        self.assertEqual(units["safe"]["gt"]["status"], "safe")
        self.assertIsNone(units["safe"]["p_vulnerable"])                   # NaN -> null
        self.assertEqual(units["find"]["findings"][0]["rule"], "team.sql-injection")
        self.assertEqual(run["eval"]["methods"][0]["tp"], 1)
        old = next(r for r in data["runs"] if r["id"] == "flask_vuln_app:old")
        self.assertEqual(old["config"]["sast_tools"], ["semgrep", "bandit"])
        gate = data["evaluation"]["gate"]
        self.assertEqual(gate["config_threshold"], 0.594)                  # so tai nguong dang dung, khong phai 0.638
        self.assertEqual(gate["at_config"]["block_vuln"], 0.2)
        self.assertEqual(gate["comparison"][0]["name"], "Gate BLOCK")
        json.dumps(data, allow_nan=False)                                  # JSON hop le cho trinh duyet

    def test_real_project_builds(self):
        if not (ROOT / "reports" / "targets").is_dir():
            self.skipTest("chua co reports/targets")
        data = collect.build(ROOT)
        json.dumps(data, allow_nan=False)
        self.assertIn("runs", data)


RULES_YML = """rules:
- id: team.python.sqli-taint
  languages:
  - python
  severity: ERROR
  message: Request data reaches an SQL query.
  metadata:
    cwe: CWE-89
    vuln_class: SQL_INJECTION
    confidence: high
    rule_version: 1.1.0
    change_v4: 'Sua: bo hmac.compare_digest
      khoi rule.'
  mode: taint
  pattern-sources:
  - pattern: request.args
- id: team.php.audit.file-path-api
  languages: [php]
  severity: INFO
  message: A file API receives a non-literal path (audit hint).
  metadata:
    vuln_class: PATH_TRAVERSAL
    confidence: audit
  pattern: fopen($P)
"""


class ProjectInfoTests(unittest.TestCase):
    def test_rules_parse_without_yaml_matches_yaml(self):
        import project_info as pi
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "semgrep.yml"
            p.write_text(RULES_YML, encoding="utf-8")
            with_yaml = pi.parse_rules(p)
            import builtins
            real = builtins.__import__
            def no_yaml(name, *a, **k):
                if name == "yaml":
                    raise ImportError
                return real(name, *a, **k)
            builtins.__import__ = no_yaml
            try:
                without = pi.parse_rules(p)
            finally:
                builtins.__import__ = real
        for rules in (with_yaml, without):
            self.assertEqual([r["id"] for r in rules], ["team.python.sqli-taint", "team.php.audit.file-path-api"])
            self.assertEqual(rules[0]["mode"], "taint")
            self.assertEqual(rules[0]["confidence"], "high")
            self.assertEqual(rules[1]["vuln_class"], "PATH_TRAVERSAL")
            self.assertIn("pattern-sources", rules[0]["source"])          # noi dung YAML goc cua rule
        self.assertEqual(without[0]["rule_version"], "1.1.0")
        self.assertIn("compare_digest", without[0]["change"])

    def test_config_info_in_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            write(root / "security-config" / "semgrep" / "semgrep.yml", RULES_YML)
            write(root / "security-config" / "semgrep" / "ruleset-manifest.json",
                  {"ruleset_version": "4.2.0", "tests_passed": 3, "tests_total": 3, "regression_passed": True})
            write(root / "security-config" / "semgrep" / "TIEU_CHI_CHON_RULE.md",
                  "# Tieu chi\n\n## 2. Tieu chi\n\n| Ma | Tieu chi | Cach kiem |\n|---|---|---|\n| TC1 | **Dung pham vi** | `check` |\n\n## 3. Khac\n")
            ci = collect.build(root)["config_info"]
        self.assertEqual(len(ci["rules"]), 2)
        self.assertEqual(ci["versions"]["ruleset"]["tests_passed"], 3)
        self.assertEqual(ci["criteria"]["rows"][0]["code"], "TC1")
        self.assertEqual(ci["versions"]["test_sets"][0]["status"], "frozen")
        self.assertIn("flask_vuln_app", ci["ground_truth"])
        self.assertEqual(ci["thresholds"][0]["value"], 0.594)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.srv = server.make_server(make_root(cls.tmp.name), port=0)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def get(self, path, host="127.0.0.1"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", path, headers={"Host": f"{host}:{self.port}"})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r, body

    def test_index_and_headers(self):
        r, body = self.get("/")
        self.assertEqual(r.status, 200)
        self.assertIn(b"AI-WhiteSec-CI", body)
        self.assertIn("script-src 'self'", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")

    def test_data_endpoint(self):
        r, body = self.get("/api/data")
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(body)["schema"], collect.SCHEMA)
        self.assertTrue(r.getheader("X-Data-Version"))

    def test_source_only_for_scanned_files(self):
        r, body = self.get("/api/source?run=flask_vuln_app:v42&file=db.py&start=3&end=4")
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(body)["lines"][0], "def find(q):")
        for bad in ("../ground_truth.json", "..%2F..%2Fmodels%2Fgate_config.json", "other.py"):
            r, _ = self.get(f"/api/source?run=flask_vuln_app:v42&file={bad}")
            self.assertEqual(r.status, 404, bad)

    def test_rejects_foreign_host_and_traversal(self):
        self.assertEqual(self.get("/api/data", host="evil.example")[0].status, 403)
        self.assertEqual(self.get("/assets/../server.py")[0].status, 404)
        self.assertEqual(self.get("/assets/%2e%2e/server.py")[0].status, 404)
        self.assertEqual(self.get("/api/figure?path=models/gate_config.json")[0].status, 404)


if __name__ == "__main__":
    unittest.main()
