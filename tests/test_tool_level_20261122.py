"""Kiem thu muc TOOL Semgrep 4 bac (nhom chot 22/11/2026, cau 6): metadata.severity x confidence.
  python -m unittest tests.test_tool_level_20261122 -v
Khong can Semgrep, khong can model. Can pyyaml (doc semgrep.yml / taxonomy).
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMGREP = ROOT / "security-config" / "semgrep"
SCAN = SEMGREP / "tools" / "scan_repo.py"
sys.path.insert(0, str(ROOT / "ci"))
from aiws_ci import common as C  # noqa: E402
from aiws_ci.p4_compare_gate import max_tool_level  # noqa: E402


def load_scan_repo():
    spec = importlib.util.spec_from_file_location("scan_repo_tl", SCAN)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestTable(unittest.TestCase):
    CASES = [("critical", "high", "Critical"), ("high", "high", "High"), ("medium", "high", "Medium"),
             ("low", "high", "Low"), ("critical", "audit", "Medium"), ("high", "audit", "Medium"),
             ("medium", "audit", "Low"), ("low", "audit", "Low"), ("CRITICAL", "HIGH", "Critical"),
             (None, "high", "Medium"), (None, "audit", "Low"), ("la", None, "Low")]

    def test_cases(self):
        for impact, conf, want in self.CASES:
            self.assertEqual(C.tool_level(impact, conf), want, (impact, conf))

    def test_scan_repo_copy_matches_common(self):
        sr = load_scan_repo()
        self.assertEqual(sr.TOOL_LEVELS, C.TOOL_LEVELS)
        for impact in ("critical", "high", "medium", "low", None, "x"):
            for conf in ("high", "audit", None):
                self.assertEqual(sr.tool_level(impact, conf), C.tool_level(impact, conf), (impact, conf))

    def test_max_level(self):
        self.assertEqual(max_tool_level("Low", "Critical", "Medium"), "Critical")
        self.assertEqual(max_tool_level(None, "Low"), "Low")
        self.assertIsNone(max_tool_level(None, "khac"))


class TestRuleset(unittest.TestCase):
    def test_distribution_v481_and_audit_cap(self):
        import yaml
        d = yaml.safe_load((SEMGREP / "semgrep.yml").read_text(encoding="utf-8"))
        got = {lv: 0 for lv in C.TOOL_LEVELS}
        for r in d["rules"]:
            md = r["metadata"]
            lv = C.tool_level(md.get("severity"), md.get("confidence"))
            got[lv] += 1
            if md.get("confidence") != "high":
                self.assertNotIn(lv, ("Critical", "High"), r["id"])
        self.assertEqual(sum(got.values()), len(d["rules"]))
        self.assertTrue(all(got.values()), f"thieu muc: {got}")   # du 4 muc


class TestScanRepoOutput(unittest.TestCase):
    def test_findings_have_tool_level(self):
        repo = Path(tempfile.mkdtemp())
        (repo / "a.py").write_text("def a(x):\n    return x\n", encoding="utf-8")
        raw = repo.parent / f"raw_{repo.name}.json"
        mk = lambda rid, sev, conf, cls, line: {
            "check_id": f"x.team.{rid}", "path": "a.py", "start": {"line": line}, "end": {"line": line},
            "extra": {"severity": "ERROR" if conf == "high" else "WARNING", "message": "m",
                      "metadata": {"vuln_class": cls, "confidence": conf, "severity": sev, "cwe": []}}}
        raw.write_text(json.dumps({"version": "1.181.0", "errors": [], "paths": {}, "results": [
            mk("r1", "critical", "high", "SQL_INJECTION", 1), mk("r2", "critical", "audit", "SQL_INJECTION", 2),
            mk("r3", None, "audit", "XSS", 1)]}), encoding="utf-8")
        out = repo.parent / f"out_{repo.name}.json"
        r = subprocess.run([sys.executable, str(SCAN), "--raw-json", str(raw), "--repo", str(repo), "--out", str(out)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        res = json.loads(out.read_text(encoding="utf-8"))
        lv = {f["rule_id"]: f["tool_level"] for f in res["findings"]}
        self.assertEqual(lv, {"team.r1": "Critical", "team.r2": "Medium", "team.r3": "Low"})   # r3: XSS mac dinh medium
        self.assertEqual(res["summary"]["by_tool_level"], {"Critical": 1, "High": 0, "Medium": 1, "Low": 1})


class TestP4(unittest.TestCase):
    def test_levels_in_report_and_decision_unchanged(self):
        d = Path(tempfile.mkdtemp())
        u = lambda n, s, e: {"id": f"a.py::{n}@L{s}", "file": "a.py", "language": "python", "unit": "function",
                             "name": n, "start": s, "end": e, "in_diff": True, "scored": True, "code": ""}
        units = [u("f1", 1, 3), u("f2", 5, 7)]
        C.write_jsonl(d / "p1-units.jsonl", units)
        C.write_json(d / "p1-scope.json", {"mode": "full", "target_files": ["a.py"], "changed_lines": {},
                                           "files": [{"path": "a.py"}], "head": "0" * 40, "created_at": C.now(),
                                           "unit_backend": "treesitter", "note": "", "summary": {}})
        C.write_json(d / "p0-authorize.json", {"source": {"ok": True}, "model": {"status": "ok"}})
        # finding cu (khong co tool_level) -> P4 tinh lai tu impact_severity x confidence
        f = lambda line, conf, imp: {"file": "a.py", "start_line": line, "end_line": line, "class": "SQL_INJECTION",
                                     "confidence": conf, "impact_severity": imp, "rule_id": f"team.{conf}",
                                     "cwes": [], "message": ""}
        C.write_json(d / "semgrep.json", {"run": {"ruleset_version": "4.8.1"}, "files": [{"path": "a.py"}],
                                          "findings": [f(2, "high", "critical"), f(6, "audit", "critical")]})
        probs = {g: 0.01 for g in C.GROUPS}
        C.write_json(d / "codebert-results.json", {"status": "completed", "thresholds": {g: 0.5 for g in C.GROUPS},
                                                   "model": {"name": "t"}, "units": [
            {"id": x["id"], "probs": probs, "groups": [], "truncated": False} for x in units]})
        env = {**os.environ, "PYTHONPATH": str(ROOT / "ci"), "AIWS_GATE_ENFORCE": "0"}
        r = subprocess.run([sys.executable, "-m", "aiws_ci.p4_compare_gate", "--out-dir", str(d), "--semgrep",
                            str(d / "semgrep.json"), "--policy", str(ROOT / "ci" / "gate-policy.json")],
                           capture_output=True, text=True, env=env)
        rep = json.loads((d / "report.json").read_text(encoding="utf-8"))
        g = rep["gate"]
        by = {x["function"]: x for x in g["units"]}
        self.assertEqual(by["f1"]["sast_level"], "Critical")
        self.assertEqual(by["f2"]["sast_level"], "Medium")
        self.assertEqual(by["f1"]["cells"][0]["semgrep_tool_level"], "Critical")
        # quyet dinh Gate 3x3 KHONG doi: High x Khong -> REVIEW; Audit x Khong -> INFO
        self.assertEqual(by["f1"]["decision"], "REVIEW")
        self.assertEqual(by["f2"]["decision"], "INFO")
        self.assertEqual(rep["summary"]["semgrep_levels"], {"Critical": 1, "High": 0, "Medium": 1, "Low": 0})
        levels = sorted(x["level"] for x in rep["tools"][0]["normalized_findings"])
        self.assertEqual(levels, ["Critical", "Medium"])
        self.assertIn("Muc tool Semgrep", (d / "summary.md").read_text(encoding="utf-8"))


def policy_5x3():
    """gate-policy.json tu 23/11 la 5x5; bang 5x3 (22/11) giu o truoc_2311 -> dung lai de kiem decide_3x3 khong doi."""
    pol = json.loads((ROOT / "ci" / "gate-policy.json").read_text(encoding="utf-8"))
    old = pol["truoc_2311"]
    p = {k: v for k, v in pol.items() if k not in ("model_levels", "levels", "truoc_2311")}
    p.update(policy_version=old["policy_version"], matrix=old["matrix"], codebert_levels=old["codebert_levels"],
             team_overrides=old["team_overrides"])
    path = Path(tempfile.mkdtemp()) / "gate-policy-5x3.json"
    path.write_text(json.dumps(p), encoding="utf-8")
    return path


class TestGate5x3(unittest.TestCase):
    """Bang 5x3 (nhom chot 22/11, nay o truoc_2311): Critical x Thap = BLOCK; XSS confidence high -> hang Medium."""
    POLICY = None

    @classmethod
    def setUpClass(cls):
        cls.POLICY = policy_5x3()

    def run_cells(self, findings, probs, th=0.5, weak=0.2):
        d = Path(tempfile.mkdtemp())
        unit = {"id": "a.py::f@L1", "file": "a.py", "language": "python", "unit": "function", "name": "f",
                "start": 1, "end": 9, "in_diff": True, "scored": True, "code": ""}
        C.write_jsonl(d / "p1-units.jsonl", [unit])
        C.write_json(d / "p1-scope.json", {"mode": "full", "target_files": ["a.py"], "changed_lines": {},
                                           "files": [{"path": "a.py"}], "head": "0" * 40, "created_at": C.now(),
                                           "unit_backend": "treesitter", "note": "", "summary": {}})
        C.write_json(d / "p0-authorize.json", {"source": {"ok": True}, "model": {"status": "ok"}})
        C.write_json(d / "semgrep.json", {"run": {}, "files": [{"path": "a.py"}], "findings": [
            {"file": "a.py", "start_line": 2, "end_line": 2, "rule_id": "team.x", "cwes": [], "message": "", **f}
            for f in findings]})
        p = {g: 0.01 for g in C.GROUPS}; p.update(probs)
        C.write_json(d / "codebert-results.json", {"status": "completed", "model": {"name": "t"},
                                                   "thresholds": {g: th for g in C.GROUPS},
                                                   "thresholds_weak": {g: weak for g in C.GROUPS},
                                                   "units": [{"id": unit["id"], "probs": p, "groups": [], "truncated": False}]})
        env = {**os.environ, "PYTHONPATH": str(ROOT / "ci"), "AIWS_GATE_ENFORCE": "0"}
        subprocess.run([sys.executable, "-m", "aiws_ci.p4_compare_gate", "--out-dir", str(d), "--semgrep",
                        str(d / "semgrep.json"), "--policy", str(self.POLICY)],
                       capture_output=True, text=True, env=env)
        u = json.loads((d / "gate.json").read_text(encoding="utf-8"))["units"][0]
        return u["decision"], {c["class"]: (c["semgrep"], c["codebert"], c["decision"]) for c in u["cells"]}

    def test_critical_x_thap_block(self):
        dec, cells = self.run_cells([{"class": "SQL_INJECTION", "confidence": "high", "impact_severity": "critical"}],
                                    {"SQL_INJECTION": 0.3})
        self.assertEqual(cells["SQL_INJECTION"], ("Critical", "Thap", "BLOCK"))
        self.assertEqual(dec, "BLOCK")

    def test_high_x_thap_review(self):
        dec, cells = self.run_cells([{"class": "PATH_TRAVERSAL", "confidence": "high", "impact_severity": "high"}],
                                    {"PATH_TRAVERSAL": 0.3})
        self.assertEqual(cells["PATH_TRAVERSAL"], ("High", "Thap", "REVIEW"))

    def test_xss_high_conf_is_medium_row(self):
        dec, cells = self.run_cells([{"class": "XSS", "confidence": "high", "impact_severity": "medium"}], {})
        self.assertEqual(cells["XSS"], ("Medium", "Khong", "INFO"))

    def test_audit_never_above_medium_row(self):
        dec, cells = self.run_cells([{"class": "SQL_INJECTION", "confidence": "audit", "impact_severity": "critical"}],
                                    {"SQL_INJECTION": 0.3})
        self.assertEqual(cells["SQL_INJECTION"], ("Medium", "Thap", "INFO"))

    def test_class_default_when_no_impact(self):
        self.assertEqual(C.class_default_severity("SQL_INJECTION"), "critical")
        self.assertEqual(C.class_default_severity("INSECURE_AUTHENTICATION"), "high")
        dec, cells = self.run_cells([{"class": "OS_COMMAND_INJECTION", "confidence": "high"}], {})
        self.assertEqual(cells["OS_COMMAND_INJECTION"], ("Critical", "Khong", "REVIEW"))

    def test_policy_matrix_is_agreed_table(self):
        pol = json.loads(self.POLICY.read_text(encoding="utf-8"))
        self.assertEqual(pol["semgrep_levels"]["field"], "tool_level")
        m = {r: [pol["matrix"][r][c] for c in ("Cao", "Thap", "Khong")] for r in pol["matrix"]}
        self.assertEqual(m, {"Critical": ["BLOCK", "BLOCK", "REVIEW"], "High": ["BLOCK", "REVIEW", "REVIEW"],
                             "Medium": ["REVIEW", "INFO", "INFO"], "Low": ["REVIEW", "INFO", "INFO"],
                             "Khong": ["REVIEW", "INFO", "PASS"]})


if __name__ == "__main__":
    unittest.main()
