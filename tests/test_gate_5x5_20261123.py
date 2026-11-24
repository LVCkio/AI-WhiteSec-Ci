"""Gate 5x5 (nhom chot 23/11/2026, giong gate_5x5.json cua worker Server 3):  python -m unittest tests.test_gate_5x5_20261123 -v
Truc Semgrep = muc tool 4 bac (nhu 5x3) + None; truc CodeBERT = muc CVSS cua lop: strong (>= thresholds.json) giu,
weak (thresholds_weak .. thresholds) ha 1 bac, con lai None. Khong can model that, khong can Semgrep, khong can tree-sitter.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ci"))
from aiws_ci import common as C  # noqa: E402
from aiws_ci.p4_compare_gate import model_level5  # noqa: E402

POLICY = ROOT / "ci" / "gate-policy.json"
TH, WEAK = 0.5, 0.2          # alpha10, alpha20 gia trong bai thu


def run_unit(findings, probs, file="a.py"):
    d = Path(tempfile.mkdtemp())
    unit = {"id": f"{file}::f@L1", "file": file, "language": "python", "unit": "function", "name": "f",
            "start": 1, "end": 9, "in_diff": True, "scored": True, "code": ""}
    C.write_jsonl(d / "p1-units.jsonl", [unit])
    C.write_json(d / "p1-scope.json", {"mode": "full", "target_files": [file], "changed_lines": {},
                                       "files": [{"path": file}], "head": "0" * 40, "created_at": C.now(),
                                       "unit_backend": "treesitter", "note": "", "summary": {}})
    C.write_json(d / "p0-authorize.json", {"source": {"ok": True}, "model": {"status": "ok"}})
    C.write_json(d / "semgrep.json", {"run": {}, "files": [{"path": file}], "findings": [
        {"file": file, "start_line": 2, "end_line": 2, "rule_id": "team.x", "cwes": [], "message": "", **f}
        for f in findings]})
    p = {g: 0.01 for g in C.GROUPS}
    p.update(probs)
    C.write_json(d / "codebert-results.json", {"status": "completed", "model": {"name": "t"},
                                               "thresholds": {g: TH for g in C.GROUPS},
                                               "thresholds_weak": {g: WEAK for g in C.GROUPS},
                                               "units": [{"id": unit["id"], "probs": p, "truncated": False,
                                                          "groups": [g for g, v in p.items() if v >= TH]}]})
    env = {**os.environ, "PYTHONPATH": str(ROOT / "ci"), "AIWS_GATE_ENFORCE": "0"}
    r = subprocess.run([sys.executable, "-m", "aiws_ci.p4_compare_gate", "--out-dir", str(d), "--semgrep",
                        str(d / "semgrep.json"), "--policy", str(POLICY)], capture_output=True, text=True, env=env)
    assert (d / "gate.json").is_file(), r.stderr[-2000:]
    g = json.loads((d / "gate.json").read_text(encoding="utf-8"))
    u = g["units"][0]
    return g, u["decision"], {c["class"]: (c["semgrep"], c["codebert"], c["decision"]) for c in u["cells"]}


SQL, XSS, HARD, PATH = "SQL_INJECTION", "XSS", "HARDCODED_CREDENTIALS", "PATH_TRAVERSAL"


class TestPolicy5x5(unittest.TestCase):
    def test_matrix_is_agreed_table(self):
        pol = json.loads(POLICY.read_text(encoding="utf-8"))
        cols = ["Critical", "High", "Medium", "Low", "None"]
        m = {r: [pol["matrix"][r][c] for c in cols] for r in pol["matrix"]}
        self.assertEqual(m, {
            "Critical": ["BLOCK", "BLOCK", "BLOCK", "REVIEW", "REVIEW"],
            "High": ["BLOCK", "BLOCK", "REVIEW", "REVIEW", "REVIEW"],
            "Medium": ["BLOCK", "REVIEW", "REVIEW", "INFO", "INFO"],
            "Low": ["REVIEW", "REVIEW", "INFO", "INFO", "INFO"],
            "None": ["REVIEW", "REVIEW", "INFO", "INFO", "PASS"]})
        self.assertEqual(pol["policy_version"], "5x5-2026-11-23")
        self.assertEqual(pol["source_gate_5x5"]["sha256"],
                         "e7beee1a14a783ab5caa30339b73d5bf1082ee440676944ed392a630c116d72e")
        self.assertEqual(pol["model_levels"]["severity_by_class"], {
            SQL: "Critical", HARD: "Critical", "OS_COMMAND_INJECTION": "High", PATH: "High",
            "AUTHENTICATION_WEAKNESS": "High", XSS: "Medium"})

    def test_model_level5(self):
        ml = json.loads(POLICY.read_text(encoding="utf-8"))["model_levels"]
        self.assertEqual([model_level5(SQL, k, ml) for k in ("strong", "weak", "none")], ["Critical", "High", "None"])
        self.assertEqual([model_level5(XSS, k, ml) for k in ("strong", "weak", "none")], ["Medium", "Low", "None"])


class TestGate5x5(unittest.TestCase):
    """Cac truong hop doi quyet dinh so voi 5x3 (bang so sanh gui nhom 23/11)."""

    def test_sql_audit_x_strong_block(self):           # 5x3: Medium x Cao = REVIEW
        g, dec, cells = run_unit([{"class": SQL, "confidence": "audit", "impact_severity": "critical"}], {SQL: 0.9})
        self.assertEqual(cells[SQL], ("Medium", "Critical", "BLOCK"))
        self.assertEqual((g["gate_kind"], g["policy_version"]), ("5x5", "5x5-2026-11-23"))
        self.assertIn("None", g["policy"])

    def test_sql_audit_x_weak_review(self):            # 5x3: Medium x Thap = INFO
        _, _, cells = run_unit([{"class": SQL, "confidence": "audit", "impact_severity": "critical"}], {SQL: 0.3})
        self.assertEqual(cells[SQL], ("Medium", "High", "REVIEW"))

    def test_sql_model_weak_only_review(self):         # 5x3: Khong x Thap = INFO
        _, dec, cells = run_unit([], {SQL: 0.3})
        self.assertEqual((cells[SQL], dec), (("None", "High", "REVIEW"), "REVIEW"))

    def test_xss_model_strong_only_info(self):         # 5x3: Khong x Cao = REVIEW
        _, dec, cells = run_unit([], {XSS: 0.9})
        self.assertEqual((cells[XSS], dec), (("None", "Medium", "INFO"), "INFO"))

    def test_hardcoded_high_x_weak_block(self):        # 5x3: High x Thap = REVIEW
        _, _, cells = run_unit([{"class": HARD, "confidence": "high", "impact_severity": "high"}], {HARD: 0.3})
        self.assertEqual(cells[HARD], ("High", "High", "BLOCK"))

    def test_hardcoded_strong_needs_095(self):         # team_overrides: strong ma p < 0.95 -> weak
        _, _, cells = run_unit([{"class": HARD, "confidence": "high", "impact_severity": "high"}], {HARD: 0.9})
        self.assertEqual(cells[HARD], ("High", "High", "BLOCK"))
        _, _, cells = run_unit([{"class": HARD, "confidence": "audit", "impact_severity": "high"}], {HARD: 0.97})
        self.assertEqual(cells[HARD], ("Medium", "Critical", "BLOCK"))

    def test_hardcoded_model_only_info(self):          # team_overrides: None/Critical, None/High -> INFO
        for p in (0.97, 0.9, 0.3):
            _, dec, cells = run_unit([], {HARD: p})
            self.assertEqual(cells[HARD][2], "INFO", p)
            self.assertEqual(dec, "INFO")

    def test_tests_dir_max_info(self):
        _, dec, cells = run_unit([{"class": SQL, "confidence": "high", "impact_severity": "critical"}], {SQL: 0.9},
                                 file="tests/test_db.py")
        self.assertEqual(cells[SQL], ("Critical", "Critical", "BLOCK"))
        self.assertEqual(dec, "INFO")


if __name__ == "__main__":
    unittest.main()
