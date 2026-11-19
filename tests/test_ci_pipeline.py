"""Kiem thu Pipeline 2 (khong can model that, khong can Semgrep):  python -m unittest tests.test_ci_pipeline -v
Can: tree-sitter + 4 grammar (ci/docker/requirements-codebert.txt).
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
from aiws_ci.units import file_units, innermost_function  # noqa: E402


def fn(units):
    return [(u["name"], u["start"], u["end"]) for u in units if u["unit"] == "function"]


class TestUnits(unittest.TestCase):
    def test_python_nested_and_decorator(self):
        src = "import os\n\n@app.route('/x')\ndef outer(a):\n    def inner(b):\n        return b\n    return inner(a)\n"
        self.assertEqual(fn(file_units("a.py", src, "python")[0]), [("outer", 4, 7), ("inner", 5, 6)])

    def test_javascript_anonymous_names(self):
        src = "const h = function (req, res) {\n  res.send(req.query.q);\n};\napp.get('/', (req, res) => {\n  x(req);\n});\n"
        names = fn(file_units("a.js", src, "javascript")[0])
        self.assertIn(("h", 1, 3), names)
        self.assertIn(("<anonymous>", 4, 6), names)
        self.assertNotIn("function", [n for n, _, _ in names])     # khong lay token tu khoa

    def test_java_and_php(self):
        j = "class A {\n  public void run(String c) throws Exception {\n    Runtime.getRuntime().exec(c);\n  }\n}\n"
        self.assertEqual(fn(file_units("A.java", j, "java")[0]), [("run", 2, 4)])
        p = "<html><?php\nfunction f($a) {\n  system($a);\n}\n?></html>\n"
        self.assertEqual(fn(file_units("a.php", p, "php")[0]), [("f", 2, 4)])

    def test_module_snippet_only_outside_functions(self):
        src = "\n".join(["import x"] * 3 + ['DB_PASSWORD = "hunter2"'] + ["y = 1"] * 8 +
                        ["def f():", '    password = "abc"', "    return password"]) + "\n"
        units = file_units("c.py", src, "python")[0]
        snip = [u for u in units if u["unit"] == "module_snippet"]
        self.assertEqual(len(snip), 1)
        self.assertEqual((snip[0]["start"], snip[0]["end"]), (1, 9))       # dong 4 +-5, khong lan vao ham (dong 13)
        self.assertEqual(snip[0]["only_groups"], ["HARDCODED_CREDENTIALS"])

    def test_code_is_raw_lines(self):
        src = "def f(x):\n    # comment giu nguyen\n    return x\n"
        u = file_units("a.py", src, "python")[0][0]
        self.assertEqual(u["code"], src.rstrip("\n"))

    def test_innermost(self):
        src = "def outer(a):\n    def inner(b):\n        return b\n    return inner(a)\n"
        units = file_units("a.py", src, "python")[0]
        self.assertEqual(innermost_function(units, "a.py", 3)["name"], "inner")
        self.assertEqual(innermost_function(units, "a.py", 4)["name"], "outer")


class TestGate(unittest.TestCase):
    """Chay p4_compare_gate tren du lieu dung tay cho 5 trang thai."""

    def run_gate(self, cb_status="completed"):
        d = Path(tempfile.mkdtemp())
        mk = lambda name, s, e: {"id": f"a.py::{name}@L{s}", "file": "a.py", "language": "python", "unit": "function",
                                 "name": name, "start": s, "end": e, "in_diff": True, "scored": True, "code": ""}
        units = [mk("agree", 1, 3), mk("sast_high", 5, 7), mk("sast_audit", 9, 11), mk("cb_only", 13, 15),
                 mk("conflict", 17, 19), mk("clean", 21, 23), mk("agree_audit", 25, 27)]
        C.write_jsonl(d / "p1-units.jsonl", units)
        C.write_json(d / "p1-scope.json", {"mode": "full", "target_files": ["a.py"], "changed_lines": {},
                                           "head": "0" * 40, "created_at": C.now(), "unit_backend": "treesitter",
                                           "note": "", "summary": {}})
        C.write_json(d / "p0-authorize.json", {"source": {"ok": True}, "model": {"status": "ok"}})
        f = lambda line, cls, conf: {"file": "a.py", "start_line": line, "end_line": line, "class": cls,
                                     "confidence": conf, "rule_id": f"team.{cls.lower()}", "cwes": [], "message": ""}
        C.write_json(d / "semgrep.json", {"run": {"ruleset_version": "4.7.0"}, "findings": [
            f(2, "SQL_INJECTION", "high"), f(6, "XSS", "high"), f(10, "PATH_TRAVERSAL", "audit"),
            f(18, "INSECURE_AUTHENTICATION", "high"), f(26, "PATH_TRAVERSAL", "audit")]})
        probs = {g: 0.1 for g in C.GROUPS}
        cbu = lambda u, groups: {"id": u["id"], "probs": {**probs, **{g: 0.9 for g in groups}}, "groups": groups,
                                 "truncated": False}
        C.write_json(d / "codebert-results.json", {
            "status": cb_status, "thresholds": {g: 0.5 for g in C.GROUPS}, "model": {"name": "t"},
            "units": [cbu(units[0], ["SQL_INJECTION"]), cbu(units[3], ["XSS"]), cbu(units[4], ["SQL_INJECTION"]),
                      cbu(units[6], ["PATH_TRAVERSAL"])]})
        env = {**os.environ, "PYTHONPATH": str(ROOT / "ci"), "AIWS_GATE_ENFORCE": "1"}
        r = subprocess.run([sys.executable, "-m", "aiws_ci.p4_compare_gate", "--out-dir", str(d), "--semgrep",
                            str(d / "semgrep.json"), "--policy", str(ROOT / "ci" / "gate-policy.json")],
                           capture_output=True, text=True, env=env)
        return r.returncode, json.loads((d / "gate.json").read_text(encoding="utf-8"))

    def test_states_and_decisions(self):
        code, g = self.run_gate()
        st = {u["function"]: (u["state"], u["decision"]) for u in g["units"]}
        self.assertEqual(st["agree"], ("agree", "BLOCK"))
        self.assertEqual(st["sast_high"], ("sast_only", "BLOCK"))
        self.assertEqual(st["sast_audit"], ("sast_only", "REVIEW"))
        self.assertEqual(st["cb_only"], ("codebert_only", "REVIEW"))
        self.assertEqual(st["conflict"], ("conflict", "REVIEW"))
        self.assertEqual(st["clean"], ("pass", "PASS"))
        self.assertEqual(st["agree_audit"], ("agree", "REVIEW"))   # ci-2: audit khong tu chan build
        self.assertEqual(g["decision"], "BLOCK")
        self.assertEqual(code, C.EXIT_BLOCK)
        conflict = next(u for u in g["units"] if u["function"] == "conflict")
        self.assertEqual(conflict["sast_classes"], ["AUTHENTICATION_WEAKNESS"])   # ten v4.7.0 quy ve ten leader chot

    def test_snippet_lines(self):
        from aiws_ci.p4_compare_gate import snippet, _src_cache
        d = Path(tempfile.mkdtemp())
        (d / "a.py").write_text("\n".join(f"line{i}" for i in range(1, 31)) + "\n", encoding="utf-8")
        _src_cache.clear()
        s = snippet(d, "a.py", 10, 11)
        self.assertEqual((s["start"], s["end"]), (7, 14))              # +-3 dong quanh dong loi
        self.assertEqual(s["code"].splitlines()[3], "line10")
        self.assertEqual(snippet(d, "a.py", 2, 2)["start"], 1)          # khong vuot dau file
        s = snippet(d, "khong_co.py", 5, 6, ctx=0, unit_code="def f():\n  x\n", unit_start=5)
        self.assertEqual((s["start"], s["code"]), (5, "def f():\n  x"))  # lay tu p1-units khi khong doc duoc file

    def test_degraded_when_codebert_failed(self):
        code, g = self.run_gate(cb_status="failed")
        st = {u["function"]: u["state"] for u in g["units"]}
        self.assertEqual(st["cb_only"], "pass")
        self.assertEqual(st["sast_high"], "degraded_sast_only")
        self.assertEqual(code, C.EXIT_CONFIG)          # policy require_model -> FAILED


if __name__ == "__main__":
    unittest.main()
