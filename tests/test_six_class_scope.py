"""Behavioral checks for six-class data preparation and SAST evaluation."""
import contextlib
import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
# Du lieu v2 Python cu (data/, PyVul/) co the da duoc don khoi workspace: bo qua test can no thay vi bao loi.
LEGACY_DATA = (ROOT / "data" / "train.csv").is_file() and (ROOT / "PyVul").is_dir()


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sast = load_script("sast", "03_run_sast.py")


def fixture_rows():
    return [
        {"id": str(i), "code": f"value = {i}\n", "cls_gt": cls,
         "programming_language": "Python"}
        for i, cls in enumerate(sast.CLASSES)
    ]


class SixClassScopeTests(unittest.TestCase):
    def test_safe_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.csv"
            sast.write_csv(path, [{**fixture_rows()[0], "cls_gt": "SAFE"}])
            with self.assertRaisesRegex(ValueError, "six vulnerability classes"):
                sast.read_python_test_rows(path)

    def test_duplicate_input_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.csv"
            sast.write_csv(path, [fixture_rows()[0], fixture_rows()[0]])
            with self.assertRaisesRegex(ValueError, "duplicate sample IDs"):
                sast.read_python_test_rows(path)

    def test_pass_assigns_no_class_and_is_scored_against_ground_truth(self):
        predictions, metrics = sast.evaluate(fixture_rows(), [], "SAST")
        self.assertEqual(len(predictions), 6)
        self.assertEqual({p["status"] for p in predictions}, {"PASS"})
        self.assertEqual({p["cls_sast"] for p in predictions}, {""})
        self.assertEqual({p["detected_classes"] for p in predictions}, {""})
        self.assertEqual([m["class"] for m in metrics], [*sast.CLASSES, "MACRO_6_VULN_CLASSES"])
        self.assertEqual([m["fn"] for m in metrics[:6]], [1] * 6)
        self.assertEqual(metrics[-1]["support"], 6)
        self.assertEqual(metrics[-1]["f1"], 0)

    def test_wrong_class_and_multiple_findings_are_counted(self):
        findings = [
            {"sample_file": "sample_000000.py", "classes": ["XSS"]},
            {"sample_file": "sample_000001.py", "classes": ["XSS", "SQL_INJECTION"]},
        ]
        predictions, metrics = sast.evaluate(fixture_rows(), findings, "SAST")
        by_class = {m["class"]: m for m in metrics}
        self.assertEqual(predictions[1]["cls_sast"], "MULTIPLE")
        self.assertEqual(predictions[1]["status"], "FINDING")
        self.assertEqual(by_class["SQL_INJECTION"]["fn"], 1)
        self.assertEqual(by_class["SQL_INJECTION"]["fp"], 1)
        self.assertEqual(by_class["XSS"]["tp"], 1)
        self.assertEqual(by_class["XSS"]["fp"], 1)

    def test_unmapped_finding_does_not_assign_a_class(self):
        predictions, metrics = sast.evaluate(
            fixture_rows(), [{"sample_file": "sample_000000.py", "classes": []}], "SAST"
        )
        self.assertTrue(predictions[0]["found_any"])
        self.assertEqual(predictions[0]["status"], "FINDING")
        self.assertEqual(predictions[0]["cls_sast"], "")
        self.assertEqual(metrics[0]["fn"], 1)

    def test_prediction_coverage_rejects_missing_extra_and_duplicate_ids(self):
        rows = fixture_rows()
        predictions, _ = sast.evaluate(rows, [], "SAST")
        cases = [predictions[:-1], predictions + [predictions[0]],
                 predictions + [{**predictions[0], "id": "unexpected"}]]
        for case in cases:
            with self.subTest(ids=[p["id"] for p in case]):
                with self.assertRaisesRegex(ValueError, "exactly once"):
                    sast.evaluate_types(rows, case)

    def test_codebert_predictions_require_same_ids_and_labels(self):
        rows = fixture_rows()
        records = [{"id": r["id"], "cls_gt": r["cls_gt"], "cls_codebert": r["cls_gt"]} for r in rows]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "predictions.csv"
            sast.write_csv(path, records)
            predictions, metrics = sast.load_codebert_predictions(path, rows)
            self.assertEqual({p["configuration"] for p in predictions}, {"CodeBERT_6class"})
            self.assertEqual(metrics[-1]["f1"], 1)
            for modified in (
                records[:-1],
                records + [records[0]],
                [{**records[0], "cls_gt": "XSS"}, *records[1:]],
                [{**records[0], "cls_codebert": "SAFE"}, *records[1:]],
            ):
                sast.write_csv(path, modified)
                with self.assertRaises(ValueError):
                    sast.load_codebert_predictions(path, rows)

    def test_runner_outputs_three_configurations_on_six_class_scope(self):
        rows = fixture_rows()
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            data_path = folder / "test.csv"
            codebert_path = folder / "codebert.csv"
            output = folder / "results"
            sast.write_csv(data_path, rows)
            sast.write_csv(codebert_path, [
                {"id": r["id"], "cls_gt": r["cls_gt"], "cls_codebert": r["cls_gt"]}
                for r in rows
            ])

            def fake_semgrep(executable, configs, samples, output_path):
                self.assertEqual(len(list(samples.glob("*.py"))), 6)
                return []

            argv = ["03_run_sast.py", "--input", str(data_path), "--output", str(output),
                    "--codebert-predictions", str(codebert_path)]
            with patch.object(sys, "argv", argv), \
                 patch.object(sast, "find_executable", return_value="test-tool"), \
                 patch.object(sast, "run_semgrep", side_effect=fake_semgrep), \
                 patch.object(sast, "run_bandit", return_value=[]), \
                 contextlib.redirect_stdout(io.StringIO()):
                sast.main()
            with (output / "sast_metrics.csv").open(encoding="utf-8-sig", newline="") as f:
                metrics = list(csv.DictReader(f))
            self.assertEqual(len(metrics), 28)
            self.assertEqual({m["configuration"] for m in metrics}, {
                "A_builtin_semgrep_bandit", "B_builtin_plus_custom_rules", "B_high_confidence", "CodeBERT_6class"
            })
            self.assertEqual({m["class"] for m in metrics}, {*sast.CLASSES, "MACRO_6_VULN_CLASSES"})
            scope = json.loads((output / "evaluation_scope.json").read_text(encoding="utf-8"))
            self.assertEqual(scope["test_samples"], 6)
            self.assertEqual(scope["languages"], ["Python"])


class MultiLanguageTests(unittest.TestCase):
    def rows(self):
        out = []
        for lang in sast.LANGUAGES:
            out += [{"id": f"{lang}-{i}", "code": "x = 1\n", "cls_gt": cls, "programming_language": lang}
                    for i, cls in enumerate(sast.CLASSES)]
        return out

    def test_parse_languages(self):
        self.assertEqual(sast.parse_languages(["python", "PHP"]), ("Python", "PHP"))
        self.assertEqual(sast.parse_languages(["all"]), sast.LANGUAGES)
        with self.assertRaises(ValueError):
            sast.parse_languages(["C++"])
        self.assertIn("p/php", sast.default_baseline(("PHP",)))
        self.assertIn("p/security-audit", sast.default_baseline(("PHP",)))

    def test_read_rows_filters_languages(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.csv"
            sast.write_csv(path, self.rows() + [{"id": "c", "code": "", "cls_gt": "XSS",
                                                 "programming_language": "C++"}])
            rows = sast.read_test_rows(path, ("Java", "PHP"))
        self.assertEqual({r["programming_language"] for r in rows}, {"Java", "PHP"})
        self.assertEqual(len(rows), 12)

    def test_metrics_per_language_and_overall(self):
        rows = self.rows()
        # moi ngon ngu chi Python co finding dung lop SQL_INJECTION
        findings = [{"sample_file": sast.sample_name(0, rows[0]), "classes": ["SQL_INJECTION"]}]
        predictions, metrics = sast.evaluate(rows, findings, "SAST")
        self.assertEqual({p["programming_language"] for p in predictions}, set(sast.LANGUAGES))
        self.assertEqual(sast.sample_name(6, rows[6]), "sample_000006.java")
        groups = {}
        for m in metrics:
            groups.setdefault(m["programming_language"], []).append(m["class"])
        self.assertEqual(set(groups), {*sast.LANGUAGES, "ALL"})
        self.assertEqual(groups["PHP"], [*sast.CLASSES, "MACRO_6_VULN_CLASSES"])
        self.assertEqual(groups["ALL"][-1], "MACRO_OVER_LANGUAGES")
        macro = {m["programming_language"]: m["f1"] for m in metrics if m["class"] == "MACRO_6_VULN_CLASSES"}
        self.assertAlmostEqual(macro["Python"], 1 / 6)
        self.assertEqual(macro["Java"], 0)
        over = [m for m in metrics if m["class"] == "MACRO_OVER_LANGUAGES"][0]
        self.assertAlmostEqual(over["f1"], (1 / 6) / 4)

    def test_fragment_wrapping_and_line_offsets(self):
        w = sast.wrap_fragment
        self.assertEqual(w("echo $_GET['a'];\n", "PHP"), ("<?php\necho $_GET['a'];\n", 1))
        self.assertEqual(w("<?php echo 1;", "PHP")[1], 0)
        text, off = w("public void run(String n) {\n  exec(n);\n}", "Java")
        self.assertTrue(text.startswith("class Wrapper {\n") and off == 1)
        self.assertEqual(w("public class A {\n  void f() {}\n}", "Java")[1], 0)
        self.assertEqual(w("  render(req, res) {\n    res.send(x);\n  }", "JavaScript")[1], 1)
        self.assertEqual(w("function f(x) {\n  return x;\n}", "JavaScript")[1], 0)
        self.assertEqual(w("if (x) {\n  y();\n}", "JavaScript")[1], 0)
        self.assertEqual(w("def f():\n    pass\n", "Python"), ("def f():\n    pass\n", 0))

    def test_wrapping_php_methods_and_brace_balance(self):
        w = sast.wrap_fragment
        text, off = w("    public function save($x) {\n        echo $x;\n    }\n", "PHP")
        self.assertTrue(text.startswith("<?php\nclass Wrapper {\n") and off == 2)
        self.assertEqual(sast.brace_balance('if (x) {\n  y("{");\n'), (0, 1))   # ngoac trong chuoi bo qua
        self.assertEqual(sast.brace_balance("  a();\n} else {\n  b();\n"), (1, 1))
        text, off = w("if (x) {\n  y();\n", "JavaScript")
        self.assertTrue(text.endswith("}\n") and off == 0)
        # Java: cau lenh rieng le -> them method; khoi co package/import -> khong boc lop
        text, off = w("    if (x) {\n      y();\n    }\n", "Java")
        self.assertTrue(text.startswith("class Wrapper {\nvoid wrapper() throws Exception {\n") and off == 2)
        self.assertEqual(w("package a;\nimport b.C;\n", "Java")[1], 0)

    def test_parse_errors_get_their_own_status(self):
        rows = [r for r in self.rows() if r["programming_language"] == "PHP"][:3]
        names = [sast.sample_name(i, r) for i, r in enumerate(rows)]
        with tempfile.TemporaryDirectory() as temp:
            sj = Path(temp) / "semgrep.json"
            sj.write_text(json.dumps({"errors": [
                {"path": f"x/{names[1]}", "type": ["PartialParsing", []], "level": "warn"},
                {"path": f"x/{names[2]}", "type": "Syntax error", "level": "warn"}]}), encoding="utf-8")
            parse = sast.parse_status([sj])
        preds, _ = sast.evaluate(rows, [], "SAST", parse)
        self.assertEqual([p["status"] for p in preds], ["PASS", "PARTIAL_PARSE", "PARSE_ERROR"])
        preds, _ = sast.evaluate(rows, [{"sample_file": names[2], "classes": ["XSS"]}], "SAST", parse)
        self.assertEqual(preds[2]["status"], "FINDING")      # co finding thi khong tinh la loi parse

    def test_confidence_tiers_and_bandit_filter(self):
        self.assertEqual(sast.finding_confidence({"confidence": "high"}), "high")
        self.assertEqual(sast.finding_confidence({"confidence": "HIGH"}), "high")   # registry metadata
        self.assertEqual(sast.finding_confidence({"confidence": "MEDIUM"}), "audit")
        self.assertEqual(sast.finding_confidence({}), "audit")
        self.assertEqual(sast.finding_confidence(None, "bandit", "HIGH", "HIGH"), "high")
        self.assertEqual(sast.finding_confidence(None, "bandit", "HIGH", "LOW"), "audit")
        report = {"errors": [], "results": [
            {"filename": "s.py", "test_id": "B404", "issue_cwe": {"id": 78}, "issue_text": "", "line_number": 1,
             "issue_severity": "LOW", "issue_confidence": "HIGH"},
            {"filename": "s.py", "test_id": "B105", "issue_cwe": {"id": 259}, "issue_text": "", "line_number": 3,
             "issue_severity": "LOW", "issue_confidence": "MEDIUM"},
            {"filename": "s.py", "test_id": "B501", "issue_cwe": {"id": 295}, "issue_text": "", "line_number": 4,
             "issue_severity": "HIGH", "issue_confidence": "HIGH"}]}
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "bandit.json"
            out.write_text(json.dumps(report), encoding="utf-8")
            with patch.object(sast, "run_command"):
                kept = sast.run_bandit("bandit", Path(temp), out)
                everything = sast.run_bandit("bandit", Path(temp), out, noise_filter=False)
        self.assertEqual([f["rule_id"] for f in kept], ["B404", "B105"])  # B501 ngoai 6 lop bi bo
        self.assertEqual(len(everything), 3)
        self.assertEqual([f["confidence"] for f in kept], ["audit", "audit"])  # B404 chi la goi y

    def test_macro_ignores_classes_absent_from_truth_and_predictions(self):
        rows = [{"id": "1", "cls_gt": "XSS"}, {"id": "2", "cls_gt": "XSS"}]
        preds = [{"id": "1", "detected_classes": "XSS"}, {"id": "2", "detected_classes": "SQL_INJECTION"}]
        macro = sast.evaluate_types(rows, preds)[-1]
        # lop dung: XSS (P=1, R=0.5, F1=2/3); SQL_INJECTION chi co FP (F1=0) -> trung binh 1/3
        self.assertAlmostEqual(macro["f1"], (2 / 3 + 0) / 2)

    def test_runner_without_python_skips_bandit(self):
        rows = [r for r in self.rows() if r["programming_language"] != "Python"]
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            data_path = folder / "test.csv"
            output = folder / "results"
            sast.write_csv(data_path, rows)
            seen = {}

            def fake_semgrep(executable, configs, samples, output_path):
                seen.setdefault("configs", configs)
                seen["suffixes"] = sorted({p.suffix for p in samples.iterdir()})
                return []

            argv = ["03_run_sast.py", "--input", str(data_path), "--output", str(output),
                    "--codebert-predictions", str(folder / "none.csv"), "--languages", "all"]
            with patch.object(sys, "argv", argv), \
                 patch.object(sast, "find_executable", return_value="test-tool"), \
                 patch.object(sast, "run_semgrep", side_effect=fake_semgrep), \
                 patch.object(sast, "run_bandit", side_effect=AssertionError("bandit must not run")), \
                 contextlib.redirect_stdout(io.StringIO()):
                sast.main()
            scope = json.loads((output / "evaluation_scope.json").read_text(encoding="utf-8"))
        self.assertEqual(seen["suffixes"], [".java", ".js", ".php"])
        self.assertIn("p/java", seen["configs"])
        self.assertNotIn("p/python", seen["configs"])
        self.assertEqual(scope["test_samples_by_language"], {"Python": 0, "Java": 6, "JavaScript": 6, "PHP": 6})
        self.assertTrue(scope["bandit"].startswith("skipped"))

    def test_no_bandit_flag_runs_semgrep_only(self):
        # Quyet dinh nhom 2026-10-21: luong SAST chinh chi Semgrep CE, ke ca voi Python
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            data_path = folder / "test.csv"
            output = folder / "results"
            sast.write_csv(data_path, self.rows())
            argv = ["03_run_sast.py", "--input", str(data_path), "--output", str(output),
                    "--codebert-predictions", str(folder / "none.csv"), "--languages", "all", "--no-bandit"]
            with patch.object(sys, "argv", argv), \
                 patch.object(sast, "find_executable", return_value="test-tool"), \
                 patch.object(sast, "run_semgrep", return_value=[]), \
                 patch.object(sast, "run_bandit", side_effect=AssertionError("bandit must not run")), \
                 contextlib.redirect_stdout(io.StringIO()):
                sast.main()
            scope = json.loads((output / "evaluation_scope.json").read_text(encoding="utf-8"))
        self.assertEqual(scope["test_samples_by_language"]["Python"], 6)
        self.assertTrue(scope["bandit"].startswith("disabled"))


class VulnMetadataTests(unittest.TestCase):
    sys.path.insert(0, str(ROOT))
    import vuln_metadata as vm

    def test_every_class_is_fully_mapped(self):
        cfg = self.vm.load()
        self.assertEqual(set(cfg["classes"]), set(sast.CLASSES))
        for cls, c in cfg["classes"].items():
            with self.subTest(cls=cls):
                self.assertIn(c["owasp"], cfg["owasp_categories"])
                self.assertIn(c["severity"], cfg["priority"]["severity_weights"])
                self.assertIn(c["cwe"], self.vm.class_cwes(cls))   # CWE chinh thuoc anh xa cua lop
                for lang in sast.LANGUAGES:
                    self.assertTrue(c["remediation"].get(lang), lang)
                self.assertTrue(c["remediation"]["references"])
                self.assertTrue(all(u.startswith("https://") for u in c["remediation"]["references"]))
        self.assertTrue(set(cfg["owasp_by_cwe"].values()) <= set(cfg["owasp_categories"]))

    def test_owasp_categories_follow_owasp_cwe_lists(self):
        expected = {"SQL_INJECTION": "A03:2021", "XSS": "A03:2021", "OS_COMMAND_INJECTION": "A03:2021",
                    "PATH_TRAVERSAL": "A01:2021", "AUTHENTICATION_WEAKNESS": "A07:2021",
                    "HARDCODED_CREDENTIALS": "A07:2021"}
        for cls, code in expected.items():
            self.assertEqual(self.vm.owasp_for(cls), code)
        # CWE-321 (hard-coded crypto key) nam trong A02 Cryptographic Failures
        self.assertEqual(self.vm.owasp_for("HARDCODED_CREDENTIALS", ["321"]), "A02:2021")
        # CWE cua lop khac khong duoc doi hang muc
        self.assertEqual(self.vm.owasp_for("XSS", ["321"]), "A03:2021")

    def test_priority_score(self):
        p = {c: 0.02 for c in sast.CLASSES}
        low = self.vm.priority("XSS", [], p)
        self.assertEqual(low["score"], round(100 * 0.6 * 0.5 * 0.02))
        self.assertEqual(low["level"], "P3")
        p_hi = {**p, "SQL_INJECTION": 0.9}
        top = self.vm.priority("SQL_INJECTION", ["SQL_INJECTION"], p_hi)
        self.assertTrue(top["components"]["agreement_bonus"])
        self.assertEqual(top["score"], 100)
        self.assertEqual(top["level"], "P1")
        # tang xac suat mo hinh khong lam giam diem; SAST dong y lam tang diem
        scores = [self.vm.priority("PATH_TRAVERSAL", [], {**p, "PATH_TRAVERSAL": x})["score"] for x in (0.1, 0.5, 0.9)]
        self.assertEqual(scores, sorted(scores))
        self.assertGreater(self.vm.priority("PATH_TRAVERSAL", ["PATH_TRAVERSAL"], p)["score"],
                           self.vm.priority("PATH_TRAVERSAL", [], p)["score"])
        for cls in sast.CLASSES:
            self.assertLessEqual(self.vm.priority(cls, [cls], {**p, cls: 1.0})["score"], 100)

    def test_enrich(self):
        self.assertIsNone(self.vm.enrich("", "Python"))
        e = self.vm.enrich("PATH_TRAVERSAL", "PHP", ["PATH_TRAVERSAL"], None, ["23"])
        self.assertEqual(e["cwe"], "CWE-23")
        self.assertTrue(e["owasp"].startswith("A01:2021"))
        self.assertIn("realpath", e["remediation"]["language_specific"])
        self.assertEqual(e["priority"]["components"]["p_model"], 0.0)


class CiScanTests(unittest.TestCase):
    scan = load_script("ci_scan", "scan.py")

    def git_repo(self, temp):
        import subprocess
        run = lambda *a: subprocess.run(["git", "-C", temp, *a], check=True, capture_output=True)
        run("init", "-q"); run("config", "user.email", "t@example.com"); run("config", "user.name", "t")
        p = Path(temp) / "m.py"
        p.write_text("X = 1\n\n\ndef a():\n    return 1\n\n\ndef b():\n    return 2\n", encoding="utf-8")
        run("add", "-A"); run("commit", "-qm", "1")
        p.write_text("X = 2\n\n\ndef a():\n    return 1\n\n\ndef b():\n    return 3\n", encoding="utf-8")
        (Path(temp) / "notes.txt").write_text("ignored", encoding="utf-8")
        run("add", "-A"); run("commit", "-qm", "2")

    def test_scan_sast_stream_is_semgrep_only_by_default(self):
        import argparse
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "m.py").write_text("def a():\n    return 1\n", encoding="utf-8")
            args = argparse.Namespace(rules=Path(temp) / "r.yml", baseline_config=["p.yml"])
            with patch.object(self.scan, "ruleset_check", return_value=(True, "")), \
                 patch.object(self.scan.sast, "find_executable", return_value="test-tool"), \
                 patch.object(self.scan.sast, "run_semgrep", return_value=[]) as sg, \
                 patch.object(self.scan.sast, "run_bandit", side_effect=AssertionError("bandit must not run")):
                self.assertEqual(self.scan.run_sast(temp, ["m.py"], None, {"m.py": "Python"}, args), [])
                self.assertEqual(sg.call_count, 1)
            self.assertEqual(self.scan.sast_tools(args), ["semgrep"])
            args.with_bandit = True
            self.assertEqual(self.scan.sast_tools(args), ["semgrep", "bandit"])

    def test_only_changed_functions_are_units(self):
        with tempfile.TemporaryDirectory() as temp:
            self.git_repo(temp)
            changed = self.scan.changed_lines(temp, "HEAD^", "HEAD")
            self.assertEqual(changed, {"m.py": {1, 9}})          # file khong phai ma nguon bi bo qua
            text = self.scan.file_text(temp, "m.py", "HEAD")
            lang, units = self.scan.units_for("m.py", text, changed["m.py"])
        self.assertEqual(lang, "Python")
        self.assertEqual([u["function"] for u in units], ["b", "<module>"])  # a() khong doi
        self.assertEqual(units[1]["module_lines"], [1])

    def test_java_js_php_changed_functions_are_units(self):
        """A03: Java/JS/PHP tach ham bang bo trich M02 (func_extract), khong con quet ca file."""
        java = ("import java.sql.*;\n\npublic class Dao {\n    public String a(String x) {\n        return x;\n    }\n\n"
                "    public String b(String id) throws SQLException {\n        String q = \"select \" + id;\n"
                "        return q;\n    }\n}\n")
        lang, units = self.scan.units_for("Dao.java", java, {9})
        self.assertEqual(lang, "Java")
        self.assertEqual([(u["function"], u["start"], u["end"]) for u in units], [("b", 8, 11)])
        self.assertIn("select", units[0]["code"])
        self.assertNotIn("return x", units[0]["code"])
        php = "<?php\n$debug = true;\nfunction q($id) {\n    return \"x\" . $id;\n}\nfunction r() {\n    return 1;\n}\n"
        lang, units = self.scan.units_for("q.php", php, {2, 4})   # dong 2 ngoai moi ham -> <module>
        self.assertEqual(lang, "PHP")
        self.assertEqual([u["function"] for u in units], ["q", "<module>"])
        self.assertEqual(units[1]["module_lines"], [2])
        js = "const f = (a) => {\n  return a;\n};\nfunction f2() {\n  return 2;\n}\n"
        self.assertEqual([u["function"] for u in self.scan.units_for("x.js", js, {5})[1]], ["f2"])
        # khong co ham nao -> ca file nhu truoc
        self.assertEqual([u["function"] for u in self.scan.units_for("c.js", "var k = 'abc';\n", {1})[1]], ["<file>"])

    def test_overloaded_java_methods_get_unique_names(self):
        java = ("class A {\n    void f(int x) {\n        x++;\n    }\n    void f(String s) {\n        s.trim();\n    }\n"
                "    void g() {\n        f(1);\n    }\n}\n")
        names = [u["function"] for u in self.scan.units_for("A.java", java, {3, 6, 9})[1]]
        self.assertEqual(names, ["f@L2", "f@L5", "g"])

    def test_target_eval_merges_function_units_for_file_level_gt(self):
        ev = load_script("eval_targets", "09_eval_targets.py")
        units = [{"file": "a.php", "function": "q"}, {"file": "a.php", "function": "<module>"},
                 {"file": "b.php", "function": "r"}]
        preds = {("a.php", "q"): {"SQL_INJECTION"}, ("a.php", "<module>"): set(), ("b.php", "r"): {"XSS"}}
        res = ev.score("m", preds, {("a.php", "<file>"): {"SQL_INJECTION"}}, units)
        self.assertEqual(res["recall"], 1.0)
        self.assertEqual((res["flagged_safe_functions"], res["safe_functions"]), (1, 1))  # b.php: mot file an toan

    def test_findings_assigned_and_sarif(self):
        units = [{"file": "m.py", "function": "b", "start": 8, "end": 9, "code": ""},
                 {"file": "m.py", "function": "<module>", "start": 1, "end": 9, "code": "", "module_lines": [1]}]
        fd = lambda line, cls: {"tool": "semgrep", "rule_id": "r", "cwes": [], "classes": [cls], "line": line,
                                "message": ""}
        self.scan.assign(units, [fd(9, "XSS"), fd(1, "HARDCODED_CREDENTIALS"), fd(5, "XSS")])
        self.assertEqual([len(u["findings"]) for u in units], [1, 1])   # dong 5 thuoc ham khong doi -> bo
        result = {"file": "m.py", "function": "b", "lines": [8, 9], "vuln_class": "XSS",
                  "findings": units[0]["findings"], "probabilities": None,
                  "metadata": self.scan.vm.enrich("XSS", "Python", ["XSS"], None, [])}
        doc = self.scan.sarif([result], {"XSS"})
        self.assertEqual(doc["version"], "2.1.0")
        res = doc["runs"][0]["results"][0]
        self.assertEqual(res["ruleId"], "XSS")
        self.assertEqual(res["locations"][0]["physicalLocation"]["region"]["startLine"], 9)
        self.assertIn(res["level"], {"error", "warning", "note"})
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "5.5")


class PreprocessTests(unittest.TestCase):
    sys.path.insert(0, str(ROOT))
    import code_preprocess as cp

    def test_strip_comments_per_language(self):
        s = self.cp.strip_comments
        py = 'def f(x):\n    """doc"""\n    # hint from fix\n    return "#not" + x  # tail\n'
        out = s(py, "Python")
        self.assertNotIn("hint from fix", out); self.assertNotIn("doc", out); self.assertNotIn("tail", out)
        self.assertIn('"#not"', out)
        js = 'const a = "http://x"; // c1\n/* block\n c2 */ f(a);\n'
        out = s(js, "JavaScript")
        self.assertIn('"http://x"', out); self.assertNotIn("c1", out); self.assertNotIn("c2", out)
        self.assertEqual(out.count("\n"), js.count("\n"))          # giu so dong
        self.assertNotIn("note", s("$a = 1; # note\n", "PHP"))
        self.assertIn("'#x'", s("$a = '#x';\n", "PHP"))

    def test_normalize_tag_and_hints(self):
        self.assertEqual(self.cp.normalize("    def f():\n\t\treturn 1   \n\n\n\n    x = 2\n"),
                         "def f():\n    return 1\n\nx = 2\n")
        cfg = self.cp.Preprocess(lang_tag=True, sast_hints=True)
        findings = [{"class": "SQL_INJECTION", "confidence": "high", "rule_id": "team.sql-injection", "start_line": 2}]
        out = self.cp.apply("def f(q):\n    cur.execute(q)\n", "Python", cfg, findings)
        self.assertTrue(out.startswith("<python> [SAST] SQL_INJECTION:high rules=sql-injection\n"))
        self.assertIn(self.cp.HINT_MARK + "     cur.execute(q)", out)
        dropped = self.cp.apply("x = 1\n", "Python", cfg, findings, drop_hint=True)
        self.assertIn("[SAST] none", dropped)
        self.assertEqual(self.cp.apply("x = 1\n", "Python", self.cp.Preprocess()), "x = 1\n")

    def test_chunks_overlap_and_cover(self):
        ch = self.cp.chunks(list(range(1000)), 512, -1, -2)
        self.assertTrue(all(len(c) <= 512 and c[0] == -1 and c[-1] == -2 for c in ch))
        covered = {t for c in ch for t in c[1:-1]}
        self.assertEqual(covered, set(range(1000)))
        self.assertEqual(len(self.cp.chunks(list(range(10)), 512, -1, -2)), 1)

    def test_prepare_default_identity_and_augment(self):
        cb = load_script("cb_prep", "02_train_codebert.py")
        df = cb.pd.DataFrame({"id": [1], "code": ["def f(path):\n    p = path\n    return open(p)\n"],
                              "programming_language": ["Python"], "cls_gt": ["PATH_TRAVERSAL"], "label": [3]})
        self.assertIs(cb.prepare(df, "train", cb.Preprocess()), df)
        aug = cb.prepare(df, "train", cb.Preprocess(augment=True), train=True)
        self.assertEqual(len(aug), 3)                       # goc + doi ten + dinh dang lai
        self.assertTrue((aug["label"] == 3).all())
        self.assertIn("v0", aug.iloc[1]["code"])


class PreparationTests(unittest.TestCase):
    def test_only_nonempty_prefix_functions_are_selected(self):
        prep = load_script("prep", "01_prepare_data.py")
        data = prep.pd.DataFrame({
            "code_before": ["vulnerable()", "", None],
            "code_after": ["patched()", "after_only()", "also_after_only()"],
            "commit": ["a", "b", "c"],
        })
        selected = prep.vulnerable_functions(data)
        self.assertEqual(selected["code"].tolist(), ["vulnerable()"])
        self.assertNotIn("code_after", selected.columns)

    @unittest.skipUnless(LEGACY_DATA, "thieu du lieu v2 cu (data/, PyVul/)")
    def test_rebuild_reproduces_committed_splits(self):
        prep = load_script("prep_rebuild", "01_prepare_data.py")
        prep.DATA_PATH = str(ROOT / prep.DATA_PATH)
        prep.CWE_MAP_JSON = str(ROOT / prep.CWE_MAP_JSON)
        prep.EXTRA_DATA = [str(ROOT / p) for p in prep.EXTRA_DATA]
        previous_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as temp:
            try:
                os.chdir(temp)
                with contextlib.redirect_stdout(io.StringIO()):
                    prep.main()
            finally:
                os.chdir(previous_cwd)
            for split in ("train", "val", "test"):
                with (ROOT / "data" / f"{split}.csv").open(encoding="utf-8-sig", newline="") as f:
                    expected = list(csv.DictReader(f))
                with (Path(temp) / "data" / f"{split}.csv").open(encoding="utf-8-sig", newline="") as f:
                    actual = list(csv.DictReader(f))
                self.assertEqual(actual, expected, split)
                self.assertLessEqual({r["cls_gt"] for r in actual}, set(sast.CLASSES))

    @unittest.skipUnless(LEGACY_DATA, "thieu du lieu v2 cu (data/, PyVul/)")
    def test_committed_splits_satisfy_constraints(self):
        prep = load_script("prep_check", "01_prepare_data.py")
        self.assertEqual(prep.check_splits(str(ROOT / "data")), [])

    def test_check_detects_leaks(self):
        prep = load_script("prep_leak", "01_prepare_data.py")
        base = {"cls_gt": "XSS", "group_id": "g", "programming_language": "Python"}
        code = "def f(x):\n    return render(x)\n"
        splits = {
            "train": [{**base, "id": 1, "commit": "a", "code": code, "group_id": "g1"}],
            "val": [{**base, "id": 2, "commit": "a", "code": "  " + code, "group_id": "g2"}],
            "test": [{**base, "id": 1, "commit": "c", "code": "pass", "cls_gt": "SAFE", "group_id": "g3"}],
        }
        with tempfile.TemporaryDirectory() as temp:
            for name, rows in splits.items():
                prep.pd.DataFrame(rows).to_csv(Path(temp) / f"{name}.csv", index=False)
            problems = " | ".join(prep.check_splits(temp))
        for expected in ("ID trung", "Nhan ngoai 6 lop", "commit xuat hien", "Code trung"):
            self.assertIn(expected, problems)

    def test_near_duplicates_share_a_group(self):
        prep = load_script("prep_groups", "01_prepare_data.py")
        a = "def add_extra(self, select, where):\n    q = 'SELECT ' + select\n    return q + where\n"
        data = prep.pd.DataFrame({
            "id": [0, 1, 2],
            "commit": ["c1", "c2", "c3"],
            "code": [a, a.replace("return q + where", "return  q+where  # x"), "def other():\n    pass\n"],
        })
        groups = prep.split_groups(data)
        self.assertEqual(groups[0], groups[1])
        self.assertNotEqual(groups[0], groups[2])


class PipelineTests(unittest.TestCase):
    pipe = load_script("pipeline", "05_pipeline.py")

    def probs(self, top, value=0.9):
        rest = (1 - value) / 5
        return {c: (value if c == top else rest) for c in sast.CLASSES}

    def test_pass_assigns_no_class_without_model(self):
        for rule in self.pipe.RULES:
            self.assertEqual(self.pipe.decide(False, [], None, rule, 0.0), ("PASS", ""))

    def test_rules_and_threshold(self):
        d = self.pipe.decide
        p = self.probs("XSS")
        self.assertEqual(d(True, ["SQL_INJECTION"], p, "model", 0.0), ("FINDING", "XSS"))
        self.assertEqual(d(True, ["SQL_INJECTION"], None, "sast_first", 0.0), ("FINDING", "SQL_INJECTION"))
        self.assertEqual(d(True, ["SQL_INJECTION", "PATH_TRAVERSAL"], p, "sast_first", 0.0), ("FINDING", "XSS"))
        self.assertEqual(d(True, ["SQL_INJECTION", "PATH_TRAVERSAL"], p, "restricted", 0.0)[0], "FINDING")
        self.assertIn(d(True, ["SQL_INJECTION", "PATH_TRAVERSAL"], p, "restricted", 0.0)[1],
                      {"SQL_INJECTION", "PATH_TRAVERSAL"})
        self.assertEqual(d(True, [], p, "restricted", 0.0), ("FINDING", "XSS"))  # finding ngoai 6 lop
        self.assertEqual(d(True, [], self.probs("XSS", 0.5), "model", 0.6), ("UNCERTAIN", ""))
        with self.assertRaises(ValueError):
            d(True, [], None, "model", 0.0)

    def test_offline_pipeline_scores_all_ids_and_ignores_ground_truth(self):
        rows = fixture_rows()
        sast_preds, _ = sast.evaluate(rows, [{"sample_file": "sample_000000.py", "classes": ["SQL_INJECTION"]},
                                             {"sample_file": "sample_000001.py", "classes": []}], "B_builtin_plus_custom_rules")
        with tempfile.TemporaryDirectory() as temp:
            sp, mp = Path(temp) / "sast.csv", Path(temp) / "model.csv"
            sast.write_csv(sp, sast_preds)
            # nhan that cua mo hinh khac -> pipeline khong duoc phu thuoc vao no
            sast.write_csv(mp, [{"id": r["id"], "cls_gt": "XSS",
                                 **{f"p_{c}": (0.9 if c == "XSS" else 0.02) for c in sast.CLASSES}} for r in rows])
            preds = self.pipe.offline_predictions(sp, mp, "sast_first", 0.0)
        self.assertEqual([p["status"] for p in preds], ["FINDING", "FINDING"] + ["PASS"] * 4)
        self.assertEqual([p["detected_classes"] for p in preds], ["SQL_INJECTION", "XSS", "", "", "", ""])
        self.assertEqual(sum(p["model_called"] for p in preds), 2)
        metrics = sast.evaluate_types(rows, preds)
        self.assertEqual(metrics[-1]["support"], 6)

    def test_code_units_and_finding_assignment(self):
        text = "import os\n\nclass A:\n    def run(self, c):\n        os.system(c)\n\ndef g():\n    return 1\n"
        units = self.pipe.code_units("x.py", text)
        self.assertEqual({u["function"] for u in units}, {"run", "g"})
        self.assertEqual(self.pipe.innermost(units, 5)["function"], "run")
        self.assertIsNone(self.pipe.innermost(units, 1))
        self.assertEqual(self.pipe.code_units("bad.py", "def (:\n")[0]["function"], "<module>")


class ParallelPipelineTests(unittest.TestCase):
    """K04-K07: hai luong SAST/CodeBERT song song, doc lap; Compare + Gate; che do suy giam."""
    scan = load_script("ci_scan_parallel", "scan.py")
    cg = scan.cg
    CLASSES = list(sast.CLASSES)
    CODE = "def f1(cur, q):\n    cur.execute(q)\n\n\ndef f2(x):\n    return x\n"

    class FakeClf:
        calls = []
        hints = False

        def __init__(self, path):
            import types
            self.cfg = types.SimpleNamespace(sast_hints=ParallelPipelineTests.FakeClf.hints)

        def probs(self, code, language="Python", findings=None):
            ParallelPipelineTests.FakeClf.calls.append(findings)
            top = "SQL_INJECTION" if ("execute" in code and "def f2" not in code) else "XSS"
            v = 0.9 if top == "SQL_INJECTION" else 0.3
            return {c: (v if c == top else (1 - v) / 5) for c in ParallelPipelineTests.CLASSES}

    def finding(self):
        return [{"file": "m.py", "sample_file": "sample_000000.py", "tool": "semgrep", "rule_id": "team.x",
                 "cwes": ["89"], "classes": ["SQL_INJECTION"], "line": 2, "message": "", "confidence": "high"}]

    def run_scan(self, temp, sast_fn, clf=None, gate_cfg=None):
        import argparse
        (Path(temp) / "m.py").write_text(self.CODE, encoding="utf-8")
        self.FakeClf.calls = []
        args = argparse.Namespace(repo=temp, files=["m.py"], commit="HEAD", base=None, head=None,
                                  json=str(Path(temp) / "r.json"), sarif=str(Path(temp) / "r.sarif"),
                                  baseline_config=None, rules=ROOT / "security-config" / "semgrep" / "semgrep.yml",
                                  fail_on="none", architecture="parallel", gate_exit=True)
        # cau hinh Gate co dinh trong test, khong phu thuoc models/gate_config.json that (verifier co the dang bat)
        with patch.object(self.scan, "run_sast", sast_fn), \
                patch.object(self.scan.cg, "load_config", lambda *a: gate_cfg or self.cg.DEFAULT_CONFIG), \
                patch.object(self.scan.pipe, "Classifier", clf or self.FakeClf), \
                patch.object(self.scan.pipe, "model_path", lambda cfg: "fake"), \
                patch.object(self.scan, "_cuda", lambda: False), \
                contextlib.redirect_stdout(io.StringIO()):
            code = self.scan.run(args)
        return code, json.loads((Path(temp) / "r.json").read_text(encoding="utf-8")), \
            json.loads((Path(temp) / "r.sarif").read_text(encoding="utf-8"))

    def test_compare_states_and_gate(self):
        p = lambda c, v: {k: (v if k == c else (1 - v) / 5) for k in self.CLASSES}
        f = lambda c, conf: [{"classes": [c], "confidence": conf, "cwes": [], "rule_id": "r", "line": 1}]
        cfg = self.cg.DEFAULT_CONFIG
        cases = [(f("XSS", "audit"), p("XSS", .9), "agree", "BLOCK"),
                 (f("XSS", "high"), p("XSS", .2), "sast_only", "BLOCK"),
                 (f("XSS", "audit"), p("XSS", .2), "sast_only", "REVIEW"),
                 ([], p("XSS", .9), "codebert_only", "REVIEW"),
                 (f("XSS", "high"), p("SQL_INJECTION", .9), "conflict", "REVIEW"),
                 ([], p("XSS", .2), "pass", "PASS")]
        for fs, pr, state, decision in cases:
            r = self.cg.evaluate_unit(fs, pr, self.CLASSES, cfg=cfg)
            self.assertEqual((r["state"], r["decision"]), (state, decision))
        self.assertEqual(self.cg.verdict(["PASS", "PASS"]), "PASS")
        self.assertEqual(self.cg.verdict(["PASS"], "degraded_sast_only"), "REVIEW")   # khong tu PASS
        self.assertEqual(self.cg.verdict(["REVIEW", "BLOCK"]), "BLOCK")

    def test_verifier_flags_ai_stream(self):
        """D04: co verifier -> luong AI bao theo p_vulnerable, khong theo xac suat lop cao nhat."""
        p = {k: (.9 if k == "XSS" else .02) for k in self.CLASSES}
        cfg = {**self.cg.DEFAULT_CONFIG, "verifier": {**self.cg.DEFAULT_CONFIG["verifier"], "enabled": True, "threshold": .6}}
        self.assertEqual(self.cg.evaluate_unit([], p, self.CLASSES, cfg=cfg, p_vulnerable=.3)["state"], "pass")
        r = self.cg.evaluate_unit([], p, self.CLASSES, cfg=cfg, p_vulnerable=.7)
        self.assertEqual((r["state"], r["vuln_class"], r["codebert"]["flag_source"]), ("codebert_only", "XSS", "verifier"))
        self.assertEqual(self.cg.evaluate_unit([], p, self.CLASSES, cfg=self.cg.DEFAULT_CONFIG,
                                               p_vulnerable=.1)["codebert"]["flag_source"], "max_class_prob")

    def test_scan_uses_verifier_and_survives_its_failure(self):
        cfg = {**self.cg.DEFAULT_CONFIG, "verifier": {**self.cg.DEFAULT_CONFIG["verifier"], "enabled": True,
                                                       "model": "fake", "threshold": .5}}
        fake = (lambda codes: [0.95 if "execute" in c and "def f2" not in c else 0.05 for c in codes]), "fake:verifier"
        with tempfile.TemporaryDirectory() as temp, patch.object(self.scan.cg, "load_config", lambda *a: cfg), \
                patch.object(self.scan, "load_verifier", lambda g: fake):
            _, rep, _ = self.run_scan(temp, lambda *a: [], gate_cfg=cfg)
        self.assertEqual(rep["a01_verification"], "fake:verifier")
        hit = [r for r in rep["results"] if r["function"] == "f1"]
        self.assertEqual((hit[0]["compare_state"], hit[0]["p_vulnerable"]), ("codebert_only", 0.95))

        def boom(g):
            raise OSError("khong co model")
        with tempfile.TemporaryDirectory() as temp, patch.object(self.scan.cg, "load_config", lambda *a: cfg), \
                patch.object(self.scan, "load_verifier", boom):
            _, rep, _ = self.run_scan(temp, lambda *a: self.finding(), gate_cfg=cfg)
        self.assertTrue(rep["a01_verification"].startswith("unavailable"))
        self.assertEqual(rep["mode"], "parallel")

    def test_parallel_streams_are_independent(self):
        with tempfile.TemporaryDirectory() as temp:
            code, rep, sar = self.run_scan(temp, lambda *a: self.finding())
        self.assertEqual(rep["architecture"], "parallel")
        self.assertEqual(rep["mode"], "parallel")
        self.assertEqual(len(self.FakeClf.calls), rep["summary"]["units"])   # CodeBERT goi cho MOI don vi, ke ca don vi SAST PASS
        self.assertGreaterEqual(rep["summary"]["units"], 2)
        self.assertTrue(all(c is None for c in self.FakeClf.calls))   # K07: khong truyen finding SAST vao model
        self.assertEqual(rep["summary"]["compare_states"]["agree"], 1)
        self.assertEqual(rep["summary"]["compare_states"]["pass"], rep["summary"]["units"] - 1)
        self.assertEqual(rep["verdict"], "BLOCK")
        self.assertEqual(code, 1)                                # --gate-exit
        self.assertEqual(sar["runs"][0]["results"][0]["properties"]["decision"], "BLOCK")
        self.assertEqual(sar["runs"][0]["properties"]["verdict"], "BLOCK")

    def test_degraded_codebert_only_when_sast_fails(self):
        def broken(*a):
            raise FileNotFoundError("'semgrep' is not installed")
        with tempfile.TemporaryDirectory() as temp:
            code, rep, _ = self.run_scan(temp, broken)
        self.assertEqual(rep["mode"], "degraded_codebert_only")
        self.assertIn("sast", rep["degraded_reason"])
        self.assertEqual(rep["verdict"], "REVIEW")
        self.assertEqual(code, 0)
        self.assertEqual(rep["results"][0]["compare_state"], "codebert_only")

    def test_degraded_sast_only_when_model_fails_or_uses_hints(self):
        class Broken:
            def __init__(self, path):
                raise OSError("model khong ton tai")
        for clf in (Broken, None):
            self.FakeClf.hints = clf is None          # model C04 (--sast-hints) bi tu choi
            with tempfile.TemporaryDirectory() as temp:
                code, rep, _ = self.run_scan(temp, lambda *a: self.finding(), clf=clf)
            self.FakeClf.hints = False
            self.assertEqual(rep["mode"], "degraded_sast_only")
            self.assertEqual(rep["results"][0]["decision"], "BLOCK")      # SAST high
            self.assertEqual(rep["summary"]["model_calls"], 0)

    def test_sast_results_do_not_depend_on_model(self):
        with tempfile.TemporaryDirectory() as temp:
            _, both, _ = self.run_scan(temp, lambda *a: self.finding())

        class Broken:
            def __init__(self, path):
                raise OSError("x")
        with tempfile.TemporaryDirectory() as temp:
            _, only, _ = self.run_scan(temp, lambda *a: self.finding(), clf=Broken)
        key = lambda rep: {(r["function"], tuple(r["sast_classes"])) for r in rep["results"] if r["sast_classes"]}
        self.assertEqual(key(both), key(only))


class PretrainVsFinetuneTests(unittest.TestCase):
    """29_pretrain_vs_finetune.py: cac phan khong can nap model."""
    pf = load_script("pretrain_vs_finetune", "29_pretrain_vs_finetune.py")

    def test_random_head_is_seeded_distribution(self):
        import numpy as np
        x = np.random.default_rng(0).normal(size=(5, 768)).astype("float32")
        p = self.pf.random_head_probs(x, 42)
        self.assertEqual(p.shape, (5, 6))
        np.testing.assert_allclose(p.sum(1), 1, rtol=1e-5)
        np.testing.assert_allclose(p, self.pf.random_head_probs(x, 42))
        self.assertFalse(np.allclose(p, self.pf.random_head_probs(x, 1)))

    def test_full_proba_maps_missing_classes_to_zero(self):
        import numpy as np

        class M:
            classes_ = np.array(["XSS", "SQL_INJECTION"])
            predict_proba = lambda self, X: np.array([[0.7, 0.3]] * X.shape[0])
        p = self.pf.full_proba(M(), np.zeros((2, 3)))
        self.assertEqual(p.shape, (2, 6))
        self.assertAlmostEqual(p[0, self.pf.LABELS.index("XSS")], 0.7)
        self.assertAlmostEqual(p[0, self.pf.LABELS.index("SQL_INJECTION")], 0.3)
        self.assertEqual(p[0, self.pf.LABELS.index("PATH_TRAVERSAL")], 0)

    def test_test_split_requires_final(self):
        with patch.object(sys, "argv", ["29", "--split", "test"]):
            with self.assertRaises(SystemExit) as cm:
                self.pf.main()
        self.assertIn("--final", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
