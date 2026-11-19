"""Kiem thu bo sung 19/11/2026 (khong can Semgrep, khong can model):
  python -m unittest tests.test_pipeline_checks_20261119 -v
- scan_repo.py: --expect-ruleset / --expect-manifest (ma 2 khi lech), --only-files, scope_signature,
  dem file ngon ngu chua ho tro (TypeScript...).
- P4: consistency_checks (P1 va Semgrep nhin cung tap file, do phu ngon ngu) chi canh bao, khong doi Gate.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "security-config" / "semgrep" / "tools" / "scan_repo.py"
MANIFEST = ROOT / "security-config" / "semgrep" / "ruleset-manifest.json"
sys.path.insert(0, str(ROOT / "ci"))
from aiws_ci.p4_compare_gate import consistency_checks  # noqa: E402


def load_scan_repo():
    spec = importlib.util.spec_from_file_location("scan_repo_t", SCAN)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def make_repo():
    d = Path(tempfile.mkdtemp())
    (d / "app").mkdir()
    (d / "app" / "a.py").write_text("def a(x):\n    return x\n", encoding="utf-8")
    (d / "app" / "b.js").write_text("function b(){ return 1 }\n", encoding="utf-8")
    (d / "web").mkdir()
    for i in range(3):
        (d / "web" / f"c{i}.ts").write_text("export const c = 1\n", encoding="utf-8")
    (d / "web" / "d.tsx").write_text("export default () => null\n", encoding="utf-8")
    return d


def run_scan(repo, out, *extra):
    raw = out.parent / "raw.json"
    raw.write_text(json.dumps({"version": "1.181.0", "results": [], "errors": [], "paths": {}}), encoding="utf-8")
    return subprocess.run([sys.executable, str(SCAN), "--raw-json", str(raw), "--repo", str(repo),
                           "--out", str(out), *extra], capture_output=True, text=True)


class TestScanRepo(unittest.TestCase):
    def setUp(self):
        self.repo = make_repo()
        self.out = Path(tempfile.mkdtemp()) / "r.json"
        self.ver = json.loads(MANIFEST.read_text(encoding="utf-8"))["ruleset_version"]

    def test_unsupported_and_signature(self):
        r = run_scan(self.repo, self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        res = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(res["summary"]["files_unsupported_language"], {"typescript": 4})
        self.assertEqual(sorted(f["path"] for f in res["files"]), ["app/a.py", "app/b.js"])
        sr = load_scan_repo()
        self.assertEqual(res["run"]["scope_signature"], sr.scope_signature(sr.load_ignore(sr.IGNORE_FILE)))
        self.assertEqual(res["run"]["targets"], "all_in_scope")

    def test_select_scope_old_signature_still_works(self):
        sr = load_scan_repo()
        files, _ = sr.select_scope(self.repo, [])          # P1 cu goi 2 tham so
        self.assertEqual(len(files), 2)

    def test_expect_ruleset(self):
        self.assertEqual(run_scan(self.repo, self.out, "--expect-ruleset", self.ver).returncode, 0)
        r = run_scan(self.repo, self.out, "--expect-ruleset", "0.0.0")
        self.assertEqual(r.returncode, 2)
        self.assertIn("AIWS_RULESET_VERSION", r.stderr)

    def test_expect_manifest(self):
        ok = run_scan(self.repo, self.out, "--expect-manifest", str(MANIFEST))
        self.assertEqual(ok.returncode, 0, ok.stderr)
        absent = run_scan(self.repo, self.out, "--expect-manifest", str(self.repo / "khong_co.json"))
        self.assertEqual(absent.returncode, 0)
        self.assertEqual(json.loads(self.out.read_text())["run"]["ruleset_check"]["repo_manifest"], "absent")
        m = json.loads(MANIFEST.read_text(encoding="utf-8"))
        m["ruleset_sha256"] = "0" * 64
        fake = self.out.parent / "m.json"
        fake.write_text(json.dumps(m), encoding="utf-8")
        bad = run_scan(self.repo, self.out, "--expect-manifest", str(fake))
        self.assertEqual(bad.returncode, 2)
        self.assertIn("chua build lai", bad.stderr)

    def test_only_files(self):
        p1 = self.out.parent / "p1-scope.json"
        p1.write_text(json.dumps({"target_files": ["app/b.js", "khong/ton_tai.py"]}), encoding="utf-8")
        r = run_scan(self.repo, self.out, "--only-files", str(p1))
        self.assertEqual(r.returncode, 0, r.stderr)
        res = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual([f["path"] for f in res["files"]], ["app/b.js"])
        self.assertEqual(res["run"]["targets"], "p1_target_files")
        self.assertEqual(res["run"]["files_in_scope_total"], 2)
        # file khong ton tai -> quet het (P1 loi khong lam mat Semgrep)
        r = run_scan(self.repo, self.out, "--only-files", str(self.out.parent / "khong_co.json"))
        self.assertEqual(len(json.loads(self.out.read_text())["files"]), 2)


class TestP4Consistency(unittest.TestCase):
    def scope(self, **kw):
        s = {"scope_signature": "abc", "files": [{"path": "a.py"}, {"path": "b.js"}], "target_files": ["a.py", "b.js"],
             "files_unsupported_language": {}}
        s.update(kw)
        return s

    def sem(self, sig="abc", files=("a.py", "b.js")):
        return {"run": {"scope_signature": sig}, "files": [{"path": p} for p in files], "findings": []}

    def test_all_consistent(self):
        c = consistency_checks(self.sem(), True, self.scope())
        self.assertTrue(c["scope_signature_match"])
        self.assertEqual(c["warnings"], [])

    def test_signature_mismatch(self):
        c = consistency_checks(self.sem(sig="xyz"), True, self.scope())
        self.assertFalse(c["scope_signature_match"])
        self.assertTrue(any("KHAC Semgrep" in w for w in c["warnings"]))

    def test_missing_and_extra_files(self):
        c = consistency_checks(self.sem(files=("a.py", "z.php")), True, self.scope())
        self.assertEqual(c["targets_missing_in_semgrep"], ["b.js"])
        self.assertEqual(c["semgrep_files_outside_p1"], ["z.php"])
        self.assertEqual(len(c["warnings"]), 2)

    def test_diff_mode_subset_is_fine(self):
        # che do diff + --only-files: Semgrep chi quet target_files -> khong canh bao
        c = consistency_checks(self.sem(files=("a.py",)), True, self.scope(target_files=["a.py"]))
        self.assertEqual(c["warnings"], [])

    def test_unsupported_language_warning(self):
        c = consistency_checks(self.sem(), True, self.scope(files_unsupported_language={"typescript": 340}))
        self.assertTrue(any("typescript 340" in w for w in c["warnings"]))

    def test_semgrep_failed(self):
        c = consistency_checks(None, False, self.scope())
        self.assertIsNone(c["scope_signature_match"])
        self.assertEqual(c["warnings"], [])


if __name__ == "__main__":
    unittest.main()
