"""ruleset.py - Quan ly bo rule Semgrep CE cua AI-WhiteSec-CI theo tieu chi cua nhom.

Lenh (chay tu thu muc main/):
  python security-config/semgrep/tools/ruleset.py check     # kiem tra metadata + do phu test (khong can Semgrep)
  python security-config/semgrep/tools/ruleset.py test      # chay Semgrep tren tests/positive va tests/negative
  python security-config/semgrep/tools/ruleset.py build     # tao semgrep.yml (bundle) + ruleset-manifest.json
  python security-config/semgrep/tools/ruleset.py all       # check -> bundle -> test -> manifest (dung truoc khi phat hanh)
  python security-config/semgrep/tools/ruleset.py verify    # dung trong CI truoc lan quet chinh thuc

Tieu chi "rule dat chuan" (xem README.md):
  1. Metadata day du: id, languages, severity, message, cwe, owasp, vuln_class, confidence,
     severity (muc do), scope (pham vi ap dung), rule_version, ruleset_version.
  2. Co it nhat 1 positive test (`ruleid: <id>`) va 1 negative test (`ok: <id>`).
  3. Positive: rule PHAI bao tren dong ngay sau chu thich. Negative: rule KHONG duoc bao tren dong do.
  4. Bundle semgrep.yml khop rules/ (khong lech), manifest ghi SHA-256 + phien ban Semgrep.
Ket qua ghi vao security-config/semgrep/reports/ (rule_test_report.md, rule_test_results.json).
"""
import argparse, datetime, hashlib, json, os, platform, re, shutil, subprocess, sys, tempfile
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parents[1]          # security-config/semgrep
MAIN = BASE.parents[1]                              # main/
RULES = BASE / "rules"
TESTS = BASE / "tests"
REPORTS = BASE / "reports"
BUNDLE = BASE / "semgrep.yml"
MANIFEST = BASE / "ruleset-manifest.json"
REGISTRY_SNAPSHOT = MAIN / "rules" / "registry_snapshot"

RULESET_VERSION = "4.2.0"
PINNED_SEMGREP = "1.181.0"
PINNED_BANDIT = "1.9.4"
LANG_EXT = {"python": ".py", "java": ".java", "javascript": ".js", "php": ".php"}
CLASSES = {"sql_injection": "SQL_INJECTION", "xss": "XSS", "os_command_injection": "OS_COMMAND_INJECTION",
           "path_traversal": "PATH_TRAVERSAL", "authentication_weakness": "AUTHENTICATION_WEAKNESS",
           "hardcoded_credentials": "HARDCODED_CREDENTIALS"}
REQUIRED_META = ("cwe", "owasp", "vuln_class", "confidence", "severity", "scope", "rule_version", "ruleset_version")
ANNOT = re.compile(r"(?:#|//)\s*(ruleid|ok)\s*:\s*([\w.\-, ]+)")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rule_files():
    return sorted(RULES.glob("*/*.yml"))


def load_rules():
    out = []
    for f in rule_files():
        for r in (yaml.safe_load(f.read_text(encoding="utf-8")) or {}).get("rules", []):
            out.append((f, r))
    return out


def annotations(path: Path):
    """[(kind, rule_id, target_line)] - target = dong code dau tien sau chu thich."""
    lines = path.read_text(encoding="utf-8").splitlines()
    res = []
    for i, line in enumerate(lines):
        m = ANNOT.search(line)
        if not m:
            continue
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or ANNOT.search(lines[j])):
            j += 1
        for rid in (x.strip() for x in m.group(2).split(",")):
            if rid:
                res.append((m.group(1), rid, j + 1))
    return res


def test_files():
    return sorted(p for p in TESTS.glob("*/*/*") if p.suffix in LANG_EXT.values())


# --------------------------------------------------------------------------- check
def cmd_check(_=None) -> dict:
    problems, seen = [], {}
    rules = load_rules()
    for f, r in rules:
        rid = r.get("id", "?")
        lang_dir, cls_file = f.parent.name, f.stem
        where = f"{f.relative_to(BASE)}::{rid}"
        if rid in seen:
            problems.append(f"{where}: id trung voi {seen[rid]}")
        seen[rid] = str(f.relative_to(BASE))
        for key in ("languages", "severity", "message"):
            if not r.get(key):
                problems.append(f"{where}: thieu '{key}'")
        md = r.get("metadata") or {}
        for key in REQUIRED_META:
            if not md.get(key):
                problems.append(f"{where}: thieu metadata.{key}")
        if md.get("confidence") not in ("high", "audit"):
            problems.append(f"{where}: confidence phai la high/audit")
        if md.get("severity") not in ("critical", "high", "medium", "low"):
            problems.append(f"{where}: metadata.severity khong hop le")
        if md.get("vuln_class") != CLASSES.get(cls_file):
            problems.append(f"{where}: vuln_class {md.get('vuln_class')} khong khop file {cls_file}.yml")
        langs = [str(x).lower() for x in r.get("languages", [])]
        # v4.2: rule regex/generic (cho file PHP template ma parser PHP khong doc duoc) hop le khi
        # paths.include gioi han dung duoi file cua thu muc ngon ngu, vd. languages: [regex] + include: ['*.php']
        includes = [str(x) for x in ((r.get("paths") or {}).get("include") or [])]
        text_rule = langs in (["regex"], ["generic"]) and includes and \
            all(x.endswith(LANG_EXT[lang_dir]) or x.endswith(".phtml") for x in includes)
        if lang_dir not in langs and not text_rule:
            problems.append(f"{where}: languages {r.get('languages')} khong gom thu muc {lang_dir}"
                            " (rule regex/generic can paths.include dung duoi file)")
        if str(md.get("ruleset_version")) != RULESET_VERSION:
            problems.append(f"{where}: ruleset_version {md.get('ruleset_version')} != {RULESET_VERSION}")
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(md.get("rule_version", ""))):
            problems.append(f"{where}: rule_version phai dang X.Y.Z")
    pos, neg = {}, {}
    for t in test_files():
        kind_dir = t.parts[-3]
        for kind, rid, line in annotations(t):
            if kind_dir == "positive" and kind == "ok":
                problems.append(f"{t.relative_to(BASE)}:{line}: positive test chi duoc dung 'ruleid:'")
            if kind_dir == "negative" and kind == "ruleid":
                problems.append(f"{t.relative_to(BASE)}:{line}: negative test chi duoc dung 'ok:'")
            (pos if kind == "ruleid" else neg).setdefault(rid, []).append(f"{t.relative_to(BASE)}:{line}")
            if rid not in seen:
                problems.append(f"{t.relative_to(BASE)}:{line}: chu thich rule khong ton tai '{rid}'")
    for rid in seen:
        if rid not in pos:
            problems.append(f"{rid}: chua co positive test")
        if rid not in neg:
            problems.append(f"{rid}: chua co negative test")
    for f in rule_files():
        lang, cls = f.parent.name, f.stem
        for kind in ("positive", "negative"):
            if not (TESTS / kind / lang / f"{cls}{LANG_EXT[lang]}").is_file():
                problems.append(f"thieu file tests/{kind}/{lang}/{cls}{LANG_EXT[lang]}")
    result = {"rules": len(rules), "problems": problems,
              "positive_cases": sum(len(v) for v in pos.values()),
              "negative_cases": sum(len(v) for v in neg.values())}
    print(f"[check] {len(rules)} rule, {result['positive_cases']} positive, "
          f"{result['negative_cases']} negative, {len(problems)} van de")
    for p in problems:
        print("   -", p)
    return result


# -------------------------------------------------------------------------- bundle
def bundle_text() -> str:
    rules = []
    for f in rule_files():
        rules.extend((yaml.safe_load(f.read_text(encoding="utf-8")) or {}).get("rules", []))
    head = (f"# AI-WhiteSec-CI Semgrep ruleset v{RULESET_VERSION} - FILE SINH TU DONG tu rules/, khong sua tay.\n"
            f"# Tao bang: python security-config/semgrep/tools/ruleset.py build\n")
    return head + yaml.safe_dump({"rules": rules}, allow_unicode=True, sort_keys=False, width=110)


def cmd_bundle(_=None):
    BUNDLE.write_text(bundle_text(), encoding="utf-8", newline="\n")
    print(f"[bundle] {BUNDLE.relative_to(MAIN)} sha256={sha256(BUNDLE)}")


# ---------------------------------------------------------------------------- test
def find_tool(name: str):
    exe = shutil.which(name)
    if exe:
        return exe
    for cand in (Path(sys.executable).parent / f"{name}.exe", Path(sys.executable).parent / name,
                 MAIN / ".venv" / "Scripts" / f"{name}.exe", MAIN / ".venv" / "bin" / name):
        if cand.is_file():
            return str(cand)
    return None


def tool_version(name: str):
    exe = find_tool(name)
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=120,
                             env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
        m = re.search(r"\d+\.\d+\.\d+", out.stdout + out.stderr)
        return m.group(0) if m else (out.stdout + out.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return f"loi: {e}"


def cmd_test(_=None) -> dict:
    semgrep = find_tool("semgrep")
    if not semgrep:
        print("[test] KHONG tim thay semgrep. Kich hoat .venv hoac cai semgrep==" + PINNED_SEMGREP)
        return {"error": "semgrep not found", "failures": ["semgrep not found"], "passed": 0}
    files = test_files()
    with tempfile.TemporaryDirectory(prefix="aiwhitesec_ruletest_") as tmp:
        tmp = Path(tmp)
        mapping = {}
        for t in files:   # chep ra thu muc tam de .semgrepignore/default ignore khong bo qua file test
            dst = tmp / t.parts[-3] / t.parts[-2] / t.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(t, dst)
            mapping[str(dst.resolve()).lower()] = t
        out_json = tmp / "result.json"
        cmd = [semgrep, "scan", "--metrics=off", "--disable-version-check", "--json", "--quiet",
               "--no-git-ignore", "--output", str(out_json), "--config", str(RULES)] + \
              [str(tmp / t.parts[-3] / t.parts[-2] / t.name) for t in files]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
        if not out_json.is_file():
            print("[test] Semgrep loi:\n" + proc.stdout[-3000:] + proc.stderr[-3000:])
            return {"error": "semgrep failed", "failures": ["semgrep failed: " + proc.stderr[-1500:]], "passed": 0}
        data = json.loads(out_json.read_text(encoding="utf-8"))
    hits = {}
    for item in data.get("results", []):
        src = mapping.get(str(Path(item["path"]).resolve()).lower())
        if src is None:
            continue
        rid = item["check_id"].split(".team.", 1)[-1]
        rid = "team." + rid if not rid.startswith("team.") else rid
        hits.setdefault((src, rid), set()).update(range(item["start"]["line"], item["end"]["line"] + 1))
    scanned = {mapping.get(str(Path(p).resolve()).lower()) for p in data.get("paths", {}).get("scanned", [])}
    failures, passed, rows = [], 0, []
    for t in files:
        if t not in scanned:
            failures.append(f"{t.relative_to(BASE)}: Semgrep khong quet file nay")
        for kind, rid, line in annotations(t):
            fired = line in hits.get((t, rid), set())
            ok = fired if kind == "ruleid" else not fired
            rows.append({"file": str(t.relative_to(BASE)).replace("\\", "/"), "line": line, "rule": rid,
                         "expect": "bao" if kind == "ruleid" else "khong bao", "pass": ok})
            if ok:
                passed += 1
            else:
                failures.append(f"{t.relative_to(BASE)}:{line} {rid}: "
                                + ("KHONG bao (positive that bai)" if kind == "ruleid" else "BAO NHAM (negative that bai)"))
    errors = [e.get("message", str(e))[:300] for e in data.get("errors", []) if e.get("level") != "warn"]
    failures += [f"Semgrep error: {e}" for e in errors]
    print(f"[test] {passed}/{len(rows)} truong hop dat, {len(failures)} loi")
    for f in failures:
        print("   -", f)
    return {"passed": passed, "total": len(rows), "failures": failures, "cases": rows,
            "semgrep_errors": errors}


# ------------------------------------------------------------------------ manifest
def git_commit():
    for d in (MAIN, MAIN.parent):
        try:
            out = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=20)
            if out.returncode == 0:
                return out.stdout.strip()
        except Exception:  # noqa: BLE001
            pass
    return None


def counts():
    by = {}
    for f, r in load_rules():
        md = r.get("metadata", {})
        key = f"{f.parent.name}/{f.stem}"
        by.setdefault(key, {"high": 0, "audit": 0})[md.get("confidence", "audit")] += 1
    return by


def write_manifest(check_res, test_res):
    semgrep_v, bandit_v = tool_version("semgrep"), tool_version("bandit")
    m = {
        "ruleset": "AI-WhiteSec-CI Semgrep CE ruleset",
        "ruleset_version": RULESET_VERSION,
        "ruleset_commit": git_commit() or "khong co git trong workspace - dien commit khi dua vao repo",
        "ruleset_sha256": sha256(BUNDLE),
        "semgrep_version": semgrep_v,
        "semgrep_version_pinned": PINNED_SEMGREP,
        "bandit_version": bandit_v,
        "bandit_version_pinned": PINNED_BANDIT,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "files": {str(f.relative_to(BASE)).replace("\\", "/"): sha256(f) for f in rule_files()},
        "tests": {str(t.relative_to(BASE)).replace("\\", "/"): sha256(t) for t in test_files()},
        "registry_snapshot": {p.name: sha256(p) for p in sorted(REGISTRY_SNAPSHOT.glob("*.yml"))},
        "rule_counts": counts(),
        "check_problems": len(check_res.get("problems", [])),
        "tests_passed": test_res.get("passed", 0),
        "tests_total": test_res.get("total", 0),
        "regression_passed": not check_res.get("problems") and not test_res.get("failures"),
    }
    MANIFEST.write_text(json.dumps(m, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"[manifest] {MANIFEST.relative_to(MAIN)} regression_passed={m['regression_passed']}")
    return m


def write_report(check_res, test_res, manifest):
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "rule_test_results.json").write_text(
        json.dumps({"check": check_res, "test": test_res, "manifest": manifest}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    lines = [f"# Ket qua kiem tra ruleset v{RULESET_VERSION}", "",
             f"- Thoi diem: {manifest.get('generated_at')}",
             f"- Semgrep: {manifest.get('semgrep_version')} (ghim {PINNED_SEMGREP}); Bandit: {manifest.get('bandit_version')}",
             f"- So rule: {check_res.get('rules')}; van de metadata/do phu: {len(check_res.get('problems', []))}",
             f"- Test: {test_res.get('passed', 0)}/{test_res.get('total', 0)} dat; loi: {len(test_res.get('failures', []))}",
             f"- ruleset_sha256: `{manifest.get('ruleset_sha256')}`",
             f"- **regression_passed: {manifest.get('regression_passed')}**", ""]
    if check_res.get("problems") or test_res.get("failures"):
        lines += ["## Loi can sua", ""] + [f"- {p}" for p in check_res.get("problems", []) + test_res.get("failures", [])] + [""]
    lines += ["## Chi tiet tung truong hop", "", "| File | Dong | Rule | Ky vong | Ket qua |", "|---|---:|---|---|---|"]
    for c in test_res.get("cases", []):
        lines.append(f"| {c['file']} | {c['line']} | `{c['rule']}` | {c['expect']} | {'dat' if c['pass'] else '**LOI**'} |")
    (REPORTS / "rule_test_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[report] {(REPORTS / 'rule_test_report.md').relative_to(MAIN)}")


def cmd_build(_=None):
    c = cmd_check()
    cmd_bundle()
    t = {"passed": 0, "total": 0, "failures": ["chua chay test (dung lenh all)"]}
    write_manifest(c, t)


def cmd_all(_=None):
    c = cmd_check()
    cmd_bundle()
    t = cmd_test()
    m = write_manifest(c, t)
    write_report(c, t, m)
    return 0 if m["regression_passed"] else 1


def cmd_verify(_=None):
    """Dung trong CI truoc lan quet chinh thuc: dung phien ban Semgrep, bundle khop manifest, regression da dat."""
    if not MANIFEST.is_file():
        print("[verify] thieu ruleset-manifest.json"); return 1
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    errs = []
    if sha256(BUNDLE) != m.get("ruleset_sha256"):
        errs.append("semgrep.yml khong khop ruleset_sha256 trong manifest")
    if bundle_text() != BUNDLE.read_text(encoding="utf-8"):
        errs.append("semgrep.yml lech voi rules/ (chay lai: ruleset.py all)")
    v = tool_version("semgrep")
    if v != m.get("semgrep_version_pinned"):
        errs.append(f"Semgrep {v} khac phien ban ghim {m.get('semgrep_version_pinned')}")
    if not m.get("regression_passed"):
        errs.append("regression test cua phien ban nay chua dat")
    print("[verify] " + ("DAT" if not errs else "KHONG DAT"))
    for e in errs:
        print("   -", e)
    return 1 if errs else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["check", "test", "build", "all", "verify"])
    a = ap.parse_args()
    fn = {"check": lambda: 1 if cmd_check()["problems"] else 0,
          "test": lambda: 1 if cmd_test().get("failures") else 0,
          "build": lambda: cmd_build() or 0, "all": cmd_all, "verify": cmd_verify}[a.command]
    sys.exit(fn())


if __name__ == "__main__":
    main()
