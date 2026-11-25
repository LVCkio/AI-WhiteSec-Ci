"""scan_repo.py - P2 Semgrep cho ha tang CI (docs/semgrep_tool.md muc 2.2, 2.3).

  python security-config/semgrep/tools/scan_repo.py --repo <thu muc repo> --out semgrep-results.json
  python security-config/semgrep/tools/scan_repo.py --repo . --out semgrep-results.json --scope-out scope.json

Cac buoc:
 1. Kiem tra cau hinh: Semgrep dung 1.181.0, bundle ton tai, `ruleset.py verify` DAT, taxonomy.yml doc duoc.
    Sai -> thoat ma 2 ("loi cau hinh va moi truong SAST"), KHONG quet.
 2. Chon file trong pham vi (dung chung voi phia CodeBERT): 4 ngon ngu theo duoi file, bo cac mau trong
    security-config/semgrep/.semgrepignore, bo file co do dai dong trung binh > 300 ky tu. Ghi scope.json neu can.
 3. Quet: chep cac file trong pham vi vao thu muc tam (co .semgrepignore rong de Semgrep khong tu loai them,
    vd. thu muc tests/), chay `semgrep scan --metrics=off --config <bundle> --json`.
 4. Trang thai parse tung file: ok | partial | failed | not_scanned. Loi parse KHONG dung quet.
 5. Hau xu ly: lop lay tu metadata.vuln_class, quy ve ten trong taxonomy (doc old_names); kiem CWE thuoc lop
    (lech -> ghi config_warnings; --strict thi thoat ma 2); bo finding ngoai 6 lop; gan tang high/audit;
    gop finding trung (cung rule, file, dong).
 6. Xuat semgrep-results.json (run / files / findings / config_warnings / summary).
Ma thoat: 0 = quet xong (co hay khong co finding; Gate quyet dinh sau), 2 = loi cau hinh, 3 = Semgrep loi khi quet.
--raw-json <file>: bo qua buoc 1 va 3, chi hau xu ly mot ket qua Semgrep co san (dung de kiem thu).

Bo sung 19/11/2026:
  --expect-ruleset <ver>   anh phai mang dung ruleset_version nay (bien AIWS_RULESET_VERSION cua job), lech -> ma 2.
  --expect-manifest <file> neu file ton tai (repo dang quet chinh la AI-WhiteSec-Ci): ruleset_version va
                           ruleset_sha256 cua anh phai khop manifest trong commit -> phat hien anh chua build lai
                           sau khi sua rule. File khong ton tai (repo khac) -> bo qua, ghi vao run.ruleset_check.
  --only-files <file>      chi quet cac file trong danh sach (p1-scope.json: target_files, hoac mang JSON duong dan),
                           giao voi pham vi da chon. Che do diff -> chi quet file bi sua. File khong ton tai -> quet het.
  run.scope_signature      sha256 cua cach chon pham vi (duoi file, .semgrepignore, nguong dong) -> P4 so voi P1.
  summary.files_unsupported_language  so file ma nguon ngon ngu chua ho tro (vd TypeScript) -> canh bao do phu.
Bo sung 22/11/2026: moi finding co tool_level (Critical / High / Medium / Low = metadata.severity x confidence, xem
  TOOL_LEVELS); summary.by_tool_level dem theo muc. Khong sua rule, khong doi SHA bo rule.
"""
import argparse, datetime, fnmatch, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
SEMGREP_DIR = TOOLS.parent
ROOT = SEMGREP_DIR.parent.parent
BUNDLE = SEMGREP_DIR / "semgrep.yml"
MANIFEST = SEMGREP_DIR / "ruleset-manifest.json"
IGNORE_FILE = SEMGREP_DIR / ".semgrepignore"
TAXONOMY = ROOT / "docs" / "taxonomy.yml"
REQUIRED_SEMGREP = "1.181.0"
EXT_LANG = {".py": "python", ".java": "java", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
            ".cjs": "javascript", ".php": "php"}
MAX_AVG_LINE = 300          # phia CodeBERT loai file co dong trung binh > 300 ky tu
# Ma nguon ngon ngu CHUA ho tro (khong co rule, model khong train): chi dem de canh bao do phu, khong quet.
UNSUPPORTED_EXT = {".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
                   ".vue": "vue", ".svelte": "svelte", ".kt": "kotlin", ".go": "go", ".rb": "ruby",
                   ".cs": "csharp", ".phtml": "php_template", ".c": "c", ".cpp": "cpp", ".rs": "rust"}
# Muc TOOL (Semgrep) - huong nhom thong nhat 22/11/2026 (cau 6): 4 muc Critical / High / Medium / Low ghep tu
#   metadata.severity cua rule (muc nghiem trong cua LOAI lo hong, gan khi viet rule: critical / high / medium; thieu ->
#   default_severity cua lop trong docs/taxonomy.yml) x metadata.confidence (high / audit).
#   confidence high : giu nguyen muc (critical -> Critical, high -> High, medium -> Medium, low -> Low)
#   confidence audit: critical / high -> Medium; medium / low -> Low   (rule audit KHONG BAO GIO len Critical / High)
#   Khong dung severity cap rule (ERROR / WARNING / INFO): o bo rule nhom, no chi la ban sao cua confidence.
#   Chi de BAO CAO / hien thi: quyet dinh Gate 3x3 van dung truc Semgrep High / Audit (confidence) trong gate-policy.json.
TOOL_LEVELS = ["Critical", "High", "Medium", "Low"]
_TOOL_IMPACT = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def tool_level(impact, confidence) -> str:
    base = _TOOL_IMPACT.get(str(impact or "").strip().lower(), "Medium")
    if str(confidence or "").strip().lower() == "high":
        return base
    return "Medium" if base in ("Critical", "High") else "Low"


CWE_RE = re.compile(r"CWE-?0*(\d+)", re.I)


class ConfigError(Exception):
    pass


# ---------------------------------------------------------------- cau hinh
def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def find_semgrep() -> str:
    exe = shutil.which("semgrep")
    if exe:
        return exe
    cand = Path(sys.executable).resolve().parent / ("semgrep.exe" if os.name == "nt" else "semgrep")
    if cand.is_file():
        return str(cand)
    raise ConfigError("khong tim thay semgrep")


def run(cmd, **kw):
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, **kw)


def check_config(exe: str, skip_verify: bool) -> str:
    out = run([exe, "--version"])
    lines = [l.strip() for l in (out.stdout or "").splitlines() if l.strip()]
    ver = lines[-1] if lines else ""
    if ver != REQUIRED_SEMGREP:
        raise ConfigError(f"Semgrep {ver or '?'} khac {REQUIRED_SEMGREP}")
    if not BUNDLE.is_file() or not MANIFEST.is_file():
        raise ConfigError("thieu semgrep.yml hoac ruleset-manifest.json")
    if not skip_verify:
        v = run([sys.executable, str(TOOLS / "ruleset.py"), "verify"])
        if v.returncode != 0:
            raise ConfigError("ruleset.py verify KHONG DAT:\n" + (v.stdout + v.stderr).strip())
    return ver


def check_expected_ruleset(expect_ver: str, expect_manifest):
    """Anh dong goi rule rieng (khong doc rule trong repo dang quet). Kiem anh dung ban rule mong doi."""
    m = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.is_file() else {}
    have_ver, have_sha = m.get("ruleset_version", ""), m.get("ruleset_sha256", "")
    res = {"image_ruleset_version": have_ver, "expected_version": expect_ver or None, "repo_manifest": None}
    if expect_ver and expect_ver != have_ver:
        raise ConfigError(f"anh mang ruleset {have_ver or '?'} nhung job yeu cau {expect_ver} "
                          f"(AIWS_RULESET_VERSION) -> build lai anh hoac sua bien")
    if expect_manifest:
        if expect_manifest.is_file():
            rm = json.loads(expect_manifest.read_text(encoding="utf-8"))
            res["repo_manifest"] = {"ruleset_version": rm.get("ruleset_version"),
                                    "ruleset_sha256": rm.get("ruleset_sha256")}
            if (rm.get("ruleset_version"), rm.get("ruleset_sha256")) != (have_ver, have_sha):
                raise ConfigError(f"anh mang ruleset {have_ver} ({have_sha[:12]}) KHAC manifest trong commit "
                                  f"{rm.get('ruleset_version')} ({str(rm.get('ruleset_sha256'))[:12]}) -> rule da sua "
                                  f"nhung anh chua build lai (server3_worker.sh)")
        else:
            res["repo_manifest"] = "absent"
    return res


def load_taxonomy():
    import yaml
    if not TAXONOMY.is_file():
        raise ConfigError(f"thieu {TAXONOMY}")
    t = yaml.safe_load(TAXONOMY.read_text(encoding="utf-8"))
    classes, alias = {}, {}
    for name, c in (t.get("classes") or {}).items():
        allowed = {str(x) for x in (c.get("cwe") or [])} | {str(x) for x in (c.get("cwe_by_rule_metadata") or [])}
        classes[name] = {"cwes": allowed, "default_severity": c.get("default_severity", "")}
        alias[name] = name
        for old in c.get("old_names") or []:
            alias[old] = name
    if len(classes) != 6:
        raise ConfigError(f"taxonomy co {len(classes)} lop, can 6")
    return str(t.get("schema_version", "")), classes, alias


# ---------------------------------------------------------------- pham vi
def load_ignore(path: Path):
    pats = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                pats.append(line)
    return pats


def ignored(rel: str, pats) -> str:
    parts = rel.split("/")
    for p in pats:
        if p.endswith("/"):
            d = p.rstrip("/")
            if "/" in d:                       # duong dan tu goc repo
                if rel.startswith(d + "/"):
                    return p
            elif d in parts[:-1]:
                return p
        elif fnmatch.fnmatch(parts[-1], p) or fnmatch.fnmatch(rel, p):
            return p
    return ""


def avg_line_len(p: Path) -> float:
    data = p.read_bytes()
    n = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
    return len(data) / max(n, 1)


def scope_signature(pats) -> str:
    """Dau van tay cua CACH chon pham vi. P1 (anh aiws-codebert) va P2 (anh aiws-semgrep) phai ra cung gia tri,
    neu khong hai ben nhin hai tap file khac nhau (anh build tu hai commit khac nhau)."""
    blob = json.dumps({"ext_lang": EXT_LANG, "max_avg_line": MAX_AVG_LINE, "excludes": list(pats)},
                      sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def load_only_files(p: Path):
    """Danh sach file can quet tu P1: p1-scope.json (target_files) hoac mang JSON. None = quet het."""
    if p is None or not p.is_file():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    lst = d.get("target_files") if isinstance(d, dict) else d
    if not isinstance(lst, list):
        raise ConfigError(f"{p}: khong co danh sach target_files")
    return {norm_path(str(x)) for x in lst}


def select_scope(repo: Path, pats, unsupported=None):
    """unsupported: dict tuy chon, duoc dem {ngon ngu: so file} cho file ngon ngu chua ho tro (khong bi ignore)."""
    files, excluded = [], []
    for dirpath, dirnames, filenames in os.walk(repo):
        reld = Path(dirpath).relative_to(repo).as_posix()
        reld = "" if reld == "." else reld
        keep = []
        for d in dirnames:
            r = f"{reld}/{d}" if reld else d
            why = ignored(r + "/x", pats)
            if why:
                excluded.append({"path": r + "/", "reason": f"ignore:{why}"})
            else:
                keep.append(d)
        dirnames[:] = sorted(keep)
        for f in sorted(filenames):
            rel = f"{reld}/{f}" if reld else f
            lang = EXT_LANG.get(Path(f).suffix.lower())
            if not lang:
                ul = UNSUPPORTED_EXT.get(Path(f).suffix.lower())
                if ul and unsupported is not None and not ignored(rel, pats):
                    unsupported[ul] = unsupported.get(ul, 0) + 1
                continue
            why = ignored(rel, pats)
            if why:
                excluded.append({"path": rel, "reason": f"ignore:{why}"}); continue
            al = avg_line_len(repo / rel)
            if al > MAX_AVG_LINE:
                excluded.append({"path": rel, "reason": f"avg_line_len>{MAX_AVG_LINE} ({al:.0f})"}); continue
            files.append({"path": rel, "language": lang})
    return files, excluded


# ---------------------------------------------------------------- quet + hau xu ly
def scan(exe: str, repo: Path, files, raw_out: Path):
    with tempfile.TemporaryDirectory(prefix="aiws_semgrep_") as tmp:
        root = Path(tmp) / "src"
        for f in files:
            dst = root / f["path"]
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repo / f["path"], dst)
        root.mkdir(exist_ok=True)
        (root / ".semgrepignore").write_text("# pham vi da chon truoc boi scan_repo.py\n", encoding="utf-8")
        cmd = [exe, "scan", "--metrics=off", "--disable-version-check", "--config", str(BUNDLE),
               "--json", "--output", str(raw_out), "."]
        r = run(cmd, cwd=root)
        if r.returncode not in (0, 1) or not raw_out.is_file():
            raise RuntimeError(f"semgrep loi (ma {r.returncode}): {(r.stderr or r.stdout)[-2000:]}")
    return " ".join(cmd[:-1] + ["<pham vi>"])


def norm_path(p: str) -> str:
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def parse_status(raw, files):
    status = {f["path"]: "ok" for f in files}
    scanned = raw.get("paths", {}).get("scanned")
    if scanned is not None:
        sc = {norm_path(x) for x in scanned}
        for f in files:
            if f["path"] not in sc:
                status[f["path"]] = "not_scanned"
    errors = []
    for e in raw.get("errors", []):
        path = norm_path(e.get("path") or "")
        kind = e.get("type")
        kind = kind[0] if isinstance(kind, list) else str(kind)
        errors.append({"path": path, "type": kind, "level": e.get("level", "")})
        if path in status:
            new = "partial" if kind == "PartialParsing" else "failed"
            if status[path] != "failed":
                status[path] = new
    return status, errors


def post_process(raw, files, classes, alias, strict: bool):
    lang = {f["path"]: f["language"] for f in files}
    findings, seen, warnings, dropped = [], set(), {}, 0
    for item in raw.get("results", []):
        extra = item.get("extra", {})
        md = extra.get("metadata", {}) or {}
        rid = item.get("check_id", "")
        i = rid.find("team.")
        rid = rid[i:] if i >= 0 else rid
        cls = alias.get(str(md.get("vuln_class", "")))
        if cls is None:
            dropped += 1
            continue
        cwes = sorted({m.group(1) for c in (md.get("cwe") if isinstance(md.get("cwe"), list) else [md.get("cwe")])
                       for m in CWE_RE.finditer(str(c or ""))})
        bad = [c for c in cwes if c not in classes[cls]["cwes"]]
        if bad:
            warnings.setdefault(rid, {"rule_id": rid, "class": cls, "cwes_not_in_taxonomy": [f"CWE-{c}" for c in bad]})
        path = norm_path(item.get("path", ""))
        start = item.get("start", {}).get("line")
        key = (rid, path, start)
        if key in seen:
            continue
        seen.add(key)
        conf = "high" if str(md.get("confidence", "")).lower() == "high" else "audit"
        findings.append({
            "file": path, "language": lang.get(path, ""), "rule_id": rid, "class": cls,
            "cwes": [f"CWE-{c}" for c in cwes], "confidence": conf,
            "semgrep_severity": extra.get("severity", ""),
            "impact_severity": md.get("severity") or classes[cls]["default_severity"],
            "tool_level": tool_level(md.get("severity") or classes[cls]["default_severity"], conf),
            "start_line": start, "end_line": item.get("end", {}).get("line"),
            "message": (extra.get("message") or "").strip(),
            "rule_version": md.get("rule_version", ""),
        })
    findings.sort(key=lambda f: (f["file"], f["start_line"] or 0, f["rule_id"]))
    if strict and warnings:
        raise ConfigError("CWE lech taxonomy: " + ", ".join(sorted(warnings)))
    return findings, list(warnings.values()), dropped


def git_commit(repo: Path) -> str:
    try:
        r = run(["git", "-C", str(repo), "rev-parse", "HEAD"])
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except OSError:
        pass
    return os.environ.get("CI_COMMIT_SHA", "")   # GitLab CI (anh Docker khong co git)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("semgrep-results.json"))
    ap.add_argument("--scope-out", type=Path, help="ghi danh sach file trong/ngoai pham vi (dung chung voi CodeBERT)")
    ap.add_argument("--ignore-file", type=Path, default=IGNORE_FILE)
    ap.add_argument("--repo-name", default="")
    ap.add_argument("--strict", action="store_true", help="CWE lech taxonomy -> loi cau hinh (ma 2)")
    ap.add_argument("--skip-verify", action="store_true", help="chi de kiem thu; CI KHONG dung")
    ap.add_argument("--raw-json", type=Path, help="hau xu ly ket qua Semgrep co san, khong chay Semgrep")
    ap.add_argument("--expect-ruleset", default="", help="ruleset_version bat buoc cua anh (lech -> ma 2)")
    ap.add_argument("--expect-manifest", type=Path, help="manifest trong repo dang quet; co file thi phai khop anh")
    ap.add_argument("--only-files", type=Path, help="p1-scope.json (target_files) hoac mang JSON: chi quet cac file nay")
    a = ap.parse_args()
    repo = a.repo.resolve()
    if not repo.is_dir():
        print(f"[scan_repo] khong co thu muc {repo}", file=sys.stderr); sys.exit(2)
    try:
        tax_ver, classes, alias = load_taxonomy()
        ver = "" if a.raw_json else check_config(find_semgrep(), a.skip_verify)
        ruleset_check = check_expected_ruleset(a.expect_ruleset, a.expect_manifest)
        only = load_only_files(a.only_files)
    except ConfigError as e:
        print(f"[scan_repo] LOI CAU HINH VA MOI TRUONG SAST: {e}", file=sys.stderr); sys.exit(2)
    pats = load_ignore(a.ignore_file)
    unsupported = {}
    files, excluded = select_scope(repo, pats, unsupported)
    files_total = len(files)
    if only is not None:
        files = [f for f in files if f["path"] in only]
    started = datetime.datetime.now().astimezone()
    if a.raw_json:
        raw, command = json.loads(a.raw_json.read_text(encoding="utf-8")), f"(hau xu ly {a.raw_json.name})"
        ver = raw.get("version", "")
    else:
        with tempfile.TemporaryDirectory(prefix="aiws_raw_") as t:
            rawp = Path(t) / "semgrep.json"
            try:
                command = scan(find_semgrep(), repo, files, rawp)
            except RuntimeError as e:
                print(f"[scan_repo] {e}", file=sys.stderr); sys.exit(3)
            raw = json.loads(rawp.read_text(encoding="utf-8"))
    fatal = [e for e in raw.get("errors", []) if e.get("level") not in ("warn", "warning") and not e.get("path")]
    if fatal:
        print(f"[scan_repo] Semgrep bao loi khong gan voi file: {fatal[:3]}", file=sys.stderr); sys.exit(3)
    status, errors = parse_status(raw, files)
    try:
        findings, warnings, dropped = post_process(raw, files, classes, alias, a.strict)
    except ConfigError as e:
        print(f"[scan_repo] LOI CAU HINH VA MOI TRUONG SAST: {e}", file=sys.stderr); sys.exit(2)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    count = lambda pred: sum(1 for f in findings if pred(f))
    st = {s: sum(1 for v in status.values() if v == s) for s in ("ok", "partial", "failed", "not_scanned")}
    result = {
        "run": {
            "semgrep_version": ver, "ruleset_version": manifest.get("ruleset_version", ""),
            "bundle_sha256": sha256_file(BUNDLE), "taxonomy_version": tax_ver,
            "repo": a.repo_name or repo.name, "commit": git_commit(repo),
            "scanned_at": started.isoformat(timespec="seconds"),
            "duration_s": round((datetime.datetime.now().astimezone() - started).total_seconds(), 1),
            "excludes": pats, "max_avg_line_len": MAX_AVG_LINE, "command": command,
            "scope_signature": scope_signature(pats), "ruleset_check": ruleset_check,
            "tool_level_rule": "metadata.severity x confidence (nhom chot 22/11/2026)",
            "targets": "p1_target_files" if only is not None else "all_in_scope",
            "files_in_scope_total": files_total,
        },
        "files": [{**f, "parse_status": status[f["path"]]} for f in files],
        "findings": findings,
        "config_warnings": warnings,
        "summary": {
            "files_in_scope": len(files), "files_excluded": len(excluded), "parse_status": st,
            "findings": len(findings), "findings_high": count(lambda f: f["confidence"] == "high"),
            "findings_audit": count(lambda f: f["confidence"] == "audit"),
            "by_class": {c: count(lambda f, c=c: f["class"] == c) for c in classes},
            "dropped_out_of_scope_classes": dropped, "scan_errors": len(errors),
            "files_unsupported_language": dict(sorted(unsupported.items())),
            "by_tool_level": {lv: count(lambda f, lv=lv: f.get("tool_level") == lv) for lv in TOOL_LEVELS},
        },
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.scope_out:
        a.scope_out.write_text(json.dumps({"repo": result["run"]["repo"], "commit": result["run"]["commit"],
                                           "files": files, "excluded": excluded}, ensure_ascii=False, indent=2),
                               encoding="utf-8")
    s = result["summary"]
    print(f"[scan_repo] {s['files_in_scope']} file trong pham vi (loai {s['files_excluded']}); parse {st}; "
          f"{s['findings']} finding (high {s['findings_high']}, audit {s['findings_audit']}); "
          f"canh bao cau hinh {len(warnings)} -> {a.out}")


if __name__ == "__main__":
    main()
