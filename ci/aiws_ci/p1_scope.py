"""P1 - Authorized Source Snapshot -> pham vi quet + danh sach don vi (ham) cho CodeBERT va Gate.

  python -m aiws_ci.p1_scope --repo "$CI_PROJECT_DIR" --out-dir aiws-out

Pham vi file: GOI LAI scan_repo.select_scope() cua bo Semgrep (cung .semgrepignore, cung 4 ngon ngu, cung nguong
do dai dong) -> CodeBERT va Semgrep nhin dung mot tap file.
Che do (bien AIWS_SCAN_MODE do Pipeline 1 tinh):
  diff : chi cac ham chua dong bi them/sua giua AIWS_BASE_SHA va HEAD (push, merge request)
  full : moi ham trong pham vi (chay tay, Dashboard/API, lan push dau cua nhanh moi)
Dau ra: p1-scope.json (che do, base/head, file, dong bi sua, thong ke) va p1-units.jsonl (moi dong mot don vi).
Ma thoat: 0 = xong (ke ca khong co gi de quet), 2 = loi cau hinh.
"""
import argparse
import importlib.util
import os
import re
import subprocess
import time
from pathlib import Path

from . import common as C
from .units import file_units, treesitter_version

STEP = "P1-scope"
ZERO = "0" * 40


def load_scan_repo():
    p = C.SEMGREP_TOOLS / "scan_repo.py"
    if not p.is_file():
        C.die(STEP, f"khong thay {p} (AIWS_SEMGREP_TOOLS)", C.EXIT_CONFIG)
    spec = importlib.util.spec_from_file_location("scan_repo", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def git(repo: Path, *args, check=False):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[-300:]}")
    return r


def have_commit(repo, sha) -> bool:
    return git(repo, "cat-file", "-e", f"{sha}^{{commit}}").returncode == 0


def changed_lines(repo: Path, base: str):
    """{file: set(dong)} cua cac dong duoc them/sua tu base -> HEAD (bo file bi xoa)."""
    out = git(repo, "diff", "--unified=0", "--no-color", "--no-ext-diff", "-M", "--diff-filter=AMR",
              f"{base}", "HEAD", check=True).stdout
    res, cur = {}, None
    for line in out.splitlines():
        if line.startswith("+++ "):
            cur = None if line[4:].strip() == "/dev/null" else line[4:].strip()
            if cur and cur.startswith("b/"):
                cur = cur[2:]
            if cur:
                res.setdefault(cur, set())
        elif line.startswith("@@") and cur:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            s, n = int(m.group(1)), int(m.group(2) or 1)
            res[cur].update(range(s, s + n))
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, default=Path("aiws-out"))
    ap.add_argument("--mode", default=os.environ.get("AIWS_SCAN_MODE", "full"), choices=["diff", "full"])
    ap.add_argument("--base", default=os.environ.get("AIWS_BASE_SHA", ""))
    ap.add_argument("--backend", default=os.environ.get("AIWS_UNIT_BACKEND", "treesitter"),
                    choices=["treesitter", "lizard"])
    a = ap.parse_args()
    t0 = time.time()
    repo = a.repo.resolve()
    sr = load_scan_repo()
    pats = sr.load_ignore(sr.IGNORE_FILE)
    unsupported = {}
    try:
        files, excluded = sr.select_scope(repo, pats, unsupported)
    except TypeError:                     # scan_repo.py cu (truoc 19/11) chua nhan tham so unsupported
        files, excluded = sr.select_scope(repo, pats)
    # dau van tay cach chon pham vi -> P4 so voi semgrep-results.json (hai anh build tu hai commit khac nhau?)
    scope_sig = sr.scope_signature(pats) if hasattr(sr, "scope_signature") else None

    head = git(repo, "rev-parse", "HEAD").stdout.strip() or os.environ.get("CI_COMMIT_SHA", "")
    mode, base, note, changed = a.mode, a.base.strip(), "", None
    if mode == "diff":
        if not re.fullmatch(r"[0-9a-f]{40}", base or "") or base == ZERO:
            mode, note = "full", "khong co commit goc hop le (nhanh moi?) -> quet toan bo"
        else:
            if not have_commit(repo, base):
                git(repo, "fetch", "--no-tags", "--depth=50", "origin", base)
            if not have_commit(repo, base):
                mode, note = "full", f"khong lay duoc commit goc {base[:12]} -> quet toan bo"
            else:
                try:
                    changed = changed_lines(repo, base)
                except RuntimeError as e:
                    mode, note = "full", f"git diff loi ({e}) -> quet toan bo"

    in_scope = {f["path"]: f["language"] for f in files}
    targets = sorted(in_scope) if mode == "full" else sorted(p for p in changed if p in in_scope)
    units, parse_errors = [], []
    for path in targets:
        text = (repo / path).read_text(encoding="utf-8", errors="replace")
        us, err = file_units(path, text, in_scope[path], a.backend)
        if err:
            parse_errors.append(path)
        lines = changed.get(path) if changed is not None else None
        for u in us:
            u["in_diff"] = True if lines is None else any(u["start"] <= l <= u["end"] for l in lines)
            units.append(u)

    scored = [u for u in units if u["in_diff"] and u["scored"]]
    scope = {
        "schema": "aiws.p1.scope.v1", "created_at": C.now(),
        "repo": os.environ.get("CI_PROJECT_PATH") or repo.name, "head": head,
        "mode": mode, "requested_mode": a.mode, "base": base if mode == "diff" else None, "note": note,
        "unit_backend": a.backend, "unit_backend_version": treesitter_version() if a.backend == "treesitter" else "lizard",
        "scope_signature": scope_sig, "files_unsupported_language": dict(sorted(unsupported.items())),
        "files": files, "excluded": excluded, "target_files": targets,
        "changed_lines": {k: sorted(v) for k, v in (changed or {}).items() if k in in_scope},
        "parse_errors": parse_errors,
        "summary": {"files_in_scope": len(files), "target_files": len(targets), "units": len(units),
                    "units_in_diff": sum(u["in_diff"] for u in units), "units_to_codebert": len(scored),
                    "module_snippets": sum(u["unit"] == "module_snippet" for u in units),
                    "files_unsupported_language": sum(unsupported.values()),
                    "duration_s": round(time.time() - t0, 2)},
    }
    C.write_json(a.out_dir / "p1-scope.json", scope)
    C.write_jsonl(a.out_dir / "p1-units.jsonl", units)
    s = scope["summary"]
    C.log(STEP, f"che do {mode}{' (' + note + ')' if note else ''}; {s['files_in_scope']} file trong pham vi, "
                f"{s['target_files']} file can quet, {s['units']} don vi ({s['units_in_diff']} trong diff, "
                f"{s['units_to_codebert']} dua vao CodeBERT); loi parse {len(parse_errors)} file"
                + (f"; CANH BAO {s['files_unsupported_language']} file ngon ngu chua ho tro "
                   f"{dict(sorted(unsupported.items()))} KHONG duoc quet" if unsupported else ""))


if __name__ == "__main__":
    main()
