"""P0 - Cap quyen cho lan quet: xac nhan ma nguon dung commit duoc giao va model dung phien ban da duyet.

  python -m aiws_ci.p0_authorize --repo "$CI_PROJECT_DIR" --out-dir aiws-out

1. Ma nguon (Authorized Source Snapshot): HEAD phai dung commit Pipeline 1 giao (AIWS_EXPECTED_SHA, mac dinh
   CI_COMMIT_SHA) va cay thu muc sach. Sai -> ma 2, KHONG quet.
2. Model (phan phoi tu Model Artifact Storage): doc model-lock.json (ten run + SHA-256 tung file da duyet),
   tim thu muc $AIWS_MODEL_STORE/<ten>, kiem SHA-256 tung file, kiem thresholds.json du 6 nhom, config multi-label 6 nhan.
   Model loi KHONG dung lan quet: ghi model_status != ok de P3 bao FAILED va Gate chay che do suy giam (chi Semgrep).
3. Cong cu: ghi phien ban ruleset/Semgrep mong doi (job Semgrep tu `ruleset.py verify` trong anh).
Dau ra: p0-authorize.json.
"""
import argparse
import os
import subprocess
from pathlib import Path

from . import common as C

STEP = "P0-authorize"


def check_source(repo: Path, expected: str):
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True).stdout.strip()
    ok = bool(head) and (not expected or head == expected) and not dirty
    return {"head": head, "expected": expected or None, "clean": not dirty, "ok": ok}


def find_lock(repo: Path) -> Path:
    cand = os.environ.get("AIWS_MODEL_LOCK")
    for p in ([Path(cand)] if cand else []) + [repo / "ci" / "model-lock.json", C.CI_HOME / "model-lock.json"]:
        p = p if p.is_absolute() else repo / p
        if p.is_file():
            return p
    return None


def check_model(repo: Path, store: Path):
    lock_p = find_lock(repo)
    if lock_p is None:
        return {"status": "no_lock", "error": "khong thay model-lock.json"}
    lock = C.read_json(lock_p)
    name = lock["name"]
    mdir = store / name
    res = {"status": "ok", "name": name, "path": str(mdir), "lock_file": str(lock_p),
           "dataset_version": lock.get("dataset_version"), "format": lock.get("format", "multilabel_sigmoid"),
           "groups": lock.get("groups", C.GROUPS), "val_macro_f1": lock.get("val_macro_f1"),
           "files_checked": 0, "problems": []}
    if not mdir.is_dir():
        res.update(status="missing", error=f"khong co thu muc model {mdir} tren worker")
        return res
    for rel, sha in sorted(lock["files"].items()):
        p = mdir / rel
        if not p.is_file():
            res["problems"].append(f"thieu {rel}")
            continue
        got = C.sha256_file(p)
        res["files_checked"] += 1
        if got != sha:
            res["problems"].append(f"SHA-256 lech: {rel}")
        if rel.endswith("model.safetensors"):
            res["checkpoint_sha256"] = got
    th = C.canon_keys(C.read_json(mdir / "thresholds.json", {}))
    if sorted(th) != sorted(C.GROUPS):
        res["problems"].append(f"thresholds.json phai co dung 6 nhom {C.GROUPS}")
    cfg = C.read_json(mdir / "checkpoint" / "config.json", {})
    if cfg.get("problem_type") != "multi_label_classification" or len(cfg.get("id2label", {})) != 6:
        res["problems"].append("config.json khong phai multi-label 6 nhan")
    if [C.canon_class(g) for g in res.get("groups") or []] != C.GROUPS:
        res["problems"].append("thu tu nhom trong model-lock.json khac thu tu cot logits da chot")
    res["thresholds"] = th
    if res["problems"]:
        res["status"] = "mismatch"
        res["error"] = "; ".join(res["problems"])
    return res


def check_code(repo: Path):
    """Ma P0-P5 chay tu anh Docker (/opt/aiws/ci). Neu repo dang quet chinh la AI-WhiteSec-Ci thi so ma trong anh
    voi ma trong commit: lech -> anh cu, phai build lai (tranh lan sua code ma job van chay ban cu)."""
    src = repo / "ci" / "aiws_ci"
    img = C.CI_HOME / "aiws_ci"
    if not src.is_dir() or src.resolve() == img.resolve():
        return {"status": "skipped", "reason": "repo khong chua ci/aiws_ci hoac dang chay truc tiep tu repo"}
    diff = sorted(p.name for p in src.glob("*.py")
                  if not (img / p.name).is_file() or C.sha256_file(p) != C.sha256_file(img / p.name))
    return {"status": "ok" if not diff else "stale", "files_differ": diff}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, default=Path("aiws-out"))
    ap.add_argument("--model-store", type=Path, default=Path(os.environ.get("AIWS_MODEL_STORE", "/models")))
    a = ap.parse_args()
    repo = a.repo.resolve()
    expected = os.environ.get("AIWS_EXPECTED_SHA") or os.environ.get("CI_COMMIT_SHA", "")
    src = check_source(repo, expected)
    model = check_model(repo, a.model_store)
    code = check_code(repo)
    out = {"schema": "aiws.p0.authorize.v1", "checked_at": C.now(), "source": src, "model": model,
           "code": code, "tools": {"semgrep_image": os.environ.get("AIWS_SEMGREP_IMAGE"),
                     "codebert_image": os.environ.get("AIWS_CODEBERT_IMAGE"),
                     "ruleset_version": os.environ.get("AIWS_RULESET_VERSION")},
           "ci": C.ci_context()}
    C.write_json(a.out_dir / "p0-authorize.json", out)
    if not src["ok"]:
        C.die(STEP, f"ma nguon khong dung commit duoc giao (HEAD {src['head'][:12]}, "
                    f"mong doi {str(expected)[:12]}, sach={src['clean']}) -> tu choi quet", C.EXIT_CONFIG)
    if code["status"] == "stale":
        C.die(STEP, f"anh {os.environ.get('AIWS_CODEBERT_IMAGE', 'aiws-codebert')} chua ma CU (lech: "
                    f"{', '.join(code['files_differ'])}) -> tren Server 3: git pull roi "
                    f"docker build -f ci/docker/Dockerfile.codebert -t aiws-codebert:0.1.0 .", C.EXIT_CONFIG)
    C.log(STEP, f"ma nguon OK @ {src['head'][:12]}; model {model.get('name', '?')}: {model['status']}"
                f"{' (' + model.get('error', '') + ')' if model['status'] != 'ok' else ''}"
                f"; {model.get('files_checked', 0)} file da kiem SHA-256")


if __name__ == "__main__":
    main()
