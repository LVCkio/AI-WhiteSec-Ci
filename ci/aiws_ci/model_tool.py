"""Phan phoi model CodeBERT (Model Artifact Storage -> worker) - dung khi leader giao checkpoint moi.

  # 1. Tao ci/model-lock.json tu goi ban giao cua leader (doc MANIFEST.json hoac SHA256SUMS.txt, KHONG tin ten file):
  python -m aiws_ci.model_tool lock <thu muc goi, vd model_v24_pair_e5> --out ci/model-lock.json
  python -m aiws_ci.model_tool lock <thu muc V3> --sums <SHA256SUMS.txt cua goi> --out ci/model-lock.V3.json
     (goi co run_config.max_windows -> inference "window": khoa them scripts/infer_window.py, train_codebert_win.py,
      eval_utils.py - P3 nap DUNG cac script nay)

  # 2. Tren Server 3: kiem SHA-256 cua goi theo lock roi cai vao kho model (thu muc theo ten run):
  python -m aiws_ci.model_tool install <thu muc goi> --lock ci/model-lock.json --store /srv/aiws/models

  # 3. (Nen chay mot lan sau khi cai) cham lai N mau val, so voi val_probs.npy cua leader:
  python -m aiws_ci.model_tool verify /srv/aiws/models/<ten> --val val.jsonl --n 20
"""
import argparse
import json
import re
import shutil
import sys
from pathlib import Path

from . import common as C
from .scoring import WINDOW_SCRIPTS

NEEDED = ["checkpoint/model.safetensors", "checkpoint/config.json", "checkpoint/tokenizer.json",
          "checkpoint/tokenizer_config.json", "thresholds.json", "run_config.json", "metrics_val.json"]


def read_sums(p: Path):
    """SHA256SUMS(.txt) cua goi: '<sha>  model_V3/checkpoint/...' -> {duong dan tuong doi trong goi: sha}."""
    out = {}
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            rel = parts[1].lstrip("*").replace("\\", "/")
            rel = re.sub(r"^model_[^/]+/", "", rel)          # bo thu muc goc trong zip
            out[rel] = parts[0].lower()
    return out


def window_inference(rc: dict):
    if not rc.get("max_windows"):
        return {"mode": "head512"}
    return {"mode": "window", "stride": rc.get("stride"), "max_windows": rc.get("max_windows"),
            "pool": rc.get("pool"), "lse_r": rc.get("lse_r"), "truncation": rc.get("truncation")}


def cmd_lock(a):
    pkg = Path(a.package)
    man = C.read_json(pkg / "MANIFEST.json")
    metrics = C.read_json(pkg / "metrics_val.json", {})
    rc = C.read_json(pkg / "run_config.json", {})
    inference = window_inference(rc)
    need = NEEDED + (WINDOW_SCRIPTS if inference["mode"] == "window" else [])
    if man is not None:
        files = {f["path"].replace("\\", "/"): f["sha256"] for f in man["files"]}
        name = man.get("package", pkg.name).replace("model_", "", 1) if man.get("run") is None else man["run"]
        meta = {"package": man.get("package", pkg.name), "dataset_version": man.get("dataset"),
                "epoch": man.get("epoch"), "dataset_sha256": man.get("dataset_sha256"), "packed_at": man.get("packed_at")}
    else:
        sums = Path(a.sums) if a.sums else next((q for q in (pkg / "SHA256SUMS.txt", pkg / "SHA256SUMS") if q.is_file()), None)
        if sums is None or not sums.is_file():
            sys.exit(f"khong thay MANIFEST.json hay SHA256SUMS(.txt) cua goi (dung --sums <file>)")
        files = read_sums(sums)
        name = rc.get("version") or pkg.name.replace("model_", "", 1)
        data = re.split(r"[\\/]", str(rc.get("data") or "").rstrip("\\/"))[-1] or None
        meta = {"package": f"model_{name}", "dataset_version": data, "epoch": metrics.get("epoch"),
                "dataset_sha256": rc.get("dataset_sha256"), "packed_at": None, "sums_file": sums.name}
    miss = [n for n in need if n not in files]
    if miss:
        sys.exit(f"danh sach SHA-256 cua goi thieu {miss}")
    bad = [n for n in need if (pkg / n).is_file() and C.sha256_file(pkg / n) != files[n]]
    if bad:
        sys.exit(f"file trong {pkg} KHAC SHA-256 cua goi: {bad}")
    groups = rc.get("groups") or C.GROUPS
    lock = {"name": name, **{k: meta[k] for k in ("package", "dataset_version", "epoch")},
            "format": "multilabel_sigmoid", "inference": inference, "groups": groups,
            "val_macro_f1": metrics.get("macro_f1"), "val_false_alarm": metrics.get("all_zero_false_alarm_rate"),
            "dataset_sha256": meta["dataset_sha256"], "packed_at": meta["packed_at"],
            "files": {n: files[n] for n in need}}
    C.write_json(a.out, lock)
    print(f"da ghi {a.out}: model {lock['name']} (dataset {lock['dataset_version']}, val macro-F1 {lock['val_macro_f1']}, "
          f"suy luan {inference['mode']}, {len(lock['files'])} file)")


def cmd_install(a):
    pkg, lock = Path(a.package), C.read_json(a.lock)
    bad = []
    for rel, sha in lock["files"].items():
        p = pkg / rel
        if not p.is_file() or C.sha256_file(p) != sha:
            bad.append(rel)
    if bad:
        sys.exit(f"goi KHONG khop lock, khong cai: {bad}")
    dst = Path(a.store) / lock["name"]
    if dst.exists() and not a.force:
        sys.exit(f"{dst} da ton tai (dung --force de ghi de)")
    dst.mkdir(parents=True, exist_ok=True)
    for rel in list(lock["files"]) + ["MANIFEST.json", "INFERENCE.md", "report_val.md", "DATA_CARD.md",
                                    "val_probs.npy", "val_ids.json", "README_HANDOFF.md", "history.json"]:
        if (pkg / rel).is_file():
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(pkg / rel, dst / rel)
    shutil.copy2(a.lock, dst / "model-lock.json")
    print(f"da cai model {lock['name']} vao {dst} ({len(lock['files'])} file da kiem SHA-256)")


def cmd_verify(a):
    """Cham lai N mau val trong kho, so voi val_probs.npy cua leader (dung cach suy luan ghi trong lock).
    Goi co val_ids.json -> ghep theo id; khong co (goi V3) -> N dong DAU cua val.jsonl (nhu infer_window --verify-val)."""
    import numpy as np
    from .scoring import Scorer
    mdir = Path(a.model_dir)
    pkg = Path(a.package or mdir)
    probs = np.load(pkg / "val_probs.npy")
    recs = [json.loads(line) for line in Path(a.val).read_text(encoding="utf-8").splitlines() if line.strip()]
    if (pkg / "val_ids.json").is_file():
        ids = json.loads((pkg / "val_ids.json").read_text(encoding="utf-8"))
        ids = ids if isinstance(ids, list) else ids.get("ids", ids)
        by_id = {r.get("id") or r.get("sample_id"): r for r in recs}
        n = min(a.n, len(ids))
        codes = [by_id[ids[i]]["code"] or "" for i in range(n)]
    else:
        n = min(a.n, len(recs), len(probs))
        codes = [r["code"] or "" for r in recs[:n]]
    scorer = Scorer(mdir)
    th = C.canon_keys(C.read_json(mdir / "thresholds.json"))
    worst, same = 0.0, 0
    for i, p in enumerate(scorer.probs(codes, batch=8)):
        p = np.array(p)
        worst = max(worst, float(abs(p - probs[i]).max()))
        same += all((p[j] >= th[g]) == (probs[i][j] >= th[g]) for j, g in enumerate(C.GROUPS))
    ok = worst < a.tol
    out = {"n": n, "max_abs_diff": worst, "same_decision": f"{same}/{n}", "tol": a.tol, "pass": ok,
           "inference": scorer.mode, "device": "cpu", "torch": scorer.torch.__version__, "checked_at": C.now()}
    print(json.dumps(out))
    if a.save:                        # P0 doc file nay -> bao cao / Dashboard (doi chieu ha tang voi luc train)
        C.write_json(mdir / "infra_verify.json", out)
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("lock"); s.add_argument("package"); s.add_argument("--out", default="ci/model-lock.json")
    s.add_argument("--sums", help="SHA256SUMS(.txt) cua goi khi goi khong co MANIFEST.json")
    s = sub.add_parser("install"); s.add_argument("package"); s.add_argument("--lock", default="ci/model-lock.json")
    s.add_argument("--store", default="/srv/aiws/models"); s.add_argument("--force", action="store_true")
    s = sub.add_parser("verify"); s.add_argument("model_dir"); s.add_argument("--package")
    s.add_argument("--val", required=True); s.add_argument("--n", type=int, default=20)
    s.add_argument("--tol", type=float, default=1e-3)
    s.add_argument("--save", action="store_true", help="ghi infra_verify.json vao thu muc model")
    a = ap.parse_args()
    {"lock": cmd_lock, "install": cmd_install, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    main()
