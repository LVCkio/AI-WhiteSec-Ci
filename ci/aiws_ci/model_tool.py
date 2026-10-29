"""Phan phoi model CodeBERT (Model Artifact Storage -> worker) - dung khi leader giao checkpoint moi.

  # 1. Tao ci/model-lock.json tu goi ban giao cua leader (doc MANIFEST.json, KHONG tin ten file):
  python -m aiws_ci.model_tool lock <thu muc goi, vd model_v24_pair_e5> --out ci/model-lock.json

  # 2. Tren Server 3: kiem SHA-256 cua goi theo lock roi cai vao kho model (thu muc theo ten run):
  python -m aiws_ci.model_tool install <thu muc goi> --lock ci/model-lock.json --store /srv/aiws/models

  # 3. (Nen chay mot lan sau khi cai) cham lai N mau val, so voi val_probs.npy cua leader:
  python -m aiws_ci.model_tool verify /srv/aiws/models/<ten> --val val.jsonl --n 20
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

from . import common as C

NEEDED = ["checkpoint/model.safetensors", "checkpoint/config.json", "checkpoint/tokenizer.json",
          "checkpoint/tokenizer_config.json", "thresholds.json", "run_config.json", "metrics_val.json"]


def cmd_lock(a):
    pkg = Path(a.package)
    man = C.read_json(pkg / "MANIFEST.json")
    if man is None:
        sys.exit(f"khong thay {pkg / 'MANIFEST.json'}")
    files = {f["path"].replace("\\", "/"): f["sha256"] for f in man["files"]}
    miss = [n for n in NEEDED if n not in files]
    if miss:
        sys.exit(f"MANIFEST thieu {miss}")
    metrics = C.read_json(pkg / "metrics_val.json", {})
    rc = C.read_json(pkg / "run_config.json", {})
    groups = rc.get("groups") or C.GROUPS
    lock = {
        "name": man.get("package", pkg.name).replace("model_", "", 1) if man.get("run") is None else man["run"],
        "package": man.get("package", pkg.name), "dataset_version": man.get("dataset"),
        "epoch": man.get("epoch"), "format": "multilabel_sigmoid", "groups": groups,
        "val_macro_f1": metrics.get("macro_f1"),
        "val_false_alarm": metrics.get("all_zero_false_alarm_rate"),
        "dataset_sha256": man.get("dataset_sha256"), "packed_at": man.get("packed_at"),
        "files": {n: files[n] for n in NEEDED},
    }
    C.write_json(a.out, lock)
    print(f"da ghi {a.out}: model {lock['name']} (dataset {lock['dataset_version']}, val macro-F1 {lock['val_macro_f1']})")


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
                                    "val_probs.npy", "val_ids.json"]:
        if (pkg / rel).is_file():
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(pkg / rel, dst / rel)
    shutil.copy2(a.lock, dst / "model-lock.json")
    print(f"da cai model {lock['name']} vao {dst} ({len(lock['files'])} file da kiem SHA-256)")


def cmd_verify(a):
    import numpy as np
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    mdir = Path(a.model_dir)
    pkg = Path(a.package or mdir)
    probs = np.load(pkg / "val_probs.npy")
    ids = json.loads((pkg / "val_ids.json").read_text(encoding="utf-8"))
    ids = ids if isinstance(ids, list) else ids.get("ids", ids)
    recs = {}
    for line in Path(a.val).read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            recs[r.get("id") or r.get("sample_id")] = r
    tok = AutoTokenizer.from_pretrained(mdir / "checkpoint")
    net = AutoModelForSequenceClassification.from_pretrained(mdir / "checkpoint").eval()
    th = C.canon_keys(C.read_json(mdir / "thresholds.json"))
    worst, same = 0.0, 0
    n = min(a.n, len(ids))
    with torch.inference_mode():
        for i in range(n):
            enc = tok(recs[ids[i]]["code"] or "", truncation=True, max_length=512, return_tensors="pt")
            p = torch.sigmoid(net(**enc).logits.float())[0].numpy()
            worst = max(worst, float(abs(p - probs[i]).max()))
            same += all((p[j] >= th[g]) == (probs[i][j] >= th[g]) for j, g in enumerate(C.GROUPS))
    ok = worst < a.tol
    out = {"n": n, "max_abs_diff": worst, "same_decision": f"{same}/{n}", "tol": a.tol, "pass": ok,
           "device": "cpu", "torch": torch.__version__, "checked_at": C.now()}
    print(json.dumps(out))
    if a.save:                        # P0 doc file nay -> bao cao / Dashboard (doi chieu ha tang voi luc train)
        C.write_json(mdir / "infra_verify.json", out)
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("lock"); s.add_argument("package"); s.add_argument("--out", default="ci/model-lock.json")
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
