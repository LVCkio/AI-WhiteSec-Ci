"""P3 - CodeBERT Inference tren cac don vi P1 tao ra (chay song song voi P2 Semgrep, khong doc ket qua cua nhau).

  python -m aiws_ci.p3_codebert --out-dir aiws-out

Dung DUNG cach leader suy luan (INFERENCE.md cua goi model):
  - dau vao = code tho cua don vi, KHONG them tag/ten file, KHONG bo comment;
  - tokenizer cua checkpoint, truncation=True, max_length=512 (giu 512 token dau);
  - sigmoid tung cot; thu tu cot = common.GROUPS; gan nhom j neu p_j >= thresholds.json[j]; khong nhom nao -> PASS;
  - don vi module_snippet chi xet HARDCODED_CREDENTIALS.
Dau ra: codebert-results.json. Ma thoat: 0 = xong, 2 = model khong dung duoc (P0 bao loi), 3 = loi khi suy luan.
"""
import argparse
import os
import time
from pathlib import Path

from . import common as C

STEP = "P3-codebert"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", type=Path, default=Path("aiws-out"))
    ap.add_argument("--batch", type=int, default=int(os.environ.get("AIWS_CODEBERT_BATCH", "8")))
    ap.add_argument("--max-units", type=int, default=int(os.environ.get("AIWS_CODEBERT_MAX_UNITS", "4000")))
    a = ap.parse_args()
    out_p = a.out_dir / "codebert-results.json"
    auth = C.read_json(a.out_dir / "p0-authorize.json")
    if auth is None:
        C.die(STEP, "thieu p0-authorize.json", C.EXIT_CONFIG)
    model = auth["model"]
    if model["status"] != "ok":
        C.write_json(out_p, {"status": "failed", "error": f"model {model['status']}: {model.get('error', '')}",
                             "model": model})
        C.die(STEP, f"model khong dung duoc: {model.get('error')}", C.EXIT_CONFIG)

    units = [u for u in C.read_jsonl(a.out_dir / "p1-units.jsonl") if u["in_diff"] and u["scored"]]
    truncated_units = len(units) > a.max_units
    units = units[:a.max_units]
    t0, started = time.time(), C.now()
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        torch.set_num_threads(max(1, int(os.environ.get("AIWS_TORCH_THREADS", os.cpu_count() or 1))))
        mdir = Path(model["path"])
        tok = AutoTokenizer.from_pretrained(mdir / "checkpoint")
        net = AutoModelForSequenceClassification.from_pretrained(mdir / "checkpoint").eval()
        th = model["thresholds"]
        load_s = time.time() - t0
        codes = [u["code"] or "" for u in units]
        n_tok = [len(ids) for ids in tok(codes, truncation=False)["input_ids"]] if codes else []
        order = sorted(range(len(units)), key=lambda i: n_tok[i])        # gom hang dai gan nhau -> it dem
        probs = [None] * len(units)
        with torch.inference_mode():
            for s in range(0, len(order), a.batch):
                idx = order[s:s + a.batch]
                enc = tok([codes[i] for i in idx], truncation=True, max_length=512, padding=True, return_tensors="pt")
                p = torch.sigmoid(net(**enc).logits.float()).tolist()
                for i, row in zip(idx, p):
                    probs[i] = row
    except Exception as e:  # noqa: BLE001
        C.write_json(out_p, {"status": "failed", "error": f"{type(e).__name__}: {e}"[:2000], "model": model})
        C.die(STEP, f"suy luan loi: {e}", C.EXIT_TOOL)

    res_units, flagged = [], 0
    for u, p, nt in zip(units, probs, n_tok):
        allowed = u.get("only_groups") or C.GROUPS
        pr = {g: round(float(x), 6) for g, x in zip(C.GROUPS, p)}
        groups = [g for g in C.GROUPS if g in allowed and pr[g] >= th[g]]
        flagged += bool(groups)
        res_units.append({"id": u["id"], "file": u["file"], "unit": u["unit"], "start": u["start"], "end": u["end"],
                          "probs": pr, "groups": groups, "n_tokens": nt, "truncated": nt > 512})
    out = {
        "schema": "aiws.p3.codebert.v1", "status": "completed", "started_at": started, "finished_at": C.now(),
        "duration_s": round(time.time() - t0, 2), "model_load_s": round(load_s, 2),
        "model": {k: model.get(k) for k in ("name", "path", "dataset_version", "format", "checkpoint_sha256",
                                            "files_checked", "val_macro_f1", "val_metrics", "infra_verify")},
        "thresholds": th, "groups_order": C.GROUPS, "max_len": 512, "truncation": "head 512 tokens",
        "device": "cpu", "torch_threads": torch.get_num_threads(),
        "units": res_units,
        "summary": {"units_scored": len(res_units), "units_flagged": flagged,
                    "units_truncated_512": sum(r["truncated"] for r in res_units),
                    "units_dropped_over_max": truncated_units,
                    "by_group": {g: sum(g in r["groups"] for r in res_units) for g in C.GROUPS}},
    }
    C.write_json(out_p, out)
    s = out["summary"]
    C.log(STEP, f"model {model['name']}: {s['units_scored']} don vi, {s['units_flagged']} vuot nguong, "
                f"{s['units_truncated_512']} bi cat 512 token; {out['duration_s']} s")


if __name__ == "__main__":
    main()
