"""P3 - CodeBERT Inference tren cac don vi P1 tao ra (chay song song voi P2 Semgrep, khong doc ket qua cua nhau).

  python -m aiws_ci.p3_codebert --out-dir aiws-out

Dung DUNG cach leader suy luan (model-lock.json "inference", xem aiws_ci/scoring.py):
  - dau vao = code tho cua don vi, KHONG them tag/ten file, KHONG bo comment;
  - head512 (v24_pair_e5): truncation=True, max_length=512 (giu 512 token dau);
    window (V3): cua so truot + gop cua scripts/infer_window.py di kem goi model;
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


def weak_thresholds(model):
    """Gate 3x3: vach Thap = alpha20 (thresholds_np_candidates.json['candidates']['0.20']) trong goi model. Khong co -> None
    (P4 dung fallback cua gate_3x3: lop vuot thresholds.json = Cao, con lai Khong)."""
    try:
        d = C.read_json(Path(model["path"]) / "thresholds_np_candidates.json") or {}
        t = (d.get("candidates") or {}).get("0.20", {}).get("thresholds")
        return C.canon_keys(t) if t else None
    except (KeyError, TypeError, OSError):
        return None


def explain_units(scorer, units, probs, th, max_units, max_blocks, batch, meta=None):
    """Giai thich ham CodeBERT gan co bang OCCLUSION: chia ham thanh toi da max_blocks khoi dong, xoa trang tung khoi
    (giu so dong), cham lai DUNG cach suy luan cua model -> muc GIAM xac suat cua lop da gan = muc model dua vao khoi
    do. Day la bang chung 'model dua vao dong nao', KHONG phai dinh vi lo hong.
    head512: chi chia phan model doc duoc (512 token dau), kem seen_until_line.
    window : chia ca ham; kem khoang dong tung cua so (ham qua K cua so: phan giua khong duoc doc -> 'truncated')."""
    cand = []
    for i, (u, p) in enumerate(zip(units, probs)):
        allowed = u.get("only_groups") or C.GROUPS
        gs = [j for j, g in enumerate(C.GROUPS) if g in allowed and p[j] >= th[g]]
        if gs:
            cand.append((max(p[j] for j in gs), i, gs))
    cand.sort(reverse=True)
    out = {}
    for _, i, gs in cand[:max_units]:
        u, code = units[i], units[i]["code"] or ""
        lines = code.split("\n")
        seen_until = scorer.seen_until(code, u["start"])
        # head512: chi chia phan model THAT SU doc (512 token dau); phan sau khong anh huong diem
        n = len(lines) if seen_until is None else max(1, min(len(lines), seen_until - u["start"] + 1))
        k = min(max_blocks, n)
        blocks = []
        if k >= 2:
            bounds = [(round(b * n / k), round((b + 1) * n / k)) for b in range(k)]
            variants = ["\n".join("" if a <= li < b else ln for li, ln in enumerate(lines)) for a, b in bounds]
            ps = scorer.probs(variants, batch)
            for (a, b), pm in zip(bounds, ps):
                blocks.append({"start": u["start"] + a, "end": u["start"] + b - 1,
                               "drop": {C.GROUPS[j]: round(probs[i][j] - pm[j], 4) for j in gs}})
        ex = {"method": "occlusion", "inference": scorer.mode, "blocks": blocks, "seen_until_line": seen_until}
        m = (meta or [None] * len(units))[i]
        if m and "windows" in m:
            ex.update(windows=m["windows"], truncated=m["truncated"])
        out[u["id"]] = ex
    return out


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
        from .scoring import Scorer
        mdir = Path(model["path"])
        scorer = Scorer(mdir, {"inference": model.get("inference"), "files": model.get("lock_files") or {}})
        th = model["thresholds"]
        load_s = time.time() - t0
        meta = scorer.score([u["code"] or "" for u in units], a.batch, [u["start"] for u in units])
        probs = [m["probs"] for m in meta]
    except Exception as e:  # noqa: BLE001
        C.write_json(out_p, {"status": "failed", "error": f"{type(e).__name__}: {e}"[:2000], "model": model})
        C.die(STEP, f"suy luan loi: {e}", C.EXIT_TOOL)

    # Giai thich (occlusion) cho cac ham gan co - loi o day KHONG lam hong ket qua cham
    explain, t_exp = {}, time.time()
    n_exp = int(os.environ.get("AIWS_CB_EXPLAIN_UNITS", "500"))
    if n_exp > 0:
        try:
            explain = explain_units(scorer, units, probs, th, n_exp,
                                    int(os.environ.get("AIWS_CB_EXPLAIN_BLOCKS", "6")), a.batch, meta)
        except Exception as e:  # noqa: BLE001
            C.log(STEP, f"canh bao: giai thich occlusion loi ({e}) -> bo qua")
    t_exp = round(time.time() - t_exp, 2)

    res_units, flagged = [], 0
    for u, p, m in zip(units, probs, meta):
        allowed = u.get("only_groups") or C.GROUPS
        pr = {g: round(float(x), 6) for g, x in zip(C.GROUPS, p)}
        groups = [g for g in C.GROUPS if g in allowed and pr[g] >= th[g]]
        flagged += bool(groups)
        res_units.append({"id": u["id"], "file": u["file"], "unit": u["unit"], "start": u["start"], "end": u["end"],
                          "probs": pr, "groups": groups, "n_tokens": m["n_tokens"], "truncated": m["truncated"],
                          "n_windows": m.get("n_windows"),
                          "explain": explain.get(u["id"])})
    out = {
        "schema": "aiws.p3.codebert.v1", "status": "completed", "started_at": started, "finished_at": C.now(),
        "duration_s": round(time.time() - t0, 2), "model_load_s": round(load_s, 2),
        "model": {k: model.get(k) for k in ("name", "path", "dataset_version", "format", "checkpoint_sha256",
                                            "files_checked", "val_macro_f1", "val_metrics", "infra_verify",
                                            "inference")},
        "thresholds": th, "thresholds_weak": weak_thresholds(model), "groups_order": C.GROUPS, "inference": scorer.describe(),
        "max_len": 512, "truncation": scorer.describe()["truncation"],
        "device": "cpu", "torch_threads": scorer.torch.get_num_threads(),
        "units": res_units,
        "summary": {"units_scored": len(res_units), "units_flagged": flagged,
                    # head512: ham dai hon 512 token (phan sau bi bo); window: ham qua K cua so (phan giua bi bo)
                    "units_truncated_512": sum(r["truncated"] for r in res_units),
                    "units_windows": sum(r["n_windows"] or 1 for r in res_units),
                    "units_dropped_over_max": truncated_units,
                    "units_explained": len(explain), "explain_s": t_exp,
                    "by_group": {g: sum(g in r["groups"] for r in res_units) for g in C.GROUPS}},
    }
    C.write_json(out_p, out)
    s = out["summary"]
    C.log(STEP, f"model {model['name']}: {s['units_scored']} don vi, {s['units_flagged']} vuot nguong, "
                f"{s['units_truncated_512']} bi cat ({scorer.mode}); giai thich {s['units_explained']} ham ({s['explain_s']} s); "
                f"{out['duration_s']} s")


if __name__ == "__main__":
    main()
