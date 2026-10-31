"""Cham diem CodeBERT dung CACH SUY LUAN cua tung goi model (dung chung cho P3 va ci/tools/explain_backfill.py).

Cach suy luan ghi trong model-lock.json, truong "inference":
  - "head512" (mac dinh, v24_pair_e5): tokenizer cua checkpoint, truncation=True, max_length=512 -> doc 512 token dau.
  - "window"  (V3 tro di): cua so truot cua leader (than 510 token + <s></s>, stride, toi da K cua so, gop LSE/max).
    KHONG viet lai: nap DUNG scripts/infer_window.py (+ train_codebert_win.py, eval_utils.py) di kem goi model,
    sau khi kiem SHA-256 cua ca 3 file voi model-lock.json (README_HANDOFF cua goi: "Dung infer_window.py, khong tu viet lai").
Ket qua moi ham: probs (6 so, thu tu common.GROUPS), n_tokens, truncated, va (che do window) n_windows + khoang dong
tung cua so. Cot logits so 4 la lop Auth: goi model ghi INSECURE_AUTHENTICATION, pipeline goi AUTHENTICATION_WEAKNESS.
"""
import importlib.util
import os
import sys
from pathlib import Path

from . import common as C

WINDOW_SCRIPTS = ["scripts/infer_window.py", "scripts/train_codebert_win.py", "scripts/eval_utils.py"]


def inference_of(lock: dict) -> dict:
    inf = dict((lock or {}).get("inference") or {})
    inf.setdefault("mode", "head512")
    return inf


def check_window_scripts(mdir: Path, lock: dict):
    """-> danh sach van de (rong = OK). Script suy luan la MA CHAY DUOC -> bat buoc khoa SHA-256 trong lock."""
    probs = []
    files = (lock or {}).get("files") or {}
    for rel in WINDOW_SCRIPTS:
        if rel not in files:
            probs.append(f"model-lock.json thieu SHA-256 cua {rel} (che do window)")
        elif not (mdir / rel).is_file():
            probs.append(f"thieu {rel}")
        elif C.sha256_file(mdir / rel) != files[rel]:
            probs.append(f"SHA-256 lech: {rel}")
    return probs


class Scorer:
    def __init__(self, mdir: Path, lock: dict = None, threads: int = None):
        import torch
        self.torch = torch
        torch.set_num_threads(max(1, threads or int(os.environ.get("AIWS_TORCH_THREADS", os.cpu_count() or 1))))
        self.mdir = Path(mdir)
        if lock is None:                       # model_tool install chep lock vao thu muc model
            lock = C.read_json(self.mdir / "model-lock.json", {})
        self.lock = lock
        self.inf = inference_of(lock)
        self.mode = self.inf["mode"]
        if self.mode == "head512":
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            self.tok = AutoTokenizer.from_pretrained(self.mdir / "checkpoint")
            self.net = AutoModelForSequenceClassification.from_pretrained(self.mdir / "checkpoint").eval()
        elif self.mode == "window":
            bad = check_window_scripts(self.mdir, lock)
            if bad:
                raise RuntimeError("; ".join(bad))
            sys.dont_write_bytecode = True     # kho model mount chi doc
            spec = importlib.util.spec_from_file_location("aiws_model_infer_window", self.mdir / WINDOW_SCRIPTS[0])
            iw = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(iw)        # tu them scripts/ vao sys.path de nap train_codebert_win, eval_utils
            if [C.canon_class(g) for g in iw.GROUPS] != C.GROUPS:
                raise RuntimeError(f"thu tu nhom cua goi model {iw.GROUPS} khac common.GROUPS")
            self.iw = iw
            self.tok, self.net, self.dev, _th, self.win = iw.load(str(self.mdir))   # doc stride/K/pool tu run_config
            self.body = iw.BODY
        else:
            raise RuntimeError(f"cach suy luan '{self.mode}' chua ho tro")

    def describe(self) -> dict:
        if self.mode == "head512":
            return {"mode": "head512", "max_len": 512, "truncation": "head 512 tokens"}
        return {"mode": "window", "max_len": 512, "body": self.body, "stride": self.win["stride"],
                "max_windows": self.win["k"], "pool": self.win["pool"], "lse_r": self.win["r"],
                "truncation": f"sliding window: body {self.body} + <s></s>, stride {self.win['stride']}, "
                              f"max {self.win['k']} windows (K-1 dau + 1 cuoi neu vuot), pool {self.win['pool']}"}

    # ------------------------------------------------------------------ cham diem
    def score(self, codes, batch=8, start_lines=None):
        """-> list dict {probs[6], n_tokens, truncated, n_windows?, windows?[[dong dau, dong cuoi], ...]}."""
        codes = [c or "" for c in codes]
        if not codes:
            return []
        if self.mode == "head512":
            return self._score_head(codes, batch)
        out = []
        step = max(1, int(os.environ.get("AIWS_CB_WINDOW_FUNCS", "64")))     # so ham moi lan goi score() cua leader
        for s in range(0, len(codes), step):
            part = codes[s:s + step]
            res = self.iw.score(part, self.tok, self.net, self.dev, self.win, chunk=batch)
            for k, (code, (p, _bw, n, starts, trunc, offs)) in enumerate(zip(part, res)):
                base = (start_lines[s + k] if start_lines else 1) or 1
                wins = [list(self.iw.window_lines(code, offs, st, n, base)) for st in starts]
                out.append({"probs": [float(x) for x in p], "n_tokens": int(n), "truncated": bool(trunc),
                            "n_windows": len(starts), "windows": wins})
        return out

    def _score_head(self, codes, batch):
        torch, tok, net = self.torch, self.tok, self.net
        n_tok = [len(ids) for ids in tok(codes, truncation=False)["input_ids"]]
        order = sorted(range(len(codes)), key=lambda i: n_tok[i])       # gom hang dai gan nhau -> it dem
        probs = [None] * len(codes)
        with torch.inference_mode():
            for s in range(0, len(order), batch):
                idx = order[s:s + batch]
                enc = tok([codes[i] for i in idx], truncation=True, max_length=512, padding=True, return_tensors="pt")
                for i, row in zip(idx, torch.sigmoid(net(**enc).logits.float()).tolist()):
                    probs[i] = row
        return [{"probs": p, "n_tokens": n, "truncated": n > 512} for p, n in zip(probs, n_tok)]

    def probs(self, codes, batch=8):
        return [r["probs"] for r in self.score(codes, batch)]

    def seen_until(self, code: str, start: int):
        """head512: dong cuoi model doc duoc (het 512 token dau). window: None (moi doan duoc doc tru phan giua
        cua ham qua K cua so - xem 'windows')."""
        if self.mode != "head512":
            return None
        try:
            enc = self.tok(code, truncation=True, max_length=512, return_offsets_mapping=True)
            last = max((e for _s, e in enc["offset_mapping"] if e), default=0)
            return start + code.count("\n", 0, last)
        except Exception:  # noqa: BLE001  tokenizer khong ho tro offset
            return None
