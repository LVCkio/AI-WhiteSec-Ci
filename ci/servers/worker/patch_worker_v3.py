"""Va aiws_infer.py cua worker (Truong) de cham model DOC THEO CUA SO (V3 tro di) dung nhu leader:
nap scripts/infer_window.py di kem goi model (khong viet lai), giu nguyen moi thu khac (v24 van 512 token dau).
Idempotent; sao luu aiws_infer.py.bak-<thoi diem>.   python3 patch_worker_v3.py <duong dan aiws_infer.py>"""
import shutil, sys, time
from pathlib import Path

p = Path(sys.argv[1]); s = p.read_text(encoding="utf-8")
MARK = "# v3-window-patch"
if MARK in s:
    print("da va truoc do -> bo qua"); sys.exit(0)


def rep(a, b):
    global s
    if s.count(a) != 1:
        sys.exit(f"KHONG tim thay dung 1 cho de va (da bi sua?):\n{a[:200]}")
    s = s.replace(a, b)


rep('''        self.max_len = int(cfg.get("max_len") or MAX_LEN)
''', '''        self.max_len = int(cfg.get("max_len") or MAX_LEN)
        # v3-window-patch: model train theo cua so truot (run_config.max_windows, vd V3) -> cham bang
        # scripts/infer_window.py DI KEM goi model (dung nhu leader, khong viet lai); khong co -> 512 token dau nhu cu
        self.window = None
        if cfg.get("max_windows"):
            if not (self.root / "scripts" / "infer_window.py").is_file():
                raise ValueError("model doc theo cua so (run_config.max_windows) nhung thieu scripts/infer_window.py")
            self.window = {"stride": cfg.get("stride"), "max_windows": cfg.get("max_windows"), "pool": cfg.get("pool"),
                           "lse_r": cfg.get("lse_r"), "truncation": cfg.get("truncation")}
''')
rep('''        if scorer_fn is not None:
            self.scorer, self.device = scorer_fn, "custom"
        else:''', '''        if scorer_fn is not None:
            self.scorer, self.device = scorer_fn, "custom"
        elif self.window:
            import importlib.util
            import torch
            self.torch = torch
            sys.dont_write_bytecode = True          # thu muc model mount chi doc
            spec = importlib.util.spec_from_file_location("model_infer_window", self.root / "scripts" / "infer_window.py")
            iw = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(iw)             # tu them scripts/ vao sys.path (train_codebert_win, eval_utils)
            if [canon(g) for g in iw.GROUPS] != [canon(g) for g in self.groups]:
                raise ValueError(f"scripts/eval_utils.GROUPS {iw.GROUPS} khac run_config groups {self.groups}")
            self.iw = iw
            self.tok, self.model, self.dev, _th, self.win = iw.load(str(self.root))   # stride/K/pool tu run_config
            self.device = str(self.dev)
            if int(self.model.config.num_labels) != len(self.groups):
                raise ValueError(f"model co {self.model.config.num_labels} dau ra, can {len(self.groups)}")
            self.scorer = self._win_scores
        else:''')
rep('''    def info(self):
        return {"schema": SCHEMA_V2, "format": "multilabel_sigmoid",''', '''    def _win_scores(self, codes):
        """Giong infer_window.py --input: cua so than 510 + <s></s>, stride, toi da K, gop (LSE/max) roi sigmoid.
        So token = do dai than (khong tinh <s></s>); truncated = ham qua K cua so (phan giua khong duoc doc)."""
        res = self.iw.score(codes, self.tok, self.model, self.dev, self.win, chunk=self.batch_size)
        self._last_trunc = [bool(r[4]) for r in res]
        self._last_windows = [len(r[3]) for r in res]
        return [[float(x) for x in r[0]] for r in res], [int(r[2]) for r in res]

    def info(self):
        return {"schema": SCHEMA_V2, "format": "multilabel_sigmoid",''')
rep('''                "max_len": self.max_len, "truncation": f"head {self.max_len} tokens", "device": self.device,''',
    '''                "max_len": self.max_len, "device": self.device,
                "inference": "window" if self.window else "head512", "window": self.window,
                "truncation": (self.window or {}).get("truncation") or f"head {self.max_len} tokens",''')
rep('''        probs, ntok = self.scorer([u["code"] for u in units])
        t_cls = time.perf_counter() - t0
        out = []
        for u, p, n in zip(units, probs, ntok):''', '''        self._last_trunc = self._last_windows = None
        probs, ntok = self.scorer([u["code"] for u in units])
        t_cls = time.perf_counter() - t0
        trunc = self._last_trunc or [n > self.max_len for n in ntok]
        wins = self._last_windows or [None] * len(units)
        out = []
        for u, p, n, tr, nw in zip(units, probs, ntok, trunc, wins):''')
rep('''                        "p_vulnerable": None, "tokens": n, "truncated": n > self.max_len})''',
    '''                        "p_vulnerable": None, "tokens": n, "truncated": bool(tr), "windows": nw})''')
bak = p.with_name(p.name + ".bak-" + time.strftime("%Y%m%d-%H%M%S"))
shutil.copy2(p, bak)
p.write_text(s, encoding="utf-8")
print(f"da va {p} (sao luu {bak.name})")
