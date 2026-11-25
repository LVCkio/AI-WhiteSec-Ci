#!/usr/bin/env python3
"""Tao lai don vi (ham) cua dataset bang tree-sitter - cung quy tac voi pipeline CI (ci/aiws_ci/units.py).

Muc dich: model hoc tren DUNG loai don vi ma pipeline dua vao luc quet (nhom chot tree-sitter 27/10/2026).
GIU NGUYEN tung mau (id, nhan, split, pair_id, nguon); CHI thay `code`, `start_line`, `end_line` bang ham tree-sitter
tim duoc trong file goc. Khong chon lai mau, khong chia lai tap.

  python rebuild_units_treesitter.py --data ..\\..\\dataset\\v2.4 --out ..\\..\\dataset\\v2.4-ts ^
      --db ..\\..\\sources\\CVEfixes.db --db ..\\..\\sources\\morefixes_auth.db --db <db MoreFixes OS_COMMAND> ^
      --units-dir <repo AI-WhiteSec-Ci>\\ci  [--creddata-root ~/CredData] [--tokenizer microsoft/codebert-base]
      [--splits train val]            # mac dinh train + val; test CHI khi nhom quyet dinh (--splits train val test)

Cach lay file goc cua tung mau:
  cvefixes-<method_change_id> / morefixes-<method_change_id> : method_change -> file_change.code_before
        (version before_fix / snapshot) hoac code_after (after_fix); tim ham tree-sitter trung ten + chong dong nhieu nhat
  cvefixes-unch-<file_change_id>-<dau>-<cuoi>                : file_change.code_before, ham tree-sitter chong [dau, cuoi]
  creddata-* (unit function, can --creddata-root)            : file CredData theo truong `file`
  module_snippet                                              : giu nguyen (quy tac +-5 dong giong CI)
  khac (vd. mau hard-negative v2.4 co id rieng)                : giu nguyen, ghi `unit_rebuild=kept_original`
Ket qua tung mau ghi o truong `unit_rebuild`: same | rebuilt | kept_original | dropped_no_ts_function | no_source
Mau `dropped_no_ts_function` (tree-sitter khong thay ham nao chong >= 50% - thuong la don vi lizard cat sai, vd
khoi `catch`, dong trong object literal) bi BO khoi tap moi va liet ke trong removed_ts.jsonl.
Dau ra: <out>/{train,val[,test]}.jsonl, removed_ts.jsonl, REBUILD_REPORT.md (bang theo nguon x ngon ngu, sha256).
"""
import argparse
import collections
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

LANG = {"Python": "python", "Java": "java", "JavaScript": "javascript", "PHP": "php"}


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class Sources:
    """Doc file goc tu cac SQLite co schema CVEfixes (CVEfixes.db, cac db MoreFixes da chuyen sang SQLite)."""

    def __init__(self, dbs):
        self.cons = []
        for d in dbs:
            c = sqlite3.connect(f"file:{d}?mode=ro", uri=True)
            tabs = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if {"method_change", "file_change"} <= tabs:
                cols = {r[1] for r in c.execute("PRAGMA table_info(file_change)")}
                if not {"code_before", "code_after"} <= cols:
                    sys.exit(f"{d}: file_change thieu code_before/code_after")
                self.cons.append((d, c))
            else:
                print(f"(bo qua {d}: khong co method_change + file_change)")
        if not self.cons:
            sys.exit("khong co db nao co method_change + file_change")

    def method(self, mid):
        for _, c in self.cons:
            r = c.execute("SELECT m.file_change_id, m.name, m.start_line, m.end_line, m.before_change, "
                          "f.code_before, f.code_after FROM method_change m JOIN file_change f "
                          "ON f.file_change_id = m.file_change_id WHERE m.method_change_id = ?", (mid,)).fetchone()
            if r:
                return r
        return None

    def file_before(self, fcid):
        for _, c in self.cons:
            r = c.execute("SELECT code_before FROM file_change WHERE file_change_id = ?", (fcid,)).fetchone()
            if r:
                return r[0]
        return None


def best_unit(units, start, end, name=None):
    """Ham tree-sitter khop nhat voi [start, end]: uu tien cung ten, roi IoU dong lon nhat."""
    best, score = None, 0.0
    for u in units:
        if u["unit"] != "function":
            continue
        inter = min(u["end"], end) - max(u["start"], start) + 1
        if inter <= 0:
            continue
        iou = inter / (max(u["end"], end) - min(u["start"], start) + 1)
        s = iou + (0.5 if name and u["name"].split(".")[-1] == str(name).split("::")[-1].split(".")[-1] else 0)
        if s > score:
            best, score = u, s
    if best is None:
        return None, 0.0
    inter = min(best["end"], end) - max(best["start"], start) + 1
    return best, inter / (end - start + 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--db", type=Path, action="append", required=True)
    ap.add_argument("--units-dir", type=Path, required=True, help="thu muc ci/ cua repo AI-WhiteSec-Ci")
    ap.add_argument("--creddata-root", type=Path)
    ap.add_argument("--tokenizer", help="tinh lai n_tokens/over_512 (vd microsoft/codebert-base)")
    ap.add_argument("--splits", nargs="+", default=["train", "val"])
    ap.add_argument("--min-overlap", type=float, default=0.5)
    a = ap.parse_args()
    sys.path.insert(0, str(a.units_dir))
    from aiws_ci.units import file_units, treesitter_version   # noqa: E402

    src = Sources(a.db)
    tok = None
    if a.tokenizer:
        from transformers import AutoTokenizer
        tok = AutoTokenizer.from_pretrained(a.tokenizer)
    a.out.mkdir(parents=True, exist_ok=True)
    cache = {}
    removed, table = [], collections.defaultdict(collections.Counter)

    def units_of(key, text, lang):
        if key not in cache:
            cache.clear() if len(cache) > 2000 else None
            cache[key] = file_units("f", text, lang)[0]
        return cache[key]

    for split in a.splits:
        inp = a.data / f"{split}.jsonl"
        if not inp.is_file():
            sys.exit(f"thieu {inp}")
        out_rows = []
        for line in inp.open(encoding="utf-8"):
            if not line.strip():
                continue
            r = json.loads(line)
            lang = LANG.get(r.get("language"))
            rid, status, text, key, s, e, name = r["id"], None, None, None, None, None, None
            if r.get("unit") == "module_snippet" or lang is None:
                status = "kept_original"
            elif rid.startswith("cvefixes-unch-"):
                fcid, s, e = rid[len("cvefixes-unch-"):].rsplit("-", 2)
                s, e = int(s), int(e)
                text, key = src.file_before(fcid), ("b", fcid)
            elif rid.startswith(("cvefixes-", "morefixes-")):
                m = src.method(rid.split("-", 1)[1])
                if m:
                    fcid, name, s, e, before, cb, ca = m
                    use_after = r.get("version") == "after_fix" or str(before) == "False"
                    text, key = (ca if use_after else cb), ("a" if use_after else "b", fcid)
                    s, e = int(s), int(e)
            elif rid.startswith("creddata-") and a.creddata_root:
                p = a.creddata_root / r["file"]
                if p.is_file():
                    text, key = p.read_text(encoding="utf-8", errors="replace"), ("c", r["file"])
                    s, e = int(r["start_line"]), int(r["end_line"])
            else:
                status = "kept_original"
            if status is None:
                if not text:
                    status = "no_source"
                else:
                    u, cover = best_unit(units_of(key, text, lang), s, e, name)
                    if u is None or cover < a.min_overlap:
                        status = "dropped_no_ts_function"
                    else:
                        same = (u["start"], u["end"]) == (s, e)
                        status = "same" if same else "rebuilt"
                        r = dict(r, code=u["code"], start_line=u["start"], end_line=u["end"],
                                 unit_orig_lines=[s, e])
            r["unit_rebuild"] = status
            table[(r.get("merge_source", "?"), r.get("language", "?"))][status] += 1
            if status == "dropped_no_ts_function":
                removed.append({"split": split, **r})
                continue
            if tok is not None and status == "rebuilt":
                n = len(tok(r["code"])["input_ids"])
                r["n_tokens"], r["over_512"] = n, n > 512
            out_rows.append(r)
        with (a.out / f"{split}.jsonl").open("w", encoding="utf-8") as fh:
            for r in out_rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"{split}: {len(out_rows)} mau -> {a.out / f'{split}.jsonl'}")
    with (a.out / "removed_ts.jsonl").open("w", encoding="utf-8") as fh:
        for r in removed:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    tot = collections.Counter()
    L = [f"# Dataset {a.out.name} - don vi tach lai bang tree-sitter", "",
         f"- Nguon: `{a.data}`; splits: {', '.join(a.splits)}; {treesitter_version()}",
         f"- Quy tac don vi: `ci/aiws_ci/units.py` (giong pipeline CI); khop ham: cung ten + chong dong >= {a.min_overlap}",
         "", "| Nguon | Ngon ngu | same | rebuilt | kept_original | dropped | no_source |", "|---|---|---|---|---|---|---|"]
    for (ms, lg), c in sorted(table.items()):
        tot.update(c)
        L.append(f"| {ms} | {lg} | {c['same']} | {c['rebuilt']} | {c['kept_original']} | "
                 f"{c['dropped_no_ts_function']} | {c['no_source']} |")
    L += ["", f"Tong: {dict(tot)}", "", "## sha256", ""]
    for split in a.splits + ["removed_ts"]:
        L.append(f"- {split}.jsonl: `{sha256(a.out / f'{split}.jsonl')}`")
    (a.out / "REBUILD_REPORT.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
