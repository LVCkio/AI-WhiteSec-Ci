"""34_baseline_v22.py - R1 (docs/semgrep_tool.md muc 8.2): do nen bo rule Semgrep tren train/val dataset v2.2.

  python 34_baseline_v22.py --split train
  python 34_baseline_v22.py --split val

Doc v2.2/<split>.jsonl (KHONG doc test). Moi mau quet rieng (che do dataset, taxonomy.yml join_rule).
Dau ra (security-config/semgrep/reports/):
  r1_baseline_v22_<split>_<ngay>.md    bang 24 o (ngon ngu x lop), ti le parse, bao nham tren mau am, tung rule
  r1_baseline_v22_<split>_<ngay>.csv   tung mau: nhan, parse, finding (khong chua code)
  r1_baseline_v22_<split>_<ngay>_rules.csv  tung rule: so lan bao tren mau duong / dung lop / mau am
  r1_fn_v22_train_<ngay>.csv           (chi train) mau duong bi sot, khong chua code: dung de tim khoang trong (R4)
Chi so (semgrep_tool.md 5.5): Recall mau (high; high+audit), Ti le dung lop (KHONG phai precision),
Ti le bao nham tren mau am, Ti le parse. Script khong sua dataset, khong dung ket qua lam nhan.
"""
import argparse, collections, csv, datetime, hashlib, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sast", ROOT / "03_run_sast.py")
sast = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sast)

SEMGREP_DIR = ROOT / "security-config" / "semgrep"
REPORTS = SEMGREP_DIR / "reports"
NEG = "NEGATIVE"
NEG_NAME = "Mẫu âm (không thuộc 6 nhóm)"
DISPLAY = {"AUTHENTICATION_WEAKNESS": "INSECURE_AUTHENTICATION"}   # ten trong taxonomy v0.3.0
LANGS = ("Python", "Java", "JavaScript", "PHP")
REQUIRED_SEMGREP = "1.181.0"


def disp(c):
    return NEG_NAME if c == NEG else DISPLAY.get(c, c)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load_rows(path: Path):
    rows = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            labels = r.get("labels") or []
            if len(labels) > 1:
                raise SystemExit(f"{r['id']}: nhieu nhan {labels} - script chua xu ly, dung lai va hoi")
            lang = sast.canonical_language(r["language"])
            if lang not in LANGS:
                raise SystemExit(f"{r['id']}: ngon ngu la {r['language']!r}")
            cls = sast.canonical_class(labels[0]) if labels else NEG
            if cls != NEG and cls not in sast.CLASSES:
                raise SystemExit(f"{r['id']}: nhan ngoai 6 lop {labels}")
            rows.append({"id": r["id"], "code": r["code"], "programming_language": lang, "cls_gt": cls,
                         "unit": r.get("unit", ""), "over_512": bool(r.get("over_512")),
                         "n_tokens": r.get("n_tokens", ""), "source": r.get("merge_source", ""),
                         "repo": r.get("repo_url", ""), "file": r.get("file", ""),
                         "signature": r.get("signature", ""), "cwe": ";".join(r.get("canonical_cwe_ids") or []),
                         "review_status": r.get("review_status", "")})
    ids = [r["id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit("id trung lap")
    return rows


def short_id(check_id):
    i = check_id.find("team.")
    return check_id[i:] if i >= 0 else check_id


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--split", choices=["train", "val"], required=True)
    ap.add_argument("--data", type=Path, default=ROOT.parent / "dataset_model" / "dataset" / "v2.3")
    ap.add_argument("--rules", type=Path, default=SEMGREP_DIR / "semgrep.yml")
    ap.add_argument("--keep-raw", action="store_true", help="giu semgrep.json tho trong sast_results/r1_v22/")
    a = ap.parse_args()
    data_file = a.data / f"{a.split}.jsonl"
    if "test" in data_file.name.lower():
        raise SystemExit("R1 khong duoc dung tap test")
    exe = sast.find_executable("semgrep")
    ver = sast.run_command([exe, "--version"]).stdout.strip().splitlines()[-1].strip()
    if ver != REQUIRED_SEMGREP:
        raise SystemExit(f"Semgrep {ver} != {REQUIRED_SEMGREP}: dung lai")
    manifest = json.loads((SEMGREP_DIR / "ruleset-manifest.json").read_text(encoding="utf-8"))
    card = a.data / "DATA_CARD.md"
    head = {"dataset_version": a.data.name, "split": a.split, "split_file": data_file.name,
            "split_file_sha256": sha256_file(data_file),
            "data_card_sha256": sha256_file(card) if card.is_file() else "",
            "semgrep_version": ver, "ruleset_version": manifest.get("ruleset_version", ""),
            "bundle_sha256": sha256_file(a.rules), "taxonomy": "docs/taxonomy.yml",
            "command": "python " + " ".join([Path(sys.argv[0]).name] + sys.argv[1:])}
    rows = load_rows(data_file)
    print(f"[{a.split}] {len(rows)} mau, Semgrep {ver}, ruleset {head['ruleset_version']}", flush=True)

    with tempfile.TemporaryDirectory(prefix="r1v22_") as tmp:
        samples = Path(tmp) / "samples"
        samples.mkdir()
        by_file = {}
        for i, r in enumerate(rows):
            name = sast.sample_name(i, r)
            text, _ = sast.wrap_fragment(sast.normalize_code(r["code"]), r["programming_language"])
            (samples / name).write_text(text, encoding="utf-8")
            by_file[name] = r
            r["sample_file"] = name
        raw = Path(tmp) / "semgrep.json"
        findings = sast.run_semgrep(exe, [str(a.rules)], samples, raw)
        status = sast.parse_status([raw])
        if a.keep_raw:
            dst = ROOT / "sast_results" / "r1_v22"
            dst.mkdir(parents=True, exist_ok=True)
            shutil.copy(raw, dst / f"semgrep_{a.split}.json")

    per = collections.defaultdict(list)
    for f in findings:
        r = by_file.get(f["sample_file"])
        if r is not None and f["classes"]:
            per[r["id"]].append({"rule": short_id(f["rule_id"]), "classes": f["classes"],
                                 "confidence": f["confidence"], "line": f["line"]})
    for r in rows:
        st = status.get(r["sample_file"], "ok")
        r["parse"] = {"error": "failed"}.get(st, st)
        fs = per.get(r["id"], [])
        r["n_findings"] = len(fs)
        r["hit_high"] = any(r["cls_gt"] in f["classes"] and f["confidence"] == "high" for f in fs)
        r["hit_any"] = any(r["cls_gt"] in f["classes"] for f in fs)
        r["any_high"] = any(f["confidence"] == "high" for f in fs)
        r["rules"] = sorted({f["rule"] for f in fs})

    date = datetime.date.today().isoformat()
    tag = f"r1_baseline_v22_{a.split}_{date}"
    REPORTS.mkdir(parents=True, exist_ok=True)

    # ---- tung mau (khong chua code)
    with (REPORTS / f"{tag}.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "language", "class", "unit", "over_512", "parse", "n_findings", "correct_high",
                    "correct_any", "rules"])
        for r in rows:
            w.writerow([r["id"], r["programming_language"], disp(r["cls_gt"]), r["unit"], r["over_512"], r["parse"],
                        r["n_findings"], int(r["hit_high"]), int(r["hit_any"]), ";".join(r["rules"])])

    # ---- tung rule
    rs = collections.defaultdict(lambda: {"conf": "", "pos_hits": 0, "pos_correct": 0, "neg_hits": 0,
                                          "classes": set(), "langs": set()})
    gt = {r["id"]: r for r in rows}
    for sid, fs in per.items():
        g = gt[sid]
        for rule in {f["rule"] for f in fs}:
            fr = [f for f in fs if f["rule"] == rule]
            s = rs[rule]
            s["conf"] = fr[0]["confidence"]
            s["classes"].update(c for f in fr for c in f["classes"])
            s["langs"].add(g["programming_language"])
            if g["cls_gt"] == NEG:
                s["neg_hits"] += 1
            else:
                s["pos_hits"] += 1
                s["pos_correct"] += any(g["cls_gt"] in f["classes"] for f in fr)
    with (REPORTS / f"{tag}_rules.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rule", "confidence", "languages", "classes", "pos_hits", "pos_correct", "class_rate",
                    "neg_hits", "tc4_verdict"])
        for rule, s in sorted(rs.items()):
            w.writerow([rule, s["conf"], "/".join(sorted(s["langs"])), "/".join(disp(c) for c in sorted(s["classes"])),
                        s["pos_hits"], s["pos_correct"],
                        f"{s['pos_correct'] / s['pos_hits']:.3f}" if s["pos_hits"] else "", s["neg_hits"],
                        verdict(s)])

    # ---- FN train
    if a.split == "train":
        with (REPORTS / f"r1_fn_v22_train_{date}.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["id", "language", "class", "cwe", "unit", "over_512", "n_tokens", "parse", "source",
                        "repo", "file", "signature", "other_rules"])
            for r in rows:
                if r["cls_gt"] != NEG and not r["hit_any"]:
                    w.writerow([r["id"], r["programming_language"], disp(r["cls_gt"]), r["cwe"], r["unit"],
                                r["over_512"], r["n_tokens"], r["parse"], r["source"], r["repo"], r["file"],
                                r["signature"], ";".join(r["rules"])])

    write_md(REPORTS / f"{tag}.md", head, rows, rs, a.split, date)
    print(f"Xong: {tag}.md/.csv/_rules.csv" + (f", r1_fn_v22_train_{date}.csv" if a.split == "train" else ""))


def verdict(s):
    n = s["pos_hits"]
    if n < 5:
        return "chua du du lieu (<5)"
    p = s["pos_correct"] / n
    thr = 0.80 if s["conf"] == "high" else 0.50
    return "dat" if p >= thr else f"rot ({'high' if s['conf'] == 'high' else 'audit'} < {thr:.2f})"


def pct(x, n):
    return f"{x / n:.2f}" if n else "-"


def write_md(path, head, rows, rs, split, date):
    classes = list(sast.CLASSES)
    md = [f"# R1 · Đo nền Semgrep trên {split} dataset v2.2", "",
          f"- Ngày: {date}",
          f"- Dataset: v2.2 · file `{head['split_file']}` sha256 `{head['split_file_sha256']}`",
          f"- DATA_CARD sha256: `{head['data_card_sha256']}`",
          f"- Semgrep {head['semgrep_version']} · ruleset {head['ruleset_version']} · bundle sha256 `{head['bundle_sha256']}`",
          f"- Lệnh: `{head['command']}`",
          "- Chế độ dataset: mỗi mẫu quét riêng; đoạn hàm được bọc cho parse được (`wrap_fragment` của 03_run_sast.py).",
          "- Không đọc, không quét tập test.", ""]
    # parse
    md += ["## 1. Tỉ lệ parse (đo trước khi diễn giải recall)", "",
           "| Ngôn ngữ | Mẫu | ok | partial | failed | Tỉ lệ ok |", "|---|---:|---:|---:|---:|---:|"]
    for lang in LANGS:
        rr = [r for r in rows if r["programming_language"] == lang]
        c = collections.Counter(r["parse"] for r in rr)
        md.append(f"| {lang} | {len(rr)} | {c['ok']} | {c['partial']} | {c['failed']} | {pct(c['ok'], len(rr))} |")
    c = collections.Counter(r["parse"] for r in rows)
    md.append(f"| **Tổng** | {len(rows)} | {c['ok']} | {c['partial']} | {c['failed']} | {pct(c['ok'], len(rows))} |")
    # 24 o
    md += ["", "## 2. Bảng 24 ô (ngôn ngữ × lớp) – mẫu dương", "",
           "Recall mẫu = mẫu có ≥ 1 finding đúng lớp / số mẫu. `parse ok` = số mẫu parse không lỗi.", "",
           "| Lớp | Ngôn ngữ | n | parse ok | Recall high | Recall high+audit |", "|---|---|---:|---:|---:|---:|"]
    tot = collections.Counter()
    for cls in classes:
        for lang in LANGS:
            rr = [r for r in rows if r["cls_gt"] == cls and r["programming_language"] == lang]
            n = len(rr)
            h = sum(r["hit_high"] for r in rr); a_ = sum(r["hit_any"] for r in rr); ok = sum(r["parse"] == "ok" for r in rr)
            tot.update(n=n, h=h, a=a_)
            md.append(f"| {disp(cls)} | {lang} | {n} | {ok} | {pct(h, n)} ({h}) | {pct(a_, n)} ({a_}) |")
        rr = [r for r in rows if r["cls_gt"] == cls]
        md.append(f"| **{disp(cls)}** | *cả lớp* | {len(rr)} | | **{pct(sum(r['hit_high'] for r in rr), len(rr))}** | "
                  f"**{pct(sum(r['hit_any'] for r in rr), len(rr))}** |")
    md.append(f"| **Tổng mẫu dương** | | {tot['n']} | | **{pct(tot['h'], tot['n'])}** | **{pct(tot['a'], tot['n'])}** |")
    # over_512
    md += ["", "### Tách theo `over_512` (mẫu dương)", "", "| over_512 | n | Recall high | Recall high+audit |", "|---|---:|---:|---:|"]
    for flag in (False, True):
        rr = [r for r in rows if r["cls_gt"] != NEG and r["over_512"] == flag]
        md.append(f"| {str(flag).lower()} | {len(rr)} | {pct(sum(r['hit_high'] for r in rr), len(rr))} | "
                  f"{pct(sum(r['hit_any'] for r in rr), len(rr))} |")
    # ti le dung lop
    pos_f = sum(rs[x]["pos_hits"] for x in rs); pos_c = sum(rs[x]["pos_correct"] for x in rs)
    md += ["", "## 3. Tỉ lệ đúng lớp (không phải precision)", "",
           f"Trên mẫu dương: {pos_c}/{pos_f} cặp (mẫu, rule) báo đúng lớp = **{pct(pos_c, pos_f)}**.", ""]
    # bao nham mau am
    md += ["## 4. Tỉ lệ báo nhầm trên mẫu âm", "",
           "| Ngôn ngữ | Mẫu âm | Có finding (bất kỳ tầng) | Có finding high | Tỉ lệ (bất kỳ) | Tỉ lệ (high) |",
           "|---|---:|---:|---:|---:|---:|"]
    for lang in list(LANGS) + ["Tổng"]:
        rr = [r for r in rows if r["cls_gt"] == NEG and (lang == "Tổng" or r["programming_language"] == lang)]
        f_any = sum(r["n_findings"] > 0 for r in rr); f_high = sum(r["any_high"] for r in rr)
        md.append(f"| {lang} | {len(rr)} | {f_any} | {f_high} | {pct(f_any, len(rr))} | {pct(f_high, len(rr))} |")
    # tung rule
    md += ["", "## 5. Từng rule (TC4 trên split này)", "",
           "Ngưỡng: high ≥ 0,80; audit ≥ 0,50; cần ≥ 5 lần báo trên mẫu dương. `Mẫu âm` = số mẫu âm rule báo.", "",
           "| Rule | Tầng | Báo (mẫu dương) | Đúng lớp | Tỉ lệ | Mẫu âm | TC4 |", "|---|---|---:|---:|---:|---:|---|"]
    for rule, s in sorted(rs.items(), key=lambda x: (-x[1]["pos_hits"], x[0])):
        md.append(f"| `{rule}` | {s['conf']} | {s['pos_hits']} | {s['pos_correct']} | "
                  f"{pct(s['pos_correct'], s['pos_hits'])} | {s['neg_hits']} | {verdict(s)} |")
    try:
        import yaml
        all_ids = {short_id(r["id"]) for r in yaml.safe_load((SEMGREP_DIR / "semgrep.yml").read_text(encoding="utf-8"))["rules"]}
        silent = sorted(all_ids - set(rs))
        md += ["", f"Rule không báo lần nào trên {split} ({len(silent)}): " + (", ".join(f"`{x}`" for x in silent) or "không có")]
    except Exception as e:  # yaml thieu thi bo qua muc nay
        md += ["", f"(Không liệt kê được rule im lặng: {e})"]
    md += ["", "## Điều chưa chắc chắn", "",
           "- Mẫu là đoạn hàm cắt ra; `wrap_fragment` bọc thêm class/`<?php` để parse. Mẫu parse lỗi vẫn được tính vào mẫu số recall.",
           "- `module_snippet` (HARDCODED, nguồn CredData) là ±5 dòng quanh credential, có thể không phải code hoàn chỉnh.",
           "- Taint của Semgrep CE chỉ trong một hàm; đơn vị mẫu là một hàm nên luồng liên hàm không được tính.",
           "- Tỉ lệ đúng lớp tính trên mẫu dương, không đo báo nhầm trên code an toàn; báo nhầm xem mục 4.",
           "- Nhãn của phần lớn mẫu là UNREVIEWED theo DATA_CARD v2.2.",
           "- Bộ rule v4.x đã được chỉnh trên dữ liệu v5/a01 trùng repo với một phần v2.2 (xem r1_overlap_v22): số trên train/val v2.2 có thể lạc quan."]
    path.write_text("\n".join(md) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
