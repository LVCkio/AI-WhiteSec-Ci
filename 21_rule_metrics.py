"""21_rule_metrics.py - K03: do chat luong TUNG rule Semgrep (v3 rules/custom vs v4 security-config) tren VAL.

  python 21_rule_metrics.py                       # val v5, ca 4 ngon ngu
  python 21_rule_metrics.py --input data/val.csv  # val Python (v2)

Chi chay custom rules cua nhom (khong registry, khong Bandit) de tach dong gop cua tung rule.
Do moi rule: so mau bi bao (finding thuoc 6 lop), so mau bao DUNG lop (= cls_gt), precision theo lop,
so mau chi rule do bat dung (unique). Do ca bo rule theo ngon ngu x lop: recall (co it nhat 1 finding
dung lop), recall tang high, ti le PASS. Danh dau rule `high` co precision < 0,8 voi >= 5 lan bao.
Luu y: du lieu chi gom code CO lo hong -> "precision" o day la do dung LOP, khong do bao nham tren code an toan.
KHONG dung tap test. Dau ra: reports/rule_metrics_v4.md, reports/rule_metrics_v4.csv, reports/rule_metrics_v4.json
"""
import argparse, collections, csv, importlib.util, json, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sast", ROOT / "03_run_sast.py")
sast = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sast)
RULESETS = {"v3": ROOT / "rules" / "custom",
            "v4.0": ROOT / "security-config" / "semgrep" / "archive" / "semgrep_v4.0.0.yml",
            "v4.1": ROOT / "security-config" / "semgrep" / "archive" / "semgrep_v4.1.0.yml",
            "v4.2": ROOT / "security-config" / "semgrep" / "semgrep.yml"}
CURRENT = "v4.2"


def short_id(check_id: str) -> str:
    i = check_id.find("team.")
    return check_id[i:] if i >= 0 else check_id


def scan(rules: Path, rows, exe, workdir: Path):
    samples = workdir / "samples"
    samples.mkdir(parents=True, exist_ok=True)
    by_file = {}
    for i, row in enumerate(rows):
        name = sast.sample_name(i, row)
        text, _ = sast.wrap_fragment(sast.normalize_code(row["code"]), row["programming_language"])
        (samples / name).write_text(text, encoding="utf-8")
        by_file[name] = row
    findings = sast.run_semgrep(exe, [str(rules)], samples, workdir / "semgrep.json")
    per_sample = collections.defaultdict(list)
    for f in findings:
        row = by_file.get(f["sample_file"])
        if row is None or not f["classes"]:
            continue
        per_sample[row["id"]].append({"rule": short_id(f["rule_id"]), "classes": f["classes"],
                                      "confidence": f["confidence"]})
    return per_sample


def rule_table(rows, per_sample):
    stats = collections.defaultdict(lambda: {"hits": 0, "correct": 0, "unique": 0, "confidence": "",
                                             "languages": set(), "classes": set()})
    gt = {r["id"]: r for r in rows}
    for sid, fs in per_sample.items():
        g = gt[sid]["cls_gt"]
        correct_rules = {f["rule"] for f in fs if g in f["classes"]}
        for rule in {f["rule"] for f in fs}:
            s = stats[rule]
            s["hits"] += 1
            s["correct"] += rule in correct_rules
            s["unique"] += correct_rules == {rule}
            s["languages"].add(gt[sid]["programming_language"])
        for f in fs:
            stats[f["rule"]]["confidence"] = f["confidence"]
            stats[f["rule"]]["classes"].update(f["classes"])
    return stats


def coverage(rows, per_sample):
    cell = collections.defaultdict(lambda: {"n": 0, "any": 0, "high": 0, "pass": 0})
    for r in rows:
        c = cell[(r["programming_language"], r["cls_gt"])]
        fs = per_sample.get(r["id"], [])
        c["n"] += 1
        c["pass"] += not fs
        c["any"] += any(r["cls_gt"] in f["classes"] for f in fs)
        c["high"] += any(r["cls_gt"] in f["classes"] and f["confidence"] == "high" for f in fs)
    return cell


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, default=ROOT / "data_versions" / "v5_multilang" / "val.csv")
    ap.add_argument("--languages", nargs="+", default=["all"])
    ap.add_argument("--out", default="rule_metrics_v4")
    a = ap.parse_args()
    if "test" in a.input.name.lower():
        raise SystemExit("K03 khong duoc dung tap test")
    rows = sast.read_test_rows(a.input, sast.parse_languages(a.languages))
    exe = sast.find_executable("semgrep")
    results = {}
    with tempfile.TemporaryDirectory(prefix="k03_") as tmp:
        for tag, rules in RULESETS.items():
            print(f"[{tag}] quet {len(rows)} mau bang {rules.relative_to(ROOT)} ...", flush=True)
            per_sample = scan(rules, rows, exe, Path(tmp) / tag)
            results[tag] = {"rules": rule_table(rows, per_sample), "cells": coverage(rows, per_sample)}
    out_csv = ROOT / "reports" / f"{a.out}.csv"
    flagged = []
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ruleset", "rule", "confidence", "languages", "classes", "hits", "correct", "precision", "unique_correct"])
        for tag in RULESETS:
            for rule, s in sorted(results[tag]["rules"].items()):
                p = s["correct"] / s["hits"] if s["hits"] else ""
                w.writerow([tag, rule, s["confidence"], "/".join(sorted(s["languages"])),
                            "/".join(sorted(s["classes"])), s["hits"], s["correct"],
                            f"{p:.3f}" if p != "" else "", s["unique"]])
                if tag == CURRENT and s["confidence"] == "high" and s["hits"] >= 5 and p < 0.8:
                    flagged.append((rule, s["hits"], s["correct"], p))
    tags = list(RULESETS)
    md = [f"# K03 - Do tung rule Semgrep ({a.input.as_posix()})", "",
          f"So mau: {len(rows)}. Chi custom rules cua nhom (khong registry, khong Bandit). "
          "Precision = ti le bao DUNG lop tren mau co lo hong; khong do bao nham tren code an toan. Khong dung test.", "",
          "## Bo rule theo ngon ngu x lop", "",
          "Recall = ti le mau co it nhat 1 finding dung lop (bat ky tang / tang high).", "",
          "| Ngon ngu | Lop | n | " + " | ".join(f"Recall {t}" for t in tags) + " | "
          + " | ".join(f"High {t}" for t in tags) + " |",
          "|---|---|---:|" + "---:|" * (2 * len(tags))]
    keys = sorted(set().union(*[set(results[t]["cells"]) for t in tags]))
    tot = {t: {"n": 0, "any": 0, "high": 0} for t in tags}
    for k in keys:
        cs = [results[t]["cells"][k] for t in tags]
        n = max(c["n"] for c in cs)
        pct = lambda x: f"{x / n:.2f}" if n else "-"
        md.append(f"| {k[0]} | {k[1]} | {n} | " + " | ".join(pct(c["any"]) for c in cs) + " | "
                  + " | ".join(pct(c["high"]) for c in cs) + " |")
        for t, c in zip(tags, cs):
            for x in ("n", "any", "high"):
                tot[t][x] += c[x]
    md.append("| **Tong** | | " + str(tot[tags[-1]]["n"]) + " | "
              + " | ".join(f"**{tot[t]['any'] / max(tot[t]['n'], 1):.3f}**" for t in tags) + " | "
              + " | ".join(f"{tot[t]['high'] / max(tot[t]['n'], 1):.3f}" for t in tags) + " |")
    for t in tags:
        hits = sum(s["hits"] for s in results[t]["rules"].values())
        corr = sum(s["correct"] for s in results[t]["rules"].values())
        md.append(f"\n- {t}: {hits} lan rule bao (theo mau x rule), {corr} dung lop -> precision lop {corr / max(hits, 1):.3f}")
    md += ["", f"## Tung rule {CURRENT}", "", "| Rule | Tang | Ngon ngu | Bao | Dung lop | Precision | Chi rule nay bat dung |",
           "|---|---|---|---:|---:|---:|---:|"]
    for rule, s in sorted(results[CURRENT]["rules"].items(), key=lambda x: -x[1]["hits"]):
        p = f"{s['correct'] / s['hits']:.2f}" if s["hits"] else "-"
        md.append(f"| `{rule}` | {s['confidence']} | {'/'.join(sorted(s['languages']))} | {s['hits']} | "
                  f"{s['correct']} | {p} | {s['unique']} |")
    silent = sorted(set(sast_rule_ids(RULESETS[CURRENT])) - set(results[CURRENT]["rules"]))
    md += ["", f"Rule {CURRENT} khong bao lan nao ({len(silent)}): " + (", ".join(f"`{r}`" for r in silent) or "khong co"), "",
           "## Rule `high` can xem lai (precision < 0,8 va >= 5 lan bao)", ""]
    md += [f"- `{r}`: {c}/{h} = {p:.2f}" for r, h, c, p in flagged] or ["- Khong co."]
    (ROOT / "reports" / f"{a.out}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    json.dump({t: {"cells": {f"{k[0]}|{k[1]}": v for k, v in results[t]["cells"].items()}} for t in RULESETS},
              open(ROOT / "reports" / f"{a.out}.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"Xong: reports/{a.out}.md, .csv, .json; rule high can xem lai: {len(flagged)}")


def sast_rule_ids(bundle: Path):
    import yaml
    return [r["id"] for r in yaml.safe_load(bundle.read_text(encoding="utf-8"))["rules"]]


if __name__ == "__main__":
    main()
