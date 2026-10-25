"""30_rule_pairs_diff.py - Tieu chi TC5 (ruleset v4.2): rule co PHAN BIET duoc ban loi va ban da va khong?

  python 30_rule_pairs_diff.py                                             # cap a01 train (dung de chinh rule)
  python 30_rule_pairs_diff.py --input data_versions/a01_pairs_v51/val.csv --out rule_pairs_diff_v42_val

Du lieu cap: moi pair_id co ban truoc khi va (`<id>_b`, co lo hong) va ban sau khi va (`<id>_a`).
Moi rule (custom, khong registry) duoc dem: so ban _b bao DUNG lop, so ban _b bao sai lop, so ban _a (da va)
van bi bao. Ban va trong a01 thuong chi khac ban loi ~2 dong (sink van con), nen ti le a/b_dung cua CA BO RULE
(muc nen) da gan 1. Moi rule duoc so voi muc nen (v4.2.1, thay nguong co dinh 0,30 cua ban dau):
  - "phan biet tot": a/b_dung <= HE_SO_TOT x muc nen (b_dung >= 5);
  - "kem hon muc nen": a/b_dung >= HE_SO_KEM x muc nen (b_dung >= 5) -> RA TAY (TC6) truoc khi ha tang/tat;
  - con lai: ngang muc nen, khong ket luan.
TC5 chi la tin hieu: khong tu no ha tang hay tat rule. "b sai lop" khong dong nghia bao nham (ham co the chua
them loi khac voi nhan cua mau).
Dau ra: reports/<out>.md va .csv. Khong dung tap test.
"""
import argparse, collections, csv, importlib.util, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("k03", ROOT / "21_rule_metrics.py")
k03 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k03)
sast = k03.sast
HE_SO_TOT, HE_SO_KEM, MIN_B = 0.5, 1.5, 5
RULESETS = {"v4.1": ROOT / "security-config" / "semgrep" / "archive" / "semgrep_v4.1.0.yml",
            "v4.2": ROOT / "security-config" / "semgrep" / "semgrep.yml"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, default=ROOT / "data_versions" / "a01_pairs_v51" / "train.csv")
    ap.add_argument("--out", default="rule_pairs_diff_v42_train")
    a = ap.parse_args()
    if "test" in a.input.name.lower():
        raise SystemExit("Khong duoc dung tap test de chon rule")
    rows = sast.read_test_rows(a.input, sast.parse_languages(["all"]))
    exe = sast.find_executable("semgrep")
    out = {}
    with tempfile.TemporaryDirectory(prefix="tc5_") as tmp:
        for tag, rules in RULESETS.items():
            print(f"[{tag}] quet {len(rows)} ham ({rules.relative_to(ROOT)}) ...", flush=True)
            per = k03.scan(rules, rows, exe, Path(tmp) / tag)
            st = collections.defaultdict(lambda: {"b_right": 0, "b_wrong": 0, "a_fixed": 0, "conf": ""})
            for r in rows:
                side = "b" if r["id"].endswith("_b") else "a"
                for rule in {f["rule"] for f in per.get(r["id"], [])}:
                    fs = [f for f in per[r["id"]] if f["rule"] == rule]
                    s = st[rule]
                    s["conf"] = fs[0]["confidence"]
                    if side == "a":
                        s["a_fixed"] += 1
                    elif any(r["cls_gt"] in f["classes"] for f in fs):
                        s["b_right"] += 1
                    else:
                        s["b_wrong"] += 1
            out[tag] = st
    with (ROOT / "reports" / f"{a.out}.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ruleset", "rule", "confidence", "b_right", "b_wrong", "a_fixed", "a_over_b_right"])
        for tag, st in out.items():
            for rule, s in sorted(st.items()):
                ratio = s["a_fixed"] / s["b_right"] if s["b_right"] else ""
                w.writerow([tag, rule, s["conf"], s["b_right"], s["b_wrong"], s["a_fixed"],
                            f"{ratio:.2f}" if ratio != "" else ""])
    md = [f"# TC5 - Rule phan biet ban loi / ban da va ({a.input.as_posix()})", "",
          f"{len(rows)} ham (cap _b/_a). b_dung = ban loi bao dung lop; a = ban da va van bi bao.", ""]
    for tag, st in out.items():
        tb = sum(s["b_right"] for s in st.values()); ta = sum(s["a_fixed"] for s in st.values())
        md.append(f"- {tag}: tong b_dung {tb}, b_sai {sum(s['b_wrong'] for s in st.values())}, a (da va) {ta}")
    st42 = out["v4.2"]
    base = sum(s["a_fixed"] for s in st42.values()) / max(sum(s["b_right"] for s in st42.values()), 1)
    md += ["", f"**Muc nen v4.2: a/b_dung = {base:.2f}.** Phan biet tot: <= {HE_SO_TOT * base:.2f}; "
           f"kem hon muc nen: >= {HE_SO_KEM * base:.2f} (chi xet khi b_dung >= {MIN_B}).", "",
           "## Tung rule v4.2", "", "| Rule | Tang | b_dung | b_sai lop | a (da va) | a/b_dung | Danh gia |",
           "|---|---|---:|---:|---:|---:|---|"]
    for rule, s in sorted(st42.items(), key=lambda x: -(x[1]["b_right"] + x[1]["a_fixed"])):
        r = s["a_fixed"] / s["b_right"] if s["b_right"] else None
        if s["b_right"] < MIN_B:
            verdict = "chua du mau"
        elif r <= HE_SO_TOT * base:
            verdict = "phan biet tot"
        elif r >= HE_SO_KEM * base:
            verdict = "kem hon muc nen -> ra tay (TC6)"
        else:
            verdict = "ngang muc nen"
        md.append(f"| `{rule}` | {s['conf']} | {s['b_right']} | {s['b_wrong']} | {s['a_fixed']} | "
                  f"{'-' if r is None else f'{r:.2f}'} | {verdict} |")
    (ROOT / "reports" / f"{a.out}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"Xong: reports/{a.out}.md, .csv")


if __name__ == "__main__":
    main()
