"""
33_overlap_keys.py - R1 (docs/semgrep_tool.md muc 8.4): kiem tra chong lan giua du lieu da dung de chinh rule
Semgrep v4.2 va tap test cua dataset v2.2. Khong mo noi dung mau test: chi so khoa va dem.

Buoc 1 (chay tren may co du lieu chinh rule, vd. may cua thanh vien viet rule):
  python 33_overlap_keys.py extract
  -> security-config/semgrep/reports/r1_tuning_keys_<ngay>.csv   (khoa cua tung mau, KHONG chua code)
     security-config/semgrep/reports/r1_tuning_keys_<ngay>.json  (nguon, sha256 tung file, so mau)

Buoc 2 (chay tren may giu dataset v2.2, vd. may leader):
  python 33_overlap_keys.py compare --test <duong dan test v2.2 (.csv/.jsonl/.parquet)> --keys <file .csv buoc 1>
  -> security-config/semgrep/reports/r1_overlap_v22_<ngay>.md + .csv (chi khoa trung va so luong)
     ...r1_overlap_v22_<ngay>_tuning_subset.csv: cac mau CHINH RULE bi trung (de chay lai 21_rule_metrics.py
     --input tren rieng tap nay, xem rule nao duoc chinh tu mau trung). Khong ghi gi cua mau test ngoai khoa.

Ba khoa (theo muc 8.4): (a) repo, (b) commit / CVE, (c) sha256 cua code da chuan hoa khoang trang
(gop moi khoang trang lien tiep thanh mot dau cach, bo dau/cuoi). Test v2.2 tach theo repo nen khoa repo quan trong nhat.
Ten cot cua test v2.2 duoc tu nhan (--code-col/--repo-col/... de chi dinh khi khac).
"""
import argparse, csv, datetime, hashlib, json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "security-config" / "semgrep" / "reports"
# Du lieu da dung de chinh / do rule truoc v4.3 (khong co tap test nao):
#   v5_multilang train/val: 21_rule_metrics.py (TC2, TC4) cho v4.0-v4.2; a01_pairs_v51 train/val: 30_rule_pairs_diff.py (TC5);
#   data/ train/val (Python v2): chinh rule v3 (con giu trong v4); v5_1_e03 train/val: nguon cua cap a01.
TUNING_SOURCES = [
    ("v5_multilang", "train", "data_versions/v5_multilang/train.csv"),
    ("v5_multilang", "val", "data_versions/v5_multilang/val.csv"),
    ("a01_pairs_v51", "train", "data_versions/a01_pairs_v51/train.csv"),
    ("a01_pairs_v51", "val", "data_versions/a01_pairs_v51/val.csv"),
    ("v5_1_e03", "train", "data_versions/v5_1_e03/train.csv"),
    ("v5_1_e03", "val", "data_versions/v5_1_e03/val.csv"),
    ("data_v2", "train", "data/train.csv"),
    ("data_v2", "val", "data/val.csv"),
]
# 4 ung dung muc tieu da duoc ra tay khi chinh v4.2 (TC6) - chi so theo repo.
TARGET_REPOS = {"dvwa": "github.com/digininja/dvwa", "webgoat": "github.com/webgoat/webgoat",
                "juice-shop": "github.com/juice-shop/juice-shop", "flask_vuln_app": "local/flask_vuln_app"}
KEY_COLS = ["source_dataset", "split", "id", "language", "cls_gt", "repo", "commit", "cve", "code_sha256"]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
REPO_RE = re.compile(r"(?:https?://)?(?:www\.)?(github\.com|gitlab\.com|bitbucket\.org)[/:]([^/\s#?]+)/([^/\s#?]+)", re.I)
GUESS = {
    "code": ["code", "func", "func_before", "function_code", "source", "code_before", "before"],
    "repo": ["repo", "repo_name", "repository", "project", "repo_url", "project_url"],
    "commit": ["commit", "commit_id", "commit_hash", "commit_url", "hash", "sha", "fix_commit"],
    "cve": ["cve", "cve_id", "cve_ids"],
    "id": ["id", "sample_id", "idx", "uid"],
    "link": ["report_link", "url", "advisory", "reference"],
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def norm_code(code):
    return re.sub(r"\s+", " ", str(code or "")).strip()


def code_key(code):
    c = norm_code(code)
    return hashlib.sha256(c.encode("utf-8")).hexdigest() if c else ""


def norm_repo(*values):
    """'https://github.com/Owner/Repo/commit/..' | 'owner/repo' -> 'github.com/owner/repo'."""
    for v in values:
        v = str(v or "").strip()
        if not v:
            continue
        m = REPO_RE.search(v)
        if m:
            name = re.sub(r"\.git$", "", m.group(3).lower())
            return f"{m.group(1).lower()}/{m.group(2).lower()}/{name}"
        if re.fullmatch(r"[\w.-]+/[\w.-]+", v):
            return "github.com/" + re.sub(r"\.git$", "", v.lower())
    return ""


def norm_commit(*values):
    for v in values:
        v = str(v or "").strip()
        m = re.search(r"/commits?/([0-9a-f]{7,40})", v, re.I)
        if m:
            return m.group(1).lower()
        if re.fullmatch(r"[0-9a-f]{7,40}", v, re.I):  # chi nhan chuoi hex dung mot minh, tranh bat nham trong URL/ten
            return v.lower()
    return ""


def norm_cve(*values):
    found = []
    for v in values:
        found += [c.upper() for c in CVE_RE.findall(str(v or ""))]
    return ";".join(sorted(set(found)))


def read_rows(path):
    """CSV / JSONL / Parquet -> iterator of dict. Khong in noi dung."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in (".jsonl", ".json"):
        with open(path, encoding="utf-8") as fh:
            if suffix == ".json":
                data = json.load(fh)
                yield from (data if isinstance(data, list) else data.get("data", []))
            else:
                for line in fh:
                    if line.strip():
                        yield json.loads(line)
    elif suffix == ".parquet":
        import pandas as pd  # chi khi test v2.2 la parquet
        yield from pd.read_parquet(path).to_dict("records")
    else:
        csv.field_size_limit(1 << 30)
        with open(path, encoding="utf-8-sig", newline="") as fh:
            yield from csv.DictReader(fh)


def pick(columns, kind, explicit=None):
    if explicit:
        if explicit not in columns:
            raise SystemExit(f"khong co cot '{explicit}' trong file test (cac cot: {sorted(columns)})")
        return explicit
    low = {c.lower(): c for c in columns}
    return next((low[g] for g in GUESS[kind] if g in low), None)


# ------------------------------------------------------------------------------------------- extract
def extract(a):
    out_rows, sources = [], []
    for name, split, rel in TUNING_SOURCES:
        p = ROOT / rel
        if not p.is_file():
            sources.append({"source_dataset": name, "split": split, "file": rel, "missing": True})
            continue
        n = 0
        for r in read_rows(p):
            out_rows.append({"source_dataset": name, "split": split, "id": r.get("id", ""),
                             "language": r.get("programming_language", ""), "cls_gt": r.get("cls_gt", ""),
                             "repo": norm_repo(r.get("commit"), r.get("report_link"), r.get("repo")),
                             "commit": norm_commit(r.get("commit")),
                             "cve": norm_cve(r.get("report_link"), r.get("commit"), r.get("cve")),
                             "code_sha256": code_key(r.get("code"))})
            n += 1
        sources.append({"source_dataset": name, "split": split, "file": rel, "sha256": sha256_file(p), "rows": n})
    for app, repo in TARGET_REPOS.items():
        out_rows.append({"source_dataset": "targets_tc6", "split": "review", "id": app, "language": "", "cls_gt": "",
                         "repo": repo, "commit": "", "cve": "", "code_sha256": ""})
    REPORTS.mkdir(parents=True, exist_ok=True)
    stem = a.out or f"r1_tuning_keys_{datetime.date.today().isoformat()}"
    with open(REPORTS / f"{stem}.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=KEY_COLS)
        w.writeheader()
        w.writerows(out_rows)
    meta = {"created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "script": "33_overlap_keys.py extract", "normalization": "code: gop khoang trang -> 1 dau cach, strip; sha256 utf-8",
            "sources": sources, "rows": len(out_rows),
            "unique": {k: len({r[k] for r in out_rows if r[k]}) for k in ("repo", "commit", "cve", "code_sha256")}}
    (REPORTS / f"{stem}.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(out_rows)} khoa -> {(REPORTS / (stem + '.csv')).relative_to(ROOT)}")
    for s in sources:
        print(f"  {s['source_dataset']}/{s['split']}: " + ("THIEU FILE" if s.get("missing") else f"{s['rows']} mau"))
    print("  khoa khac nhau:", meta["unique"])


# ------------------------------------------------------------------------------------------- compare
def compare(a):
    keys = list(read_rows(a.keys))
    if not keys or set(KEY_COLS) - set(keys[0]):
        raise SystemExit(f"{a.keys} khong phai file khoa cua buoc extract")
    index = {k: defaultdict(list) for k in ("repo", "commit", "cve", "code_sha256")}
    for r in keys:
        for k in index:
            for v in (r[k].split(";") if k == "cve" else [r[k]]):
                if v:
                    index[k][v].append(r)
    rows = read_rows(a.test)
    first = next(rows, None)
    if first is None:
        raise SystemExit("file test rong")
    cols = list(first.keys())
    col = {k: pick(cols, k, getattr(a, f"{k}_col", None)) for k in ("code", "repo", "commit", "cve", "id", "link")}
    print("Cot dung de so khop:", {k: v for k, v in col.items() if v})
    if not any(col[k] for k in ("code", "repo", "commit")):
        raise SystemExit("khong nhan duoc cot code/repo/commit nao; chi dinh bang --code-col/--repo-col/--commit-col")
    test_n, hits, test_repos = 0, [], Counter()
    matched_tuning = {}
    tuning_by_type = {k: set() for k in index}
    def scan(r, i):
        g = lambda k: r.get(col[k]) if col[k] else None
        tid = str(g("id")) if col["id"] and g("id") not in (None, "") else f"row{i}"
        tkeys = {"repo": norm_repo(g("repo"), g("commit"), g("link")), "commit": norm_commit(g("commit")),
                 "cve": norm_cve(g("cve"), g("link"), g("commit")), "code_sha256": code_key(g("code")) if col["code"] else ""}
        if tkeys["repo"]:
            test_repos[tkeys["repo"]] += 1
        for k, v in tkeys.items():
            for val in (v.split(";") if k == "cve" else [v]):
                matches = index[k].get(val, []) if val else []
                if not matches:
                    continue
                # mot dong cho moi (khoa, mau test); khong nhan theo tung mau chinh rule de file khong phinh khi trung repo
                hits.append({"key_type": k, "key": val, "test_id": tid, "tuning_matches": len(matches),
                             "tuning_sources": ";".join(sorted({f"{t['source_dataset']}/{t['split']}" for t in matches}))})
                for t in matches:
                    ref = (t["source_dataset"], t["split"], t["id"])
                    tuning_by_type[k].add(ref)
                    matched_tuning[ref] = t
    scan(first, 0)
    test_n = 1
    for i, r in enumerate(rows, 1):
        scan(r, i)
        test_n += 1
    REPORTS.mkdir(parents=True, exist_ok=True)
    stem = a.out or f"r1_overlap_v22_{datetime.date.today().isoformat()}"
    with open(REPORTS / f"{stem}.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["key_type", "key", "test_id", "tuning_matches", "tuning_sources"])
        w.writeheader()
        w.writerows(hits)
    by_type = Counter(h["key_type"] for h in hits)
    tests_by_type = {k: len({h["test_id"] for h in hits if h["key_type"] == k}) for k in index}
    tuning_by_type = {k: len(v) for k, v in tuning_by_type.items()}
    repos = Counter(h["key"] for h in hits if h["key_type"] == "repo")  # so mau test trung theo repo
    # tap con mau CHINH RULE bi trung (lay tu file du lieu cua nhom, khong lay tu test) de chay lai 21_rule_metrics.py
    subset = []
    wanted = defaultdict(set)
    for (src, split, tid) in matched_tuning:
        wanted[(src, split)].add(tid)
    for name, split, rel in TUNING_SOURCES:
        ids = wanted.get((name, split))
        if ids and (ROOT / rel).is_file():
            subset += [dict(r, source_dataset=name, split_origin=split) for r in read_rows(ROOT / rel) if r.get("id") in ids]
    if subset:
        cols_sub = list(dict.fromkeys(k for r in subset for k in r))
        with open(REPORTS / f"{stem}_tuning_subset.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols_sub)
            w.writeheader()
            w.writerows(subset)
    tsha = sha256_file(a.test)
    L = [f"# R1 · Kiểm tra chồng lấn: dữ liệu chỉnh rule v4.2 ↔ test v2.2", "",
         f"- Ngày: {datetime.date.today().isoformat()}. Script: `33_overlap_keys.py compare` (không mở nội dung mẫu test, chỉ so khóa).",
         f"- File test: `{Path(a.test).name}` · sha256 `{tsha}` · {test_n} mẫu · cột dùng: " + ", ".join(f"{k}=`{v}`" for k, v in col.items() if v),
         f"- File khóa: `{Path(a.keys).name}` · sha256 `{sha256_file(a.keys)}` · {len(keys)} khóa",
         f"- Chuẩn hóa: repo `host/owner/repo` chữ thường; commit = sha hex; CVE chữ hoa; code: gộp khoảng trắng rồi sha256.", "",
         "## Kết quả", "", "| Khóa | Cặp (khóa, mẫu test) trùng | Mẫu test bị trùng | Mẫu chỉnh rule bị trùng |", "|---|---:|---:|---:|"]
    for k in ("repo", "commit", "cve", "code_sha256"):
        L.append(f"| {k} | {by_type.get(k, 0)} | {tests_by_type[k]} | {tuning_by_type[k]} |")
    L += ["", f"Test v2.2 có {len(test_repos)} repo nhận được từ cột dữ liệu." if test_repos else "Không nhận được repo nào từ test v2.2 (kiểm tra --repo-col).", ""]
    if repos:
        L += ["## Repo trùng (khóa quan trọng nhất)", "", "| Repo | Mẫu test thuộc repo này |", "|---|---:|"] + [f"| {r} | {n} |" for r, n in repos.most_common()] + [""]
    L += ["## Bước tiếp theo", "",
          ("- **Không trùng**: ghi vào báo cáo R1, tiếp tục đo trên train/val v2.2." if not hits else
           f"- **Có trùng**: chạy `21_rule_metrics.py --input security-config/semgrep/reports/{stem}_tuning_subset.csv --out r1_overlap_rules` "
           "để biết rule nào được chỉnh từ các mẫu này; đánh giá lại các quyết định đó chỉ bằng train v2.2; ở R5 báo thêm kết quả test khi bỏ các repo trùng."),
          "", "## Điều chưa chắc chắn", "",
          "- Khóa code chỉ bắt trùng nguyên văn sau chuẩn hóa khoảng trắng, không bắt bản gần giống (đổi tên biến, comment).",
          "- Repo nhận từ URL commit/report; mẫu không có URL sẽ không có khóa repo.",
          "- Mẫu `targets_tc6` chỉ có khóa repo (4 ứng dụng mục tiêu đã rà tay ở TC6)."]
    (REPORTS / f"{stem}.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"{test_n} mau test; trung: " + ", ".join(f"{k} {tests_by_type[k]}" for k in index))
    print(f"-> {(REPORTS / (stem + '.md')).relative_to(ROOT)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract", help="trich khoa cua du lieu da dung de chinh rule")
    e.add_argument("--out", default=None)
    c = sub.add_parser("compare", help="so khoa voi test v2.2 (chay tren may giu dataset)")
    c.add_argument("--test", required=True, type=Path)
    c.add_argument("--keys", required=True, type=Path)
    c.add_argument("--out", default=None)
    for k in ("code", "repo", "commit", "cve", "id", "link"):
        c.add_argument(f"--{k}-col", dest=f"{k}_col", default=None)
    a = ap.parse_args()
    if a.cmd == "extract":
        extract(a)
    else:
        compare(a)


if __name__ == "__main__":
    sys.exit(main())
