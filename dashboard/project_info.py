"""
dashboard/project_info.py - Thong tin cau hinh rieng cua nhom cho man hinh "Cau hinh & Rule":
phien ban (cong cu, ruleset, mo hinh, du lieu, tap test, ket qua test), nguong va chinh sach,
toan bo rule Semgrep cua nhom (noi dung, test, so lieu), rule da tat, tieu chi chon rule,
thanh phan du lieu, anh xa CWE -> lop, ground truth 4 ung dung muc tieu.

Chi doc file; khong chay semgrep/model. Khong can PyYAML (dung neu co, neu khong tach rule bang regex).
"""
import csv, glob, json, re
from collections import Counter, defaultdict
from pathlib import Path

SEMGREP = Path("security-config") / "semgrep"
APPS = ["flask_vuln_app", "dvwa", "webgoat", "juice-shop"]


def _json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _text(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return ""


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------- tach rule tu YAML
RULE_START = re.compile(r"^- id:\s*(.+?)\s*$", re.M)


def _blocks(text):
    """semgrep.yml -> [(id, khoi YAML goc)] theo dung thu tu trong file."""
    starts = [m for m in RULE_START.finditer(text)]
    out = []
    for i, m in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        out.append((m.group(1).strip().strip("'\""), text[m.start():end].rstrip()))
    return out


def _scalar(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        v = v[1:-1].replace("''", "'") if v[0] == "'" else v[1:-1]
    return v


def _regex_rule(block):
    """Tach truong co ban khi khong co PyYAML (du cho ruleset do tools/ruleset.py sinh ra)."""
    lines = block.splitlines()
    rule, meta, cur, key = {"languages": []}, {}, None, None
    for ln in lines:
        if re.match(r"^- id:", ln):
            rule["id"] = _scalar(ln.split(":", 1)[1])
            continue
        m2 = re.match(r"^  (\w[\w-]*):\s*(.*)$", ln)
        if m2:
            cur, val = m2.group(1), m2.group(2)
            if cur in ("severity", "message", "mode"):
                rule[cur] = _scalar(val) if val else ""
            key = None
            continue
        if cur == "languages":
            m = re.match(r"^  - (.+)$", ln)
            if m:
                rule["languages"].append(_scalar(m.group(1)))
        elif cur == "metadata":
            m4 = re.match(r"^    (\w[\w-]*):\s*(.*)$", ln)
            if m4:
                key = m4.group(1)
                meta[key] = _scalar(m4.group(2))
            elif key and ln.startswith("      "):
                meta[key] = (meta[key] + " " + ln.strip()).strip()
        elif cur == "message" and ln.startswith("    "):
            rule["message"] = (rule.get("message", "") + " " + ln.strip()).strip()
    rule["metadata"] = meta
    return rule


def parse_rules(path):
    text = _text(path)
    if not text:
        return []
    blocks = _blocks(text)
    parsed = None
    try:
        import yaml  # co san trong .venv (phu thuoc cua semgrep)
        doc = yaml.safe_load(text) or {}
        parsed = {r.get("id"): r for r in doc.get("rules", [])}
    except Exception:
        parsed = None
    rules = []
    for rid, block in blocks:
        r = (parsed or {}).get(rid) or _regex_rule(block)
        md = r.get("metadata") or {}
        mode = r.get("mode") or ("taint" if "pattern-sources" in block else "search")
        langs = r.get("languages") or []
        rules.append({
            "id": rid, "languages": langs, "severity": r.get("severity"), "message": str(r.get("message") or "").strip(),
            "cwe": md.get("cwe"), "owasp": md.get("owasp"), "vuln_class": md.get("vuln_class"),
            "confidence": md.get("confidence"), "risk": md.get("severity"), "scope": md.get("scope"),
            "rule_version": str(md.get("rule_version") or ""), "ruleset_version": str(md.get("ruleset_version") or ""),
            "change": md.get("change_v4") or md.get("change"), "disabled_reason": md.get("disabled_v42") or md.get("disabled"),
            "mode": mode, "regex": "regex" in langs or "pattern-regex" in block, "source": block,
        })
    return rules


# ----------------------------------------------------------------- so lieu theo rule
def _csv_rows(path):
    if not Path(path).is_file():
        return []
    with open(path, encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _ruleset_tag(version):
    """'4.2.0' -> 'v4.2' (cot ruleset trong reports/rule_metrics_*.csv)."""
    parts = str(version or "").split(".")
    return f"v{parts[0]}.{parts[1]}" if len(parts) >= 2 else None


def rule_metrics(root, version):
    tag = _ruleset_tag(version)
    short = (tag or "").replace(".", "")
    out = defaultdict(dict)
    for split in ("train", "val"):
        for r in _csv_rows(root / "reports" / f"rule_metrics_{short}_{split}.csv"):
            if r.get("ruleset") == tag:
                out[r["rule"]][split] = {"hits": int(r["hits"] or 0), "correct": int(r["correct"] or 0),
                                         "precision": _num(r.get("precision")), "unique_correct": int(r.get("unique_correct") or 0)}
        for r in _csv_rows(root / "reports" / f"rule_pairs_diff_{short}_{split}.csv"):
            if r.get("ruleset") == tag:
                out[r["rule"]].setdefault("pairs", {})[split] = {"b_right": int(r["b_right"] or 0), "b_wrong": int(r.get("b_wrong") or 0),
                                                                 "a_fixed": int(r["a_fixed"] or 0), "ratio": _num(r.get("a_over_b_right"))}
    return out, tag


def rule_tests(root):
    doc = _json(root / SEMGREP / "reports" / "rule_test_results.json") or {}
    per = defaultdict(lambda: {"positive": 0, "negative": 0, "passed": 0, "total": 0})
    for c in (doc.get("test") or {}).get("cases", []):
        t = per[c.get("rule")]
        neg = "khong" in str(c.get("expect", "")) or "/negative/" in str(c.get("file", ""))
        t["negative" if neg else "positive"] += 1
        t["total"] += 1
        t["passed"] += 1 if c.get("pass") else 0
    return per, doc


# ----------------------------------------------------------------- tieu chi (markdown)
def criteria(root):
    """Bang TC1-TC8 trong TIEU_CHI_CHON_RULE.md (muc 2) -> [{code, name, check}] (giu markdown inline)."""
    text = _text(root / SEMGREP / "TIEU_CHI_CHON_RULE.md")
    m = re.search(r"^## 2\..*?$(.*?)^## 3\.", text, re.M | re.S)
    if not m:
        return None
    rows = []
    for ln in m.group(1).splitlines():
        cells = [c.strip() for c in ln.strip().strip("|").split("|")] if ln.strip().startswith("|") else []
        if len(cells) >= 3 and re.match(r"^TC\d+$", cells[0]):
            rows.append({"code": cells[0], "name": cells[1], "check": cells[2]})
    title = re.search(r"^# (.+)$", text, re.M)
    return {"title": title.group(1) if title else None, "rows": rows, "file": (SEMGREP / "TIEU_CHI_CHON_RULE.md").as_posix()}


# ----------------------------------------------------------------- du lieu
def find_dataset(root, model_info):
    """Thu muc data_versions/* co train.csv trung SHA voi du lieu da train mo hinh."""
    want = ((model_info or {}).get("data") or {}).get("train")
    for man in sorted(glob.glob(str(root / "data_versions" / "*" / "manifest.json"))):
        doc = _json(man) or {}
        if want and (doc.get("files") or {}).get("train.csv") == want:
            return Path(man).parent, doc
    return None, None


def dataset_counts(ddir):
    """Dem mau theo tap x ngon ngu x lop va theo nguon (chi dem, khong doc noi dung code ra ngoai)."""
    csv.field_size_limit(1 << 30)
    out = {}
    for split in ("train", "val", "test"):
        p = ddir / f"{split}.csv"
        if not p.is_file():
            return None
        cells, src, total = Counter(), Counter(), 0
        with open(p, encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                cells[f"{r.get('programming_language')}|{r.get('cls_gt')}"] += 1
                src[r.get("source") or "?"] += 1
                total += 1
        out[split] = {"n": total, "cells": dict(cells), "sources": dict(src)}
    return out


def unit_tests(root):
    p = root / "reports" / "unittest_log.txt"
    text = _text(p)
    if not text:
        return None
    ran = re.findall(r"Ran (\d+) tests? in ([\d.]+)s", text)
    ok = bool(re.search(r"^OK\b", text, re.M))
    failed = re.search(r"FAILED \(([^)]*)\)", text)
    return {"ran": int(ran[-1][0]) if ran else None, "ok": ok, "failed": failed.group(1) if failed else None,
            "file": "reports/unittest_log.txt", "time": None}


# ----------------------------------------------------------------- toan bo
def build(root, model_dir, model_info, verifier_dir, gate, pipe, file_time, runs):
    root = Path(root)
    manifest = _json(root / SEMGREP / "ruleset-manifest.json") or {}
    version = manifest.get("ruleset_version")
    rules = parse_rules(root / SEMGREP / "semgrep.yml")
    metrics, tag = rule_metrics(root, version)
    tests, test_doc = rule_tests(root)
    for r in rules:
        r["metrics"] = metrics.get(r["id"]) or {}
        r["tests"] = tests.get(r["id"]) or {"positive": 0, "negative": 0, "passed": 0, "total": 0}
    disabled = []
    for p in sorted((root / SEMGREP / "rules_disabled").rglob("*.yml")) if (root / SEMGREP / "rules_disabled").is_dir() else []:
        for r in parse_rules(p):
            r["file"] = p.relative_to(root / SEMGREP).as_posix()
            disabled.append(r)
    check = test_doc.get("check") or {}

    ddir, dman = find_dataset(root, model_info)
    counts = dataset_counts(ddir) if ddir else None
    if counts is None:  # ban chup (khong co CSV): dung so da dem san
        snap = _json(root / "reports" / "dataset_summary.json") or {}
        counts = snap.get("counts")
        dman = dman or snap.get("manifest")
    e05 = _json(root / "data_versions" / "e05_temporal" / "manifest.json") or (_json(root / "reports" / "dataset_summary.json") or {}).get("e05")
    j01_lock = root / "reports" / "j01_test_used.json"
    ut = unit_tests(root)
    if ut:
        ut["time"] = file_time(root / ut["file"], root)

    vm = _json(root / "rules" / "vuln_metadata.json") or {}
    ver = (gate or {}).get("verifier") or {}
    mi = model_info or {}
    tool_version = next((r.get("tool_version") for r in runs if r.get("tool_version")), None)

    gts = {}
    for app in APPS:
        doc = _json(root / "targets" / app / "ground_truth.json")
        if doc:
            gts[app] = {"source": doc.get("source"), "n": doc.get("n"), "by_class": doc.get("by_class"),
                        "items": [{"id": v.get("id"), "file": v.get("file"), "function": v.get("function"), "line": v.get("line"),
                                   "class": v.get("class"), "cwe": v.get("cwe"),
                                   "note": v.get("description") or v.get("evidence") or v.get("challenge")} for v in doc.get("vulnerabilities", [])]}

    thresholds = [
        {"name": "Ngưỡng verifier p_vulnerable", "value": ver.get("threshold"), "unit": "xác suất",
         "where": "models/gate_config.json → verifier.threshold",
         "how": f"Chọn trên {ver.get('selected_on') or 'val cặp trước/sau vá'} ngày {ver.get('selected') or '?'}: J lớn nhất (J = {round(ver['J'], 3) if isinstance(ver.get('J'), (int, float)) else '?'}); không chỉnh theo ứng dụng mục tiêu, không dùng test.",
         "effect": "Luồng AI chỉ báo khi p_vulnerable ≥ ngưỡng; lớp 6-lớp chỉ dùng để gọi tên lỗ hổng."},
        {"name": "Ngưỡng xác suất lớp CodeBERT", "value": (gate or {}).get("codebert_threshold"), "unit": "xác suất",
         "where": "models/gate_config.json → codebert_threshold",
         "how": (gate or {}).get("codebert_threshold_note") or "",
         "effect": "Chỉ dùng khi tắt verifier (luồng AI báo theo xác suất lớp cao nhất)."},
        {"name": "Mức nghiêm trọng tối thiểu để BLOCK", "value": (gate or {}).get("block_min_severity"), "unit": "mức",
         "where": "models/gate_config.json → block_min_severity",
         "how": "Theo mức nghiêm trọng của lớp trong rules/vuln_metadata.json.",
         "effect": "Quyết định BLOCK của lớp có mức thấp hơn được hạ xuống REVIEW."},
        {"name": "Tầng finding Semgrep", "value": "high / audit", "unit": "",
         "where": "metadata.confidence của từng rule",
         "how": "TC8 (taint không qua sanitizer hoặc mẫu gần như chắc chắn sai → high); TC4: high ≥ 0,80, audit ≥ 0,50 tỉ lệ báo đúng lớp trên train/val.",
         "effect": "Chỉ Semgrep báo: high → BLOCK, audit → REVIEW."},
        {"name": "Độ dài đầu vào CodeBERT", "value": mi.get("max_len"), "unit": "token",
         "where": f"{model_dir}/run_info.json → max_len", "how": "Giới hạn của microsoft/codebert-base.",
         "effect": "Phần sau token cuối bị cắt (E07 xử lý hàm dài)."},
        {"name": "Siêu tham số huấn luyện C03", "value": f"lr {mi.get('lr')} · batch {mi.get('batch_size')} · {mi.get('epochs')} epoch · patience {mi.get('early_stopping_patience')}",
         "unit": "", "where": f"{model_dir}/run_info.json", "how": "Chọn bằng lưới C01 trên val (≥ 3 seed), trọng số lớp " + str(mi.get("class_weight_mode")),
         "effect": "Early stopping theo macro-F1 trên val."},
        {"name": "Điểm ưu tiên cảnh báo", "value": "P1 ≥ 70 · P2 ≥ 40 · P3", "unit": "điểm",
         "where": "rules/vuln_metadata.json → priority", "how": (vm.get("priority") or {}).get("formula") or "",
         "effect": "Sắp xếp cảnh báo; không thay đổi quyết định Gate."},
    ]

    return {
        "versions": {
            "tool": {"name": "scan.py (AI-WhiteSec-CI)", "version": tool_version},
            "ruleset": {"version": version, "sha256": manifest.get("ruleset_sha256"), "semgrep": manifest.get("semgrep_version"),
                        "semgrep_pinned": manifest.get("semgrep_version_pinned"), "generated_at": manifest.get("generated_at"),
                        "python": manifest.get("python"), "n_rules": check.get("rules") or len(rules), "n_disabled": len(disabled),
                        "tests_passed": manifest.get("tests_passed"), "tests_total": manifest.get("tests_total"),
                        "positive_cases": check.get("positive_cases"), "negative_cases": check.get("negative_cases"),
                        "regression_passed": manifest.get("regression_passed"), "commit": manifest.get("ruleset_commit"),
                        "registry_snapshot": sorted((manifest.get("registry_snapshot") or {}).keys())},
            "model": {"dir": model_dir, "base": mi.get("model"), "seed": mi.get("seed"), "device": mi.get("device"),
                      "versions": mi.get("versions"), "data_version": (dman or {}).get("version"),
                      "train_sha256": (mi.get("data") or {}).get("train"), "val_sha256": (mi.get("data") or {}).get("val"),
                      "best_checkpoint": Path(str(mi.get("best_checkpoint") or "")).name or None},
            "verifier": {"dir": verifier_dir, "threshold": ver.get("threshold"), "selected": ver.get("selected")},
            "gate": {"version": (gate or {}).get("version"), "architecture": (gate or {}).get("architecture")},
            "dataset": {"dir": ddir.relative_to(root).as_posix() if ddir else None, "version": (dman or {}).get("version"),
                        "created": (dman or {}).get("created"), "counts": (dman or {}).get("counts"), "files": (dman or {}).get("files"),
                        "cwe_map": (dman or {}).get("cwe_map"), "exact_duplicates_dropped": (dman or {}).get("exact_duplicates_dropped"),
                        "near_duplicate_pairs": (dman or {}).get("near_duplicate_pairs"),
                        "max_per_repo_language_class": (dman or {}).get("max_per_repo_language_class")},
            "test_sets": [
                {"name": "Tập test chính (J01/K08)", "version": (dman or {}).get("version"), "n": ((dman or {}).get("counts") or {}).get("test"),
                 "sha256": ((dman or {}).get("files") or {}).get("test.csv"), "created": (dman or {}).get("created"),
                 "status": "used" if j01_lock.is_file() else "frozen",
                 "note": "Đóng băng cùng lần chia dữ liệu; chỉ chạy một lần ở J01 (22_j01_eval.py --split test --final, khóa reports/j01_test_used.json)."},
                *([{"name": "Tập test theo thời gian (E05)", "version": "e05_temporal", "n": e05.get("n_functions"),
                    "sha256": (e05.get("files") or {}).get("temporal_test.csv"), "created": str(e05.get("created") or "")[:10],
                    "status": "built", "range": e05.get("published_range"), "by_class": e05.get("by_class"),
                    "note": f"Hàm Python từ {e05.get('n_advisories_used')} advisory công bố sau {str(e05.get('cutoff_published_after') or '')[:10]}; loại trùng với dữ liệu train/val/test."}] if e05 else []),
            ],
            "rule_tests": {"passed": manifest.get("tests_passed"), "total": manifest.get("tests_total"),
                           "positive": check.get("positive_cases"), "negative": check.get("negative_cases"),
                           "time": manifest.get("generated_at"), "file": (SEMGREP / "reports" / "rule_test_results.json").as_posix()},
            "unit_tests": ut,
        },
        "thresholds": thresholds,
        "policy": {"policy": (gate or {}).get("policy"), "degraded": (gate or {}).get("degraded_policy")},
        "rules": rules, "disabled_rules": disabled, "metrics_tag": tag,
        "criteria": criteria(root),
        "dataset": {"counts": counts, "sources": (dman or {}).get("sources")},
        "cwe_map": [{"class": k, "cwe": v.get("cwe"), "cwe_name": v.get("cwe_name"), "owasp": v.get("owasp"), "severity": v.get("severity")}
                    for k, v in (vm.get("classes") or {}).items()],
        "ground_truth": gts,
    }


def dataset_summary(root, model_info):
    """Cho ban chup: so mau da dem (khong kem du lieu)."""
    ddir, dman = find_dataset(Path(root), model_info)
    return {"manifest": dman, "counts": dataset_counts(ddir) if ddir else None,
            "e05": _json(Path(root) / "data_versions" / "e05_temporal" / "manifest.json")}
