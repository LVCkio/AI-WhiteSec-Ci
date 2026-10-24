"""
dashboard/collect.py - Gom ket qua THAT cua AI-WhiteSec-CI thanh mot tai lieu JSON cho dashboard.

Chi doc file da co trong main/ (khong quet, khong suy luan lai, khong sua file nao):
  * reports/targets/<app>_scan<tag>.json  - ket qua scan.py (kien truc song song) tren 4 ung dung muc tieu
  * reports/targets/<app>_eval<tag>.json  - doi chieu ground truth cua 09_eval_targets.py
  * reports/scans/*.json                  - scan.py --json cua commit/CI (tuy chon, nguoi dung tu them)
  * targets/<app>/ground_truth.json       - nhan lo hong cua ung dung muc tieu
  * models/pipeline_config.json, models/gate_config.json, models/<model>/run_info.json, labels.json
  * reports/gate_eval_val_*.json, reports/j01_val*.json, reports/pretrain_vs_finetune_*_val.json,
    reports/rule_metrics_v*_val.json, reports/c01_grid.csv

  python dashboard/collect.py --out dashboard_data.json     # xuat ra file de kiem tra
"""
import argparse, csv, glob, hashlib, json, math, re
from datetime import datetime, timezone
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import project_info  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "aiws-dashboard/1.0"
CLASSES = ["SQL_INJECTION", "XSS", "OS_COMMAND_INJECTION", "PATH_TRAVERSAL",
           "AUTHENTICATION_WEAKNESS", "HARDCODED_CREDENTIALS"]
LANGS = ["Python", "Java", "JavaScript", "PHP"]
APPS = {"flask_vuln_app": "Flask Vuln App", "dvwa": "DVWA", "webgoat": "WebGoat", "juice-shop": "OWASP Juice Shop"}
SCAN_RE = re.compile(r"^(?P<app>.+)_scan(?P<tag>_[A-Za-z0-9]+)?\.json$")


# ----------------------------------------------------------------- tien ich
def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def clean(o):
    """NaN/Infinity -> None (JSON hop le cho trinh duyet)."""
    if isinstance(o, float):
        return None if (math.isnan(o) or math.isinf(o)) else o
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [clean(v) for v in o]
    return o


def rel(path, root):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(path).name


def mtime_iso(path):
    return datetime.fromtimestamp(Path(path).stat().st_mtime, timezone.utc).isoformat(timespec="seconds")


_SNAPSHOT = {}  # reports/snapshot_times.json: thoi diem goc cua file trong ban chup (git clone lam mat mtime)


def file_time(path, root):
    return _SNAPSHOT.get(rel(path, root)) or mtime_iso(path)


def short_rule(rule_id):
    """'D.nFCA26IA18.main.security-config.semgrep.team.sql-injection' -> 'team.sql-injection'."""
    rule_id = str(rule_id or "")
    for marker in ("security-config.semgrep.", "registry_snapshot."):
        if marker in rule_id:
            return rule_id.split(marker, 1)[1]
    return rule_id


def norm_path(p):
    return str(p or "").replace("\\", "/")


def current_ruleset(root):
    text = (root / "security-config" / "semgrep" / "tools" / "ruleset.py")
    m = re.search(r'RULESET_VERSION\s*=\s*"([^"]+)"', text.read_text(encoding="utf-8")) if text.is_file() else None
    yml = root / "security-config" / "semgrep" / "semgrep.yml"
    n_rules = len(re.findall(r"^\s*-\s+id:", yml.read_text(encoding="utf-8"), re.M)) if yml.is_file() else None
    return {"version": m.group(1) if m else None, "n_rules": n_rules}


# ----------------------------------------------------------------- cau hinh pipeline
def config_signature(scan):
    ver = (scan.get("gate_config") or {}).get("verifier") or {}
    verifier_on = str(scan.get("a01_verification", "")).split(":")[0] in ("tfidf", "codebert")
    return {
        "ruleset": (scan.get("ruleset") or {}).get("ruleset_version"),
        "sast_tools": scan.get("sast_tools") or ["semgrep", "bandit"],  # truoc 2026-10-21 scan.py khong ghi -> co Bandit
        "model_dir": norm_path((scan.get("pipeline") or {}).get("model_dir")),
        "verifier": norm_path(ver.get("model")) if verifier_on else None,
        "verifier_kind": (ver.get("kind") or str(scan.get("a01_verification", "")).split(":")[0]) if verifier_on else None,
        "verifier_threshold": ver.get("threshold") if verifier_on else None,
        "gate_version": (scan.get("gate_config") or {}).get("version"),
        "policy": (scan.get("gate_config") or {}).get("policy"),
    }


def config_label(sig):
    model = Path(sig["model_dir"] or "?").name
    tools = " + ".join("Semgrep CE" if t == "semgrep" else t.capitalize() for t in sig["sast_tools"])
    ver = (f"verifier {('CodeBERT' if sig['verifier_kind'] == 'codebert' else 'TF-IDF')} ≥ {sig['verifier_threshold']}"
           if sig["verifier"] else "không verifier")
    return f"{tools} v{sig['ruleset']} · {model} · {ver}"


def sig_key(sig):
    s = json.dumps({k: sig[k] for k in ("ruleset", "sast_tools", "model_dir", "verifier", "verifier_threshold")},
                   sort_keys=True)
    return hashlib.sha1(s.encode()).hexdigest()[:8]


def current_signature(root, ruleset):
    pipe = read_json(root / "models" / "pipeline_config.json") or {}
    gate = read_json(root / "models" / "gate_config.json") or {}
    ver = gate.get("verifier") or {}
    on = bool(ver.get("enabled") and ver.get("model"))
    return {"ruleset": ruleset["version"], "sast_tools": ["semgrep"], "model_dir": norm_path(pipe.get("model_dir")),
            "verifier": norm_path(ver.get("model")) if on else None,
            "verifier_kind": ver.get("kind") if on else None,
            "verifier_threshold": ver.get("threshold") if on else None,
            "gate_version": gate.get("version"), "policy": gate.get("policy")}, gate, pipe


# ----------------------------------------------------------------- ground truth ung dung muc tieu
def load_gt(root, app):
    doc = read_json(root / "targets" / app / "ground_truth.json")
    if not doc:
        return None
    src = root / "targets" / app / "scan_src"
    out = {}
    for v in doc.get("vulnerabilities", []):
        f = norm_path(v["file"])
        if src.is_dir() and not (src / f).exists() and "/" in f:
            f = f.split("/", 1)[1]  # flask: 'app/x.py' -> 'x.py' (giong 09_eval_targets.py)
        out.setdefault((f, v.get("function") or "<file>"), []).append(
            {"id": v.get("id"), "class": v.get("class"), "cwe": v.get("cwe"), "line": v.get("line"),
             "description": v.get("description") or v.get("evidence") or v.get("challenge")})
    return {"n": doc.get("n", len(doc.get("vulnerabilities", []))), "by_key": out,
            "file_level": bool(out) and all(fn == "<file>" for _, fn in out)}


def gt_for(unit, gt):
    if gt is None:
        return None
    hits = gt["by_key"].get((unit["file"], unit["function"])) or gt["by_key"].get((unit["file"], "<file>")) or []
    if not hits:
        return {"status": "safe", "classes": [], "items": []}
    classes = sorted({h["class"] for h in hits})
    exact = (unit["file"], unit["function"]) in gt["by_key"]
    return {"status": "vulnerable" if exact else "vulnerable_file", "classes": classes, "items": hits}


# ----------------------------------------------------------------- lan quet
def build_units(scan, gt):
    detail = {(r["file"], r["function"]): r for r in scan.get("results", [])}
    units = []
    for u in scan.get("all_units", []):
        key = (u["file"], u["function"])
        r = detail.get(key)
        item = {"id": f"{u['file']}::{u['function']}", "file": u["file"], "function": u["function"],
                "decision": u.get("decision"), "compare_state": u.get("compare_state"),
                "sast_classes": u.get("sast_classes") or [], "codebert_class": u.get("codebert_class"),
                "p_vulnerable": u.get("p_vulnerable")}
        if r:
            md = r.get("metadata") or {}
            item.update({
                "language": r.get("language"), "lines": r.get("lines"), "status": r.get("status"),
                "reported_by": r.get("reported_by") or [], "vuln_class": r.get("vuln_class"),
                "related_classes": r.get("related_classes") or [],
                "codebert": r.get("codebert"), "probabilities": r.get("probabilities"),
                "cwe": md.get("cwe"), "cwe_url": md.get("cwe_url"), "owasp": md.get("owasp"),
                "owasp_url": md.get("owasp_url"), "severity": md.get("severity"),
                "priority": md.get("priority"), "remediation": md.get("remediation"),
                "findings": [{"rule": short_rule(f.get("rule_id")), "tool": f.get("tool"),
                              "confidence": f.get("confidence"), "line": f.get("line"),
                              "classes": f.get("classes") or [], "cwes": f.get("cwes") or [],
                              "message": f.get("message")} for f in r.get("findings", [])],
            })
        g = gt_for(item, gt)
        if g is not None:
            flagged = item["decision"] in ("BLOCK", "REVIEW")
            related = set(item.get("related_classes") or ([item["vuln_class"]] if item.get("vuln_class") else []))
            g["class_match"] = bool(flagged and related & set(g["classes"])) if g["classes"] else None
            item["gt"] = g
        units.append(item)
    return units


def eval_summary(doc):
    if not doc:
        return None
    methods = []
    for r in doc.get("results", []):
        methods.append({"method": r["method"],
                        "tp": sum(c["detected"] for c in r["per_class"]), "gt": sum(c["gt"] for c in r["per_class"]),
                        "n_predictions": r.get("n_predictions"),
                        "vuln_units_flagged": round(r.get("detected_any_class", 0) * doc.get("n_vulnerable_units", 0)),
                        "vuln_units": doc.get("n_vulnerable_units"),
                        "flagged_safe": r.get("flagged_safe_functions"), "safe": r.get("safe_functions"),
                        "wrong_class": r.get("wrong_class_on_vulnerable"),
                        "per_class": r.get("per_class")})
    return {"n_vulnerabilities": doc.get("n_vulnerabilities"), "n_vulnerable_units": doc.get("n_vulnerable_units"),
            "n_units": doc.get("n_units"), "verifier_threshold": doc.get("verifier_threshold"), "methods": methods}


def load_runs(root):
    runs, gts = [], {}
    sources = [(p, "target") for p in sorted((root / "reports" / "targets").glob("*_scan*.json"))]
    sources += [(p, "commit") for p in sorted((root / "reports" / "scans").glob("*.json"))]
    for path, kind in sources:
        scan = read_json(path)
        if not isinstance(scan, dict) or "all_units" not in scan or scan.get("architecture") != "parallel":
            continue  # bo ban scan cu (kien truc SAST lam cong, khong co all_units)
        app = tag = None
        if kind == "target":
            m = SCAN_RE.match(path.name)
            if not m or m.group("app") not in APPS:
                continue
            app, tag = m.group("app"), (m.group("tag") or "")[1:]
            if app not in gts:
                gts[app] = load_gt(root, app)
        gt = gts.get(app)
        sig = config_signature(scan)
        units = build_units(scan, gt)
        ev = None
        if kind == "target":
            ev = eval_summary(read_json(path.with_name(path.name.replace("_scan", "_eval"))))
        repo_name = APPS.get(app) if app else Path(norm_path(scan.get("repo"))).name or "repo"
        langs = sorted({u.get("language") for u in units if u.get("language")} |
                       {lang for lang, exts in (("Python", (".py",)), ("Java", (".java",)),
                                                ("JavaScript", (".js", ".ts", ".jsx", ".tsx")), ("PHP", (".php",)))
                        for u in units if u["file"].endswith(exts)})
        runs.append({
            "id": f"{app}:{tag}" if kind == "target" else f"scan:{path.stem}",
            "kind": kind, "app": app, "tag": tag, "repo_name": repo_name,
            "source_file": rel(path, root), "created": file_time(path, root),
            "commit": scan.get("commit"), "base": scan.get("base"),
            "config_id": sig_key(sig), "config": sig,
            "mode": scan.get("mode"), "degraded_reason": scan.get("degraded_reason"), "verdict": scan.get("verdict"),
            "a01_verification": scan.get("a01_verification"), "device": scan.get("device"),
            "ruleset": scan.get("ruleset"), "tool_version": (scan.get("tool") or {}).get("version"),
            "summary": scan.get("summary"), "timing": scan.get("timing_seconds"), "languages": langs,
            "has_gt": gt is not None, "gt_n": gt["n"] if gt else None,
            "gt_file_level": gt["file_level"] if gt else None,
            "eval": ev, "units": units,
        })
    return runs


def mark_superseded(runs):
    """Nhieu lan quet cung cau hinh + cung ung dung/repo: chi lan moi nhat dung cho tong hop (cac lan cu van xem duoc)."""
    newest = {}
    for r in runs:
        k = (r["config_id"], r["app"] or f"repo:{r['repo_name']}")
        if k not in newest or r["created"] > newest[k]["created"]:
            newest[k] = r
    for r in runs:
        r["superseded"] = newest[(r["config_id"], r["app"] or f"repo:{r['repo_name']}")] is not r


def build_configs(runs, cur_sig, ruleset):
    cur_key = sig_key(cur_sig)
    configs = {}
    for r in runs:
        c = configs.setdefault(r["config_id"], {"id": r["config_id"], "label": config_label(r["config"]),
                                                "signature": r["config"], "runs": [], "tags": [], "latest": r["created"]})
        c["runs"].append(r["id"])
        if r["tag"] and r["tag"] not in c["tags"]:
            c["tags"].append(r["tag"])
        c["latest"] = max(c["latest"], r["created"])
    for c in configs.values():
        c["current"] = sig_key(c["signature"]) == cur_key
        c["apps"] = sorted({next(r for r in runs if r["id"] == rid)["app"] or "" for rid in c["runs"]} - {""})
        # tong hop 4 ung dung (giong 26_targets_summary.py)
        tot = {}
        for rid in c["runs"]:
            r = next(x for x in runs if x["id"] == rid)
            if r["superseded"]:
                continue
            for m in (r["eval"] or {}).get("methods", []):
                t = tot.setdefault(m["method"], {"tp": 0, "gt": 0, "pred": 0, "vuln_units_flagged": 0,
                                                 "vuln_units": 0, "flagged_safe": 0, "safe": 0})
                t["tp"] += m["tp"]; t["gt"] += m["gt"]; t["pred"] += m["n_predictions"] or 0
                t["vuln_units_flagged"] += m["vuln_units_flagged"]; t["vuln_units"] += m["vuln_units"] or 0
                t["flagged_safe"] += m["flagged_safe"] or 0; t["safe"] += m["safe"] or 0
        c["targets_summary"] = [{"method": k, **v} for k, v in tot.items()]
    ordered = sorted(configs.values(), key=lambda c: (not c["current"], c["latest"]), reverse=False)
    ordered = [c for c in ordered if c["current"]] + sorted([c for c in ordered if not c["current"]],
                                                            key=lambda c: c["latest"], reverse=True)
    return ordered


# ----------------------------------------------------------------- danh gia mo hinh (chi val)
def latest(paths, root):
    paths = [Path(p) for p in paths if Path(p).is_file()]
    return max(paths, key=lambda p: file_time(p, root)) if paths else None


def history(log, key):
    return [{"epoch": h["epoch"], "value": h[key]} for h in (log or []) if key in h]


def load_model(root, model_dir):
    d = root / model_dir
    info = read_json(d / "run_info.json")
    if not info:
        return None
    labels = read_json(d / "labels.json") or CLASSES
    val = info.get("val") or {}
    by_lang = {k[len("macro_f1_"):]: {"macro_f1": v, "n": val.get(f"n_{k[len('macro_f1_'):]}")}
               for k, v in val.items() if k.startswith("macro_f1_")}
    by_source = {k[len("accuracy_"):]: {"accuracy": v, "n": val.get(f"n_{k[len('accuracy_'):]}")}
                 for k, v in val.items() if k.startswith("accuracy_")}
    return {"dir": norm_path(model_dir), "base_model": info.get("model"), "languages": info.get("languages"),
            "labels": labels, "seed": info.get("seed"), "lr": info.get("lr"), "epochs": info.get("epochs"),
            "max_len": info.get("max_len"), "batch_size": info.get("batch_size"),
            "class_weight_mode": info.get("class_weight_mode"), "patience": info.get("early_stopping_patience"),
            "n_train": info.get("n_train"), "n_val": info.get("n_val"), "train_seconds": info.get("train_seconds"),
            "device": info.get("device"), "versions": info.get("versions"),
            "best_val_macro_f1": info.get("best_val_macro_f1"),
            "val": {"macro_f1": val.get("macro_f1"), "accuracy": val.get("accuracy"),
                    "truncated_rate": val.get("truncated_rate"), "confusion_matrix": val.get("confusion_matrix"),
                    "by_language": by_lang, "by_source": by_source},
            "curve": history(info.get("log_history"), "eval_macro_f1"),
            "loss": history(info.get("log_history"), "loss")}


def load_verifier(root, model_dir):
    if not model_dir:
        return None
    info = read_json(root / model_dir / "run_info.json")
    if not info:
        return None
    return {"dir": norm_path(model_dir), "init": norm_path(info.get("init")), "data": norm_path(info.get("data")),
            "epochs": info.get("epochs"), "lr": info.get("lr"), "n_train_rows": info.get("n_train_rows"),
            "train_seconds": info.get("train_seconds"), "val": info.get("val"),
            "curve": history(info.get("log_history"), "eval_roc_auc")}


GATE_LABELS = [("mọi finding", "SAST (mọi finding)"), ("tầng high", "SAST tầng high"),
               ("verifier đơn lẻ", "AI đơn lẻ (verifier)"), ("∪", "SAST ∪ AI"), ("∩", "SAST ∩ AI"),
               ("BLOCK hoặc REVIEW", "Gate BLOCK + REVIEW"), ("Gate: BLOCK", "Gate BLOCK")]


def gate_label(name):
    for needle, label in GATE_LABELS:
        if needle in name:
            return label
    return name


def load_gate_eval(root, verifier, config_threshold=None):
    cands = [p for p in glob.glob(str(root / "reports" / "gate_eval_val_*.json"))
             if norm_path((read_json(p) or {}).get("verifier")) == verifier]
    path = latest(cands, root)
    doc = read_json(path) if path else None
    if not doc:
        return None
    sweep = sorted(({"threshold": float(t), **v} for t, v in (doc.get("sweep") or {}).items()),
                   key=lambda x: x["threshold"])
    at_config = None
    if config_threshold is not None and sweep:
        near = min(sweep, key=lambda x: abs(x["threshold"] - config_threshold))
        at_config = {**near, "exact": abs(near["threshold"] - config_threshold) < 1e-9}
    return {"file": rel(path, root), "created": doc.get("created"), "sast": norm_path(doc.get("sast")),
            "config_threshold": config_threshold, "at_config": at_config,
            "n_vulnerable": doc.get("n_vulnerable"), "n_patched": doc.get("n_patched"),
            "threshold": doc.get("selected_threshold"), "selection": doc.get("selection"),
            "at_threshold": doc.get("at_threshold"), "by_language": doc.get("by_language"),
            "comparison": [{"name": gate_label(k), "raw_name": k, **v} for k, v in (doc.get("comparison") or {}).items()],
            "sweep": sweep}


def load_j01(root):
    path = latest(glob.glob(str(root / "reports" / "j01_val*.json")), root)
    doc = read_json(path) if path else None
    if not doc:
        return None
    return {"file": rel(path, root), "created": doc.get("created"), "n_vulnerable": doc.get("n_vulnerable"),
            "n_patched": doc.get("n_patched"), "verifier_threshold": doc.get("verifier_threshold"),
            "classification": doc.get("classification"), "macro_f1_ci": doc.get("codebert_macro_f1_ci"),
            "cells": doc.get("cells"),
            "detection": [{"name": gate_label(k), "raw_name": k, **v} for k, v in (doc.get("detection") or {}).items()],
            "timing": doc.get("timing")}


def load_c06(root, model_dir):
    tag = Path(model_dir or "").name
    path = root / "reports" / f"pretrain_vs_finetune_{tag}_val.json"
    doc = read_json(path)
    if not doc:
        return None
    res = {k: {kk: v.get(kk) for kk in ("desc", "macro_f1", "accuracy", "macro_f1_ci95", "per_language_macro_f1",
                                         "macro_f1_seeds")} for k, v in (doc.get("results") or {}).items()}
    tsne = doc.get("tsne")
    return {"file": rel(path, root), "n_train": doc.get("n_train"), "n_eval": doc.get("n_eval"),
            "results": res, "diff_ci95": doc.get("macro_f1_diff_ci95"), "silhouette": doc.get("silhouette_cosine"),
            "tsne": norm_path(tsne) if tsne and (root / norm_path(tsne)).is_file() else None}


def load_rule_metrics(root):
    path = latest(glob.glob(str(root / "reports" / "rule_metrics_v*_val.json")), root)
    doc = read_json(path) if path else None
    if not doc:
        return None
    versions = list(doc)
    return {"file": rel(path, root), "versions": versions,
            "cells": {v: (doc[v] or {}).get("cells") for v in versions[-2:]}}


def load_c01(root):
    path = root / "reports" / "c01_grid.csv"
    if not path.is_file():
        return None
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    num = lambda x: float(x) if x not in (None, "") else None
    return [{"lr": r["lr"], "class_weight": r["class_weight"], "seed": r["seed"], "val_macro_f1": num(r["val_macro_f1"]),
             "val_acc": num(r.get("val_acc")), "best_epoch": num(r.get("best_epoch"))} for r in rows]


# ----------------------------------------------------------------- toan bo
def build(root=ROOT):
    root = Path(root)
    _SNAPSHOT.clear()
    _SNAPSHOT.update(read_json(root / "reports" / "snapshot_times.json") or {})
    ruleset = current_ruleset(root)
    cur_sig, gate, pipe = current_signature(root, ruleset)
    runs = load_runs(root)
    mark_superseded(runs)
    configs = build_configs(runs, cur_sig, ruleset)
    model_dir = norm_path(pipe.get("model_dir"))
    verifier = cur_sig["verifier"]
    data = {
        "schema": SCHEMA, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "project": {"name": "AI-WhiteSec-CI", "classes": CLASSES, "languages": LANGS, "apps": APPS,
                    "ruleset": ruleset, "gate": {"version": gate.get("version"), "policy": gate.get("policy"),
                                                 "degraded_policy": gate.get("degraded_policy"),
                                                 "block_min_severity": gate.get("block_min_severity"),
                                                 "verifier": gate.get("verifier")},
                    "current_config": sig_key(cur_sig), "current_signature": cur_sig,
                    "current_label": config_label(cur_sig)},
        "configs": configs,
        "runs": runs,
        "evaluation": {"model": load_model(root, model_dir) if model_dir else None,
                       "verifier": load_verifier(root, verifier),
                       "gate": load_gate_eval(root, verifier, cur_sig["verifier_threshold"]), "j01": load_j01(root),
                       "c06": load_c06(root, model_dir), "rules": load_rule_metrics(root), "c01": load_c01(root)},
    }
    raw_info = read_json(root / model_dir / "run_info.json") if model_dir else None
    data["config_info"] = project_info.build(root, model_dir, raw_info, verifier, gate, pipe, file_time, runs)
    return clean(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--dataset-summary", type=Path, default=None,
                    help="ghi so mau da dem (cho ban chup khong kem CSV), vd. reports/dataset_summary.json")
    a = ap.parse_args()
    if a.dataset_summary:
        pipe = read_json(a.root / "models" / "pipeline_config.json") or {}
        info = read_json(a.root / norm_path(pipe.get("model_dir")) / "run_info.json")
        a.dataset_summary.write_text(json.dumps(project_info.dataset_summary(a.root, info), ensure_ascii=False, indent=1),
                                     encoding="utf-8")
    data = build(a.root)
    text = json.dumps(data, ensure_ascii=False, indent=1)
    if a.out:
        a.out.write_text(text, encoding="utf-8")
    print(f"{len(data['runs'])} lan quet, {len(data['configs'])} cau hinh; hien tai: {data['project']['current_label']}")


if __name__ == "__main__":
    main()
