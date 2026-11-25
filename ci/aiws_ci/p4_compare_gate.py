"""P4 - Normalize & Merge Findings + Security Gate 5x5 (FAIL / BLOCK / REVIEW / INFO / PASS).

  python -m aiws_ci.p4_compare_gate --out-dir aiws-out --semgrep semgrep-results.json

1. Normalize: finding Semgrep (scan_repo.py) -> lop + tang high/audit; ket qua CodeBERT -> nhom vuot nguong.
2. Gan finding Semgrep vao ham NHO NHAT chua dong bat dau (theo danh sach don vi P1); nam ngoai moi ham ->
   don vi "module" rieng. Che do diff: chi xet don vi trong diff va finding tren dong bi sua.
3. Compare tung don vi: agree (cung lop) | conflict (ca hai bao, khac lop) | sast_only | codebert_only | pass.
4. Gate theo ci/gate-policy.json: moi lop xet o (muc Semgrep x muc CodeBERT); quyet dinh don vi = o nang nhat.
   Tu 22/11/2026 truc Semgrep = muc tool 4 bac (Critical/High/Medium/Low) -> bang 5x3; truoc do High/Audit (3x3).
   Tu 23/11/2026 (policy co "model_levels") truc CodeBERT = 5 muc: muc CVSS cua lop (strong >= alpha10 giu, weak
   alpha20..alpha10 ha 1 bac, con lai None) -> bang 5x5, CUNG bang/luat voi gate_5x5.json cua worker Server 3.
   Mot luong loi -> tran REVIEW; ca hai loi -> FAIL. "state" cu van ghi de dashboard doc.
Dau ra: gate.json, report.json (schema_version 3, dung dinh dang dashboard dang doc), ai-whitesec.sarif,
        gl-code-quality-report.json (widget merge request), summary.md.
Ma thoat: 0 = PASS/INFO/REVIEW, 1 = BLOCK (khi enforce_block), 2 = thieu model ma policy bat buoc, 3 = ca hai luong loi.
"""
import argparse
import hashlib
import os
import re
from pathlib import Path

from . import common as C
from .units import innermost_function

STEP = "P4-gate"
RANK = {"PASS": 0, "INFO": 1, "REVIEW": 2, "BLOCK": 3, "FAIL": 4}


def consistency_checks(sem, sem_ok, scope):
    """19/11: kiem Semgrep (anh aiws-semgrep) va P1 (anh aiws-codebert) nhin CUNG mot tap file, va do phu ngon ngu.
    Chi CANH BAO (report.json: consistency + warnings; summary.md), KHONG doi quyet dinh Gate.
    Dashboard chua hien muc warnings (can them o dashboard/static/js)."""
    out = {"scope_signature_p1": scope.get("scope_signature"), "scope_signature_semgrep": None,
           "scope_signature_match": None, "targets_missing_in_semgrep": [], "semgrep_files_outside_p1": [],
           "files_unsupported_language": scope.get("files_unsupported_language") or {}, "warnings": []}
    W = out["warnings"]
    if sem_ok:
        srun = sem.get("run", {})
        out["scope_signature_semgrep"] = srun.get("scope_signature")
        a, b = out["scope_signature_p1"], out["scope_signature_semgrep"]
        if a and b:
            out["scope_signature_match"] = a == b
            if a != b:
                W.append("Cach chon pham vi file cua P1 (anh aiws-codebert) KHAC Semgrep (anh aiws-semgrep): "
                         "hai anh build tu hai commit khac nhau -> build lai ca hai tu cung mot commit")
        else:
            W.append("Khong so duoc dau van tay pham vi (anh cu chua ghi scope_signature) -> build lai anh")
        sem_files = {f["path"] for f in sem.get("files", [])}
        targets = set(scope.get("target_files") or [])
        p1_files = {f["path"] for f in scope.get("files", [])}
        miss = sorted(targets - sem_files)
        extra = sorted(sem_files - p1_files)
        out["targets_missing_in_semgrep"], out["semgrep_files_outside_p1"] = miss[:50], extra[:50]
        out["targets_missing_in_semgrep_count"], out["semgrep_files_outside_p1_count"] = len(miss), len(extra)
        if miss:
            W.append(f"{len(miss)} file P1 can quet nhung Semgrep KHONG quet (vd {miss[0]}): cac ham nay chi co CodeBERT")
        if extra:
            W.append(f"{len(extra)} file Semgrep quet nhung nam ngoai pham vi P1 (vd {extra[0]}): finding o day bi bo")
    uns = out["files_unsupported_language"]
    if uns:
        n = sum(uns.values())
        W.append(f"{n} file ma nguon ngon ngu chua ho tro ({', '.join(f'{k} {v}' for k, v in uns.items())}) "
                 f"KHONG duoc Semgrep va CodeBERT quet; PASS khong bao gom cac file nay")
    return out


def load_policy(path: Path):
    p = C.read_json(path)
    if p is None:
        C.die(STEP, f"khong thay {path}", C.EXIT_CONFIG)
    return p, C.sha256_file(path)


def max_tool_level(*levels):
    """Muc tool nang nhat (Critical > High > Medium > Low); None neu khong co."""
    xs = [x for x in levels if x in C.TOOL_LEVELS]
    return min(xs, key=C.TOOL_LEVELS.index) if xs else None


def cb_level(c, probs, th, weak, flagged):
    """Cao >= alpha10 (thresholds.json); Thap >= alpha20; Khong. Khong co vach Thap -> fallback gate_3x3."""
    p = (probs or {}).get(c)
    if p is None or c not in th:
        return "Cao" if c in flagged else "Khong"
    if p >= th[c]:
        return "Cao"
    if weak and c in weak and p >= weak[c]:
        return "Thap"
    return "Khong"


def decide_3x3(policy, sf, r, th, weak, analysis, path):
    """Tra ve (quyet dinh don vi, danh sach o). sf: finding Semgrep cua don vi; r: ket qua CodeBERT cua don vi."""
    other = policy.get("other_class", "OTHER")
    prop = policy.get("team_overrides") or policy.get("proposals_not_approved") or {}
    on = bool(prop.get("enabled"))
    th = dict(th or {})
    if on:
        for c, t in (prop.get("class_thresholds") or {}).items():
            th[c] = t.get("Cao", th.get(c))
    probs = (r or {}).get("probs") or {}
    flagged = set((r or {}).get("groups") or [])
    # Truc Semgrep doc tu gate-policy.json: tu 22/11 = tool_level (Critical/High/Medium/Low); bang 3x3 cu = confidence.
    sl = policy["semgrep_levels"]
    sem_map, field = sl["map"], sl.get("field", "confidence")
    order = sl.get("order") or [x for x in policy["matrix"] if x != "Khong"]
    sem_cls, sem_tool = {}, {}
    for f in sf:
        c = f["class"] if f["class"] in C.GROUPS else other
        lv = sem_map.get(f.get(field), sl.get("default", order[-1]))
        sem_cls[c] = min((x for x in (sem_cls.get(c), lv) if x in order), key=order.index)   # muc nang nhat
        sem_tool[c] = max_tool_level(sem_tool.get(c), f.get("tool_level"))
    classes = set(sem_cls)
    if analysis != "sast_only":
        classes |= {c for c in C.GROUPS if cb_level(c, probs, th, weak, flagged) != "Khong"}
    cells, best = [], "PASS"
    for c in sorted(classes):
        s_lv = sem_cls.get(c, "Khong")
        b_lv = cb_level(c, probs, th, weak, flagged) if (c in C.GROUPS and analysis != "sast_only") else "Khong"
        d = policy["matrix"][s_lv][b_lv]
        if on:
            d = (prop.get("class_cell_overrides") or {}).get(c, {}).get(f"{s_lv}/{b_lv}", d)
        if analysis in ("sast_only", "codebert_only") and RANK[d] > RANK[policy["tool_status"]["degraded_cap"]]:
            d = policy["tool_status"]["degraded_cap"]
        cells.append({"class": c, "semgrep": s_lv, "semgrep_tool_level": sem_tool.get(c), "codebert": b_lv,
                      "codebert_p": probs.get(c), "decision": d})
        best = max(best, d, key=RANK.get)
    pm = prop.get("path_max_decision") if on else None
    if pm and any(re.search(x, path) for x in pm["patterns"]) and RANK[best] > RANK[pm["max"]]:
        best = pm["max"]
    return best, cells


SNIP_CTX, SNIP_MAX_LINES, SNIP_MAX_CHARS = 3, 40, 240
_src_cache = {}


LV5 = ["Critical", "High", "Medium", "Low", "None"]
_STEP = {"keep": 0, "down_one": 1}


def model_level5(c, conf, ml):
    """Muc CodeBERT 5 bac (gate 5x5): muc CVSS cua lop (model_levels.severity_by_class), strong giu, weak ha 1 bac
    (khong duoi Low), none -> None. Giong _model_level5 cua worker Server 3."""
    base = (ml.get("severity_by_class") or {}).get(c, "Medium")
    if conf not in ("strong", "weak") or base not in LV5[:4]:
        return "None"
    return LV5[min(LV5.index(base) + _STEP.get(ml.get(conf), 0 if conf == "strong" else 1), LV5.index("Low"))]


def sem_level_cvss(c, confidence, policy):
    """Muc tool Semgrep khi semgrep_levels.rule = class_cvss (nhom chot 25/11/2026): muc CVSS cua lop
    (model_levels.severity_by_class - CUNG bang CodeBERT) x confidence rule: high giu, audit ha 1 bac (khong duoi Low).
    Giong sem_level5 cua worker Server 3 (worker_5x5_dongbo)."""
    ml = policy.get("model_levels") or {}
    base = (ml.get("severity_by_class") or {}).get(c) or (policy.get("semgrep_levels") or {}).get("default", "Medium")
    if base not in LV5[:4]:
        base = "Medium"
    step = 0 if str(confidence or "").strip().lower() == "high" else 1
    return LV5[min(LV5.index(base) + step, LV5.index("Low"))]


def decide_5x5(policy, sf, r, th, weak, analysis, path):
    """Gate 5x5 (23/11/2026): (muc tool Semgrep | None) x (muc CodeBERT 5 bac). Cung dau vao/dau ra voi decide_3x3.
    team_overrides: class_strong_min_p (strong ma p < vach -> weak), class_cell_overrides "Hang/Cot", path_max_decision."""
    other = policy.get("other_class", "OTHER")
    ov = policy.get("team_overrides") or {}
    on = bool(ov.get("enabled"))
    min_p = (ov.get("class_strong_min_p") or {}) if on else {}
    cell_ov = (ov.get("class_cell_overrides") or {}) if on else {}
    ml = policy["model_levels"]
    probs = (r or {}).get("probs") or {}
    flagged = set((r or {}).get("groups") or [])
    sl = policy["semgrep_levels"]
    field, smap, order = sl.get("field", "tool_level"), sl.get("map") or {}, sl["order"]
    sdef = sl.get("default", "Medium")
    sem, sem_rule = {}, {}
    for f in sf:
        c = f["class"] if f["class"] in C.GROUPS else other
        lv = smap.get(f.get(field), f.get(field))
        lv = lv if lv in order else sdef
        if c not in sem or order.index(lv) < order.index(sem[c]):      # muc nang nhat cua lop trong don vi
            sem[c], sem_rule[c] = lv, f.get("rule_id")
    conf = {}
    if analysis != "sast_only":
        for c in C.GROUPS:
            k = {"Cao": "strong", "Thap": "weak"}.get(cb_level(c, probs, th, weak, flagged), "none")
            t, p = min_p.get(c), probs.get(c)
            if k == "strong" and t is not None and isinstance(p, (int, float)) and p < t:
                k = "weak"
            if k != "none":
                conf[c] = k
    cells, best = [], "PASS"
    for c in sorted(set(sem) | set(conf)):
        s_lv = sem.get(c, "None")
        m_lv = model_level5(c, conf[c], ml) if c in conf and c != other else "None"
        d = policy["matrix"][s_lv][m_lv]
        d = (cell_ov.get(c) or {}).get(f"{s_lv}/{m_lv}", d)
        if analysis in ("sast_only", "codebert_only") and RANK[d] > RANK[policy["tool_status"]["degraded_cap"]]:
            d = policy["tool_status"]["degraded_cap"]
        cells.append({"class": c, "semgrep": s_lv, "codebert": m_lv, "tool": s_lv, "model": m_lv,
                      "semgrep_tool_level": None if s_lv == "None" else s_lv, "tool_rule": sem_rule.get(c),
                      "model_base": (ml.get("severity_by_class") or {}).get(c), "model_confidence": conf.get(c, "none"),
                      "codebert_p": probs.get(c), "decision": d})
        best = max(best, d, key=RANK.get)
    pm = ov.get("path_max_decision") if on else None
    if pm and any(re.search(x, path or "") for x in pm.get("patterns", [])) and RANK[best] > RANK[pm.get("max", "INFO")]:
        best = pm.get("max", "INFO")
    return best, cells


def decide_gate(policy, sf, r, th, weak, analysis, path):
    """Chon bang theo gate-policy.json: co "model_levels" -> 5x5 (tu 23/11); khong -> 5x3 / 3x3 cu."""
    fn = decide_5x5 if policy.get("model_levels") else decide_3x3
    return fn(policy, sf, r, th, weak, analysis, path)


def src_lines(repo: Path, rel: str):
    if rel not in _src_cache:
        try:
            _src_cache[rel] = (repo / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            _src_cache[rel] = None
    return _src_cache[rel]


def snippet(repo: Path, rel: str, start, end, ctx=SNIP_CTX, unit_code=None, unit_start=None):
    """Doan ma nguyen van quanh dong loi (Dashboard to dam dong start..end). Doc tu repo da checkout dung commit
    (p0 da kiem); khong co file -> lay tu code cua don vi trong p1-units.jsonl. Gioi han kich thuoc bao cao."""
    lines = src_lines(repo, rel)
    base = 1
    if lines is None and unit_code is not None:
        lines, base = unit_code.splitlines(), unit_start or 1
    if not lines or not start:
        return None
    end = max(start, end or start)
    a = max(base, start - ctx)
    b = min(base + len(lines) - 1, end + ctx, a + SNIP_MAX_LINES - 1)
    if b < a:
        return None
    out = [ln if len(ln) <= SNIP_MAX_CHARS else ln[:SNIP_MAX_CHARS] + " …" for ln in lines[a - base:b - base + 1]]
    return {"start": a, "end": b, "code": "\n".join(out)}


UNIT_MAX_LINES, UNIT_MAX_CHARS = 400, 60000


def unit_code(u):
    code = u.get("code")
    if not code:
        return None
    lines = code.split("\n")[:UNIT_MAX_LINES]
    out = "\n".join(ln if len(ln) <= SNIP_MAX_CHARS else ln[:SNIP_MAX_CHARS] + " …" for ln in lines)
    return out[:UNIT_MAX_CHARS]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", type=Path, default=Path("aiws-out"))
    ap.add_argument("--semgrep", type=Path, default=Path("semgrep-results.json"))
    ap.add_argument("--policy", type=Path, default=None)
    a = ap.parse_args()
    od = a.out_dir
    pol_path = a.policy or next((p for p in (Path(os.environ.get("CI_PROJECT_DIR", ".")) / "ci" / "gate-policy.json",
                                             C.CI_HOME / "gate-policy.json") if p.is_file()), C.CI_HOME / "gate-policy.json")
    policy, policy_sha = load_policy(pol_path)
    scope = C.read_json(od / "p1-scope.json") or C.die(STEP, "thieu p1-scope.json (P1 loi?)", C.EXIT_CONFIG)
    auth = C.read_json(od / "p0-authorize.json", {})
    units = C.read_jsonl(od / "p1-units.jsonl")
    repo = Path(os.environ.get("CI_PROJECT_DIR", "."))
    sem = C.read_json(a.semgrep)
    cb = C.read_json(od / "codebert-results.json")

    sem_ok = bool(sem) and "findings" in sem
    cb_ok = bool(cb) and cb.get("status") == "completed"
    if not sem_ok and not cb_ok:
        analysis = "failed"
    elif sem_ok and cb_ok:
        analysis = "sast_and_codebert"
    else:
        analysis = "sast_only" if sem_ok else "codebert_only"

    checks = consistency_checks(sem, sem_ok, scope)
    for w in checks["warnings"]:
        C.log(STEP, f"CANH BAO: {w}")

    mode = scope["mode"]
    targets = set(scope["target_files"])
    changed = {k: set(v) for k, v in scope.get("changed_lines", {}).items()}
    by_id = {u["id"]: u for u in units}

    # ---- gan finding Semgrep vao don vi
    per_unit_sast, sem_kept = {}, []
    for f in (sem.get("findings", []) if sem_ok else []):
        if f["file"] not in targets:
            continue
        cls = C.canon_class(f["class"])
        # muc tool 4 bac (22/11); semgrep-results cu (truoc 22/11) chua co -> tinh lai tu impact_severity x confidence
        if policy.get("model_levels") and (policy.get("semgrep_levels") or {}).get("rule") == "class_cvss":   # 25/11 (5x5): cung muc CVSS lop voi CodeBERT
            f = {**f, "tool_level": sem_level_cvss(cls, f.get("confidence"), policy)}
        else:
            f = {**f, "tool_level": f.get("tool_level") or C.tool_level(
                f.get("impact_severity") or C.class_default_severity(cls), f.get("confidence"))}
        line = f.get("start_line") or 0
        u = innermost_function(units, f["file"], line)
        if u is None:   # ngoai moi ham: thuoc doan module neu co, neu khong tao don vi "module"
            u = next((x for x in units if x["file"] == f["file"] and x["unit"] == "module_snippet"
                      and x["start"] <= line <= x["end"]), None)
        if u is None:
            uid = f"{f['file']}::<module>@L{line}"
            u = by_id.setdefault(uid, {"id": uid, "file": f["file"], "unit": "module", "name": "<module>",
                                       "start": line, "end": f.get("end_line") or line, "in_diff": False})
        on_changed = mode == "full" or bool(changed.get(f["file"], set()) &
                                            set(range(line, (f.get("end_line") or line) + 1)))
        if mode == "diff" and not (u.get("in_diff") or on_changed):
            continue
        u["in_diff"] = True
        per_unit_sast.setdefault(u["id"], []).append({**f, "class": cls})
        sem_kept.append({**f, "class": cls, "unit_id": u["id"],
                         "snippet": snippet(repo, f["file"], f.get("start_line"), f.get("end_line"),
                                            unit_code=u.get("code"), unit_start=u.get("start"))})

    cb_units = {r["id"]: r for r in (cb.get("units", []) if cb_ok else [])}

    # ---- compare + gate tung don vi
    out_units, states, decisions = [], {}, {k: 0 for k in RANK}
    weak = C.canon_keys((cb or {}).get("thresholds_weak")) if cb_ok else None
    th_cb = C.canon_keys((cb or {}).get("thresholds")) if cb_ok else {}
    considered = [u for u in by_id.values() if u.get("in_diff")]
    for u in sorted(considered, key=lambda x: (x["file"], x["start"], x["id"])):
        sf = per_unit_sast.get(u["id"], [])
        S = sorted({f["class"] for f in sf})
        tier = "high" if any(f["confidence"] == "high" for f in sf) else ("audit" if sf else None)
        r = cb_units.get(u["id"])
        B = list(r["groups"]) if r else []
        common = [c for c in S if c in B]
        if analysis == "sast_only":
            state = "degraded_sast_only" if S else "pass"
        elif analysis == "codebert_only":
            state = "degraded_codebert_only" if B else "pass"
        elif common:
            state = "agree"
        elif S and B:
            state = "conflict"
        elif S:
            state = "sast_only"
        elif B:
            state = "codebert_only"
        else:
            state = "pass"
        dec, cells = decide_gate(policy, sf, r, th_cb, weak, analysis, u["file"])
        top_cells = [x for x in cells if x["decision"] == dec]
        if top_cells and dec != "PASS":
            vclass = top_cells[0]["class"]
        elif state == "agree":
            vclass = common[0]
        elif S:
            vclass = sorted(S, key=lambda c: (c not in {f["class"] for f in sf if f["confidence"] == "high"}, c))[0]
        elif B:
            vclass = max(B, key=lambda g: r["probs"][g])
        else:
            vclass = None
        states[state] = states.get(state, 0) + 1
        decisions[dec] += 1
        out_units.append({
            "id": u["id"], "file": u["file"], "unit": u["unit"], "function": u.get("name"),
            "start": u["start"], "end": u["end"], "state": state, "decision": dec, "vuln_class": vclass, "cells": cells,
            "sast_tier": tier, "sast_level": max_tool_level(*(f.get("tool_level") for f in sf)), "sast_classes": S, "sast_rules": sorted({f["rule_id"] for f in sf}),
            "codebert_classes": B,
            "codebert": {g: r["probs"][g] for g in B} if r else {},
            "codebert_probs": r["probs"] if r else None,
            "codebert_explain": r.get("explain") if r else None,
            # ma nguyen van CA HAM (du ngu canh) cho ham co tin hieu -> Dashboard to dam dong Semgrep / khoi CodeBERT
            "code": unit_code(u) if state not in ("pass",) else None,
            "truncated": bool(r and r.get("truncated")),
            "related_classes": sorted(set(S) | set(B)),
            # CodeBERT chi cham ca ham (khong chi ra dong) -> luu 25 dong dau ham de xem; chi cho ham CodeBERT gan co ma Semgrep khong bao
            "snippet": snippet(repo, u["file"], u["start"], min(u["end"], u["start"] + 24), ctx=0, unit_code=u.get("code"),
                               unit_start=u.get("start")) if state == "codebert_only" else None,
        })

    if analysis == "failed":
        decision = policy["tool_status"]["both_failed"]          # FAIL
    else:
        decision = max((x["decision"] for x in out_units), key=RANK.get, default="PASS")
        if analysis != "sast_and_codebert":                      # mot luong loi -> it nhat REVIEW
            decision = max(decision, policy["tool_status"]["one_failed"], key=RANK.get)
    th = (cb or {}).get("thresholds") or (auth.get("model") or {}).get("thresholds") or {}
    model = (cb or {}).get("model") or {k: (auth.get("model") or {}).get(k) for k in
                                        ("name", "path", "dataset_version", "format", "checkpoint_sha256",
                                         "val_macro_f1", "val_metrics", "infra_verify")}
    gate = {
        "mode": "parallel", "scan_mode": mode, "status": "configured", "decision": decision,
        "decisions": decisions, "states": states, "units": out_units,
        "units_evaluated": len(out_units),
        "units_truncated": sum(u["truncated"] for u in out_units),
        "policy": policy["matrix"], "tool_status": policy["tool_status"], "policy_version": policy["policy_version"], "semgrep_rule": (policy.get("semgrep_levels") or {}).get("rule") or "metadata_severity",
        "pipeline_action": policy["pipeline"].get(decision), "thresholds_weak_available": bool(weak),
        "policy_note": policy.get("note"), "gate_config_sha256": policy_sha, "model_format": "multilabel_sigmoid",
        "gate_kind": "5x5" if policy.get("model_levels") else ("5x3" if "Critical" in policy["matrix"] else "3x3"),
        "model_severity": (policy.get("model_levels") or {}).get("severity_by_class"),
    }
    C.write_json(od / "gate.json", gate)

    # ---- bao cao schema 3 (giong worker Server 3 de dashboard doc chung)
    ci = C.ci_context()
    srun = (sem or {}).get("run", {})
    tools = [{
        "tool_name": "semgrep", "status": "completed" if sem_ok else "failed",
        "tool_version": f"semgrep {srun.get('semgrep_version', '')}".strip(), "exit_code": 0 if sem_ok else None,
        "image_id": os.environ.get("AIWS_SEMGREP_IMAGE"),
        "config": {"ruleset_version": srun.get("ruleset_version"), "ruleset_sha256": srun.get("bundle_sha256"),
                   "taxonomy_version": srun.get("taxonomy_version"), "excludes": srun.get("excludes")},
        "started_at": srun.get("scanned_at"), "finished_at": None,
        "error_message": None if sem_ok else "khong co semgrep-results.json (job Semgrep loi)",
        "summary": (sem or {}).get("summary"),
        "normalized_findings": [{"file": f["file"], "line": f.get("start_line"), "end_line": f.get("end_line"),
                                 "level": f.get("tool_level"), "impact_severity": f.get("impact_severity"),
                                 "rule_id": f["rule_id"], "classes": [f["class"]],
                                 "cwes": [c.replace("CWE-", "") for c in f.get("cwes", [])],
                                 "confidence": f["confidence"], "severity": f.get("semgrep_severity"),
                                 "message": f.get("message"), "snippet": f.get("snippet")} for f in sem_kept],
    }, {
        "tool_name": "codebert", "status": "completed" if cb_ok else "failed",
        "tool_version": "transformers (CPU)", "exit_code": None, "image_id": os.environ.get("AIWS_CODEBERT_IMAGE"),
        "config": {"model": model, "thresholds": th, "model_format": "multilabel_sigmoid", "device": "cpu",
                   "max_len": 512, "truncation": (cb or {}).get("truncation", "head 512 tokens"),
                   "inference": (cb or {}).get("inference"), "model_val_macro_f1": model.get("val_macro_f1"),
                   "unit_backend": scope.get("unit_backend"), "unit_backend_version": scope.get("unit_backend_version"),
                   "units_by_type": {t: sum(1 for u in units if u["unit"] == t and u["in_diff"] and u["scored"])
                                     for t in ("function", "module_snippet")}},
        "started_at": (cb or {}).get("started_at"), "finished_at": (cb or {}).get("finished_at"),
        "error_message": None if cb_ok else (cb or {}).get("error", "khong co codebert-results.json"),
        "summary": (cb or {}).get("summary"),
    }]
    status = "completed" if analysis == "sast_and_codebert" else ("failed" if analysis == "failed" else "incomplete")
    report = {
        "schema_version": 3, "report_type": "security_scan", "source_type": "git", "status": status,
        "analysis_status": analysis, "codebert_status": tools[1]["status"],
        "security_gate": decision, "gate": gate, "model": model, "tools": tools,
        "ruleset": {"ruleset_version": srun.get("ruleset_version"), "ruleset_sha256": srun.get("bundle_sha256"),
                    "semgrep_version_pinned": srun.get("semgrep_version")},
        "summary": {"gate_decision": decision, "high_findings": sum(f["confidence"] == "high" for f in sem_kept),
                    "semgrep_levels": {lv: sum(f.get("tool_level") == lv for f in sem_kept) for lv in C.TOOL_LEVELS},
                    "audit_findings": sum(f["confidence"] == "audit" for f in sem_kept),
                    "codebert_flagged": sum(bool(u["codebert_classes"]) for u in out_units),
                    "scan_mode": mode, "units_in_scope": len(out_units)},
        "branch": ci["ref"], "target_commit": scope.get("head"), "base_commit": scope.get("base"),
        "target_repository_url": ci["project_url"], "executor": "gitlab_ci", "worker_id": ci["runner"],
        "ci": ci, "scope": {k: scope[k] for k in ("mode", "note", "unit_backend", "summary")},
        "consistency": checks, "warnings": checks["warnings"],
        "authorize": {"source": auth.get("source"), "model_status": (auth.get("model") or {}).get("status")},
        "created_at": scope.get("created_at"), "started_at": scope.get("created_at"), "finished_at": C.now(),
    }
    C.write_json(od / "report.json", report)
    write_sarif(od / "ai-whitesec.sarif", out_units, report)
    write_codequality(od / "gl-code-quality-report.json", out_units)
    write_summary(od / "summary.md", report)

    C.log(STEP, f"phan tich {analysis}; {len(out_units)} don vi ({mode}); quyet dinh {decision}; "
                f"BLOCK {decisions['BLOCK']} / REVIEW {decisions['REVIEW']} / INFO {decisions['INFO']} / PASS {decisions['PASS']}; "
                f"trang thai {states}")
    print((od / "summary.md").read_text(encoding="utf-8"))
    if analysis == "failed":
        C.die(STEP, "ca Semgrep va CodeBERT deu loi", C.EXIT_TOOL)
    if not cb_ok and policy.get("require_model", True):
        C.die(STEP, "CodeBERT khong chay duoc ma policy bat buoc co model -> FAILED (bao cao van duoc luu)",
              C.EXIT_CONFIG)
    if decision == "BLOCK" and policy.get("enforce_block", True) and os.environ.get("AIWS_GATE_ENFORCE", "1") == "1":
        C.die(STEP, "Security Gate = BLOCK", C.EXIT_BLOCK)


SEV = {"FAIL": ("error", "blocker"), "BLOCK": ("error", "critical"), "REVIEW": ("warning", "major"),
       "INFO": ("note", "minor"), "PASS": ("note", "info")}


def write_sarif(p, units, report):
    flagged = [u for u in units if u["decision"] != "PASS"]
    rules = sorted({u["vuln_class"] for u in flagged if u["vuln_class"]})
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "AI-WhiteSec-CI", "informationUri": report["ci"].get("project_url") or "",
                            "version": report["gate"]["policy_version"],
                            "rules": [{"id": r, "shortDescription": {"text": r}} for r in rules]}},
        "results": [{
            "ruleId": u["vuln_class"] or "UNKNOWN", "level": SEV[u["decision"]][0],
            "message": {"text": f"{u['decision']} ({u['state']}): {u['vuln_class']} trong {u['function']} - "
                                f"Semgrep {', '.join(u['sast_rules']) or '-'}; CodeBERT "
                                f"{', '.join(f'{g} {p:.2f}' for g, p in u['codebert'].items()) or '-'}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": u["file"]},
                                                "region": {"startLine": max(1, u["start"]),
                                                           "endLine": max(1, u["end"])}}}],
            "properties": {"state": u["state"], "decision": u["decision"], "unit": u["unit"]},
        } for u in flagged]}]}
    C.write_json(p, sarif)


def write_codequality(p, units):
    rows = []
    for u in units:
        if u["decision"] == "PASS":
            continue
        fp = hashlib.sha1(f"{u['id']}|{u['vuln_class']}|{u['state']}".encode()).hexdigest()
        rows.append({"description": f"[{u['decision']}] {u['vuln_class']} ({u['state']}) - {u['function']}",
                     "check_name": f"aiws/{u['vuln_class']}", "fingerprint": fp,
                     "severity": SEV[u["decision"]][1],
                     "location": {"path": u["file"], "lines": {"begin": max(1, u["start"])}}})
    C.write_json(p, rows)


def write_summary(p, rep):
    g, s = rep["gate"], rep["summary"]
    lines = [f"## AI-WhiteSec-CI - Security Gate: **{rep['security_gate']}**", "",
             f"- Che do: `{s['scan_mode']}` · phan tich: `{rep['analysis_status']}` · policy `{g['policy_version']}`",
             f"- Model: `{rep['model'].get('name')}` (dataset {rep['model'].get('dataset_version')}) · "
             f"ruleset Semgrep `{rep['ruleset'].get('ruleset_version')}`",
             f"- Don vi: {g['units_evaluated']} · BLOCK {g['decisions']['BLOCK']} · REVIEW {g['decisions']['REVIEW']} "
             f"· INFO {g['decisions']['INFO']} · PASS {g['decisions']['PASS']} · pipeline: {g.get('pipeline_action')}",
             f"- Semgrep: {s['high_findings']} high, {s['audit_findings']} audit · CodeBERT gan co {s['codebert_flagged']} don vi",
             "- Muc tool Semgrep (metadata.severity x confidence): " + " · ".join(
                 f"{lv} {(s.get('semgrep_levels') or {}).get(lv, 0)}" for lv in C.TOOL_LEVELS),
             ""]
    if rep.get("warnings"):
        lines += ["**Canh bao:**", *[f"- {w}" for w in rep["warnings"]], ""]
    lines += ["| Quyet dinh | Trang thai | Lop | File | Ham | Semgrep | CodeBERT |", "|---|---|---|---|---|---|---|"]
    top = sorted([u for u in g["units"] if u["decision"] != "PASS"], key=lambda u: (-RANK[u["decision"]], u["file"]))
    for u in top[:30]:
        cbs = ", ".join(f"{k} {v:.2f}" for k, v in u["codebert"].items()) or "-"
        lines.append(f"| {u['decision']} | {u['state']} | {u['vuln_class']} | `{u['file']}:{u['start']}` | "
                     f"{u['function']} | {', '.join(u['sast_rules']) or '-'} | {cbs} |")
    if len(top) > 30:
        lines.append(f"\n... va {len(top) - 30} don vi khac (xem gate.json).")
    Path(p).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
