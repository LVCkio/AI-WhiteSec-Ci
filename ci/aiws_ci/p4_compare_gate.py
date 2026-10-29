"""P4 - Normalize & Merge Findings + Security Gate (BLOCK / REVIEW / PASS).

  python -m aiws_ci.p4_compare_gate --out-dir aiws-out --semgrep semgrep-results.json

1. Normalize: finding Semgrep (scan_repo.py) -> lop + tang high/audit; ket qua CodeBERT -> nhom vuot nguong.
2. Gan finding Semgrep vao ham NHO NHAT chua dong bat dau (theo danh sach don vi P1); nam ngoai moi ham ->
   don vi "module" rieng. Che do diff: chi xet don vi trong diff va finding tren dong bi sua.
3. Compare tung don vi: agree (cung lop) | conflict (ca hai bao, khac lop) | sast_only | codebert_only | pass.
4. Gate theo ci/gate-policy.json (co phien ban, SHA-256 ghi vao bao cao). Mot luong loi -> che do suy giam.
Dau ra: gate.json, report.json (schema_version 3, dung dinh dang dashboard dang doc), ai-whitesec.sarif,
        gl-code-quality-report.json (widget merge request), summary.md.
Ma thoat: 0 = PASS/REVIEW, 1 = BLOCK (khi enforce_block), 2 = thieu model ma policy bat buoc, 3 = ca hai luong loi.
"""
import argparse
import hashlib
import os
from pathlib import Path

from . import common as C
from .units import innermost_function

STEP = "P4-gate"
RANK = {"PASS": 0, "REVIEW": 1, "BLOCK": 2}


def load_policy(path: Path):
    p = C.read_json(path)
    if p is None:
        C.die(STEP, f"khong thay {path}", C.EXIT_CONFIG)
    return p, C.sha256_file(path)


def decide(policy, state, tier):
    rule = policy["states"].get(state) if not state.startswith("degraded_") else policy["degraded"].get(state)
    if isinstance(rule, dict):
        return rule.get(tier or "audit", "REVIEW")
    return rule or "REVIEW"


SNIP_CTX, SNIP_MAX_LINES, SNIP_MAX_CHARS = 3, 40, 240
_src_cache = {}


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
    out_units, states, decisions = [], {}, {"PASS": 0, "REVIEW": 0, "BLOCK": 0}
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
        dec = decide(policy, state, tier) if state != "pass" else "PASS"
        if state == "agree":
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
            "start": u["start"], "end": u["end"], "state": state, "decision": dec, "vuln_class": vclass,
            "sast_tier": tier, "sast_classes": S, "sast_rules": sorted({f["rule_id"] for f in sf}),
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
        decision = None
    else:
        decision = max((x["decision"] for x in out_units), key=RANK.get, default="PASS")
    th = (cb or {}).get("thresholds") or (auth.get("model") or {}).get("thresholds") or {}
    model = (cb or {}).get("model") or {k: (auth.get("model") or {}).get(k) for k in
                                        ("name", "path", "dataset_version", "format", "checkpoint_sha256",
                                         "val_macro_f1", "val_metrics", "infra_verify")}
    gate = {
        "mode": "parallel", "scan_mode": mode, "status": "configured", "decision": decision,
        "decisions": decisions, "states": states, "units": out_units,
        "units_evaluated": len(out_units),
        "units_truncated": sum(u["truncated"] for u in out_units),
        "policy": policy["states"], "degraded_policy": policy["degraded"], "policy_version": policy["policy_version"],
        "policy_note": policy.get("note"), "gate_config_sha256": policy_sha, "model_format": "multilabel_sigmoid",
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
                                 "rule_id": f["rule_id"], "classes": [f["class"]],
                                 "cwes": [c.replace("CWE-", "") for c in f.get("cwes", [])],
                                 "confidence": f["confidence"], "severity": f.get("semgrep_severity"),
                                 "message": f.get("message"), "snippet": f.get("snippet")} for f in sem_kept],
    }, {
        "tool_name": "codebert", "status": "completed" if cb_ok else "failed",
        "tool_version": "transformers (CPU)", "exit_code": None, "image_id": os.environ.get("AIWS_CODEBERT_IMAGE"),
        "config": {"model": model, "thresholds": th, "model_format": "multilabel_sigmoid", "device": "cpu",
                   "max_len": 512, "truncation": "head 512 tokens", "model_val_macro_f1": model.get("val_macro_f1"),
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
                    "audit_findings": sum(f["confidence"] == "audit" for f in sem_kept),
                    "codebert_flagged": sum(bool(u["codebert_classes"]) for u in out_units),
                    "scan_mode": mode, "units_in_scope": len(out_units)},
        "branch": ci["ref"], "target_commit": scope.get("head"), "base_commit": scope.get("base"),
        "target_repository_url": ci["project_url"], "executor": "gitlab_ci", "worker_id": ci["runner"],
        "ci": ci, "scope": {k: scope[k] for k in ("mode", "note", "unit_backend", "summary")},
        "authorize": {"source": auth.get("source"), "model_status": (auth.get("model") or {}).get("status")},
        "created_at": scope.get("created_at"), "started_at": scope.get("created_at"), "finished_at": C.now(),
    }
    C.write_json(od / "report.json", report)
    write_sarif(od / "ai-whitesec.sarif", out_units, report)
    write_codequality(od / "gl-code-quality-report.json", out_units)
    write_summary(od / "summary.md", report)

    C.log(STEP, f"phan tich {analysis}; {len(out_units)} don vi ({mode}); quyet dinh {decision}; "
                f"BLOCK {decisions['BLOCK']} / REVIEW {decisions['REVIEW']} / PASS {decisions['PASS']}; "
                f"trang thai {states}")
    print((od / "summary.md").read_text(encoding="utf-8"))
    if analysis == "failed":
        C.die(STEP, "ca Semgrep va CodeBERT deu loi", C.EXIT_TOOL)
    if not cb_ok and policy.get("require_model", True):
        C.die(STEP, "CodeBERT khong chay duoc ma policy bat buoc co model -> FAILED (bao cao van duoc luu)",
              C.EXIT_CONFIG)
    if decision == "BLOCK" and policy.get("enforce_block", True) and os.environ.get("AIWS_GATE_ENFORCE", "1") == "1":
        C.die(STEP, "Security Gate = BLOCK", C.EXIT_BLOCK)


SEV = {"BLOCK": ("error", "critical"), "REVIEW": ("warning", "major"), "PASS": ("note", "info")}


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
             f"· PASS {g['decisions']['PASS']}",
             f"- Semgrep: {s['high_findings']} high, {s['audit_findings']} audit · CodeBERT gan co {s['codebert_flagged']} don vi",
             "", "| Quyet dinh | Trang thai | Lop | File | Ham | Semgrep | CodeBERT |", "|---|---|---|---|---|---|---|"]
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
