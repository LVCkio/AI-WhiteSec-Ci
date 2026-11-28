"""Hang so va ham dung chung cho cac buoc P0-P5 cua Pipeline 2."""
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path

# Thu tu cot logits cua model (INFERENCE.md muc 2; eval_utils.GROUPS). KHONG doc tu config.json (LABEL_0..5).
# Ten lop Auth: leader chot AUTHENTICATION_WEAKNESS (29/10). Goi model v24_pair_e5 va bo rule v4.7.0 con ghi
# INSECURE_AUTHENTICATION -> moi ten doc vao deu qua canon_class() (cung cot logits so 4, chi khac ten).
GROUPS = ["PATH_TRAVERSAL", "XSS", "OS_COMMAND_INJECTION", "SQL_INJECTION",
          "AUTHENTICATION_WEAKNESS", "HARDCODED_CREDENTIALS"]
OLD_NAMES = {"INSECURE_AUTHENTICATION": "AUTHENTICATION_WEAKNESS"}

# Ma thoat thong nhat cho moi buoc
EXIT_OK, EXIT_BLOCK, EXIT_CONFIG, EXIT_TOOL = 0, 1, 2, 3

CI_HOME = Path(os.environ.get("AIWS_CI_HOME", Path(__file__).resolve().parent.parent))   # thu muc ci/
SEMGREP_TOOLS = Path(os.environ.get("AIWS_SEMGREP_TOOLS",
                                    CI_HOME.parent / "security-config" / "semgrep" / "tools"))


def now() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with Path(p).open("rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def read_json(p, default=None):
    p = Path(p)
    if not p.is_file():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


def write_json(p, obj):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def read_jsonl(p):
    p = Path(p)
    if not p.is_file():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def write_jsonl(p, rows):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


# Muc TOOL (Semgrep) - huong nhom thong nhat 22/11/2026 (cau 6): 4 muc Critical / High / Medium / Low ghep tu
#   metadata.severity cua rule (muc nghiem trong cua LOAI lo hong, gan khi viet rule: critical / high / medium; thieu ->
#   default_severity cua lop trong docs/taxonomy.yml) x metadata.confidence (high / audit).
#   confidence high : giu nguyen muc (critical -> Critical, high -> High, medium -> Medium, low -> Low)
#   confidence audit: critical / high -> Medium; medium / low -> Low   (rule audit KHONG BAO GIO len Critical / High)
#   Khong dung severity cap rule (ERROR / WARNING / INFO): o bo rule nhom, no chi la ban sao cua confidence.
#   Chi de BAO CAO / hien thi: quyet dinh Gate 3x3 van dung truc Semgrep High / Audit (confidence) trong gate-policy.json.
TOOL_LEVELS = ["Critical", "High", "Medium", "Low"]
_TOOL_IMPACT = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def tool_level(impact, confidence) -> str:
    base = _TOOL_IMPACT.get(str(impact or "").strip().lower(), "Medium")
    if str(confidence or "").strip().lower() == "high":
        return base
    return "Medium" if base in ("Critical", "High") else "Low"


# Muc nghiem trong mac dinh cua lop (docs/taxonomy.yml, default_severity) - dung khi finding Semgrep thieu impact_severity
# (semgrep-results cu / du lieu dung tay). Doc tu taxonomy.yml neu co (anh aiws-codebert co chep file nay), khong thi bang duoi.
_CLASS_SEVERITY_FALLBACK = {"SQL_INJECTION": "critical", "OS_COMMAND_INJECTION": "critical", "XSS": "medium",
                            "PATH_TRAVERSAL": "high", "AUTHENTICATION_WEAKNESS": "high", "HARDCODED_CREDENTIALS": "high"}
_class_severity_cache = None


def class_default_severity(cls):
    global _class_severity_cache
    if _class_severity_cache is None:
        m = dict(_CLASS_SEVERITY_FALLBACK)
        for p in (CI_HOME.parent / "docs" / "taxonomy.yml", Path(os.environ.get("CI_PROJECT_DIR", ".")) / "docs" / "taxonomy.yml"):
            try:
                import yaml
                t = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                for name, c in (t.get("classes") or {}).items():
                    if c.get("default_severity"):
                        m[canon_class(name)] = str(c["default_severity"]).lower()
                break
            except Exception:
                continue
        _class_severity_cache = m
    return _class_severity_cache.get(canon_class(cls))


def canon_class(name: str) -> str:
    return OLD_NAMES.get(name, name)


def canon_keys(d: dict) -> dict:
    """thresholds.json / xac suat theo ten lop -> ten da chot."""
    return {canon_class(k): v for k, v in (d or {}).items()}


def log(step: str, msg: str):
    print(f"[{step}] {msg}", flush=True)


def die(step: str, msg: str, code: int):
    print(f"[{step}] LOI: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def ci_context() -> dict:
    """Thong tin GitLab CI dua vao bao cao (khong co bien bi mat)."""
    e = os.environ.get
    return {
        "pipeline_id": e("CI_PIPELINE_ID"), "pipeline_url": e("CI_PIPELINE_URL"),
        "parent_pipeline_id": e("AIWS_PARENT_PIPELINE_ID") or e("CI_PIPELINE_ID"),
        "parent_pipeline_url": e("AIWS_PARENT_PIPELINE_URL"),
        # 28/11b: so thu tu pipeline trong project (#iid tren GitLab) - dashboard hien "CI #<iid>"
        "pipeline_iid": e("CI_PIPELINE_IID"),
        "parent_pipeline_iid": e("AIWS_PARENT_PIPELINE_IID") or e("CI_PIPELINE_IID"),
        "source": e("AIWS_PIPELINE_SOURCE") or e("CI_PIPELINE_SOURCE"),
        "project_path": e("CI_PROJECT_PATH"), "project_url": e("CI_PROJECT_URL"),
        "ref": e("CI_COMMIT_REF_NAME"), "commit": e("CI_COMMIT_SHA"),
        "merge_request_iid": e("AIWS_MR_IID") or e("CI_MERGE_REQUEST_IID"),
        "runner": e("CI_RUNNER_DESCRIPTION"),
    }
