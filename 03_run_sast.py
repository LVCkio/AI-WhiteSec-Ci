"""Compare six vulnerability classes using Semgrep + Bandit and CodeBERT.

Only vulnerable test samples of the selected languages (--languages, default
Python; Python, Java, JavaScript, PHP supported) are evaluated. Metrics are
reported per language x class, with a macro per language and, for several
languages, an overall block (ALL). No SAFE class or binary
SAFE/vulnerable detection metric is included. Samples without findings PASS
with no class assigned. PASS is a workflow status, not a seventh class.

Install tools with: python -m pip install semgrep bandit
Run from the project root with: python 03_run_sast.py
Semgrep downloads registry rules when the baseline configurations are first used.
Source files remain local; telemetry is disabled with --metrics=off.
"""
import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_INPUT = ROOT / "data" / "test.csv"
DEFAULT_OUTPUT = ROOT / "sast_results"
DEFAULT_CODEBERT = ROOT / "predictions_codebert_6class.csv"
RULESET_V4 = ROOT / "security-config" / "semgrep"  # K02: ruleset v4 (tieu chi nhom, co manifest)
CUSTOM_RULES = RULESET_V4 / "semgrep.yml"           # mac dinh: bundle v4 sinh tu security-config/semgrep/rules
CUSTOM_RULES_V3 = ROOT / "rules" / "custom"         # v3 (R02/R03) dong bang: --rules rules/custom de tai lap
FROZEN_RULES_V2 = ROOT / "rules" / "semgrep_rules.yml"  # T05/T07 rules (Python only, frozen)
# Bandit checks too noisy to conclude from (R03): module-level `import subprocess` and subprocess
# calls without a shell / with a partial path. They are kept as audit-tier hints, never 'high'.
BANDIT_NOISE = {"B404", "B603", "B607"}
CLASSES = (
    "SQL_INJECTION",
    "XSS",
    "OS_COMMAND_INJECTION",
    "PATH_TRAVERSAL",
    "AUTHENTICATION_WEAKNESS",
    "HARDCODED_CREDENTIALS",
)
CWE_TO_CLASS = {
    "89": "SQL_INJECTION",
    "79": "XSS",
    "78": "OS_COMMAND_INJECTION",
    "77": "OS_COMMAND_INJECTION",
    "88": "OS_COMMAND_INJECTION",
    "22": "PATH_TRAVERSAL",
    "23": "PATH_TRAVERSAL",
    "36": "PATH_TRAVERSAL",
    "287": "AUTHENTICATION_WEAKNESS",
    "306": "AUTHENTICATION_WEAKNESS",
    "307": "AUTHENTICATION_WEAKNESS",
    "798": "HARDCODED_CREDENTIALS",
    "259": "HARDCODED_CREDENTIALS",
    "321": "HARDCODED_CREDENTIALS",
}
CWE_PATTERN = re.compile(r"\bCWE-?0*(\d+)\b", re.IGNORECASE)
TAXONOMY = ROOT / "docs" / "taxonomy.yml"


def _load_class_aliases() -> dict[str, str]:
    """Ten lop tuong duong -> ten noi bo trong CLASSES (docs/taxonomy.yml: ten chuan + old_names).

    Taxonomy v0.3.0 goi lop Auth la INSECURE_AUTHENTICATION (ten cu AUTHENTICATION_WEAKNESS). Pipeline
    hien tai (mo hinh C03, Gate, bao cao) van dung ten cu, nen moi ten tuong duong deu quy ve ten trong
    CLASSES truoc khi so sanh. Chi doi ten, khong doi logic so khop.
    """
    aliases = {"INSECURE_AUTHENTICATION": "AUTHENTICATION_WEAKNESS"}  # du phong khi khong doc duoc taxonomy
    try:
        import yaml
        tax = yaml.safe_load(TAXONOMY.read_text(encoding="utf-8")) or {}
        for cls, cfg in (tax.get("classes") or {}).items():
            group = {cls, *((cfg or {}).get("old_names") or [])}
            internal = next((c for c in group if c in CLASSES), None)
            for name in group:
                if internal and name != internal:
                    aliases[name] = internal
    except Exception:  # khong co PyYAML / file taxonomy: dung bang du phong
        pass
    return aliases


CLASS_ALIASES = _load_class_aliases()


def canonical_class(name: Any) -> Any:
    """Quy ten lop ve ten trong CLASSES (vd. INSECURE_AUTHENTICATION -> AUTHENTICATION_WEAKNESS)."""
    if not isinstance(name, str):
        return name
    value = name.strip()
    return value if value in CLASSES else CLASS_ALIASES.get(value, value)
LANGUAGES = ("Python", "Java", "JavaScript", "PHP")
EXTENSIONS = {"Python": ".py", "Java": ".java", "JavaScript": ".js", "PHP": ".php"}
# Built-in Semgrep registry configs per language; p/security-audit is added for every run.
BASELINE_BY_LANGUAGE = {"Python": ["p/python"], "Java": ["p/java"],
                        "JavaScript": ["p/javascript"], "PHP": ["p/php"]}
COMMON_BASELINE = ["p/security-audit"]


def canonical_language(value: str) -> str | None:
    folded = value.strip().casefold()
    return next((lang for lang in LANGUAGES if lang.casefold() == folded), None)


def parse_languages(values: list[str]) -> tuple[str, ...]:
    if any(v.casefold() == "all" for v in values):
        return LANGUAGES
    langs = []
    for v in values:
        lang = canonical_language(v)
        if lang is None:
            raise ValueError(f"Unsupported language {v!r}; choose from {', '.join(LANGUAGES)} or 'all'")
        if lang not in langs:
            langs.append(lang)
    return tuple(langs)


def ruleset_info(rules: Path) -> dict[str, Any]:
    """K02: ghi phien ban ruleset vao moi ket qua SAST (v4 doc tu ruleset-manifest.json)."""
    try:
        inside_v4 = RULESET_V4.resolve() in [rules.resolve(), *rules.resolve().parents]
    except OSError:
        inside_v4 = False
    manifest = RULESET_V4 / "ruleset-manifest.json"
    if inside_v4 and manifest.is_file():
        m = json.loads(manifest.read_text(encoding="utf-8"))
        return {k: m.get(k) for k in ("ruleset_version", "ruleset_sha256", "semgrep_version_pinned",
                                      "regression_passed")}
    return {"ruleset_version": "v3 (rules/custom)" if "custom" in str(rules) else str(rules)}


def default_baseline(languages: tuple[str, ...]) -> list[str]:
    return [c for lang in languages for c in BASELINE_BY_LANGUAGE[lang]] + COMMON_BASELINE


def sample_name(index: int, row: dict[str, str]) -> str:
    """Temporary file name; the extension lets Semgrep pick the language."""
    return f"sample_{index:06d}{EXTENSIONS[row['programming_language']]}"


def read_python_test_rows(path: Path) -> list[dict[str, str]]:
    return read_test_rows(path, ("Python",))


def read_test_rows(path: Path, languages: tuple[str, ...] = ("Python",)) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"id", "code", "cls_gt", "programming_language"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path} is missing required columns: {sorted(missing)}")
        rows = []
        for row in reader:
            lang = canonical_language(row["programming_language"])
            if lang in languages:
                # nhan theo taxonomy (vd. INSECURE_AUTHENTICATION cua dataset v2.2) quy ve ten trong CLASSES
                rows.append({**row, "programming_language": lang, "cls_gt": canonical_class(row["cls_gt"]),
                             "cls_gt_original": row["cls_gt"]})
    if not rows:
        raise ValueError(f"No {'/'.join(languages)} rows found in {path}")
    unknown = sorted({row["cls_gt"] for row in rows} - set(CLASSES))
    if unknown:
        raise ValueError(
            f"{path} must contain the six vulnerability classes only; "
            f"unexpected cls_gt labels: {unknown}. Run 01_prepare_data.py first."
        )
    ids = [row["id"] for row in rows]
    if any(not sample_id for sample_id in ids) or len(ids) != len(set(ids)):
        raise ValueError(f"{path} contains empty or duplicate sample IDs")
    return rows


def normalize_code(code: str) -> str:
    lines = code.splitlines()
    first = next((line for line in lines if line.strip()), "")
    prefix = first[:len(first) - len(first.lstrip(" \t"))]
    if not prefix:
        return code
    return "\n".join(
        line[len(prefix):] if line.startswith(prefix) else line
        for line in lines
    )


JS_METHOD = re.compile(r"^\s*(?:static\s+|async\s+|get\s+|set\s+)*(?!function\b|if\b|for\b|while\b|switch\b|catch\b)"
                       r"[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{")
JAVA_TYPE = re.compile(r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public\s+|private\s+|protected\s+|abstract\s+|final\s+|static\s+)*"
                       r"(?:class|interface|enum|record)\s+\w+", re.MULTILINE)


JAVA_FILE_LEVEL = re.compile(r"^\s*(?:package|import)\s+[\w.*]+\s*;", re.MULTILINE)
JAVA_METHOD = re.compile(r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*"
                         r"(?:<[^>]{0,80}>\s+)?[\w.$\[\]?]{1,80}(?:<[^()]{0,120}>)?(?:\[\])*\s+\w+\s*\(")
PHP_METHOD = re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)+function\b")


def brace_balance(code: str) -> tuple[int, int]:
    """(missing_openers, missing_closers) of a C-like fragment, ignoring strings and comments."""
    depth, low, i, n, quote = 0, 0, 0, len(code), None
    while i < n:
        c = code[i]
        if quote:
            if c == "\\":
                i += 2; continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif code.startswith("//", i) or c == "#":
            j = code.find("\n", i); i = n if j < 0 else j; continue
        elif code.startswith("/*", i):
            j = code.find("*/", i + 2); i = n if j < 0 else j + 2; continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            low = min(low, depth)
        i += 1
    return -low, depth - low


def wrap_fragment(code: str, language: str) -> tuple[str, int]:
    """Make a function-level fragment parseable (R01). Returns (text, line_offset):
    finding line in the wrapped file minus line_offset = line in the original fragment.
    PHP needs `<?php` (and a class around a method with a visibility modifier); a Java
    method or statement needs an enclosing class; a JavaScript class method (no `function`
    keyword) needs an enclosing class. Cut top-level blocks of Java/JS/PHP get their braces
    balanced (missing `{` prepended, missing `}` appended). Python is unchanged."""
    if language == "Python":
        return code, 0
    head, tail = [], []
    if language in ("Java", "JavaScript", "PHP"):
        opens, closes = brace_balance(code)
        head += ["{"] * opens
        tail += ["}"] * closes
    first = next((line for line in code.splitlines() if line.strip()), "")
    if language == "PHP":
        if code.lstrip().startswith("<?"):
            return code, 0
        if PHP_METHOD.match(first):
            head, tail = ["class Wrapper {"] + head, tail + ["}"]
        head = ["<?php"] + head
    elif language == "Java" and not JAVA_TYPE.search(code) and not JAVA_FILE_LEVEL.search(code):
        if JAVA_METHOD.match(first):
            head, tail = ["class Wrapper {"] + head, tail + ["}"]
        else:  # bare statements: a class body cannot hold them, so add a method as well
            head, tail = ["class Wrapper {", "void wrapper() throws Exception {"] + head, tail + ["}", "}"]
    elif language == "JavaScript" and JS_METHOD.match(first):
        head, tail = ["class Wrapper {"] + head, tail + ["}"]
    if not head and not tail:
        return code, 0
    body = code if code.endswith("\n") else code + "\n"
    return "\n".join(head) + ("\n" if head else "") + body + "\n".join(tail) + ("\n" if tail else ""), len(head)


def parse_status(semgrep_json: list[Path], bandit_json: Path | None = None) -> dict[str, str]:
    """Sample file -> 'error' (could not be parsed) or 'partial' (parsed with errors)."""
    status: dict[str, str] = {}
    for path in semgrep_json:
        if not path.is_file():
            continue
        for e in json.loads(path.read_text(encoding="utf-8")).get("errors", []):
            name = Path(e.get("path") or "").name
            kind = e.get("type")
            kind = kind[0] if isinstance(kind, list) else str(kind)
            if not name:
                continue
            new = "partial" if kind == "PartialParsing" else "error"
            if status.get(name) != "error":
                status[name] = new
    if bandit_json is not None and bandit_json.is_file():
        for e in json.loads(bandit_json.read_text(encoding="utf-8")).get("errors", []):
            name = Path(e.get("filename") or "").name
            # Bandit could not build the AST; Semgrep may still have parsed part of the file
            if name and "syntax error" in e.get("reason", "") and name not in status:
                status[name] = "partial"
    return status


def get_cwe_numbers(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return sorted({
        match.group(1).lstrip("0") or "0"
        for item in values
        for match in CWE_PATTERN.finditer(str(item))
    })


def finding_confidence(metadata: dict[str, Any] | None, tool: str = "semgrep",
                       bandit_confidence: str = "", bandit_severity: str = "") -> str:
    """'high' (conclude directly) or 'audit' (needs verification)."""
    if tool == "bandit":
        return "high" if bandit_confidence == "HIGH" and bandit_severity in {"HIGH", "MEDIUM"} else "audit"
    value = str((metadata or {}).get("confidence", "")).lower()
    return "high" if value == "high" else "audit"


def rules_digest(path: Path) -> str:
    files = [path] if path.is_file() else sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml"))
    h = hashlib.sha256()
    for f in files:
        h.update(f.name.encode()); h.update(f.read_bytes())
    return h.hexdigest()


def finding_classes(cwes: list[str], metadata: dict[str, Any] | None = None) -> list[str]:
    found = {CWE_TO_CLASS[cwe] for cwe in cwes if cwe in CWE_TO_CLASS}
    metadata = metadata or {}
    declared = canonical_class(metadata.get("vuln_class"))
    if declared in CLASSES:
        found.add(declared)
    return sorted(found)


def run_command(command: list[str], *, allowed_returncodes: set[int] = {0}) -> subprocess.CompletedProcess[str]:
    # Semgrep/Bandit are Python tools: force UTF-8 so non-cp1252 source text can be
    # written to their JSON output on Windows.
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", env=env)
    if result.returncode not in allowed_returncodes:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(
            f"Command failed ({result.returncode}): {subprocess.list2cmdline(command)}\n{detail}"
        )
    return result


def find_executable(name: str) -> str:
    executable = shutil.which(name)
    if executable:
        return executable
    suffix = ".exe" if sys.platform == "win32" else ""
    candidate = Path(sys.executable).resolve().parent / f"{name}{suffix}"
    if candidate.is_file():
        return str(candidate)
    raise FileNotFoundError(
        f"'{name}' is not installed. Install with "
        "'python -m pip install semgrep bandit' and rerun."
    )


def run_semgrep(
    executable: str, configs: list[str], samples: Path, output_path: Path
) -> list[dict[str, Any]]:
    command = [executable, "scan", "--metrics=off", "--json", "--output", str(output_path)]
    for config in configs:
        command.extend(["--config", config])
    command.append(str(samples))
    run_command(command)
    data = json.loads(output_path.read_text(encoding="utf-8"))
    # PyVul functions can be fragments; partial-parse warnings are recorded in the
    # raw JSON output and do not abort the scan. Real errors still do.
    fatal = [e for e in data.get("errors", []) if e.get("level") != "warn"]
    if fatal:
        raise RuntimeError(f"Semgrep reported scan errors: {fatal}")
    findings = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        cwes = get_cwe_numbers(metadata.get("cwe"))
        findings.append({
            "sample_file": Path(item["path"]).name,
            "tool": "semgrep",
            "rule_id": item.get("check_id", ""),
            "cwes": cwes,
            "classes": finding_classes(cwes, metadata),
            "message": extra.get("message", ""),
            "line": item.get("start", {}).get("line", ""),
            "end_line": item.get("end", {}).get("line", ""),
            "severity": extra.get("severity", ""),
            "confidence": finding_confidence(metadata),
        })
    return findings


def run_bandit(executable: str, samples: Path, output_path: Path,
               noise_filter: bool = True) -> list[dict[str, Any]]:
    run_command(
        [executable, "-r", str(samples), "-f", "json", "-o", str(output_path)],
        allowed_returncodes={0, 1},
    )
    data = json.loads(output_path.read_text(encoding="utf-8"))
    # Function fragments that do not parse yield no Bandit findings (counted as
    # unparsed in evaluation_scope.json); other errors abort.
    fatal = [e for e in data.get("errors", []) if "syntax error" not in e.get("reason", "")]
    if fatal:
        raise RuntimeError(f"Bandit reported scan errors: {fatal}")
    findings = []
    for item in data.get("results", []):
        cwe_id = item.get("issue_cwe", {}).get("id")
        cwes = [str(cwe_id)] if cwe_id is not None else []
        classes = finding_classes(cwes)
        if noise_filter and not classes:
            continue  # R03: keep only Bandit findings that map to the six classes
        findings.append({
            "sample_file": Path(item["filename"]).name,
            "tool": "bandit",
            "rule_id": item.get("test_id", ""),
            "cwes": cwes,
            "classes": finding_classes(cwes),
            "message": item.get("issue_text", ""),
            "line": item.get("line_number", ""),
            "end_line": item.get("line_number", ""),
            "severity": item.get("issue_severity", ""),
            # noisy checks (module-level import, subprocess without shell) stay as audit hints
            "confidence": ("audit" if item.get("test_id") in BANDIT_NOISE else
                           finding_confidence(None, "bandit", item.get("issue_confidence", ""),
                                              item.get("issue_severity", ""))),
        })
    return findings


def count_scan_errors(path: Path) -> int:
    """Number of distinct sample files a scanner could not (fully) parse."""
    if not path.is_file():
        return 0
    errors = json.loads(path.read_text(encoding="utf-8")).get("errors", [])
    return len({Path(e.get("filename") or e.get("path") or "").name for e in errors})


def tool_versions(semgrep_executable: str, bandit_executable: str | None) -> dict[str, str]:
    versions = {}
    for name, command in (("semgrep", [semgrep_executable, "--version"]),
                          ("bandit", [bandit_executable, "--version"])):
        if command[0] is None:
            continue
        try:
            out = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
            versions[name] = (out.stdout or out.stderr).strip().splitlines()[0]
        except (OSError, IndexError):
            versions[name] = "unknown"
    return versions


def metric_row(name: str, truth: list[bool], pred: list[bool]) -> dict[str, Any]:
    tp = sum(actual and guess for actual, guess in zip(truth, pred))
    fp = sum(not actual and guess for actual, guess in zip(truth, pred))
    fn = sum(actual and not guess for actual, guess in zip(truth, pred))
    tn = sum(not actual and not guess for actual, guess in zip(truth, pred))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "class": name,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "support": sum(truth),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }


def evaluate(
    rows: list[dict[str, str]],
    findings: list[dict[str, Any]],
    configuration: str,
    parse: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    parse = parse or {}
    filename_to_id = {sample_name(index, row): row["id"] for index, row in enumerate(rows)}
    by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        sample_id = filename_to_id.get(finding["sample_file"])
        if sample_id is not None:
            finding = {**finding, "id": sample_id, "configuration": configuration}
            by_id[sample_id].append(finding)

    predictions = []
    for index, row in enumerate(rows):
        item_findings = by_id[row["id"]]
        parsed = parse.get(sample_name(index, row), "ok")
        status = ("FINDING" if item_findings else
                  {"ok": "PASS", "partial": "PARTIAL_PARSE", "error": "PARSE_ERROR"}[parsed])
        detected = sorted({
            cls for finding in item_findings for cls in finding["classes"]
        })
        predictions.append({
            "id": row["id"],
            "configuration": configuration,
            "programming_language": row["programming_language"],
            "cls_gt": row["cls_gt"],
            "found_any": bool(item_findings),
            "status": status,
            "parse": parsed,
            "detected_classes": ";".join(detected),
            "cls_sast": (
                detected[0] if len(detected) == 1
                else "MULTIPLE" if detected
                else ""
            ),
        })

    return predictions, evaluate_by_language(rows, predictions)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def evaluate_types(
    rows: list[dict[str, str]],
    predictions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows_by_id = {row["id"]: row for row in rows}
    predictions_by_id = {row["id"]: row for row in predictions}
    if (
        len(rows_by_id) != len(rows)
        or len(predictions_by_id) != len(predictions)
        or set(predictions_by_id) != set(rows_by_id)
    ):
        raise ValueError("Six-class predictions must cover each test row exactly once")
    unknown = {row["cls_gt"] for row in rows} - set(CLASSES)
    if unknown:
        raise ValueError(f"Unexpected six-class ground-truth labels: {sorted(unknown)}")

    metrics = []
    for cls in CLASSES:
        truth = [row["cls_gt"] == cls for row in rows]
        pred = [
            cls in predictions_by_id[row["id"]]["detected_classes"].split(";")
            for row in rows
        ]
        metrics.append(metric_row(cls, truth, pred))
    # Macro over classes present in the ground truth or predictions (sklearn's
    # default); identical to the plain six-class mean when every class occurs,
    # and avoids zero rows for classes a small language subset does not contain.
    used = [row for row in metrics if row["support"] or row["fp"]] or metrics
    metrics.append({
        "class": "MACRO_6_VULN_CLASSES",
        "precision": sum(row["precision"] for row in used) / len(used),
        "recall": sum(row["recall"] for row in used) / len(used),
        "f1": sum(row["f1"] for row in used) / len(used),
        "support": sum(row["support"] for row in metrics),
        "tp": "",
        "fp": "",
        "fn": "",
        "tn": "",
    })
    return metrics


def evaluate_by_language(
    rows: list[dict[str, str]],
    predictions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Six class rows + macro per language; with several languages also an ALL
    block (pooled per-class rows and macro) and MACRO_OVER_LANGUAGES (mean of
    the per-language macro-F1, so a large language cannot hide a small one)."""
    evaluate_types(rows, predictions)  # coverage and label checks on the full set
    by_id = {p["id"]: p for p in predictions}
    languages = [lang for lang in LANGUAGES if any(r["programming_language"] == lang for r in rows)]
    metrics, macros = [], []
    for lang in languages:
        subset = [r for r in rows if r["programming_language"] == lang]
        lang_metrics = evaluate_types(subset, [by_id[r["id"]] for r in subset])
        metrics += [{"programming_language": lang, **m} for m in lang_metrics]
        macros.append(lang_metrics[-1])
    if len(languages) > 1:
        metrics += [{"programming_language": "ALL", **m} for m in evaluate_types(rows, predictions)]
        metrics.append({
            "programming_language": "ALL", "class": "MACRO_OVER_LANGUAGES",
            **{k: sum(m[k] for m in macros) / len(macros) for k in ("precision", "recall", "f1")},
            "support": sum(m["support"] for m in macros), "tp": "", "fp": "", "fn": "", "tn": "",
        })
    return metrics


def load_codebert_predictions(
    path: Path, rows: list[dict[str, str]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"id", "cls_gt", "cls_codebert"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"{path} is missing required columns: {sorted(missing)}"
            )
        records = list(reader)
        prediction_ids = [record["id"] for record in records]
        if len(prediction_ids) != len(set(prediction_ids)):
            raise ValueError(f"{path} contains duplicate sample IDs")
        by_id = {record["id"]: record for record in records}

    expected_ids = {row["id"] for row in rows}
    if set(by_id) != expected_ids:
        missing = sorted(expected_ids - set(by_id))
        unexpected = sorted(set(by_id) - expected_ids)
        raise ValueError(
            "Six-class CodeBERT predictions must contain the selected vulnerable test "
            f"rows only; missing IDs={missing[:10]}, unexpected IDs={unexpected[:10]}"
        )

    predictions = []
    for row in rows:
        prediction = by_id[row["id"]]
        if prediction["cls_gt"] != row["cls_gt"]:
            raise ValueError(
                f"Ground-truth mismatch for id={row['id']}: "
                f"test={row['cls_gt']}, CodeBERT={prediction['cls_gt']}"
            )
        predicted_class = prediction["cls_codebert"]
        if predicted_class not in CLASSES:
            raise ValueError(
                f"Unexpected CodeBERT class for id={row['id']}: {predicted_class}"
            )
        detected = [predicted_class]
        predictions.append({
            "id": row["id"],
            "configuration": "CodeBERT_6class",
            "programming_language": row["programming_language"],
            "cls_gt": row["cls_gt"],
            "found_any": True,
            "status": "CLASSIFIED",
            "detected_classes": ";".join(detected),
            "cls_sast": predicted_class,
        })

    metrics = evaluate_by_language(rows, predictions)
    return predictions, metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="test split CSV")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="results directory")
    parser.add_argument(
        "--codebert-predictions",
        type=Path,
        default=DEFAULT_CODEBERT,
        help="optional vulnerable-only predictions_codebert_6class.csv from 02_train_codebert.py",
    )
    parser.add_argument("--rules", type=Path, default=CUSTOM_RULES,
                        help="custom Semgrep rules file or directory (configuration B); default: "
                             "security-config/semgrep/semgrep.yml (v4); rules/custom = v3; "
                             "rules/semgrep_rules.yml reproduces T07")
    parser.add_argument("--no-bandit", action="store_true",
                        help="chi Semgrep CE (quyet dinh nhom 2026-10-21); mac dinh giu Bandit de tai lap ket qua cu")
    parser.add_argument("--keep-all-bandit", action="store_true",
                        help="do not drop Bandit noise / out-of-scope findings (T07 behaviour)")
    parser.add_argument(
        "--baseline-config", nargs="+", default=None,
        help="built-in Semgrep configs (default: registry configs of the selected languages "
             "+ p/security-audit); pass rules/registry_snapshot/*.yml for a pinned run",
    )
    parser.add_argument(
        "--languages", nargs="+", default=["Python"],
        help="languages to evaluate: Python Java JavaScript PHP, or 'all' (default: Python)",
    )
    args = parser.parse_args()
    languages = parse_languages(args.languages)

    rows = read_test_rows(args.input, languages)
    present = tuple(lang for lang in languages if any(r["programming_language"] == lang for r in rows))
    if len(present) < len(languages):
        print(f"WARNING: no test rows for {', '.join(set(languages) - set(present))}")
    args.baseline_config = args.baseline_config or default_baseline(present)
    semgrep_executable = find_executable("semgrep")
    use_bandit = not args.no_bandit and any(r["programming_language"] == "Python" for r in rows)
    bandit_executable = find_executable("bandit") if use_bandit else None
    if not args.rules.exists():
        raise FileNotFoundError(f"Custom Semgrep rules not found: {args.rules}")

    args.output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="sast_samples_", dir=args.output) as temp:
        samples = Path(temp)
        offsets = {}
        for index, row in enumerate(rows):
            text, offsets[sample_name(index, row)] = wrap_fragment(
                normalize_code(row["code"]), row["programming_language"])
            (samples / sample_name(index, row)).write_text(text, encoding="utf-8")

        baseline = run_semgrep(
            semgrep_executable,
            args.baseline_config,
            samples,
            args.output / "semgrep_baseline.json",
        )
        custom = run_semgrep(
            semgrep_executable,
            [str(args.rules)],
            samples,
            args.output / "semgrep_custom.json",
        )
        # Bandit only analyses Python; other languages get Semgrep only (M05 adds tools).
        bandit = run_bandit(
            bandit_executable, samples, args.output / "bandit.json", not args.keep_all_bandit
        ) if use_bandit else []
        # map finding lines back to the unwrapped fragment
        for finding in baseline + custom + bandit:
            if isinstance(finding["line"], int):
                finding["line"] = max(1, finding["line"] - offsets.get(finding["sample_file"], 0))
        parse = parse_status([args.output / "semgrep_baseline.json", args.output / "semgrep_custom.json"],
                             args.output / "bandit.json" if use_bandit else None)

    all_predictions = []
    all_metrics = []
    configurations = (
        ("A_builtin_semgrep_bandit", baseline + bandit),
        ("B_builtin_plus_custom_rules", baseline + custom + bandit),
        # R03: only the 'high' tier (built-in, custom and Bandit findings marked high)
        ("B_high_confidence", [f for f in baseline + custom + bandit if f.get("confidence") == "high"]),
    )
    for name, findings in configurations:
        predictions, metrics = evaluate(rows, findings, name, parse)
        all_predictions.extend(predictions)
        all_metrics.extend({"configuration": name, **metric} for metric in metrics)
        print(f"{name}: {len(predictions)} test samples ({'/'.join(languages)}), {len(findings)} findings")

    if args.codebert_predictions.is_file():
        predictions, metrics = load_codebert_predictions(
            args.codebert_predictions, rows
        )
        all_predictions.extend(predictions)
        all_metrics.extend({
            "configuration": "CodeBERT_6class",
            **metric,
        } for metric in metrics)
        print(
            "CodeBERT 6-class: classified "
            f"{len(predictions)} test samples across the six vulnerability classes"
        )
    else:
        print(
            f"CodeBERT comparison skipped: {args.codebert_predictions} not found. "
            "Run 02_train_codebert.py first to include it."
        )

    write_csv(args.output / "sast_predictions.csv", all_predictions)
    write_csv(args.output / "sast_metrics.csv", all_metrics)
    filename_to_id = {sample_name(index, row): row["id"] for index, row in enumerate(rows)}
    with (args.output / "sast_findings.jsonl").open("w", encoding="utf-8") as f:
        for configuration, findings in configurations:
            for finding in findings:
                sample_id = filename_to_id.get(finding["sample_file"])
                f.write(json.dumps(
                    {**finding, "id": sample_id, "configuration": configuration},
                    ensure_ascii=False,
                ) + "\n")
    scope = {
        "scope": "six_vulnerability_classes",
        "languages": list(languages),
        "classes": list(CLASSES),
        "test_samples": len(rows),
        "test_samples_by_language": {
            lang: sum(r["programming_language"] == lang for r in rows) for lang in languages
        },
        "evaluation": "Fresh Semgrep and Bandit scans",
        "pass_policy": "No scanner findings => PASS, with no vulnerability class assigned",
        "bandit_unparsed_samples": count_scan_errors(args.output / "bandit.json") if use_bandit else 0,
        "parse_status_by_language": {
            lang: {st: sum(1 for i, r in enumerate(rows) if r["programming_language"] == lang
                           and parse.get(sample_name(i, r), "ok") == st) for st in ("ok", "partial", "error")}
            for lang in languages
        },
        "fragment_wrapping": "PHP: <?php; Java: class Wrapper{} khi khong co khai bao kieu; "
                             "JavaScript: class Wrapper{} cho method lop; Python: khong boc",
        "semgrep_partial_parse_samples": count_scan_errors(args.output / "semgrep_baseline.json"),
        "rules_sha256": rules_digest(args.rules),
        "ruleset": ruleset_info(args.rules),
        "bandit_noise_filter": not args.keep_all_bandit,
        "rules": str(args.rules),
        "baseline_config": [str(c) for c in args.baseline_config],
        "tool_versions": tool_versions(semgrep_executable, bandit_executable),
        "bandit": "run" if use_bandit else ("disabled (--no-bandit)" if args.no_bandit else "skipped (no Python rows)"),
        "input": str(args.input.resolve()),
        "input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
    }
    if args.codebert_predictions.is_file():
        scope["codebert_predictions_sha256"] = hashlib.sha256(
            args.codebert_predictions.read_bytes()
        ).hexdigest()
    (args.output / "evaluation_scope.json").write_text(
        json.dumps(scope, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Results written to {args.output.resolve()}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, RuntimeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
