"""Tach DON VI quet (ham + doan cap module) - dung chung cho CodeBERT (P3) va Compare/Gate (P4).

Backend mac dinh: tree-sitter (nhom chot 27/10/2026). Backend lizard giu lai de DO DO LECH voi du lieu train
(mau am / CredData cua dataset v2.x tach bang lizard; mau duong CVEfixes lay tu bang method_change).

Quy tac (ghi ro de bao cao va de leader dung lai khi tao dataset bang tree-sitter):
  - Don vi "function": moi node ham/phuong thuc, KE CA ham long nhau (ham cha van chua than ham con, giong lizard).
      python     : function_definition (bat dau tu dong `def`, khong tinh decorator)
      java       : method_declaration, constructor_declaration, compact_constructor_declaration
      javascript : function_declaration, generator_function_declaration, function_expression, function,
                   arrow_function, method_definition
      php        : function_definition, method_declaration, anonymous_function, arrow_function
  - Noi dung = NGUYEN VAN cac dong tu dong dau toi dong cuoi cua node (khong bo comment, khong chuan hoa) -
    dung nhu INFERENCE.md muc 3 (model doc code tho, 512 token dau).
  - Ham ngan hon AIWS_MIN_FUNC_LINES dong (mac dinh 2) van la don vi de gan finding Semgrep, nhung KHONG dua vao CodeBERT.
  - Don vi "module_snippet" (chi cho nhom HARDCODED_CREDENTIALS, giong CredData): dong NGOAI moi ham co dang
    gan credential -> lay +-5 dong, cat de khong lan vao ham; cac doan chong nhau duoc gop.
"""
import os
import re

MIN_FUNC_LINES = int(os.environ.get("AIWS_MIN_FUNC_LINES", "2"))
SNIPPET_CONTEXT = int(os.environ.get("AIWS_SNIPPET_CONTEXT", "5"))
CRED_RE = re.compile(
    r"""(?ix)
    (pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|
     client[_-]?secret|credential|auth[_-]?key|db[_-]?pass|conn(ection)?[_-]?str(ing)?)
    \w*['"]?\s*(=|:|=>|\.equals\()\s*['"]""")

FUNC_NODES = {
    "python": {"function_definition"},
    "java": {"method_declaration", "constructor_declaration", "compact_constructor_declaration"},
    "javascript": {"function_declaration", "generator_function_declaration", "function_expression", "function",
                   "arrow_function", "method_definition"},
    "php": {"function_definition", "method_declaration", "anonymous_function", "anonymous_function_creation_expression",
            "arrow_function"},
}

_PARSERS = {}


def _parser(lang: str):
    if lang in _PARSERS:
        return _PARSERS[lang]
    import tree_sitter as ts
    if lang == "python":
        import tree_sitter_python as m; L = m.language()
    elif lang == "java":
        import tree_sitter_java as m; L = m.language()
    elif lang == "javascript":
        import tree_sitter_javascript as m; L = m.language()
    elif lang == "php":
        import tree_sitter_php as m; L = m.language_php()       # PHP lan HTML (<?php ... ?>)
    else:
        raise ValueError(f"ngon ngu khong ho tro: {lang}")
    p = ts.Parser(ts.Language(L))
    _PARSERS[lang] = p
    return p


def treesitter_version() -> str:
    try:
        from importlib.metadata import version
        return "tree-sitter " + version("tree-sitter") + " (" + ", ".join(
            f"{g} {version('tree-sitter-' + g)}" for g in ("python", "java", "javascript", "php")) + ")"
    except Exception:  # noqa: BLE001
        return "tree-sitter ?"


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _name(node, src: bytes) -> str:
    n = node.child_by_field_name("name")
    if n is not None:
        return _text(n, src)
    p = node.parent                                   # ham vo danh: lay ten bien / khoa / thuoc tinh duoc gan
    for _ in range(3):
        if p is None:
            break
        if p.type in ("variable_declarator", "assignment_expression", "pair", "assignment",
                      "property_assignment", "field_definition", "public_field_definition"):
            k = (p.child_by_field_name("name") or p.child_by_field_name("left")
                 or p.child_by_field_name("key") or p.child_by_field_name("property"))
            if k is not None:
                return _text(k, src).split(".")[-1][:120]
        p = p.parent
    return "<anonymous>"


def _ts_functions(text: str, lang: str):
    src = text.encode("utf-8", "replace")
    tree = _parser(lang).parse(src)
    kinds = FUNC_NODES[lang]
    out, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        if node.is_named and node.type in kinds:          # bo token tu khoa `function`
            out.append((_name(node, src), node.start_point[0] + 1, node.end_point[0] + 1, bool(node.has_error)))
        stack.extend(reversed(node.children))
    return out, bool(tree.root_node.has_error)


def _lizard_functions(path: str, text: str):
    import lizard
    fl = lizard.analyze_file.analyze_source_code(path, text).function_list
    return [(f.name.split("::")[-1], f.start_line, f.end_line, False) for f in fl], False


def file_units(path: str, text: str, lang: str, backend: str = "treesitter"):
    """-> (danh sach don vi, co loi parse hay khong). path la duong dan tuong doi trong repo (dau '/')."""
    lines = text.splitlines()
    if backend == "lizard":
        funcs, err = _lizard_functions(path, text)
    else:
        funcs, err = _ts_functions(text, lang)
    units, covered = [], set()
    for name, s, e, has_err in sorted(funcs, key=lambda x: (x[1], -x[2])):
        e = max(s, min(e, len(lines)))
        covered.update(range(s, e + 1))
        n = e - s + 1
        units.append({
            "id": f"{path}::{name}@L{s}", "file": path, "language": lang, "unit": "function", "name": name,
            "start": s, "end": e, "n_lines": n, "parse_error": has_err,
            "scored": n >= MIN_FUNC_LINES,
            "code": "\n".join(lines[s - 1:e]),
        })
    # doan cap module cho HARDCODED_CREDENTIALS
    spans = []
    for i, line in enumerate(lines, 1):
        if i in covered or not CRED_RE.search(line):
            continue
        a, b = i, i
        while a > 1 and i - (a - 1) <= SNIPPET_CONTEXT and (a - 1) not in covered:
            a -= 1
        while b < len(lines) and (b + 1) - i <= SNIPPET_CONTEXT and (b + 1) not in covered:
            b += 1
        if spans and a <= spans[-1][1] + 1:
            spans[-1][1] = max(spans[-1][1], b)
        else:
            spans.append([a, b])
    for a, b in spans:
        units.append({
            "id": f"{path}::<module>@L{a}", "file": path, "language": lang, "unit": "module_snippet",
            "name": "<module>", "start": a, "end": b, "n_lines": b - a + 1, "parse_error": False,
            "scored": True, "only_groups": ["HARDCODED_CREDENTIALS"],
            "code": "\n".join(lines[a - 1:b]),
        })
    return units, err


def innermost_function(units, file: str, line: int):
    """Don vi ham NHO NHAT chua dong `line` (dung de gan finding Semgrep)."""
    best = None
    for u in units:
        if u["file"] == file and u["unit"] == "function" and u["start"] <= line <= u["end"]:
            if best is None or (u["end"] - u["start"]) < (best["end"] - best["start"]):
                best = u
    return best
