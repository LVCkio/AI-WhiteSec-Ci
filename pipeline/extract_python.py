from __future__ import annotations

import argparse
import ast
from pathlib import Path
from typing import Iterable


EXCLUDED_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__", "site-packages"}


def python_files(root: Path, selected: list[str] | None = None) -> Iterable[Path]:
    if selected:
        for item in selected:
            path = (root / item).resolve()
            if path.suffix == ".py" and path.is_file():
                yield path
        return
    for path in root.rglob("*.py"):
        if not any(part in EXCLUDED_PARTS for part in path.parts):
            yield path


def qualified_name(node: ast.AST, parents: list[str]) -> str:
    name = getattr(node, "name", "module")
    return ".".join([*parents, name])


def extract_file(path: Path, root: Path) -> list[dict]:
    source = path.read_text(encoding="utf-8", errors="replace")
    relative = path.relative_to(root).as_posix()
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return [
            {
                "file_path": relative,
                "function_name": None,
                "start_line": 1,
                "end_line": max(1, len(source.splitlines())),
                "code": source,
                "source_type": "module_fallback",
                "parse_error": str(error),
            }
        ]

    lines = source.splitlines(keepends=True)
    units: list[dict] = []

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.parents: list[str] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.parents.append(node.name)
            self.generic_visit(node)
            self.parents.pop()

        def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            end_line = getattr(node, "end_lineno", node.lineno)
            units.append(
                {
                    "file_path": relative,
                    "function_name": qualified_name(node, self.parents),
                    "start_line": node.lineno,
                    "end_line": end_line,
                    "code": "".join(lines[node.lineno - 1 : end_line]),
                    "source_type": "full_function",
                    "parse_error": None,
                }
            )
            self.parents.append(node.name)
            self.generic_visit(node)
            self.parents.pop()

        visit_FunctionDef = _visit_function
        visit_AsyncFunctionDef = _visit_function

    Visitor().visit(tree)
    return units


def extract_repository(root: Path, selected: list[str] | None = None) -> list[dict]:
    root = root.resolve()
    units: list[dict] = []
    for path in python_files(root, selected):
        units.extend(extract_file(path.resolve(), root))
    return units


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract Python functions for AI inference")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--files", nargs="*")
    args = parser.parse_args()
    import json

    print(json.dumps(extract_repository(args.root, args.files), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

