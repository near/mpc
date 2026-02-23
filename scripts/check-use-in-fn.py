#!/usr/bin/env python3
"""Check that no `use` declarations appear inside function bodies."""

from __future__ import annotations

import sys
from pathlib import Path

import tree_sitter_rust as tsrust
from tree_sitter import Language, Parser, Query, QueryCursor

RUST_LANGUAGE = Language(tsrust.language())
USE_QUERY = Query(RUST_LANGUAGE, "(use_declaration) @use")
FUNCTION_TYPES = frozenset({"function_item", "closure_expression"})


def has_fn_ancestor(node):
    while (node := node.parent) is not None:
        if node.type in FUNCTION_TYPES:
            return True
    return False


def main():
    root = Path.cwd()
    crates_dir = root / "crates"
    if not crates_dir.is_dir():
        sys.exit(f"error: {crates_dir} not found. Run from the repo root.")

    parser = Parser(RUST_LANGUAGE)
    violations = []

    rs_files = sorted(crates_dir.rglob("*.rs"))
    for filepath in rs_files:
        tree = parser.parse(filepath.read_bytes())
        for node in QueryCursor(USE_QUERY).captures(tree.root_node).get("use", []):
            if has_fn_ancestor(node):
                violations.append(
                    (
                        str(filepath.relative_to(root)),  # path
                        node.start_point[0] + 1,  # line (1-indexed)
                        node.start_point[1] + 1,  # column (1-indexed)
                        node.text.decode() if node.text else "",  # source text
                    )
                )

    if violations:
        print(
            f"Found {len(violations)} `use` statement(s) inside function bodies:\n",
            file=sys.stderr,
        )
        for path, line, col, text in sorted(violations):
            print(f"  {path}:{line}:{col}: {text}", file=sys.stderr)
        sys.exit("\nMove these `use` statements to module scope.")

    print(
        f"All {len(rs_files)} files checked. No `use` statements inside function bodies."
    )


if __name__ == "__main__":
    main()
