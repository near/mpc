#!/usr/bin/env python3
"""Check that no `use` declarations appear inside function bodies.

Uses tree-sitter-rust for proper AST parsing. Walks all .rs files under
crates/ (skipping libs/nearcore) and flags any use_declaration whose
parent chain passes through a function body block.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import tree_sitter_rust as tsrust
from tree_sitter import Language, Parser

RUST_LANGUAGE = Language(tsrust.language())

# Node types whose `body` (a block) constitutes a function body.
FUNCTION_LIKE_TYPES = frozenset({"function_item", "closure_expression"})


def is_inside_function_body(node):
    """Walk up the tree and return True if this node is inside a function body block."""
    current = node.parent
    while current is not None:
        if current.type == "block":
            parent = current.parent
            if parent is not None and parent.type in FUNCTION_LIKE_TYPES:
                body = parent.child_by_field_name("body")
                if body is not None and body.id == current.id:
                    return True
        current = current.parent
    return False


def find_violations(root_node):
    """Yield (line, col, text) for every use_declaration inside a function body."""
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.type == "use_declaration" and is_inside_function_body(node):
            line = node.start_point[0] + 1  # 1-indexed
            col = node.start_point[1] + 1
            text = node.text.decode("utf-8") if node.text else ""
            yield line, col, text
        for child in node.children:
            stack.append(child)


def main():
    root = Path.cwd()
    crates_dir = root / "crates"

    if not crates_dir.is_dir():
        print(
            f"error: {crates_dir} not found. Run from the repo root.", file=sys.stderr
        )
        sys.exit(1)

    parser = Parser(RUST_LANGUAGE)

    violations = []
    files_checked = 0

    for dirpath, _dirnames, filenames in os.walk(crates_dir):
        for filename in filenames:
            if not filename.endswith(".rs"):
                continue
            filepath = Path(dirpath) / filename
            files_checked += 1

            source = filepath.read_bytes()
            tree = parser.parse(source)

            for line, col, text in find_violations(tree.root_node):
                rel_path = filepath.relative_to(root)
                violations.append((str(rel_path), line, col, text))

    if violations:
        print(
            f"Found {len(violations)} `use` statement(s) inside function bodies:\n",
            file=sys.stderr,
        )
        for path, line, col, text in sorted(violations):
            print(f"  {path}:{line}:{col}: {text}", file=sys.stderr)
        print(
            "\nMove these `use` statements to module scope.",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        print(
            f"All {files_checked} files checked. No `use` statements inside function bodies."
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
