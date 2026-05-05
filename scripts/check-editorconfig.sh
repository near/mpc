#!/usr/bin/env bash
set -euo pipefail

# Enforce every rule declared in .editorconfig (trim_trailing_whitespace,
# insert_final_newline, end_of_line, charset, ...) on every tracked file.
#
# Why pipe `git ls-files`: `editorconfig-checker .` walks the working tree
# and produces false positives for contributor-local artefacts
# (.ruff_cache/, .pytest_cache/, build locks, vendored libs/). Restricting
# the input to tracked files mirrors the .editorconfig exemptions and
# keeps the run fast.
#
# Why --no-run-if-empty: GNU xargs (Linux/CI) runs the command once with
# no arguments on empty input. With no args, editorconfig-checker walks
# the working tree — the exact behavior we are avoiding.
git ls-files -z | xargs -0 --no-run-if-empty editorconfig-checker
