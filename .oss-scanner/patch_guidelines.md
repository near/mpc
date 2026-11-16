# How we would like patches made

Our full conventions are in AGENTS.md and docs/development/engineering-standards.md.
The points below matter most.

## Size and scope of a fix
- Fix the root cause narrowly. No refactoring, renames or formatting changes
  outside the lines the fix needs.
- Keep contract state layout and wire formats (Borsh/JSON DTOs, P2P messages)
  backward compatible unless the fix cannot be made otherwise; say so if it can't.

## Code style
- Avoid `unwrap`, `expect` and `panic!` in production code; return errors
  instead.
- No `as` numeric conversions; use `From` / `TryFrom`.
- Use explicit arithmetic methods (`checked_add`, `wrapping_add`, ...) instead
  of raw operators in production code.
- Few comments: only where the reason for the code is not obvious. No comments
  that restate the code.
- Format with `cargo fmt` and keep `cargo clippy --all-targets --all-features
  --locked -- -D warnings` clean.

## Tests
- Add a regression test next to the affected code, failing before the fix.
- Name it `<system_under_test>__should_<assertion>` and structure it with bare
  `// Given`, `// When`, `// Then` markers.
- Use `rstest` cases instead of copying a test for different inputs.
- Do not update snapshots, weaken assertions or skip tests to make the patch pass.

## Commit message
- Conventional Commits, e.g. `fix(contract): reject responses for unknown requests`.
