# How we would like patches made

Follow AGENTS.md and docs/development/engineering-standards.md. In addition:

- Fix the root cause narrowly, without unrelated refactoring.
- Keep contract state layout and wire formats backward compatible unless the
  fix cannot be made otherwise; say so if it can't.
- Add a regression test that fails before the fix. Do not weaken assertions or
  skip tests to make the patch pass.
- Update a snapshot only when the fix intentionally changes that output, and
  explain the change in the patch description. Regenerate snapshots with
  `INSTA_UPDATE=always mpc-tests -E '<filter>'` and review the diff.
