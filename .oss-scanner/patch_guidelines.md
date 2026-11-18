# How we would like patches made

Follow AGENTS.md and docs/development/engineering-standards.md. In addition:

- Security fixes ship as patch releases, so any mix of patched and unpatched
  nodes and contracts must keep working (RELEASES.md, "SemVer compatibility
  guarantees"). Keep wire formats and storage layouts compatible.
- Update a snapshot only when the fix intentionally changes that output, and
  explain the change in the patch description. Regenerate snapshots with
  `INSTA_UPDATE=always mpc-tests -E '<filter>'` and review the diff.
