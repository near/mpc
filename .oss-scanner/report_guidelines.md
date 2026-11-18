# How we would like reports written

## Layout and length
- One root cause per report, at most about one page plus the reproducer.
- Sections, in this order: Summary, Severity, Attacker position, Affected code,
  Impact, Reproduction, Suggested fix.

## What every report should state
- The commit the report was made against.
- The severity and the reasoning behind it, using the scale in threat_model.md.
- The attacker position from threat_model.md (any NEAR account, network
  attacker, N malicious participants, foreign-chain RPC provider, TEE host) and
  how the attacker's input reaches the faulty code: the contract method, P2P
  message or chain data that carries it. An internal function accepting an
  input that no entry point can produce is not a vulnerability.
- Whether the impact hits one node, one request, or the whole network.
- A reproducer as a test that fails before the fix, runnable with
  `mpc-tests <filter>` or `cargo nextest run --cargo-profile=test-release
  --all-features <filter>`. Prefer a contract sandbox test or an in-process
  node test over a unit test of an internal helper.

## Style
- Plain Markdown, no tables.
- Start the title with the crate name, e.g. `mpc-contract: ...`.
- Cite code as `path/to/file.rs:line`.
