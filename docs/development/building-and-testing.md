# Building and Testing

## Development environment

A Nix flake provides a reproducible development environment with the Rust toolchain, LLVM/Clang, NEAR CLI, and all system dependencies pre-configured. Run `nix develop` to enter the shell; see [nix-dev-environment.md](nix-dev-environment.md) for setup details (direnv integration, VS Code config, verification).

Outside Nix, the Rust toolchain version is pinned in [`rust-toolchain.toml`](../../rust-toolchain.toml); rustup handles installation automatically.

## Building

Build the MPC node:

```bash
cargo build -p mpc-node --release
```

Build the smart contract:

```bash
cargo near build non-reproducible-wasm --features abi --profile=release-contract \
  --manifest-path crates/contract/Cargo.toml --locked
```

Both the node and launcher Docker images also support [reproducible builds](../guide/reproducible-builds.md), producing identical binaries from the same source.

## Testing

### Terminology

- _unit test_ -> a rust test in `/src` folder (per crate)
- _integration test_ -> a rust test in `/tests` folder (per crate)
- _e2e test_ -> a rust test in the `crates/e2e-tests` crate

### Run tests

- **Unit and integration tests**: Run with `cargo nextest run --cargo-profile=test-release`
- **E2E tests**: See the README in [`crates/e2e-tests`](../../crates/e2e-tests/README.md).

### Updating snapshots

We use [`cargo insta`](https://insta.rs/) for snapshot testing to guard against
unintended changes to ABIs, serialization formats, and deterministic outputs.

If a snapshot test fails, it means the output has changed relative to the
accepted `.snap` file. To resolve this:

1. **Review the diff.** Run the failing test to see what changed:
   ```bash
   cargo nextest run --cargo-profile=test-release <test_name>
   ```
   This creates a `.snap.new` file next to the existing `.snap` file.

2. **Accept or reject.** Use `cargo insta` to interactively review pending
   snapshots:
   ```bash
   cargo insta review
   ```
   This walks you through each changed snapshot and lets you accept or reject it.

   Alternatively, to accept all pending snapshots at once:
   ```bash
   cargo insta accept
   ```

3. **Commit the updated `.snap` files.** The updated snapshots should be
   committed alongside your code changes.

> **Important:** Snapshot tests exist to catch accidental breaking changes.
> Before accepting a new snapshot, make sure the change is intentional and
> won't break compatibility (e.g. with existing on-chain data or client
> integrations).

If you don't have `cargo insta` installed:
```bash
cargo install cargo-insta
```

## Running checks locally

We run several checks in CI that require tools beyond the default Rust toolchain. The [nix environment](nix-dev-environment.md) installs all of them automatically.

- [`cargo-make`](https://github.com/sagiegurari/cargo-make)
- [`cargo-nextest`](https://github.com/nextest-rs/nextest)
- [`cargo-sort`](https://github.com/DevinR528/cargo-sort)
- [`cargo-shear`](https://github.com/Boshen/cargo-shear)
- [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny)
- [`zizmor`](https://github.com/woodruffw/zizmor)
- [`lychee`](https://github.com/lycheeverse/lychee)
- [`editorconfig-checker`](https://github.com/editorconfig-checker/editorconfig-checker)
- [`ast-grep`](https://github.com/ast-grep/ast-grep)

This set does not include all checks, but only the most common reasons for CI
failures. Therefore, we suggest running these checks locally before opening a
PR. Running these checks with the correct parameters can be done easily with
`cargo-make`.

Running fast checks:

```console
cargo make check-all-fast
```

Running all `cargo-make` supported checks:

```console
cargo make check-all
```
