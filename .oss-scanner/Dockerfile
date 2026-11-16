# syntax=docker/dockerfile:1
# Build image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this with network access, then runs the image offline, so
# everything the tests need is fetched and compiled here.
FROM rust:1.97.1-trixie

ENV DEBIAN_FRONTEND=noninteractive \
    RUST_BACKTRACE=1 \
    INSTA_UPDATE=no \
    CC_wasm32_unknown_unknown=clang \
    AR_wasm32_unknown_unknown=llvm-ar \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=lld" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=lld" \
    CARGO_PROFILE_TEST_RELEASE_DEBUG=line-tables-only \
    NEAR_SANDBOX_BIN_PATH=/opt/near-sandbox/near-sandbox

# The x86-64 rustflags above are joined with the `target-cpu=x86-64-v3` flags in
# .cargo/config.toml, not substituted for them. lld keeps linking the node, which
# pulls in nearcore and RocksDB, within the scanner's memory budget.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libclang-dev lld cmake pkg-config libssl-dev libudev-dev \
      libdbus-1-dev protobuf-compiler zlib1g-dev git python3 curl ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# Versions match nix/cargo-near.nix, the nixpkgs cargo-nextest used in CI, and
# DEFAULT_SANDBOX_VERSION in crates/test-utils/src/lib.rs.
RUN curl --proto '=https' --tlsv1.2 -fsSL \
      https://github.com/near/cargo-near/releases/download/cargo-near-v0.22.0/cargo-near-installer.sh \
      -o /tmp/cargo-near-installer.sh \
    && sh /tmp/cargo-near-installer.sh \
    && rm /tmp/cargo-near-installer.sh \
    && cargo near --version
RUN curl --proto '=https' --tlsv1.2 -fsSL \
      "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.136/cargo-nextest-0.9.136-$(uname -m)-unknown-linux-gnu.tar.gz" \
      -o /tmp/nextest.tar.gz \
    && tar -xzf /tmp/nextest.tar.gz -C /usr/local/cargo/bin cargo-nextest \
    && rm /tmp/nextest.tar.gz \
    && cargo nextest --version
RUN mkdir -p /opt/near-sandbox \
    && curl --proto '=https' --tlsv1.2 -fsSL \
      "https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/Linux-$(uname -m)/2.14.0/near-sandbox.tar.gz" \
      -o /tmp/near-sandbox.tar.gz \
    && tar -xzf /tmp/near-sandbox.tar.gz --strip-components=1 -C /opt/near-sandbox \
    && rm /tmp/near-sandbox.tar.gz \
    && "$NEAR_SANDBOX_BIN_PATH" --version

COPY . /src
WORKDIR /src

# Installs the toolchain, components and wasm target pinned in rust-toolchain.toml.
RUN rustup toolchain install && rustc --version && cargo fetch --locked

RUN <<'SH'
cat > /usr/local/bin/mpc-tests <<'SCRIPT'
#!/bin/sh
# Runs the unit and integration tests as CI does, minus the E2E suite and the
# tests that need Internet access. Extra arguments are passed to nextest.
set -eu
cd /src
exec cargo nextest run --cargo-profile=test-release --all-features --locked \
  --no-fail-fast \
  -E 'not package(e2e-tests) and not package(contract-history) and not test(=tee_authority::tests::test_fetch_collateral_from_pccs) and not (test(/^validation::tests::/) and package(tee-launcher)) and not (test(fetch_from_intel) and package(attestation-cli))' \
  "$@"
SCRIPT
chmod +x /usr/local/bin/mpc-tests
SH

# Only compiles the tests: running them would not fit the scanner's 45-minute
# build limit. The contract tests build their wasm variants on first run, offline,
# from the dependencies fetched above. Jobs are capped to bound linker memory.
RUN <<'SH'
set -eu
jobs=$(nproc)
if [ "$jobs" -gt 8 ]; then jobs=8; fi
export CARGO_BUILD_JOBS="$jobs"
cargo build --profile test-release --all-features --locked -p mpc-node
cargo near build non-reproducible-wasm --no-abi --profile=release-contract \
  --manifest-path crates/contract/Cargo.toml --locked
mpc-tests --no-run
SH

ENV CARGO_NET_OFFLINE=true
