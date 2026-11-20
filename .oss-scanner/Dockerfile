# syntax=docker/dockerfile:1
# Build image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this with network access, then runs the image offline, so
# everything the tests need is fetched and compiled here.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_BACKTRACE=1 \
    INSTA_UPDATE=no \
    CC=clang \
    CXX=clang++ \
    CC_wasm32_unknown_unknown=clang \
    AR_wasm32_unknown_unknown=llvm-ar \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=lld" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=lld" \
    CARGO_PROFILE_TEST_RELEASE_DEBUG=line-tables-only \
    NEAR_SANDBOX_BIN_PATH=/opt/near-sandbox/near-sandbox

# The x86-64 rustflags above are joined with the `target-cpu=x86-64-v3` flags in
# .cargo/config.toml, not substituted for them. lld keeps linking, which pulls in
# nearcore and RocksDB, within the scanner's memory budget.
# We need clang for C and C++ because RocksDB's C++ build is the critical path
# of the image build: it compiles about 30% faster with clang than with gcc.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang llvm libclang-dev lld cmake pkg-config libssl-dev \
      libudev-dev libdbus-1-dev protobuf-compiler zlib1g-dev git python3 curl \
      ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# Tool versions come from the files that pin them for development and CI, so
# they cannot drift. Each file is copied just above the step that reads it, so
# editing one only reruns the steps from there on.
COPY rust-toolchain.toml /versions/
RUN cd /versions \
    && curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --default-toolchain none \
    && rustup toolchain install \
    && rustup default "$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)" \
    && rustc --version

COPY nix/cargo-near.nix /versions/
RUN set -eu; \
    v=$(sed -n 's/^ *version = "\(.*\)";$/\1/p' /versions/cargo-near.nix); \
    test -n "$v"; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://github.com/near/cargo-near/releases/download/cargo-near-v$v/cargo-near-installer.sh" \
      -o /tmp/cargo-near-installer.sh; \
    sh /tmp/cargo-near-installer.sh; \
    rm /tmp/cargo-near-installer.sh; \
    cargo near --version

# Any recent nextest reads .config/nextest.toml; the version is not coupled to the repo.
RUN curl --proto '=https' --tlsv1.2 -fsSL \
      "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.136/cargo-nextest-0.9.136-$(uname -m)-unknown-linux-gnu.tar.gz" \
      | tar -xz -C /usr/local/cargo/bin cargo-nextest \
    && cargo nextest --version

# Last, as test-utils/src/lib.rs is a regular source file that changes often.
COPY crates/test-utils/src/lib.rs /versions/test-utils-lib.rs
RUN set -eu; \
    v=$(sed -n 's/^pub const DEFAULT_SANDBOX_VERSION: &str = "\(.*\)";$/\1/p' /versions/test-utils-lib.rs); \
    test -n "$v"; \
    mkdir -p /opt/near-sandbox; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/Linux-$(uname -m)/$v/near-sandbox.tar.gz" \
      | tar -xz --strip-components=1 -C /opt/near-sandbox; \
    "$NEAR_SANDBOX_BIN_PATH" --version

COPY . /src
WORKDIR /src
RUN cargo fetch --locked

RUN <<'SH'
cat > /usr/local/bin/mpc-tests <<'SCRIPT'
#!/bin/sh
# Runs the tests under the `oss-scanner` nextest profile, which leaves out the
# E2E suite and the tests that need Internet access. Extra arguments are passed
# to nextest and narrow the run.
# We need to skip building the out-of-scope crates nothing else depends on
# because the full build barely fits the scanner's 40-minute build limit.
set -eu
cd /src
exec cargo nextest run --profile oss-scanner --cargo-profile=test-release \
  --all-features --locked --workspace \
  --exclude e2e-tests --exclude mpc-devnet --exclude proposal-generator \
  --exclude foreign-chain-config-tester --exclude ckd-example-cli \
  --exclude attestation-cli --exclude test-parallel-contract \
  --exclude test-migration-contract "$@"
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
cargo near build non-reproducible-wasm --no-abi --profile=release-contract \
  --manifest-path crates/contract/Cargo.toml --locked
mpc-tests --no-run
SH

ENV CARGO_NET_OFFLINE=true
