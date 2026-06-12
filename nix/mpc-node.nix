{
  lib,
  stdenv,
  openssl,
  zlib,
  libiconv,
  snappy,
  lz4,
  zstd,
  bzip2,
  udev,
  dbus,
  buildRustBin,
  # Short git revision injected from flake.nix (`self.shortRev`); the build
  # sandbox has no `.git` for the `built` crate to probe.
  gitCommitHashShort,
}:

# mpc-node links nearcore's rocksdb (snappy/lz4/zstd/bzip2), openssl, and
# udev/dbus on Linux. Everything not listed here flows from the shared
# builder in nix/rust-build-common.nix.

buildRustBin {
  pname = "mpc-node";
  cargoExtraArgs = "-p mpc-node --bin mpc-node --locked";
  description = "MPC node binary for NEAR threshold signer";

  buildInputs = [
    openssl
    zlib
    libiconv
    snappy
    lz4
    zstd
    bzip2
  ]
  ++ lib.optionals stdenv.isLinux [
    udev
    dbus
  ];

  extraEnv = {
    # The `built` crate reports GIT_COMMIT_HASH_SHORT = None inside the Nix
    # sandbox (no `.git`), which would surface as "unknown" in
    # `mpc-node --version` and the build-info metrics. Override it with the
    # flake's revision. Same idea as the BUILT_OVERRIDE used by the old
    # repro-env pipeline (#3441), and equally reproducible: the value is a
    # pure function of the commit being built.
    BUILT_OVERRIDE_mpc_node_GIT_COMMIT_HASH_SHORT = gitCommitHashShort;
  };
}
