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
}
