{
  lib,
  pkgs,
  stdenv,
  rustPlatform,
  rust-bin,
  llvmPackages_19,
  pkg-config,
  openssl,
  zlib,
  libiconv,
  snappy,
  lz4,
  zstd,
  bzip2,
  udev,
  dbus,
  # Darwin-only. Defaulted to null so evaluating this package on Linux does
  # not require a nixpkgs attr that may not exist there.
  apple-sdk_14 ? null,
  crane,
}:

let
  llvmPkgs = llvmPackages_19;

  # Pin the Rust toolchain to rust-toolchain.toml so Nix builds match what
  # `cargo build` uses locally.
  rustToolchain = (rust-bin.fromRustupToolchainFile ../rust-toolchain.toml).override {
    extensions = [ "rust-src" ];
  };

  craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

  isX86 = stdenv.hostPlatform.isx86_64;

  # Take the version from [workspace.package.version] so this file stays in
  # sync on every release bump.
  workspaceCargoToml = lib.importTOML ../Cargo.toml;
  pname = "mpc-node";
  version = workspaceCargoToml.workspace.package.version;

  # Source filter. `filterCargoSources` keeps `.rs`, `Cargo.toml`, `Cargo.lock`
  # and a couple of other Cargo-relevant files — anything else that is pulled
  # in by `include_str!` / `include_bytes!` at compile time must be allow-
  # listed here, otherwise the build fails with "file not found".
  src = lib.cleanSourceWith {
    src = craneLib.path ../.;
    filter =
      path: type:
      (craneLib.filterCargoSources path type)
      # `#![doc = include_str!("../README.md")]` on these two crates:
      || (lib.hasSuffix "crates/contract/README.md" path)
      || (lib.hasSuffix "crates/near-mpc-contract-interface/README.md" path)
      # `include_str!` for the rendered third-party license bundle served by
      # the node's web handler (crates/node/src/web.rs).
      || (lib.hasSuffix "third-party-licenses/licenses.html" path)
      # `include_bytes!` for historical signer contract snapshots
      # (crates/contract-history/src/lib.rs).
      || (lib.hasInfix "/crates/contract-history/archive/" path)
      # Every `crates/*/assets/` directory — picked up by various
      # `include_str!` / `include_bytes!` calls across the workspace.
      || (lib.hasInfix "/assets/" path);
  };

  # Pre-compute the vendored cargo deps so we can pass the exact same path to
  # --remap-path-prefix below. Without an explicit handle, crane picks its own
  # path and we cannot reference it for the remap.
  cargoVendorDir = craneLib.vendorCargoDeps { inherit src; };

  commonArgs = {
    inherit pname version src cargoVendorDir;

    strictDeps = true;
    cargoProfile = "reproducible";
    cargoExtraArgs = "-p mpc-node --bin mpc-node --locked";

    nativeBuildInputs = [
      pkg-config
      # Sets LIBCLANG_PATH and the base BINDGEN_EXTRA_CLANG_ARGS (clang
      # resource dir, libc headers) so rust-bindgen works inside the Nix
      # sandbox. Anything we add to BINDGEN_EXTRA_CLANG_ARGS below is appended
      # to the hook's value, not replaced.
      rustPlatform.bindgenHook
      llvmPkgs.clang
    ];

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
    ]
    ++ lib.optionals stdenv.isDarwin [
      # Modern apple-sdk_14 bundles Security / SystemConfiguration /
      # CoreFoundation and friends; no need to list them separately.
      apple-sdk_14
    ];

    env = {
      # Reproducibility knobs ------------------------------------------------

      # Fixed epoch for any build-script that stamps timestamps into output.
      SOURCE_DATE_EPOCH = "0";

      # Link against nixpkgs' openssl instead of openssl-sys' vendored copy.
      # The vendored copy varies with the host; the nixpkgs one is pinned
      # through flake.lock.
      OPENSSL_NO_VENDOR = "1";

      # Prevents rocksdb's build.rs from probing /proc/cpuinfo and baking
      # host-specific ISA choices into its object files.
      PORTABLE = "1";

      # Pin the target ISA for both C/C++ (cc-crate for rocksdb, snappy,
      # zstd, ...) and Rust itself. Without this, the cc crate defaults to
      # the build host's CPU and output bytes vary by machine.
      #
      # x86-64-v3 ≈ Haswell (2013) and newer: AVX2, BMI2, FMA. Deployment
      # targets MUST be at least this CPU level; older hardware will SIGILL.
      CFLAGS = lib.optionalString isX86 "-march=x86-64-v3";
      CXXFLAGS = "-include cstdint" + lib.optionalString isX86 " -march=x86-64-v3";

      RUSTFLAGS = lib.concatStringsSep " " (
        lib.optionals isX86 [ "-C target-cpu=x86-64-v3" ]
        ++ [
          # Scrub nix store paths out of rustc-emitted debug info and panic
          # messages so two builds from different /nix/store/<hash>-source
          # paths produce identical bytes.
          "--remap-path-prefix=${src}=/build/source"
          "--remap-path-prefix=${cargoVendorDir}=/cargo-vendor"
        ]
      );

      # Extra bindgen flags — paths are already provided by bindgenHook.
      BINDGEN_EXTRA_CLANG_ARGS = lib.concatStringsSep " " (
        lib.optionals isX86 [ "-march=x86-64-v3" ]
        ++ [ "-fno-stack-protector" ]
      );
    }
    // lib.optionalAttrs stdenv.isDarwin {
      # Deployment target is independent of the SDK version; pin it so the
      # Mach-O LC_BUILD_VERSION load command is identical across builders.
      MACOSX_DEPLOYMENT_TARGET = "14.0";
    };

    doCheck = false;
  };

  # Build deps in a separate derivation so that they're cached across
  # mpc-node source changes.
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;

    meta = with lib; {
      description = "MPC node binary for NEAR threshold signer";
      license = licenses.mit;
      platforms = platforms.unix;
      mainProgram = "mpc-node";
    };
  }
)
