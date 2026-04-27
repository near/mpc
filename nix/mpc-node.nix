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

  # Vendor the cargo lockfile via nixpkgs' importCargoLock instead of crane's
  # default `cargo package`-based vendoring. Two reasons:
  #
  #   1. `cargo package --exclude-lockfile` (used by recent crane) requires
  #      cargo >= 1.88, but rust-toolchain.toml pins 1.86.0.
  #   2. `cargo package` only ships files inside a crate's own directory.
  #      Some git deps (e.g. nearcore's `near-jsonrpc`) pull files from
  #      sibling directories via `include_bytes!("../../../...")`; those get
  #      stripped by cargo's packaging rules. `fetchgit` copies the entire
  #      git checkout, preserving siblings.
  #
  # `allowBuiltinFetchGit = true` uses `builtins.fetchGit`, which is
  # reproducible: the revision fully determines content, no `sha256` needed.
  importedVendorDir = rustPlatform.importCargoLock {
    lockFile = ../Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  # Repackage `importedVendorDir` into the layout crane expects, with one
  # extra wrinkle:
  #
  #   `near-jsonrpc` (lib.rs) does `include_bytes!("../../../chain/jsonrpc/
  #   openapi/openapi.json")` — a workspace-relative path that only resolves
  #   in the original nearcore checkout, where the crate lives at
  #   `chain/jsonrpc/`. Cargo's vendor format flattens every crate to a
  #   single directory, so the macro's `..` traversal walks past the vendor
  #   root and the file is "not found".
  #
  # We work around this by laying out the vendor dir so that the `..`
  # traversal lands somewhere we control:
  #
  #   $out/                           ← cargoVendorDir (3 ups from src/lib.rs)
  #   ├── vendor/                     ← config.toml's `directory = "..."`
  #   │   ├── near-jsonrpc-2.11.1 ──┐ relative symlink (stays inside $out)
  #   │   └── (other crates as symlinks into importedVendorDir)
  #   ├── chain/jsonrpc/  ←──────────┘ real copy of the near-jsonrpc tree
  #   │   ├── src/lib.rs
  #   │   └── openapi/openapi.json    ← what the broken macro wants
  #   └── config.toml                 ← crane reads this
  #
  # The relative `../chain/jsonrpc` symlink keeps `..` traversal inside
  # `$out` (an absolute symlink to importedVendorDir would push it back
  # into /nix/store and re-break path resolution). The crate has to be a
  # real directory tree (not symlinks) for `..` to walk through it
  # correctly, hence `cp -aL`.
  cargoVendorDir = pkgs.runCommand "vendor-cargo-deps-crane" { } ''
    mkdir -p $out/vendor $out/chain

    cp -aL ${importedVendorDir}/near-jsonrpc-2.11.1 $out/chain/jsonrpc
    chmod -R u+w $out/chain/jsonrpc
    ln -s ../chain/jsonrpc $out/vendor/near-jsonrpc-2.11.1

    for entry in ${importedVendorDir}/*; do
      name=$(basename "$entry")
      if [ "$name" != "near-jsonrpc-2.11.1" ]; then
        ln -s "$entry" "$out/vendor/"
      fi
    done

    sed "s|directory = \"cargo-vendor-dir\"|directory = \"$out/vendor\"|" \
      ${importedVendorDir}/.cargo/config.toml > $out/config.toml
  '';

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

    # Remap the runtime build directory. The `${src}` remap above only
    # rewrites `/nix/store/<hash>-source` paths, but rustc never sees those
    # at compile time — it sees `$NIX_BUILD_TOP/source/...`, which is
    # `/build/source` under the Linux sandbox but
    # `/nix/var/nix/builds/nix-<pid>-<rand>/source/...` under macOS or a
    # non-default sandbox. Without this hook the Linux output happens to
    # match by coincidence and other platforms drift.
    preBuild = ''
      export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$NIX_BUILD_TOP/source=/build/source --remap-path-prefix=$NIX_BUILD_TOP=/build"
    '';

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
