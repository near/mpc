{
  lib,
  pkgs,
  stdenv,
  rustPlatform,
  rust-bin,
  llvmPackages_19,
  pkg-config,
  apple-sdk_14 ? null,
  crane,
  # Shared production ISA flag string (e.g. "-march=x86-64-v3 -mpclmul -maes"),
  # passed in from flake.nix so the dev shell, the reproducible build, and
  # bindgen-parsed headers all agree on the same feature-test macros.
  prodCFlags,
}:

# Returns a builder function. Each per-crate leaf (nix/mpc-node.nix,
# nix/tee-launcher.nix) calls this with its `pname` / `cargoExtraArgs` /
# crate-specific `buildInputs`, and gets back a fully-configured
# craneLib.buildPackage derivation.
#
# Everything in here is shared across all reproducible binaries: the source
# filter, the cargo vendor dir layout (with the near-jsonrpc workaround),
# the build env (CFLAGS, JEMALLOC_*, RUSTFLAGS), and the path-remap preBuild
# hook. Anything binary-specific (link-time C deps, metadata) flows in via
# the function arguments below.

{
  pname,
  cargoExtraArgs,
  buildInputs ? [ ],
  description ? "Rust binary built from the mpc workspace",
  mainProgram ? pname,
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

  # `prodCFlags` (passed from flake.nix) carries the production ISA string —
  # see flake.nix for the rationale. Pinned to a fixed level rather than
  # `-march=native` so output bytes don't vary with the build host's CPU.
  marchFlag = lib.optionalString isX86 prodCFlags;

  # Take the version from [workspace.package.version] so this file stays in
  # sync on every release bump.
  workspaceCargoToml = lib.importTOML ../Cargo.toml;
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

    # Match only `near-jsonrpc-<version>`
    set -- ${importedVendorDir}/near-jsonrpc-[0-9]*
    if [ "$1" = '${importedVendorDir}/near-jsonrpc-[0-9]*' ]; then
      echo "error: could not find vendored near-jsonrpc crate in ${importedVendorDir}" >&2
      exit 1
    fi
    if [ "$#" -ne 1 ]; then
      echo "error: expected exactly one vendored near-jsonrpc crate in ${importedVendorDir}, found $# matches" >&2
      exit 1
    fi
    near_jsonrpc_entry="$1"
    near_jsonrpc_name=$(basename "$near_jsonrpc_entry")

    cp -aL "$near_jsonrpc_entry" $out/chain/jsonrpc
    chmod -R u+w $out/chain/jsonrpc
    ln -s ../chain/jsonrpc "$out/vendor/$near_jsonrpc_name"

    for entry in ${importedVendorDir}/*; do
      name=$(basename "$entry")
      if [ "$name" != "$near_jsonrpc_name" ]; then
        ln -s "$entry" "$out/vendor/"
      fi
    done

    sed "s|directory = \"cargo-vendor-dir\"|directory = \"$out/vendor\"|" \
      ${importedVendorDir}/.cargo/config.toml > $out/config.toml
  '';

  commonArgs = {
    inherit
      pname
      version
      src
      cargoVendorDir
      cargoExtraArgs
      ;

    strictDeps = true;
    cargoProfile = "reproducible";

    nativeBuildInputs = [
      pkg-config
      # Sets LIBCLANG_PATH and the base BINDGEN_EXTRA_CLANG_ARGS (clang
      # resource dir, libc headers) so rust-bindgen works inside the Nix
      # sandbox. Anything we add to BINDGEN_EXTRA_CLANG_ARGS below is appended
      # to the hook's value, not replaced.
      rustPlatform.bindgenHook
      llvmPkgs.clang
    ];

    # Caller supplies crate-specific link-time deps. Modern apple-sdk_14
    # bundles Security / SystemConfiguration / CoreFoundation and friends,
    # which any darwin Rust build needs at link time, so we add it here
    # uniformly rather than making every leaf repeat the conditional.
    buildInputs = buildInputs ++ lib.optionals stdenv.isDarwin [ apple-sdk_14 ];

    env = {
      # Reproducibility knobs ------------------------------------------------

      # Fixed epoch for any build-script that stamps timestamps into output.
      SOURCE_DATE_EPOCH = "0";

      # Link against nixpkgs' openssl instead of openssl-sys' vendored copy.
      # The vendored copy varies with the host; the nixpkgs one is pinned
      # through flake.lock. (No-op for crates that don't link openssl.)
      OPENSSL_NO_VENDOR = "1";

      # Prevents rocksdb's build.rs from probing /proc/cpuinfo and baking
      # host-specific ISA choices into its object files. (No-op for crates
      # that don't link rocksdb.)
      PORTABLE = "1";

      # tikv-jemalloc-sys runs jemalloc's `./configure`, which auto-detects
      # these from the build host (CPUID, sysconf, /proc/meminfo). When the
      # detected values diverge between builders, the static `emap_global`
      # rtree is sized differently and .bss — plus a few inlined .text
      # constants — drift. Pin to the standard x86_64 Linux values; values
      # are base-2 logarithms (so LG_PAGE=12 ↔ 2^12 B = 4 KiB). Option
      # semantics:
      # https://github.com/jemalloc/jemalloc/blob/5.3.0/INSTALL.md#advanced-configuration
      # (No-op for crates that don't link jemalloc.)
      #
      # 48-bit user VA (4-level paging)
      # https://github.com/torvalds/linux/blob/v6.7/Documentation/arch/x86/x86_64/mm.rst#L7
      JEMALLOC_SYS_WITH_LG_VADDR = "48";
      # 4 KiB base page (PAGE_SHIFT = 12)
      # https://github.com/torvalds/linux/blob/v6.7/arch/x86/include/asm/page_types.h#L10
      JEMALLOC_SYS_WITH_LG_PAGE = "12";
      # 2 MiB huge page (HPAGE_SHIFT = PMD_SHIFT = 21)
      # https://github.com/torvalds/linux/blob/v6.7/arch/x86/include/asm/pgtable_64_types.h#L91
      JEMALLOC_SYS_WITH_LG_HUGEPAGE = "21";

      # Pin the target ISA for both C/C++ (cc-crate for rocksdb, snappy,
      # zstd, ...) and Rust itself. Without this, the cc crate defaults to
      # the build host's CPU and output bytes vary by machine.
      CFLAGS = marchFlag;
      CXXFLAGS = "-include cstdint ${marchFlag}";

      RUSTFLAGS = lib.concatStringsSep " " (
        lib.optionals isX86 [ "-C target-cpu=x86-64-v3" ]
        ++ [
          # Scrub the vendor dir's /nix/store path out of rustc-emitted debug
          # info and panic messages. The build-sandbox path is handled in
          # `preBuild` below; do NOT add `${src}` here — it would re-key
          # cargoArtifacts on every source change and defeat the dep cache.
          "--remap-path-prefix=${cargoVendorDir}=/cargo-vendor"
        ]
      );

      # Extra bindgen flags — paths are already provided by bindgenHook.
      BINDGEN_EXTRA_CLANG_ARGS = marchFlag;
    }
    // lib.optionalAttrs stdenv.isDarwin {
      # Deployment target is independent of the SDK version; pin it so the
      # Mach-O LC_BUILD_VERSION load command is identical across builders.
      MACOSX_DEPLOYMENT_TARGET = "14.0";
    };

    # Remap the runtime build directory.
    #
    # The `${src}` remap in RUSTFLAGS above only rewrites
    # `/nix/store/<hash>-source` paths, but rustc never sees those at
    # compile time — it sees the path where Nix actually unpacks the
    # sources, i.e. `$NIX_BUILD_TOP/source/...`. That path varies by Nix
    # installation type:
    #
    #   * multi-user (daemon) Nix on Linux: `$NIX_BUILD_TOP` is `/build`,
    #     because the daemon bind-mounts the sandbox there.
    #   * single-user (per-user) Nix on Linux: no daemon, so no `/build`
    #     mount — `$NIX_BUILD_TOP` is `/nix/var/nix/builds/nix-<pid>-<rand>`.
    #   * Nix on macOS: same per-build temp dir as single-user Linux,
    #     `/nix/var/nix/builds/nix-<pid>-<rand>`.
    #
    # Without this remap, only multi-user Linux builds happen to be
    # reproducible (and only because `/build` coincides with the remap
    # target above); per-user Linux and any macOS build embeds its own
    # ephemeral sandbox path in panic messages, debug info, and
    # `track_caller` location strings, which makes the binary differ from
    # builds on other machines. This hook normalises `$NIX_BUILD_TOP` to
    # `/build` for everyone so the output is bit-identical regardless of
    # how Nix is installed on the builder.
    preBuild = ''
      export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$NIX_BUILD_TOP/source=/build/source --remap-path-prefix=$NIX_BUILD_TOP=/build"
    '';

    doCheck = false;
  };

  # Build deps in a separate derivation so that they're cached across
  # source changes.
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;

    meta = {
      inherit description mainProgram;
      license = lib.licenses.mit;
      platforms = lib.platforms.unix;
    };
  }
)
