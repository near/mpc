{
  lib,
  stdenv,
  rustPlatform,
  rust-bin,
  llvmPackages_19,
  binaryen,
  cargo-near,
}:

let
  llvmPkgs = llvmPackages_19;

  # Clang resource include dir — needed when cross-compiling wasm32 via
  # `-nostdlibinc`, so `<stddef.h>` & friends are still found. cc-rs sets
  # `-nostdlibinc` for any `ring` / blst-style C build, and without the clang
  # resource dir on the include path, every wasm32 cc-build fails.
  clangVersion = lib.versions.major llvmPkgs.clang-unwrapped.version;
  clangResourceInclude = "${llvmPkgs.clang-unwrapped.lib}/lib/clang/${clangVersion}/include";

  # Pin the Rust toolchain to rust-toolchain.toml — same source of truth as
  # the dev shell (flake.nix).
  rustToolchain = (rust-bin.fromRustupToolchainFile ../rust-toolchain.toml).override {
    extensions = [ "rust-src" ];
  };

  workspaceCargoToml = lib.importTOML ../Cargo.toml;
  pname = "mpc-contract";
  version = workspaceCargoToml.workspace.package.version;

  # Source filter — keep Cargo files, *.rs, and the `include_str!` /
  # `include_bytes!` allow-list so compile-time path resolution works.
  # The contract only links a subset of crates, but
  # `cargo` still parses the full workspace manifest, so we keep the
  # workspace tree intact.
  src = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      type == "directory"
      || (lib.hasSuffix ".rs" path)
      || (lib.hasSuffix "/Cargo.toml" path)
      || (lib.hasSuffix "/Cargo.lock" path)
      || (lib.hasSuffix "/rust-toolchain.toml" path)
      || (lib.hasSuffix "crates/contract/README.md" path)
      || (lib.hasSuffix "crates/near-mpc-contract-interface/README.md" path)
      || (lib.hasSuffix "third-party-licenses/licenses.html" path)
      || (lib.hasInfix "/crates/contract-history/archive/" path)
      || (lib.hasInfix "/assets/" path)
      # Workspace cargo config — pins `-C target-cpu=x86-64-v3` for x86_64
      # host builds. Irrelevant for the wasm32 output but kept so the build
      # tree matches what `cargo` sees in dev.
      || (lib.hasSuffix "/.cargo/config.toml" path);
  };

  # Vendor the workspace lockfile. `allowBuiltinFetchGit = true` uses
  # `builtins.fetchGit`, which is reproducible: the revision fully determines
  # content, no `sha256` needed.
  vendorDir = rustPlatform.importCargoLock {
    lockFile = ../Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  # The Nix sandbox provides the hermetic environment (toolchain, vendored
  # registry, fixed SOURCE_DATE_EPOCH), and cargo-near drives the build —
  # `non-reproducible-wasm` inside a hermetic environment becomes reproducible.
  cargoNearArgs = [
    "non-reproducible-wasm"
    "--locked"
    "--profile=release-contract"
    "--features"
    "abi"
    "--manifest-path"
    "crates/contract/Cargo.toml"
  ];

in
stdenv.mkDerivation {
  inherit pname version src;

  strictDeps = true;

  nativeBuildInputs = [
    rustToolchain
    cargo-near
    binaryen # provides wasm-opt, invoked by cargo-near
    llvmPkgs.clang # for ring's / blst's build.rs (cc-rs) when targeting wasm32
  ];

  env = {
    # Fixed epoch for any build-script that stamps timestamps into output.
    SOURCE_DATE_EPOCH = "0";

    # Cargo + rustup interop: don't try to resolve a system rustup toolchain.
    RUSTUP_TOOLCHAIN = "";

    # WASM cross-compile toolchain — `ring` and `blst` (via blstrs) both have
    # build.rs scripts that use cc-rs; without these, cc-rs falls back to the
    # host gcc which cannot target wasm32. The CFLAGS line is essential
    # because cc-rs sets `-nostdlibinc` for wasm32 builds, which strips the
    # default include search path; we put the clang resource dir back so
    # `<stddef.h>` etc. resolve. Same toolchain envs as the dev shell (see
    # flake.nix).
    CC_wasm32_unknown_unknown = "${llvmPkgs.clang-unwrapped}/bin/clang";
    AR_wasm32_unknown_unknown = "${llvmPkgs.llvm}/bin/llvm-ar";
    CFLAGS_wasm32_unknown_unknown = "-I${clangResourceInclude}";

    # Scrub absolute /nix/store paths out of rustc-emitted strings. The
    # release-contract profile sets `strip = true`, but `panic = "abort"`
    # still keeps a few path strings around via `track_caller` location
    # info baked into monomorphisations.
    CARGO_BUILD_RUSTFLAGS = "--remap-path-prefix=${vendorDir}=/cargo-vendor";
  };

  configurePhase = ''
    runHook preConfigure

    # Point cargo at the vendored crates. CARGO_HOME must be writable so
    # cargo can drop its lockfile / fingerprint state there. `importCargoLock`
    # writes `directory = "cargo-vendor-dir"` (a relative path that cargo
    # resolves from the cwd, i.e. `/build/source/cargo-vendor-dir`); rewrite
    # to the absolute Nix-store path so the lookup is cwd-independent.
    export CARGO_HOME=$PWD/.cargo-home
    mkdir -p "$CARGO_HOME"
    sed 's|directory = "cargo-vendor-dir"|directory = "${vendorDir}"|' \
      ${vendorDir}/.cargo/config.toml > "$CARGO_HOME/config.toml"

    # cargo-near writes a near-cli-rs config under $XDG_CONFIG_HOME (defaults
    # to $HOME/.config) on first run; stdenv's default $HOME is
    # /homeless-shelter (read-only), so redirect to a writable build-local
    # directory.
    export HOME=$TMPDIR/home
    mkdir -p "$HOME"

    runHook postConfigure
  '';

  buildPhase = ''
    runHook preBuild

    # Re-assert SOURCE_DATE_EPOCH after stdenv's unpackPhase resets it to
    # the newest mtime of the unpacked source tree.
    export SOURCE_DATE_EPOCH=0

    # Also remap the build sandbox path so panic-location strings don't
    # embed `$NIX_BUILD_TOP`.
    export CARGO_BUILD_RUSTFLAGS="$CARGO_BUILD_RUSTFLAGS --remap-path-prefix=$NIX_BUILD_TOP/source=/build/source --remap-path-prefix=$NIX_BUILD_TOP=/build"

    cargo near build ${lib.escapeShellArgs cargoNearArgs}

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out
    cp target/near/mpc_contract/mpc_contract.wasm $out/

    runHook postInstall
  '';

  doCheck = false;

  meta = with lib; {
    description = "Reproducible mpc-contract WASM";
    license = licenses.mit;
    platforms = platforms.unix;
  };
}
