{
  lib,
  pkgs,
  stdenv,
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
  apple-sdk_14,
  darwin, # Add darwin for frameworks
  crane,
}:

let
  llvmPkgs = llvmPackages_19;

  rustToolchain = (rust-bin.fromRustupToolchainFile ../rust-toolchain.toml).override {
    extensions = [ "rust-src" ];
  };

  craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

  clangResourceInclude =
    let
      clangVersion = lib.versions.major llvmPkgs.clang-unwrapped.version;
    in
    "${llvmPkgs.clang-unwrapped.lib}/lib/clang/${clangVersion}/include";

  libcDev = lib.getDev stdenv.cc.libc;
  isX86 = stdenv.hostPlatform.isx86_64;

  # Load TOML safely
  cargoToml = lib.importTOML ../Cargo.toml;
  pname = "mpc-node";
  version = cargoToml.workspace.package.version;

  # FIX 1: Use crane's source cleaner for better caching
  src = lib.cleanSourceWith {
    src = craneLib.path ../.;
    filter =
      path: type:
      # Keep standard Rust/Cargo files (rs, toml, lock)
      (craneLib.filterCargoSources path type)

      # license file
      || (lib.hasSuffix "hird-party-licenses/licenses.html" path)

      # README files that are included in docs
      || (lib.hasSuffix "crates/contract-interface/README.md" path)
      || (lib.hasSuffix "crates/contract/README.md" path)

      # TODO: --release should not need these assets.
      || (lib.hasInfix "assets/" path);

  };

  commonArgs = {
    inherit pname version src;

    strictDeps = true;

    # FIX 2: Removed `cargoLock` (unused by Crane)

    cargoProfile = "reproducible";
    cargoExtraArgs = "-p mpc-node --bin mpc-node --locked";

    nativeBuildInputs = [
      pkg-config
      pkgs.rustPlatform.bindgenHook
      llvmPkgs.clang
      llvmPkgs.libclang
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
      apple-sdk_14
      # FIX 3: Explicit frameworks are often required on macOS
      darwin.apple_sdk.frameworks.Security
      darwin.apple_sdk.frameworks.SystemConfiguration
      darwin.apple_sdk.frameworks.CoreFoundation
    ];

    env = {
      SOURCE_DATE_EPOCH = "0";
      OPENSSL_NO_VENDOR = "1";
      # LIBCLANG_PATH is handled by bindgenHook, but keep if you have specific version reqs
      LIBCLANG_PATH = "${llvmPkgs.libclang.lib}/lib";

      BINDGEN_EXTRA_CLANG_ARGS = lib.concatStringsSep " " [
        "-I${clangResourceInclude}"
        "-I${libcDev}/include"
        "-fno-stack-protector"
      ];
      CXXFLAGS = "-include cstdint" + lib.optionalString isX86 " -msse4.2 -mpclmul";
    }
    // lib.optionalAttrs stdenv.isDarwin {
      SDKROOT = "${apple-sdk_14}/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk";
      MACOSX_DEPLOYMENT_TARGET = "14.0";
      CRATE_CC_NO_DEFAULTS = "1";
      CMAKE_CXX_STANDARD = "17";
      WASM_OPT_CXX_FLAGS = "-std=c++17 -stdlib=libc++";
    };

    # Disable tests during artifact build to speed it up
    doCheck = false;
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;

    # Re-enable checks for the final build if desired
    doCheck = true;

    meta = with lib; {
      description = "MPC node binary for NEAR threshold signer";
      license = licenses.mit;
      platforms = platforms.unix;
      mainProgram = "mpc-node";
    };
  }
)
