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
  darwin,
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

  cargoToml = lib.importTOML ../Cargo.toml;
  pname = "mpc-node";
  version = cargoToml.workspace.package.version;

  src = lib.cleanSourceWith {
    src = craneLib.path ../.;
    filter =
      path: type:
      # Keep standard Rust/Cargo files (.rs, .toml, .lock, etc.)
      (craneLib.filterCargoSources path type)

      # license file
      || (lib.hasSuffix "hird-party-licenses/licenses.html" path)

      # README files that are included in docs
      || (lib.hasSuffix "crates/contract-interface/README.md" path)
      || (lib.hasSuffix "crates/contract/README.md" path)

      # TODO: --release should not need these assets.
      || (lib.hasInfix "assets/" path);
  };

  cargoVendorDir = craneLib.vendorCargoDeps { inherit src; };

  commonArgs = {
    inherit pname version src cargoVendorDir;
    strictDeps = true;
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
      darwin.apple_sdk.frameworks.Security
      darwin.apple_sdk.frameworks.SystemConfiguration
      darwin.apple_sdk.frameworks.CoreFoundation
    ];

    env = {
      SOURCE_DATE_EPOCH = "0";
      OPENSSL_NO_VENDOR = "1";
      LIBCLANG_PATH = "${llvmPkgs.libclang.lib}/lib";

      # FIX: Standardize target-cpu for both C and Rust in the environment.
      # This ensures crates like 'rocksdb' and 'zstd' build identically.
      CFLAGS = lib.optionalString isX86 "-march=x86-64-v3";
      CXXFLAGS = "-include cstdint" + lib.optionalString isX86 " -march=x86-64-v3";

      # Forces Rust to use the v3 instruction set (AVX2, BMI2, etc.)
      RUSTFLAGS = lib.concatStringsSep " " (
        lib.optionals isX86 [ "-C target-cpu=x86-64-v3" ]
        ++ [
          "--remap-path-prefix=${src}=/build/source"
          "--remap-path-prefix=${cargoVendorDir}=/cargo-vendor"
        ]
      );

      # Tell C-based build scripts (like rocksdb) to stop host-CPU probing
      PORTABLE = "1";

      BINDGEN_EXTRA_CLANG_ARGS = lib.concatStringsSep " " [
        "-I${clangResourceInclude}"
        "-I${libcDev}/include"
        (lib.optionalString isX86 "-march=x86-64-v3")
        "-fno-stack-protector"
      ];

      SHELL = "${pkgs.bash}/bin/bash";
      CONFIG_SHELL = "${pkgs.bash}/bin/bash";
    }
    // lib.optionalAttrs stdenv.isDarwin {
      SDKROOT = "${apple-sdk_14}/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk";
      MACOSX_DEPLOYMENT_TARGET = "14.0";
      CRATE_CC_NO_DEFAULTS = "1";
      CMAKE_CXX_STANDARD = "17";
      WASM_OPT_CXX_FLAGS = "-std=c++17 -stdlib=libc++";
    };

    doCheck = false;
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;
    doCheck = false;

    meta = with lib; {
      description = "MPC node binary for NEAR threshold signer";
      license = licenses.mit;
      platforms = platforms.unix;
      mainProgram = "mpc-node";
    };
  }
)
