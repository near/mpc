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
  crane,
}:

let
  llvmPkgs = llvmPackages_19;

  rustToolchain = (rust-bin.fromRustupToolchainFile ../rust-toolchain.toml).override {
    extensions = [
      "rust-src"
    ];
  };

  craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

  clangResourceInclude =
    let
      clangVersion = lib.versions.major llvmPkgs.clang-unwrapped.version;
    in
    "${llvmPkgs.clang-unwrapped.lib}/lib/clang/${clangVersion}/include";

  libcDev = lib.getDev stdenv.cc.libc;
  isX86 = stdenv.hostPlatform.isx86_64;
  pname = "mpc-node";
  version = (lib.importTOML ../Cargo.toml).workspace.package.version;

  src = lib.cleanSource ../.;

  commonArgs = {
    inherit pname version src;

    strictDeps = true;

    cargoLock = {
      lockFile = ../Cargo.lock;
    };

    cargoExtraArgs = "-p mpc-node --bin mpc-node --profile reproducible --locked";

    nativeBuildInputs = [
      pkg-config
      pkgs.rustPlatform.bindgenHook
      llvmPkgs.clang
      llvmPkgs.libclang
    ];

    buildInputs =
      [
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
      ];

    env =
      {
        SOURCE_DATE_EPOCH = "0";
        OPENSSL_NO_VENDOR = "1";
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

    doCheck = false;
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (commonArgs // { inherit cargoArtifacts; } // {
  meta = with lib; {
    description = "MPC node binary for NEAR threshold signer";
    license = licenses.mit;
    platforms = platforms.unix;
    mainProgram = "mpc-node";
  };
})
