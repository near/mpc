{
  lib,
  stdenv,
  rustPlatform,
  fetchFromGitHub,
  pkg-config,
  openssl,
  udev,
  apple-sdk_14,
}:

rustPlatform.buildRustPackage rec {
  pname = "neard";
  version = "2.10.4";

  src = fetchFromGitHub {
    owner = "near";
    repo = "nearcore";
    # the revision is not on tag 2.10.4, since https://github.com/near/nearcore/pull/14902
    # is required to build neard in a sandboxed environment.
    rev = "3c4442e48af2e0ad12e84e10fec269d1b25638fc";
    hash = "sha256-lzM8QMozsjSDjFvMkkgaPayL2Fcmpe/knw+3I/ACQtc=";
  };

  cargoHash = "sha256-qnZfvDWYU935za9RlbkdlgNyCwpwcNHFUVg6E7+0dAQ=";

  buildNoDefaultFeatures = true;

  cargoBuildFlags = [
    "-p"
    "neard"
    "--bin"
    "neard"
  ];

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    openssl
  ]
  ++ lib.optionals stdenv.isLinux [
    udev
  ]
  ++ lib.optionals stdenv.isDarwin [
    apple-sdk_14
  ];

  env = {
    # Prevent the crate from trying to build its own OpenSSL
    OPENSSL_NO_VENDOR = 1;
  }
  // lib.optionalAttrs stdenv.isDarwin {
    # Darwin Sonoma / SDK 14 Compatibility
    SDKROOT = "${apple-sdk_14}/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk";
    MACOSX_DEPLOYMENT_TARGET = "14.0";
    CRATE_CC_NO_DEFAULTS = "1";

    # Required for crates like wasm-opt-sys that need explicit C++ standard alignment
    CMAKE_CXX_STANDARD = "17";
    WASM_OPT_CXX_FLAGS = "-std=c++17 -stdlib=libc++";
  };

  # skip tests as they require network access
  doCheck = false;

  meta = with lib; {
    description = "neard binary for running validators";
    homepage = "https://github.com/near/nearcore";
    platforms = platforms.unix;
    mainProgram = "neard";
  };
}
