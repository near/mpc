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
  pname = "cargo-near";
  version = "0.18.0";

  src = fetchFromGitHub {
    owner = "near";
    repo = "cargo-near";
    rev = "cargo-near-v${version}";
    hash = "sha256-rkqXOfItKO1MmdUFCih6b6g5057iWI6s1JWu/F6r0DY=";
  };

  cargoHash = "sha256-6GoSN+BrM0sw4rqW+6PIPwkTqZsJDyZAHOm78MtOm90=";

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
    description = "Cargo extension for reproducible builds of NEAR smart contracts";
    homepage = "https://github.com/near/cargo-near";
    platforms = platforms.unix;
    mainProgram = "cargo near";
  };
}
