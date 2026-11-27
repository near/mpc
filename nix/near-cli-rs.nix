{
  lib,
  rustPlatform,
  fetchFromGitHub,
  pkg-config,
  openssl,
  stdenv,
  udev,
}:

rustPlatform.buildRustPackage rec {
  pname = "near-cli-rs";
  version = "0.30.1";

  src = fetchFromGitHub {
    owner = "near";
    repo = "near-cli-rs";
    rev = "v${version}";
    hash = "sha256-V6J26TY/nC/xf0Sf13meVq58f2GjJRX2FwgOKeT1Vo4=";
  };

  cargoHash = "sha256-KGJvd9x2IpRkGNTnn255HXhT9QDw+QHLdbSjDxBqTYY=";

  # nativeBuildInputs: Tools needed on the host to compile the package
  nativeBuildInputs = [
    pkg-config
  ];

  # buildInputs: Libraries the resulting binary will link against
  buildInputs = [
    openssl
  ]
  ++ lib.optionals stdenv.hostPlatform.isLinux [
    udev
  ];

  env = {
    # Prevent the crate from trying to build its own OpenSSL
    OPENSSL_NO_VENDOR = 1;
  };

  # skip tests as they require network access
  doCheck = false;

  meta = with lib; {
    description = "CLI tool for interacting with the NEAR blockchain. Needed for local development and deployment of smart contracts.";
    homepage = "https://github.com/near/near-cli-rs";
    platforms = platforms.unix;
    mainProgram = "near";
  };
}
