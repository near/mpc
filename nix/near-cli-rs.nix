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
  version = "0.23.6";

  src = fetchFromGitHub {
    owner = "near";
    repo = "near-cli-rs";
    rev = "v${version}";
    hash = "sha256-o3sz/6u9XghqCro9HMAckVfCoOM30oYOeXlaU2PtEqI=";
  };

  cargoHash = "sha256-K038gY/fKEz9vJdqJwRYlDCjnFdy9sp8EwPL0Mv1NCk=";

  # nativeBuildInputs: Tools needed on the host to compile the package
  nativeBuildInputs = [
    pkg-config
  ];

  # buildInputs: Libraries the resulting binary will link against
  buildInputs = [
    openssl
  ]
  ++ lib.optionals stdenv.isLinux [
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
