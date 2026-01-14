{
  lib,
  rustPlatform,
  fetchCrate,
}:

rustPlatform.buildRustPackage rec {
  pname = "cargo-shear";
  version = "1.6.0";

  src = fetchCrate {
    inherit pname version;
    hash = "sha256-i27DQnWCMTZ5og5KE2Fes5S7RZy/P3SwS5aEtTUoRd0=";
  };

  cargoHash = "sha256-1FuLkcYezcrzzZ7B+n5r4oY/1BI0QYwjOqUjqWopeS0=";
  doCheck = false;

  meta = with lib; {
    description = "Detect unused dependencies in Cargo.toml";
    mainProgram = "cargo-shear";
  };
}
