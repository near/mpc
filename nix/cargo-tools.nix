{
  lib,
  rustPlatform,
  fetchCrate,
  pkgs,
}:

let
  buildTool =
    {
      pname,
      version,
      hash,
      cargoHash,
    }:
    rustPlatform.buildRustPackage {
      inherit pname version;
      src = fetchCrate {
        inherit pname version hash;
      };
      inherit cargoHash;
      doCheck = false;
    };
in
[
  (buildTool {
    pname = "cargo-shear";
    version = "1.6.0";
    hash = "sha256-i27DQnWCMTZ5og5KE2Fes5S7RZy/P3SwS5aEtTUoRd0=";
    cargoHash = "sha256-1FuLkcYezcrzzZ7B+n5r4oY/1BI0QYwjOqUjqWopeS0=";
  })

  (buildTool {
    pname = "cargo-nextest";
    version = "0.9.106";
    hash = "sha256-J8S8Xys/GedOBNZ+MDdxtQq8C1rZOj+qpl+78fcvge0=";
    cargoHash = "sha256-wDN09EKLB4jvVGNt1PvrdH9Iqe3EozCFI+wUAFjjGlM=";
  })

  (buildTool {
    pname = "cargo-sort";
    version = "2.0.2";
    hash = "sha256-U/LakNUSPqj6FmYimi5ZNVJCRiS7zM4Vzvu4Gb3w38Q=";
    cargoHash = "sha256-FoFzBf24mNDTRBfFyTEr9Q7sJjUhs0X/XWRGEoierQ4=";
  })

  (buildTool {
    pname = "cargo-deny";
    version = "0.18.9";
    hash = "sha256-WnIkb4OXutgufNWpFooKQiJ5TNhamtTsFJu8bWyWeR4=";
    cargoHash = "sha256-2u1DQtvjRfwbCXnX70M7drrMEvNsrVxsbikgrnNOkUE=";
  })

  (buildTool {
    pname = "cargo-about";
    version = "0.8.4";
    hash = "sha256-DGuznLAalGVhooyU2RJfjFozP3/q2OCfVbgFFG+FcPk=";
    cargoHash = "sha256-oO5Kp5A2v1w6EUwgcHhyagZDIK7a/2d9uTiCoXHuHhY=";
  })

  # --- STANDARD NIXPKGS VERSIONS ---
  pkgs.cargo-binstall
  pkgs.cargo-insta
  pkgs.cargo-make
]
