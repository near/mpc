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
    version = "1.9.1";
    hash = "sha256-QRWYVmFCxntEFzC9iqEoZQ5sG57P2gpBUFu8A8aI+7g=";
    cargoHash = "sha256-yMUdZCIJTWCvi+07a1Erj6SD7i34opnvZ2CZ027PWzU=";
  })

  (buildTool {
    pname = "cargo-sort";
    version = "2.0.2";
    hash = "sha256-U/LakNUSPqj6FmYimi5ZNVJCRiS7zM4Vzvu4Gb3w38Q=";
    cargoHash = "sha256-FoFzBf24mNDTRBfFyTEr9Q7sJjUhs0X/XWRGEoierQ4=";
  })

  (buildTool {
    pname = "cargo-deny";
    version = "0.19.0";
    hash = "sha256-jciPa0M8KdKEkjSspSo14lHipPz7dtDDuppsywMZYCE=";
    cargoHash = "sha256-Lu1KhQmsQGvzgozFTcv9/hY3ZXOuaxkv0I+QPmAdZBU=";
  })

  (buildTool {
    pname = "cargo-about";
    version = "0.8.4";
    hash = "sha256-DGuznLAalGVhooyU2RJfjFozP3/q2OCfVbgFFG+FcPk=";
    cargoHash = "sha256-oO5Kp5A2v1w6EUwgcHhyagZDIK7a/2d9uTiCoXHuHhY=";
  })

  (buildTool {
    pname = "git-cliff";
    version = "2.12.0";
    hash = "sha256-V/dLd4yzMLOhMyoV5j/jKSGi0ZSYRFcZuUwlyz+Q3fk=";
    cargoHash = "sha256-8OhCb2b22S7/UaUAeaRUg0+haRIQ9+1m8eEiItMVTR4=";
  })

  (buildTool {
    pname = "zizmor";
    version = "1.22.0";
    hash = "sha256-VRw3+MCqG6Kmob7gM9Shv8E61muyuOijIMsg72xQ6cU=";
    cargoHash = "sha256-GGOLUMhbXmgN8MspiiddA9+irjv9CQCZgWbcrbE7cY8=";
  })

  (buildTool {
    pname = "cargo-make";
    version = "0.37.24";
    hash = "sha256-POMi8k8vLL3ZMWmGkSBg3BWSO6d8A4xoDawWDZXHpmk=";
    cargoHash = "sha256-ml/OW4S4fIMLmm7vVPgsXB7CigDYORGFpN3jZRp1f8c=";
  })

  # --- STANDARD NIXPKGS VERSIONS ---
  pkgs.cargo-binstall
  pkgs.cargo-insta
  pkgs.cargo-nextest

]
