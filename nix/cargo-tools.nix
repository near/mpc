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
      postPatch ? null,
    }:
    rustPlatform.buildRustPackage (
      {
        inherit pname version;
        src = fetchCrate {
          inherit pname version hash;
        };
        inherit cargoHash;
        doCheck = false;
      }
      // lib.optionalAttrs (postPatch != null) {
        inherit postPatch;
      }
    );
in
[
  (buildTool {
    pname = "cargo-shear";
    version = "1.11.2";
    hash = "sha256-1NQ9Ws6aMFuMawoCPHjvbVLCP2ztLgAeXvKY4952aqU=";
    cargoHash = "sha256-PkcRFzwC5M0wFSFXOuuLxWcZWrznzs9GdykE/8AjSMw=";
  })

  (buildTool {
    pname = "cargo-sort";
    version = "2.1.3";
    hash = "sha256-mSxXrPDexaIMFunmOPt5ysYkVyF8BCuOOumT+44zrGA=";
    cargoHash = "sha256-ygMtfhwoUEIZx+q6KB5yOr8/Fj5FRMIs7dXlYDUKb2U=";
  })

  (buildTool {
    pname = "cargo-deny";
    version = "0.19.4";
    hash = "sha256-YQYaJh/XFcgqYVVZQ/H8fQB7nLTpFNAq3stHi6U8q/g=";
    cargoHash = "sha256-NjGGe5K0fpS9EDfuSOmBi9BGiObh8XITHQoSb7iktWc=";
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
    version = "1.24.1";
    hash = "sha256-gbVhFi4wKpwdhHuP7tW/Im+5J2Ky0bTzfqSv8Ht6cgk=";
    cargoHash = "sha256-xyXUauig4dWpur7sWLoOevtbESNOTNVhspN4MMrgBKk=";
  })

  (buildTool {
    pname = "cargo-make";
    version = "0.37.24";
    hash = "sha256-POMi8k8vLL3ZMWmGkSBg3BWSO6d8A4xoDawWDZXHpmk=";
    cargoHash = "sha256-ml/OW4S4fIMLmm7vVPgsXB7CigDYORGFpN3jZRp1f8c=";
  })

  (buildTool {
    pname = "lychee";
    version = "0.23.0";
    hash = "sha256-cl2AeeisWO9co5PIqWlvFUubmjZOBjGYK6Xb7lga5Rg=";
    cargoHash = "sha256-SgOKU0RMaof3b4oaBs8vTUCQe+9iPJG9656qP4mFT9c=";
    # build.rs unconditionally runs `git show` to embed the commit date into the
    # binary (used only for `lychee --man` output). There is no git repo inside the
    # Nix sandbox, so we replace build.rs with a stub that hardcodes the release date.
    postPatch = ''
      echo 'fn main() { println!("cargo:rustc-env=GIT_DATE=2026-02-13"); }' > build.rs
    '';
  })

  # --- STANDARD NIXPKGS VERSIONS ---
  pkgs.cargo-binstall
  pkgs.cargo-insta
  pkgs.cargo-nextest
]
