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
      buildFeatures ? null,
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
      // lib.optionalAttrs (buildFeatures != null) {
        inherit buildFeatures;
      }
    );
in
[
  (buildTool {
    pname = "cargo-shear";
    version = "1.13.0";
    hash = "sha256-yG06OUiAYKK1S9t9TsytXAPF4W7FkeQHFNiWisjOQXA=";
    cargoHash = "sha256-BDvzoPTPwylmOznpuuCswUIkv3btVHh8QvnujuVqqVY=";
  })

  (buildTool {
    pname = "cargo-sort";
    version = "2.1.4";
    hash = "sha256-41Zht2qKulVaYmKOJRGCzmSVGCBa1nglUXpHrACAEgY=";
    cargoHash = "sha256-6Nxy2s0hXQqwCz82Xc1U10cYn6NdOqEX6JNXMrqIJOo=";
  })

  (buildTool {
    pname = "cargo-deny";
    version = "0.19.8";
    hash = "sha256-OQrIPhuTPuRxs1IbX4P0upwcBxIK1DnUIg6ZMSSPUeE=";
    cargoHash = "sha256-I2BHVcpULObHtsqBxzTvEPevZa/CkhlC/gj0ldofDwA=";
  })

  (buildTool {
    pname = "cargo-about";
    version = "0.9.0";
    hash = "sha256-NUtmZtUGmttr1KwZ1Fdle7foRekBb/u6ZQOpYnYkETM=";
    cargoHash = "sha256-Hp2PRwPpSUKdExOvF2szb8W5+juPv2HfK7cPBm1rm5Q=";
    # 0.9.0 gates the `cargo-about` binary behind the non-default `cli` feature.
    buildFeatures = [ "cli" ];
  })

  (buildTool {
    pname = "git-cliff";
    version = "2.13.1";
    hash = "sha256-mUna7Y2frPE0ZPhNgBzwYMPxoYGjEZkq80hrDFKHC7k=";
    cargoHash = "sha256-tBJUBVq3rPfoYiXBDU+xatE5IU6o2geqHiRXC4teXds=";
  })

  (buildTool {
    pname = "zizmor";
    version = "1.25.2";
    hash = "sha256-7QdSHT/CRPFRnjpQ/QypX4s451kpz5sv8IAqfs8+bQM=";
    cargoHash = "sha256-DW0a7Qr8q3fD9ZkSbf9R4KBhPOVEVPTqYwQ9sF4Btiw=";
  })

  (buildTool {
    pname = "cargo-make";
    version = "0.37.24";
    hash = "sha256-POMi8k8vLL3ZMWmGkSBg3BWSO6d8A4xoDawWDZXHpmk=";
    cargoHash = "sha256-ml/OW4S4fIMLmm7vVPgsXB7CigDYORGFpN3jZRp1f8c=";
  })

  (buildTool {
    pname = "lychee";
    version = "0.24.2";
    hash = "sha256-3v0iy3v6Ky8JziCj5Fm9jA+321tAZZI6jeJV97KWLrg=";
    cargoHash = "sha256-E0vs6tQElQ+DbhqKLBidrmElz74KKlKhNNVsQwIS3SE=";
    # build.rs unconditionally runs `git show` to embed the commit date into the
    # binary (used only for `lychee --man` output). There is no git repo inside the
    # Nix sandbox, so we replace build.rs with a stub that hardcodes the release date.
    postPatch = ''
      echo 'fn main() { println!("cargo:rustc-env=GIT_DATE=2026-05-01"); }' > build.rs
    '';
  })

  # --- STANDARD NIXPKGS VERSIONS ---
  pkgs.cargo-binstall
  pkgs.cargo-insta
  pkgs.cargo-nextest
]
