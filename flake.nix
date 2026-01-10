{
  description = "Rust development environment for NEAR (Workspace)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      # Ensures rust-overlay uses the same nixpkgs version as this flake
      inputs.nixpkgs.follows = "nixpkgs";
    };
    utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      utils,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        # Use the recommended flake output for the overlay
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };

        inherit (pkgs) lib;
        llvmPkg = pkgs.llvmPackages_19;

        # Load toolchain from file and add necessary components
        rustToolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "clippy"
            "rustfmt"
          ];
        };

        pythonEnv = import ./nix/python-env.nix { inherit pkgs; };

        # Helper variables for Clang/LLVM paths
        clangVersion = lib.versions.major llvmPkg.clang-unwrapped.version;
        clangResourceDir = "${llvmPkg.clang-unwrapped.lib}/lib/clang/${clangVersion}/include";
        libcInc = lib.getDev pkgs.stdenv.cc.libc;

        # Near tools
        cargo-near = pkgs.callPackage ./nix/cargo-near.nix { };
        near-cli-rs = pkgs.callPackage ./nix/near-cli-rs.nix { };
      in
      {
        devShells.default = pkgs.mkShell {
          # strictDeps ensures that build-time tools and run-time libs are correctly separated
          strictDeps = true;

          # Developer Tools
          nativeBuildInputs = with pkgs; [
            pkg-config
            llvmPkg.clang
            llvmPkg.libclang

            # Rust
            rustToolchain
            rustPlatform.bindgenHook

            # Cargo extensions
            cargo-binstall
            cargo-deny
            cargo-insta
            cargo-make
            cargo-nextest
            cargo-shear
            cargo-sort

            # wasm-opt
            binaryen

            # Near CLI and SDK
            near-cli-rs
            cargo-near

            # python
            pythonEnv

            # Various utilities
            git
            zizmor
          ];

          # Dynamic libraries required for build
          buildInputs =
            with pkgs;
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
              pkgs.apple-sdk
            ];

          env = {
            # Needed for neard's librockdb build
            # Apply x86-specific flags ONLY on x86_64 machines
            CXXFLAGS =
              let
                isX86 = lib.strings.hasPrefix "x86_64" system;
              in
              "-include cstdint" + (lib.optionalString isX86 " -msse4.2 -mpclmul");

            # WASM Toolchain
            CC_wasm32_unknown_unknown = "${llvmPkg.clang-unwrapped}/bin/clang";
            AR_wasm32_unknown_unknown = "${llvmPkg.llvm}/bin/llvm-ar";
            CFLAGS_wasm32_unknown_unknown = "-I${clangResourceDir}";

            # Bindgen & Standard Library Path
            LIBCLANG_PATH = "${llvmPkg.libclang.lib}/lib";
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

            BINDGEN_EXTRA_CLANG_ARGS = lib.concatStringsSep " " [
              "-I${clangResourceDir}"
              "-I${libcInc}/include"
              "-fno-stack-protector"
            ];

            # Use cargo home specific to this nix shell to avoid polluting user's cargo home
            CARGO_HOME = ".nix-cargo";

            PYTHONPATH = "./pytest:./nearcore_pytest:./tee_launcher";

          };

          shellHook = ''
            export PATH="$CARGO_HOME/bin:$PATH"
            mkdir -p "$CARGO_HOME"

            echo "🦀 NEAR Dev Shell Active (Nixpkgs Unstable)"
            echo "Toolchain: $(rustc --version)"
          '';
        };
      }
    );
}
