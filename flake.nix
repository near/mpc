{
  description = "Rust development environment for NEAR (Workspace)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      # ensures the overlay uses the same nixpkgs as the cargo project
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      # 1. Define supported architectures
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      # 2. Helper to iterate over systems without flake-utils
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # 3. Functional helper to get pkgs with overlay applied
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          inherit (pkgs) lib;
          llvmPkg = pkgs.llvmPackages_19;

          # Rust Toolchain setup
          rustToolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
              "rustfmt"
            ];
          };

          pythonEnv = import ./nix/python-env.nix { inherit pkgs; };

          # LLVM/Clang Helpers
          clangVersion = lib.versions.major llvmPkg.clang-unwrapped.version;
          clangResourceDir = "${llvmPkg.clang-unwrapped.lib}/lib/clang/${clangVersion}/include";
          libcInc = lib.getDev pkgs.stdenv.cc.libc;

          # Custom NEAR local packages
          cargo-near = pkgs.callPackage ./nix/cargo-near.nix { };
          near-cli-rs = pkgs.callPackage ./nix/near-cli-rs.nix { };
        in
        {
          default = pkgs.mkShell {
            strictDeps = true;

            nativeBuildInputs = with pkgs; [
              # Docker Tools, note docker daemon must be running separately
              docker
              docker-compose

              # LLVM/Clang Tools
              pkg-config
              llvmPkg.clang
              llvmPkg.libclang

              # Rust Toolchain
              rustToolchain
              rustPlatform.bindgenHook

              # Cargo & Build tools
              cargo-binstall
              cargo-deny
              cargo-insta
              cargo-make
              cargo-nextest
              cargo-shear
              cargo-sort

              # wasm-opt
              binaryen

              # NEAR CLI Tools
              near-cli-rs
              cargo-near

              # Python environment for pytests
              pythonEnv

              # Misc Utilities
              git
              zizmor
            ];

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
              # needed for neard's rocksdb build to avoid unsupported CPU features
              CXXFLAGS =
                let
                  isX86 = pkgs.stdenv.hostPlatform.isx86_64;
                in
                "-include cstdint" + (lib.optionalString isX86 " -msse4.2 -mpclmul");

              # WASM Toolchain
              CC_wasm32_unknown_unknown = "${llvmPkg.clang-unwrapped}/bin/clang";
              AR_wasm32_unknown_unknown = "${llvmPkg.llvm}/bin/llvm-ar";
              CFLAGS_wasm32_unknown_unknown = "-I${clangResourceDir}";

              # Bindgen & Paths
              LIBCLANG_PATH = "${llvmPkg.libclang.lib}/lib";
              RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

              BINDGEN_EXTRA_CLANG_ARGS = lib.concatStringsSep " " [
                "-I${clangResourceDir}"
                "-I${libcInc}/include"
                "-fno-stack-protector"
              ];

              PYTHONPATH = "./pytest:./nearcore_pytest:./tee_launcher";

              # Prevent Cargo from trying to use the system rustup
              RUSTUP_TOOLCHAIN = "";
              CARGO_HOME = ".nix-cargo";
            };

            # Remove the hardening added by nix to fix jmalloc compilation error.
            # More info: https://github.com/tikv/jemallocator/issues/108
            hardeningDisable = [ "fortify" ];

            shellHook = ''
              mkdir -p .nix-cargo
              export PATH="$PWD/.nix-cargo/bin:$PATH"

              printf "\e[32m🦀 NEAR Dev Shell Active\e[0m\n"

              # echo "🦀 NEAR Dev Shell Active | $(rustc --version)"
            '';
          };
        }
      );
    };
}
