{
  description = "Rust development environment for NEAR (Workspace)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
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
      lib = nixpkgs.lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

      forAllSystems = f: lib.genAttrs systems (system: f (pkgsFor system));

      # Helper: compute clang resource include dir for bindgen/wasm.
      clangResourceInclude =
        llvmPkgs:
        let
          clangVersion = lib.versions.major llvmPkgs.clang-unwrapped.version;
        in
        "${llvmPkgs.clang-unwrapped.lib}/lib/clang/${clangVersion}/include";

    in
    {
      devShells = forAllSystems (
        pkgs:
        let
          inherit (pkgs) stdenv;

          llvmPkgs = pkgs.llvmPackages_19;

          rustToolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
              "rustfmt"
            ];
          };

          # Local NEAR tooling
          cargo-near = pkgs.callPackage ./nix/cargo-near.nix { };
          near-cli-rs = pkgs.callPackage ./nix/near-cli-rs.nix { };

          # Pinned to CI version
          cargo-shear = pkgs.callPackage ./nix/cargo-shear.nix { };

          libcDev = lib.getDev stdenv.cc.libc;

          isX86 = stdenv.hostPlatform.isx86_64;

          envCommon = {
            # needed for neard's rocksdb build to avoid unsupported CPU features
            CXXFLAGS = "-include cstdint" + lib.optionalString isX86 " -msse4.2 -mpclmul";

            # WASM Toolchain
            CC_wasm32_unknown_unknown = "${llvmPkgs.clang-unwrapped}/bin/clang";
            AR_wasm32_unknown_unknown = "${llvmPkgs.llvm}/bin/llvm-ar";
            CFLAGS_wasm32_unknown_unknown = "-I${clangResourceInclude llvmPkgs}";

            # Bindgen & Paths
            LIBCLANG_PATH = "${llvmPkgs.libclang.lib}/lib";
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

            BINDGEN_EXTRA_CLANG_ARGS = lib.concatStringsSep " " [
              "-I${clangResourceInclude llvmPkgs}"
              "-I${libcDev}/include"
              "-fno-stack-protector"
            ];

            PYTHONPATH = "./pytest:./nearcore_pytest:./tee_launcher";

            # Prevent Cargo from trying to use the system rustup
            RUSTUP_TOOLCHAIN = "";
            CARGO_HOME = ".nix-cargo";
          };

          envDarwin = lib.optionalAttrs stdenv.isDarwin {
            # Force build scripts to use Nix wrappers (not host clang)
            CC = "${stdenv.cc}/bin/cc";
            CXX = "${stdenv.cc}/bin/c++";

            # cc crate looks for these first on macOS
            CC_aarch64_apple_darwin = "${stdenv.cc}/bin/cc";
            CXX_aarch64_apple_darwin = "${stdenv.cc}/bin/c++";

            AR = "${stdenv.cc.bintools}/bin/ar";
            RANLIB = "${stdenv.cc.bintools}/bin/ranlib";
          };

          dockerTools = with pkgs; [
            docker
            docker-compose
          ];

          llvmTools = [
            pkgs.pkg-config
            llvmPkgs.clang
            llvmPkgs.libclang
          ];

          rustTools = with pkgs; [
            rustToolchain
            rustPlatform.bindgenHook
          ];

          cargoTools = with pkgs; [
            cargo-binstall
            cargo-deny
            cargo-insta
            cargo-make
            cargo-nextest
            cargo-shear
            cargo-sort
          ];

          nearTools = with pkgs; [
            python3Packages.keyring
            near-cli-rs
            cargo-near
          ];

          miscTools = with pkgs; [
            git
            zizmor
            binaryen
          ];

          buildLibs =
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
            ];

          hardening = [
            "fortify"
          ]
          ++ lib.optionals stdenv.isDarwin [
            "stackprotector"
            "strictoverflow"
            "format"
            "zerocallusedregs"
          ];

        in
        {
          default = pkgs.mkShell {
            strictDeps = true;

            packages =
              dockerTools ++ llvmTools ++ rustTools ++ cargoTools ++ nearTools ++ miscTools ++ buildLibs;

            env = envCommon // envDarwin;

            # Remove the hardening added by nix to fix jmalloc compilation error.
            # More info: https://github.com/tikv/jemallocator/issues/108
            hardeningDisable = hardening;

            shellHook = ''
              mkdir -p .nix-cargo
              export PATH="$PWD/.nix-cargo/bin:$PATH"
              printf "\e[32m🦀 NEAR Dev Shell Active\e[0m\n"
            '';
          };
        }
      );
    };
}
