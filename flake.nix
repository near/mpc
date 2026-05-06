{
  description = "Rust development environment for NEAR (Workspace)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
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
      packages = forAllSystems (pkgs: {
        mpc-node = pkgs.callPackage ./nix/mpc-node.nix {
          inherit crane;
        };
      });

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
          cargoTools = pkgs.callPackage ./nix/cargo-tools.nix { };

          libcDev = lib.getDev stdenv.cc.libc;

          isX86 = stdenv.hostPlatform.isx86_64;

          # Production ISA: x86-64-v3 plus PCLMUL and AES. The v3 micro-arch
          # level (per System V psABI) covers AVX2/BMI2/F16C/FMA/LZCNT/MOVBE
          # but NOT PCLMUL or AES — we add those explicitly so rocksdb's
          # PCLMUL-accelerated CRC32C path is compiled in. See
          # .cargo/config.toml, nix/mpc-node.nix, and deployment/build-images.sh
          # for the matching production-build settings. Host fleet is all
          # v3-capable (Haswell / Excavator and newer).
          prodCFlags = "-march=x86-64-v3 -mpclmul -maes";

          envCommon = {
            # `-include cstdint` is needed by neard's rocksdb C++ build
            # regardless of host. Production ISA flags are scoped to the
            # x86_64 Linux host target below so wasm cross-compilation
            # (e.g. the contract WASM build via blst) isn't polluted —
            # `-march=x86-64-v3` is invalid for the wasm32 target.
            CXXFLAGS = "-include cstdint";

            # WASM Toolchain
            CC_wasm32_unknown_unknown = "${llvmPkgs.clang-unwrapped}/bin/clang";
            AR_wasm32_unknown_unknown = "${llvmPkgs.llvm}/bin/llvm-ar";
            CFLAGS_wasm32_unknown_unknown = "-I${clangResourceInclude llvmPkgs}";

            # Bindgen & Paths
            LIBCLANG_PATH = "${llvmPkgs.libclang.lib}/lib";
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

            # Match the production-build feature-test macros (`__AVX2__`,
            # `__FMA__`, `__BMI2__`, `__PCLMUL__`, `__AES__`) so rust-bindgen
            # generates the same Rust bindings as `nix/mpc-node.nix` does.
            BINDGEN_EXTRA_CLANG_ARGS = lib.concatStringsSep " " (
              [
                "-I${clangResourceInclude llvmPkgs}"
                "-I${libcDev}/include"
                "-fno-stack-protector"
              ]
              ++ lib.optional isX86 prodCFlags
            );

            # OpenSSL
            PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
            OPENSSL_DIR = "${pkgs.openssl.dev}";
            OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
            OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";

            # Prevent Cargo from trying to use the system rustup
            RUSTUP_TOOLCHAIN = "";
          }
          // lib.optionalAttrs (stdenv.isLinux && isX86) {
            # Production ISA for cc-crate dependencies (rocksdb, snappy, zstd,
            # jemalloc). Target-scoped so wasm cross-builds aren't polluted.
            CFLAGS_x86_64_unknown_linux_gnu = prodCFlags;
            CXXFLAGS_x86_64_unknown_linux_gnu = "${prodCFlags} -include cstdint";
          };

          envDarwin = lib.optionalAttrs stdenv.isDarwin {
            # Cargo resolves its linker separately from CC — force it to use the
            # LLVM 19 clang so -lSystem (and other SDK libs) are found.
            CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER = "${llvmPkgs.clang}/bin/clang";
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

          nearTools = with pkgs; [
            near-cli-rs
            cargo-near
          ];

          pythonTools = with pkgs; [
            python311
            python311Packages.keyring
            python311Packages.tree-sitter
            python311Packages.tree-sitter-rust
            ruff # linter and formatter
          ];

          miscTools = with pkgs; [
            git
            binaryen
            editorconfig-checker
            jq
            perl
            procps  # pgrep, used by the kill-orphan-mpc-nodes cargo-make task
            pprof
            graphviz
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
            ]
            ++ lib.optionals stdenv.isDarwin [
              apple-sdk_14
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
              dockerTools ++
              llvmTools ++
              rustTools ++
              cargoTools ++
              pythonTools ++
              nearTools ++
              miscTools ++
              buildLibs;

            env = envCommon // envDarwin;

            # Remove the hardening added by nix to fix jmalloc compilation error.
            # More info: https://github.com/tikv/jemallocator/issues/108
            hardeningDisable = hardening;

            shellHook = ''
              ${lib.optionalString stdenv.isDarwin ''
                # Override CC/CXX to use LLVM 19 clang, matching Rust 1.86.0's
                # bundled LLVM version. The default stdenv's clang 21 produces
                # LLVM bitcode that Rust's LLVM 19 cannot read.
                export CC="${llvmPkgs.clang}/bin/clang"
                export CXX="${llvmPkgs.clang}/bin/clang++"
                export CC_aarch64_apple_darwin="${llvmPkgs.clang}/bin/clang"
                export CXX_aarch64_apple_darwin="${llvmPkgs.clang}/bin/clang++"
                export AR="${llvmPkgs.llvm}/bin/llvm-ar"
                export RANLIB="${llvmPkgs.llvm}/bin/llvm-ranlib"
              ''}
              printf "\e[32m🦀 NEAR Dev Shell Active\e[0m\n"
            '';
          };
        }
      );
    };
}
