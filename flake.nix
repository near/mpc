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

      # Production ISA: x86-64-v3 plus PCLMUL and AES. The v3 micro-arch
      # level (per System V psABI) covers AVX2/BMI2/F16C/FMA/LZCNT/MOVBE
      # but NOT PCLMUL or AES — we add those explicitly so rocksdb's
      # PCLMUL-accelerated CRC32C path is compiled in. Production node
      # fleet is all v3-capable (Haswell / Excavator and newer).
      #
      # Shared between the reproducible mpc-node build (nix/mpc-node.nix)
      # and the dev shell (devShells.default below) so feature-test macros
      # in bindgen-parsed headers, cc-rs-compiled C/C++ deps, and the
      # rustc target-cpu line up across all build paths.
      prodCFlags = "-march=x86-64-v3 -mpclmul -maes";

    in
    {
      packages = forAllSystems (pkgs: {
        mpc-node = pkgs.callPackage ./nix/mpc-node.nix {
          inherit crane prodCFlags;
        };
        mpc-contract = pkgs.callPackage ./nix/mpc-contract.nix {
          cargo-near = pkgs.callPackage ./nix/cargo-near.nix { };
        };
        near-sandbox = pkgs.callPackage ./nix/near-sandbox.nix { };
        opengrep = pkgs.callPackage ./nix/opengrep.nix { };
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
          near-sandbox = pkgs.callPackage ./nix/near-sandbox.nix { };

          # Pinned to CI version
          cargoTools = pkgs.callPackage ./nix/cargo-tools.nix { };
          opengrep = pkgs.callPackage ./nix/opengrep.nix { };

          libcDev = lib.getDev stdenv.cc.libc;

          isX86 = stdenv.hostPlatform.isx86_64;

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

            # The near-sandbox crate downloads a prebuilt dynamically-linked
            # neard, which cannot run on NixOS (no FHS loader). Point it at the
            # nix-packaged binary instead; the env var short-circuits the
            # download for every consumer (near-sandbox, near-workspaces).
            NEAR_SANDBOX_BIN_PATH = "${near-sandbox}/bin/near-sandbox";
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

          nearTools = [
            near-cli-rs
            cargo-near
            near-sandbox
          ];

          miscTools = with pkgs; [
            git
            curl  # launch-localnet.sh, wait-for-endpoint polling
            gettext  # envsubst, used by launch-localnet.sh
            binaryen
            ast-grep  # structural lints, e.g. lints/rules/*
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

          # repro-env bind-mounts an init binary into the build container as its
          # entrypoint, hardcoded to /usr/bin/catatonit — a path NixOS has no
          # reason to populate. It has to be statically linked: it is mounted
          # into a Debian container, so a nix-store binary would fail there
          # looking for its glibc interpreter.
          catatonitStatic = pkgs.pkgsStatic.catatonit.overrideAttrs (_: {
            # The static cross stdenv has no readelf for installCheckPhase to
            # run; the link itself succeeds.
            doInstallCheck = false;
          });

          reproEnv = pkgs.repro-env.overrideAttrs (old: {
            postPatch = (old.postPatch or "") + ''
              substituteInPlace src/container.rs \
                --replace-fail /usr/bin/catatonit ${catatonitStatic}/bin/catatonit
            '';
          });

          # near-verify-rs runs the cargo-near build container as the host's own
          # uid/gid, hardcoded with no override. Under the rootless daemon below
          # that is precisely wrong: rootlesskit maps the host user to container
          # uid 0, so `-u <host uid>:<gid>` names an unmapped subuid that cannot
          # write the bind-mounted build site, and the build dies creating
          # `target/`. Rewriting the value to 0:0 gets what the flag was reaching
          # for anyway — output lands on the host owned by the invoking user.
          # `-it` goes too, so the build works with no tty (CI, `nix develop -c`).
          reproDocker = pkgs.writeShellApplication {
            name = "docker";
            text = ''
              args=()
              while [ "$#" -gt 0 ]; do
                case "$1" in
                  -u | --user)
                    args+=("$1" 0:0)
                    shift 2
                    ;;
                  -it)
                    shift
                    ;;
                  *)
                    args+=("$1")
                    shift
                    ;;
                esac
              done
              exec ${pkgs.docker}/bin/docker "''${args[@]}"
            '';
          };

          # Tooling for `deployment/build-images.sh` and the cargo-near contract
          # build. `reproDocker` stands in for `pkgs.docker`: nothing in this
          # shell should reach the unwrapped client.
          reproTools = [
            reproEnv
            reproDocker
          ]
          ++ (with pkgs; [
            podman
            skopeo
            docker-buildx
            git
            coreutils
            findutils
            jq
          ]);

          # Paths shared by the `repro` shell and its dockerd helper. The socket
          # lives in XDG_RUNTIME_DIR so it dies with the login session; the data
          # root has to outlive it to keep the pinned builder's image cache.
          reproDirs = ''
            runtime_dir="''${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
            state_dir="''${XDG_STATE_HOME:-$HOME/.local/share}/mpc-repro"
            docker_sock="$runtime_dir/mpc-repro-docker.sock"
          '';

          # repro-env only ever shells out to podman, which needs no daemon. The
          # buildx half of build-images.sh does need one, and a rootless dockerd
          # supplies it without root or any NixOS-level docker service: the
          # nixpkgs wrapper bundles rootlesskit, slirp4netns and fuse-overlayfs,
          # and the host already provides the pieces rootless mode cannot fake
          # (subuid/subgid ranges plus setuid newuidmap/newgidmap).
          reproDockerd = pkgs.writeShellApplication {
            name = "repro-dockerd";
            runtimeInputs = [
              pkgs.docker
              pkgs.coreutils
            ];
            text = ''
              ${reproDirs}
              export DOCKER_HOST="unix://$docker_sock"

              if docker info >/dev/null 2>&1; then
                echo "rootless dockerd already running"
                echo "DOCKER_HOST=$DOCKER_HOST"
                exit 0
              fi

              mkdir -p "$state_dir/docker-data" "$state_dir/log"
              log="$state_dir/log/dockerd.log"
              echo "starting rootless dockerd..."
              nohup dockerd-rootless \
                --host "$DOCKER_HOST" \
                --data-root "$state_dir/docker-data" \
                --exec-root "$runtime_dir/mpc-repro-docker-exec" \
                --pidfile "$runtime_dir/mpc-repro-docker.pid" \
                >"$log" 2>&1 &

              for i in $(seq 60); do
                if docker info >/dev/null 2>&1; then
                  echo "rootless dockerd up (''${i}s)"
                  echo "DOCKER_HOST=$DOCKER_HOST"
                  exit 0
                fi
                sleep 1
              done

              echo "dockerd did not come up within 60s; see $log" >&2
              exit 1
            '';
          };

        in
        {
          default = pkgs.mkShell {
            strictDeps = true;

            packages =
              dockerTools ++
              llvmTools ++
              rustTools ++
              cargoTools ++
              nearTools ++
              miscTools ++
              buildLibs ++
              [ opengrep ];

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
        // lib.optionalAttrs stdenv.hostPlatform.isLinux {
          repro = pkgs.mkShellNoCC {
            packages = reproTools ++ [
              reproDockerd
              # The contract's NEP-330 build compiles inside the pinned
              # sourcescan image, but cargo-near resolves the workspace on the
              # host first, and its `cargo metadata` shells out to `rustc -vV` —
              # so the host needs the toolchain even though it builds nothing.
              rustToolchain
              cargo-near
            ];

            shellHook = ''
              ${reproDirs}

              # buildx stores builder definitions under $DOCKER_CONFIG, and
              # build-images.sh re-`inspect`s its pinned builder on every run, so
              # this must be a stable directory — a temp one loses the builder
              # between runs. Deliberately not ~/.docker: the shell should never
              # write to a config the user also drives a real daemon with.
              export DOCKER_CONFIG="$state_dir/docker-config"
              mkdir -p "$DOCKER_CONFIG/cli-plugins"
              ln -sfn ${pkgs.docker-buildx}/libexec/docker/cli-plugins/docker-buildx \
                "$DOCKER_CONFIG/cli-plugins/docker-buildx"

              export DOCKER_HOST="unix://$docker_sock"

              # containers/image refuses to pull with no signature policy on
              # disk, and NixOS only populates /etc/containers when
              # virtualisation.containers is enabled — which rootless podman
              # does not otherwise require.
              policy="''${XDG_CONFIG_HOME:-$HOME/.config}/containers/policy.json"
              if [ ! -e "$policy" ]; then
                mkdir -p "$(dirname "$policy")"
                echo '{"default":[{"type":"insecureAcceptAnything"}]}' >"$policy"
                echo "wrote default container signature policy to $policy"
              fi

              printf "\e[32m🔁 MPC reproducible-build shell\e[0m\n"
              printf "  repro-dockerd                       start the rootless docker daemon\n"
              printf "  ./deployment/build-images.sh --node  build (from the repo root)\n"
              printf "  cargo near build reproducible-wasm --manifest-path crates/contract/Cargo.toml\n"
              printf "\e[33m  build-images.sh resets the mtime of every path in the repo,\n"
              printf "  including .git — run it in a throwaway worktree.\e[0m\n"
            '';
          };
        }
      );
    };
}
