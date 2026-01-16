# MPC

This repository contains the code for the Near MPC node. It is a rewrite of [Near MPC](https://github.com/near/mpc_old).

## Dependencies and submodules

- **Nearcore Node**: This repository depends on the nearcore node, included as a submodule in the `/libs` directory.
- **Other Dependencies**: All other dependencies are handled by Cargo.

## Development Environment (Nix)

This repository includes a [flake.nix](flake.nix) file that provides a reproducible development environment using Nix. This environment pre-configures the Rust toolchain, LLVM/Clang tools, NEAR CLI tools, and all necessary system dependencies.
Prerequisites
  - **Nix**: [Install Nix](https://nixos.org/download/) with [Flakes enabled](https://nixos.wiki/wiki/Flakes)
  - **Docker**: While tools are provided in the shell, the Docker daemon must be running separately on your host system. Docker is required for reproducible builds of the MPC contract.

### Entering the Shell
To activate the development environment, run the following command in the project root:
```shell
nix develop
```

### Automatic environment loading (Optional)
To avoid typing `nix develop` each time you want to activate your shell environment, we can configure our shell
to  **automatically enter the dev environment when you `cd` into the repo** using **direnv** with **nix-direnv**.

#### 1. Install direnv and nix-direnv (Nix profile)

Install [direnv](https://direnv.net/docs/installation.html) and [nix-direnv](https://github.com/nix-community/nix-direnv?tab=readme-ov-file#installation)

You can install both with nix profiles:

```shell
nix profile add nixpkgs#direnv nixpkgs#nix-direnv
```

#### 2. Create an `.envrc` file to use the project's nix flake
```shell
echo "use flake" >> .envrc
```

#### 3. Allow the `.envrc` file from the repository root
```shell
direnv allow
```

#### 4. Add direnv hook to your shell

For `direnv` command to automatically run in the project, it must bee hooked to your shell.

See https://direnv.net/docs/installation.html for instructions.

#### 5. Making direnv quiet (Optional)
By default `direnv` will print all exports each time the environment is activated which can be quite noisy.
<details>
<summary><b>Example verbose log</b></summary>

```log
$ cd mpc
direnv: loading ~/Dev/mpc/.envrc
direnv: using flake
warning: Git tree '/home/dsharifi/Dev/mpc' is dirty
🦀 NEAR Dev Shell Active
direnv: export +AR +AR_FOR_BUILD +AR_wasm32_unknown_unknown +AS +AS_FOR_BUILD +BINDGEN_EXTRA_CLANG_ARGS +CARGO_HOME +CC +CC_FOR_BUILD +CC_wasm32_unknown_unknown +CFLAGS_wasm32_unknown_unknown +CONFIG_SHELL +CXX +CXXFLAGS +CXX_FOR_BUILD +DETERMINISTIC_BUILD +IN_NIX_SHELL +LD +LD_FOR_BUILD +LIBCLANG_PATH +NIX_BINTOOLS +NIX_BINTOOLS_FOR_BUILD +NIX_BINTOOLS_WRAPPER_TARGET_BUILD_x86_64_unknown_linux_gnu +NIX_BINTOOLS_WRAPPER_TARGET_HOST_x86_64_unknown_linux_gnu +NIX_BUILD_CORES +NIX_BUILD_TOP +NIX_CC +NIX_CC_FOR_BUILD +NIX_CC_WRAPPER_TARGET_BUILD_x86_64_unknown_linux_gnu +NIX_CC_WRAPPER_TARGET_HOST_x86_64_unknown_linux_gnu +NIX_CFLAGS_COMPILE +NIX_CFLAGS_COMPILE_FOR_BUILD +NIX_ENFORCE_NO_NATIVE +NIX_HARDENING_ENABLE +NIX_LDFLAGS +NIX_LDFLAGS_FOR_BUILD +NIX_PKG_CONFIG_WRAPPER_TARGET_HOST_x86_64_unknown_linux_gnu +NIX_STORE +NM +NM_FOR_BUILD +OBJCOPY +OBJCOPY_FOR_BUILD +OBJDUMP +OBJDUMP_FOR_BUILD +PKG_CONFIG +PYTHONHASHSEED +PYTHONNOUSERSITE +PYTHONPATH +RANLIB +RANLIB_FOR_BUILD +READELF +READELF_FOR_BUILD +RUSTUP_TOOLCHAIN +RUST_SRC_PATH +SIZE +SIZE_FOR_BUILD +SOURCE_DATE_EPOCH +STRINGS +STRINGS_FOR_BUILD +STRIP +STRIP_FOR_BUILD +TEMP +TEMPDIR +TMP +TMPDIR +_PYTHON_HOST_PLATFORM +_PYTHON_SYSCONFIGDATA_NAME +__structuredAttrs +buildInputs +buildPhase +builder +cmakeFlags +configureFlags +depsBuildBuild +depsBuildBuildPropagated +depsBuildTarget +depsBuildTargetPropagated +depsHostHost +depsHostHostPropagated +depsTargetTarget +depsTargetTargetPropagated +doCheck +doInstallCheck +dontAddDisableDepTrack +hardeningDisable +mesonFlags +name +nativeBuildInputs +out +outputs +patches +phases +preferLocalBuild +propagatedBuildInputs +propagatedNativeBuildInputs +shell +shellHook +stdenv +strictDeps +system ~PATH ~XDG_DATA_DIRS
```

</details>

To silence these logs we need to create a `direnv.toml` and add `log_filter` and `hide_env_diff` configuration values to it.

You can do this with the command below:
> NB! This command **is not idempotent**, so only run it once!
```shell
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/direnv" && cat <<EOF >> "${XDG_CONFIG_HOME:-$HOME/.config}/direnv/direnv.toml"

[global]
log_filter = "^$"
hide_env_diff = true
EOF
```

#### 6. VS Code rust-analyzer plugin support

For `rust-analyzer` installed through nix to work with the VS Code extension, you must configure the server path in your settings:

Add the following to your project settings in `.vscode/settings.json`:
```json
{
    "rust-analyzer.server.path": "rust-analyzer"
}
```

## How it works

There are two main parts of the binary: NEAR indexer and MPC signing:

- NEAR Indexer: this is a NEAR node that tracks the shard where the signing smart contract is on. For mainnet, it is `v1.signer`.
The indexer tracks incoming requests by looking at successful calls to the `sign` function. Each request is hashed and gets mapped to a
specific node in the MPC network, which is known as the leader for this specific request. The leader initiates the signing process and submits the final signature back to the smart contract. If the leader is offline, there is a secondary leader who can initiate the signing
- MPC signing: A threshold ecdsa implementation based on [cait-sith](https://cronokirby.com/Posts/Some-Bits-about-Cait-Sith). Each node does the following:
  - Participates in Beaver triple generation in the background. Each node both initiates triple generation and passively participates in triple generation initiated by other nodes. This is constantly running until each node generates 1M Beaver triples.
  - Presignature generation. It also runs in the background. Each presignature generation requires two Beaver triples.
  - Signature generation. When a request comes in, a signature can be generated using a presignature and one round of communication.

  One thing to note is that from Beaver triple generation to signature generation, the request denotes the participating set. It is guaranteed that if a Beaver triple is generated by a specific set of participants, presignatures and signatures using that Beaver triple is generated by the same set of participants.

## Testing

### Terminology

We use the following terminology when referring to tests:
- _unit test_ -> a rust test in `/src` folder (per crate)
- _integration test_ -> a rust test in `/tests` folder (per crate)
- _system test_ -> a pytest in the `/pytest` folder

### Run tests

- **Unit and integration tests**: Run with `cargo test --profile test-release`
- **System Tests** : c.f. README located in the `/pytest` directory.

## Compilation

This repository uses `rust-toolchain.toml` files, as some code sections may require specific compiler versions. Be aware of potential overrides from:

- Directory-specific toolchain overrides
- Environment variables  

For more information, refer to the [Rustup book on overrides](https://rust-lang.github.io/rustup/overrides.html).

## Reproducible Builds

This project supports reproducible builds for both the node and launcher Docker images. Reproducible builds ensure that the same source code always produces identical binaries, which is important for security and verification purposes.

### Prerequisites

**Common requirements** (for both node and launcher):

- `docker` with buildx support
- `jq`
- `git`

**Additional requirements for building the node image**:

- `repro-env` - Tool for reproducible build environments ([install here](https://github.com/kpcyrd/repro-env))
- `podman`

### Building Images

The build script is located at `deployment/build-images.sh` and must be run from the project root directory.

**Build both node and launcher images** (default behavior):

```bash
./deployment/build-images.sh
```

**Build only the node image**:

```bash
./deployment/build-images.sh --node
```

**Build only the launcher image**:

```bash
./deployment/build-images.sh --launcher
```

The script will output the image hashes and other build information, which can be used to verify the reproducibility of the build.

## Releases

This project follows a standard release process with semantic versioning. Each release includes both the MPC node binary and the chain signatures contract as a single bundle.

For detailed information about our release process, compatibility guarantees, and procedures, see [RELEASES.md](RELEASES.md).

**Key Release Principles:**

- Releases are created from the `main` branch using semantic versioning.
- Minor versions maintain backward compatibility with previous node versions.
- Major versions ensure contract compatibility with the previous major version.

## TEE Integration

Efforts are made to allow running MPC nodes inside a trusted execution environment (TEE). For more details, see [TEE.md](TEE.md).

## Contributions

The NEAR MPC Node is actively maintained by **[NEAR One](https://github.com/Near-One)** and **[HOT Labs](https://github.com/hot-dao)** <img src="https://storage.herewallet.app/ft/1:hot.png" alt="HOT Labs" height="20" style="position: relative; top: 10px;"/>, with valuable contributions from the broader open-source community.

We welcome contributions in the form of issues, feature requests, and pull requests. Please ensure any changes are well-documented and tested. For major changes, open an issue to discuss the proposed modifications first.

### Development workflow

We run several checks in CI, which are backed by several tools not present by
default in rust developer environments:

- `cargo-nextest`
- `cargo-sort`
- `cargo-shear`
- `zizmor`
- `ruff`

This set does not include all checks, but only the most common reasons for CI
failures. Therefore, we suggest running these checks locally before opening a
PR. Running these checks with the correct parameters can be done easily with
`cargo-make`.

Running fast checks:

```console
cargo make check-all-fast
```

Running all `cargo-make` supported checks:

```console
cargo make check-all
```
