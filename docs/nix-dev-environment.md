# Development Environment (Nix)

This repository includes a [flake.nix](../flake.nix) file that provides a reproducible development environment using Nix. This environment pre-configures the Rust toolchain, LLVM/Clang tools, NEAR CLI tools, and all necessary system dependencies.

Prerequisites
  - **Nix**: [Install Nix](https://nixos.org/download/) with [Flakes enabled](https://nixos.wiki/wiki/Flakes)
  - **Docker**: While tools are provided in the shell, the Docker daemon must be running separately on your host system. Docker is required for reproducible builds of the MPC contract.

## Entering the Shell
To activate the development environment, run the following command in the project root:
```shell
nix develop
```

## Automatic environment loading (Optional)
To avoid typing `nix develop` each time you want to activate your shell environment, we can configure our shell
to  **automatically enter the dev environment when you `cd` into the repo** using **direnv** with **nix-direnv**.

### 1. Install direnv and nix-direnv (Nix profile)

Install [direnv](https://direnv.net/docs/installation.html) and [nix-direnv](https://github.com/nix-community/nix-direnv?tab=readme-ov-file#installation)

You can install both with nix profiles:

```shell
nix profile add nixpkgs#direnv nixpkgs#nix-direnv
```

### 2. Create an `.envrc` file to use the project's nix flake
```shell
echo "use flake" >> .envrc
```

### 3. Allow the `.envrc` file from the repository root
```shell
direnv allow
```

### 4. Add direnv hook to your shell

For `direnv` command to automatically run in the project, it must bee hooked to your shell.

See https://direnv.net/docs/installation.html for instructions.

### 5. Making direnv quiet (Optional)
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

### 6. VS Code rust-analyzer plugin support

For `rust-analyzer` installed through nix to work with the VS Code extension, you must configure the server path in your settings:

Add the following to your project settings in `.vscode/settings.json`:
```json
{
    "rust-analyzer.server.path": "rust-analyzer"
}
```

## Verifying the Nix shell is complete

Because `nix develop` inherits the system `$PATH`, missing packages can go unnoticed
if the host already has them installed. To verify the shell provides everything needed,
run the checks in a clean environment that hides system binaries:

```shell
nix develop --ignore-environment --command bash -c 'cargo make check-all-fast'
```

This should be done after modifying `flake.nix` or adding new tool dependencies.
