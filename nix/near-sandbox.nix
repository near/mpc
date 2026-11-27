{
  lib,
  pkgs,
  stdenv,
  rustPlatform,
  rust-bin,
  llvmPackages_19,
  pkg-config,
  openssl,
  zlib,
  apple-sdk_14 ? null,
  crane,
  # The `nearcore` flake input. Its tag must match `DEFAULT_SANDBOX_VERSION`
  # in crates/test-utils; scripts/check-sandbox-image-version.sh enforces it.
  nearcore,
}:

let
  nearcoreToml = lib.importTOML "${nearcore}/Cargo.toml";

  # nearcore pins an older Rust than this workspace, and its tags do not
  # necessarily compile under ours.
  rustToolchain =
    rust-bin.stable.${(lib.importTOML "${nearcore}/rust-toolchain.toml").toolchain.channel}.minimal;

  craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
in
craneLib.buildPackage {
  pname = "near-sandbox";
  inherit (nearcoreToml.workspace.package) version;
  src = nearcore;

  strictDeps = true;
  # nearcore's `make sandbox-release`, which produces the artifact the
  # near-sandbox crate downloads on non-Nix hosts, minus the default
  # `dump-test-contract` feature: its build script compiles wasm contracts in
  # a nested cargo build with its own lockfiles, which cannot run offline.
  CARGO_PROFILE = "release";
  cargoExtraArgs = "-p neard --no-default-features --features json_rpc,rosetta_rpc,sandbox --locked";
  # A pinned tag is rebuilt only on bumps, so a separate dependency
  # derivation would buy nothing.
  cargoArtifacts = null;
  doCheck = false;

  # The `tcp` import is gated behind `dump-test-contract`, so neard does not
  # compile without that feature.
  postPatch = ''
    substituteInPlace neard/src/cli.rs \
      --replace-fail ' tcp::ListenerAddr::new(rpc_addr' ' near_network::tcp::ListenerAddr::new(rpc_addr'
  '';

  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
    llvmPackages_19.clang
  ];

  buildInputs = [
    openssl
    zlib
  ]
  ++ lib.optionals stdenv.hostPlatform.isDarwin [ apple-sdk_14 ];

  env.OPENSSL_NO_VENDOR = "1";

  postInstall = ''
    ln -s neard $out/bin/near-sandbox
  '';

  meta = {
    description = "neard built with the sandbox feature, for sandbox tests and scripts/launch-localnet.sh";
    mainProgram = "neard";
    platforms = lib.platforms.unix;
  };
}
