{
  lib,
  stdenv,
  fetchurl,
  autoPatchelfHook,
}:

let
  # Must match `DEFAULT_SANDBOX_VERSION` in crates/test-utils/src/lib.rs (and
  # thereby the nearcore tag in Cargo.toml); scripts/check-sandbox-image-version.sh
  # enforces the pairing.
  version = "2.13.4";

  # Slugs are the `platform()` strings of the near-sandbox crate, which
  # downloads the same artifacts at test time on non-Nix hosts.
  platforms = {
    x86_64-linux = {
      slug = "Linux-x86_64";
      hash = "sha256-VpCkY1FyJjzwJmg/dZZcrAndkWkSWE8ScJl0/tYgFj8=";
    };
    aarch64-linux = {
      slug = "Linux-aarch64";
      hash = "sha256-7dd9bSi5YIUiQ/xvRWVsl6eXb8Kzz+U82okySmgEvTA=";
    };
    aarch64-darwin = {
      slug = "Darwin-arm64";
      hash = "sha256-FYztsC5ag9UbR8FuE80EqEq/ST8fOGiO4lfLAmNFBjE=";
    };
  };

  platform =
    platforms.${stdenv.hostPlatform.system}
      or (throw "near-sandbox: unsupported system ${stdenv.hostPlatform.system}");
in
stdenv.mkDerivation {
  pname = "near-sandbox";
  inherit version;

  src = fetchurl {
    url = "https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/${platform.slug}/${version}/near-sandbox.tar.gz";
    inherit (platform) hash;
  };

  nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [ autoPatchelfHook ];
  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [ stdenv.cc.cc.lib ];

  installPhase = ''
    runHook preInstall
    install -Dm755 near-sandbox $out/bin/near-sandbox
    runHook postInstall
  '';

  meta = {
    description = "Prebuilt neard with the sandbox feature, as used by sandbox tests";
    mainProgram = "near-sandbox";
    platforms = lib.attrNames platforms;
  };
}
