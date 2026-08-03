{
  lib,
  stdenv,
  fetchurl,
  autoPatchelfHook,
}:

# nixpkgs ships magika-cli, but it is unusable on Darwin: the binary it installs
# has no LC_RPATH, so it cannot resolve libonnxruntime.dylib and aborts on any
# invocation. Upstream's own release binaries work on both platforms, so take
# those, as nix/opengrep.nix does for the same reason.
let
  version = "1.1.0";

  assets = {
    x86_64-linux = {
      target = "x86_64-unknown-linux-gnu";
      hash = "sha256-a0wQEMhNH08GIFzO9Fl/FpC813RPRthB7uJkJrwQBIU=";
    };
    aarch64-linux = {
      target = "aarch64-unknown-linux-gnu";
      hash = "sha256-IYPkdF4fDlnRtwZtH/iP5AmzjJ6/EZqd5qga/RDmqvc=";
    };
    aarch64-darwin = {
      target = "aarch64-apple-darwin";
      hash = "sha256-VLicWen/AkaZBmF4xF5Y1zGDPMJbfBObQoV9XTG3uAQ=";
    };
  };

  asset = assets.${stdenv.hostPlatform.system} or (throw "magika: unsupported system ${stdenv.hostPlatform.system}");
in
stdenv.mkDerivation {
  pname = "magika";
  inherit version;

  src = fetchurl {
    # Releases are tagged cli/vX.Y.Z; that version is also what `magika
    # --version` reports, unlike the separately numbered Python package.
    url = "https://github.com/google/magika/releases/download/cli/v${version}/magika-cli-${asset.target}.tar.xz";
    inherit (asset) hash;
  };

  # The prebuilt ELF names the host's dynamic linker, which does not exist under
  # nix, so without this it fails with "cannot execute: required file not found".
  nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [ autoPatchelfHook ];
  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [ stdenv.cc.cc.lib ];

  # The tarball's single directory becomes the source root, so the binary is at
  # the top level here rather than under magika-cli-<target>/.
  installPhase = ''
    runHook preInstall
    install -Dm755 magika $out/bin/magika
    runHook postInstall
  '';

  # Runs the binary, so it catches a platform whose prebuilt artifact cannot
  # actually start - which is exactly how nixpkgs' Darwin build is broken.
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    $out/bin/magika --version | grep -q '${version}'
    runHook postInstallCheck
  '';

  meta = {
    description = "Determines file content types using a deep-learning model";
    homepage = "https://github.com/google/magika";
    license = lib.licenses.asl20;
    mainProgram = "magika";
    platforms = builtins.attrNames assets;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
}
