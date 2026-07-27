{
  lib,
  stdenvNoCC,
  fetchurl,
}:

let
  version = "1.25.0";

  # Upstream publishes standalone signed binaries per platform, no docker image.
  assets = {
    x86_64-linux = {
      name = "opengrep_manylinux_x86";
      hash = "sha256-msSuu0e6P3sNj8ZBrIdJy2wvJT9hYTGmfZYx4A1L6jM=";
    };
    aarch64-linux = {
      name = "opengrep_manylinux_aarch64";
      hash = "sha256-/UASQnLQBggqVZSxmuzuB7Ad1Qkz2K3XpP1cVX0r5fY=";
    };
    aarch64-darwin = {
      name = "opengrep_osx_arm64";
      hash = "sha256-NUP8q66dsq5byXSjt1QmNT8KPjaRgbIVfvJ/RoZ5lsg=";
    };
  };

  system = stdenvNoCC.hostPlatform.system;
  asset = assets.${system} or (throw "opengrep: unsupported system ${system}");
in
stdenvNoCC.mkDerivation {
  pname = "opengrep";
  inherit version;

  src = fetchurl {
    url = "https://github.com/opengrep/opengrep/releases/download/v${version}/${asset.name}";
    inherit (asset) hash;
  };

  dontUnpack = true;

  installPhase = ''
    install -Dm755 $src $out/bin/opengrep
  '';

  meta = {
    description = "Static code analysis engine (LGPL fork of semgrep)";
    homepage = "https://github.com/opengrep/opengrep";
    license = lib.licenses.lgpl21Plus;
    mainProgram = "opengrep";
  };
}
