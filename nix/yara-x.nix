{
  lib,
  stdenvNoCC,
  fetchurl,
}:

# Pinned rather than taken from nixpkgs so the dev shell and CI run the same
# scanner: nixpkgs currently has 1.16.0, and a nixpkgs bump would otherwise
# change the engine underneath the measured blocking allowlist without anyone
# noticing. See .github/yara/README.md.
let
  version = "1.19.0";

  assets = {
    x86_64-linux = {
      target = "x86_64-unknown-linux-gnu";
      hash = "sha256-qX14GJ41SHl6xFt7Sl/Yl1eDhhh1xZT3cuybi7X6TXI=";
    };
    aarch64-linux = {
      target = "aarch64-unknown-linux-gnu";
      hash = "sha256-IEQ/wWCBxo96LKBw/rhK4zqJx9xyaFG/BQaQ5Vk323c=";
    };
    aarch64-darwin = {
      target = "aarch64-apple-darwin";
      hash = "sha256-tuYtY4hBKoZlU0BRPM/XrJ6l6Yho6HDdSkwCmQnr+Hs=";
    };
  };

  system = stdenvNoCC.hostPlatform.system;
  asset = assets.${system} or (throw "yara-x: unsupported system ${system}");
in
stdenvNoCC.mkDerivation {
  pname = "yara-x";
  inherit version;

  src = fetchurl {
    url = "https://github.com/VirusTotal/yara-x/releases/download/v${version}/yara-x-v${version}-${asset.target}.tar.gz";
    inherit (asset) hash;
  };

  # The tarball holds a bare `yr`, so there is no directory to strip.
  sourceRoot = ".";

  installPhase = ''
    runHook preInstall
    install -Dm755 yr $out/bin/yr
    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    $out/bin/yr --version | grep -q '${version}'
    runHook postInstallCheck
  '';

  meta = {
    description = "Pattern matching engine for malware research, the successor to YARA";
    homepage = "https://github.com/VirusTotal/yara-x";
    license = lib.licenses.bsd3;
    mainProgram = "yr";
    platforms = builtins.attrNames assets;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
}
