{
  lib,
  dockerTools,
  mpc-node,
  bashInteractive,
  coreutils,
  gnused,
  python3Minimal,
  google-cloud-sdk,
  withGcloud ? false,
}:

dockerTools.buildLayeredImage {
  name = if withGcloud then "mpc-node-gcp" else "mpc-node";
  tag = "latest";
  compressor = "none";

  contents = [
    mpc-node
    bashInteractive
    coreutils
    gnused
    python3Minimal
    dockerTools.caCertificates
    dockerTools.fakeNss
  ]
  ++ lib.optional withGcloud google-cloud-sdk;

  extraCommands = ''
    mkdir -p app root
    # The node writes its allowed image hashes here and nothing else creates it
    mkdir -m 1777 tmp
    ln -s ${lib.getExe mpc-node} app/mpc-node
    install -m 755 ${../deployment/start.sh} app/start.sh
    install -m 644 ${../deployment/localnet/genesis.json} app/localnet-genesis.json
  '';

  config = {
    Cmd = [ "/app/start.sh" ];
    WorkingDir = "/app";
    Env = [
      "PATH=/bin"
      "HOME=/root"
      "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
    ];
  };
}
