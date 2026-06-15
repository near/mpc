{
  dockerTools,
  bash,
  coreutils,
  gnused,
  python3,
  cacert,
  google-cloud-sdk,
  runCommand,
  mpc-node,
}:

# GCP variant of the node image — same start.sh / genesis layout as the
# vanilla node image, plus `gcloud` so start.sh can resolve the
# `gcloud secrets versions access latest ...` calls used to populate
# MPC_P2P_PRIVATE_KEY / MPC_ACCOUNT_SK / MPC_SECRET_STORE_KEY at boot.

let
  appFiles = runCommand "mpc-node-gcp-app-files" { } ''
    mkdir -p $out/app
    install -m 0755 ${../deployment/start.sh} $out/app/start.sh
    install -m 0644 ${../deployment/localnet/genesis.json} $out/app/localnet-genesis.json
    ln -s ${mpc-node}/bin/mpc-node $out/app/mpc-node
  '';
in
dockerTools.buildLayeredImage {
  name = "mpc-node-gcp";
  tag = "latest";
  created = "1970-01-01T00:00:00Z";

  contents = [
    bash
    coreutils
    gnused
    python3
    cacert
    google-cloud-sdk
    appFiles
  ];

  config = {
    Cmd = [ "/app/start.sh" ];
    WorkingDir = "/app";
    Env = [
      "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
      "PATH=/bin:/usr/bin"
    ];
  };
}
