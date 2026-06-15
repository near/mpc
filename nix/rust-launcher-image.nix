{
  dockerTools,
  cacert,
  docker-client,
  runCommand,
  tee-launcher,
}:

# Image for the TEE launcher (`tee-launcher`). The launcher shells out to
# `docker compose -f ... up -d` and `docker pull`, so the image needs the
# docker CLI plus the v2 compose plugin. nixpkgs' `docker-client` is a
# CLI-only build of docker that ships the compose plugin.
#
# `/app-data` and `/mnt/shared` are pre-created here so they exist at runtime
# without depending on the launcher to mkdir on first boot.

let
  appFiles = runCommand "tee-launcher-app-files" { } ''
    mkdir -p $out/app $out/app-data $out/mnt/shared
    ln -s ${tee-launcher}/bin/tee-launcher $out/app/tee-launcher
  '';
in
dockerTools.buildLayeredImage {
  name = "mpc-rust-launcher";
  tag = "latest";
  created = "1970-01-01T00:00:00Z";

  contents = [
    cacert
    docker-client
    appFiles
  ];

  config = {
    Cmd = [ "/app/tee-launcher" ];
    WorkingDir = "/app";
    Env = [
      "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
      "PATH=/bin:/usr/bin"
    ];
  };
}
