{
  lib,
  dockerTools,
  backup-cli,
}:

dockerTools.buildLayeredImage {
  name = "backup-service";
  compressor = "none";

  contents = [
    backup-cli
    dockerTools.caCertificates
    dockerTools.fakeNss
  ];

  extraCommands = ''
    mkdir app
    ln -s ${lib.getExe backup-cli} app/backup-cli
  '';

  config = {
    Cmd = [ "/app/backup-cli" ];
    Env = [ "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt" ];
  };
}
