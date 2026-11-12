{
  lib,
  dockerTools,
  tee-launcher,
  docker-client,
  bashInteractive,
  coreutils,
}:

dockerTools.buildLayeredImage {
  name = "mpc-launcher";
  compressor = "none";

  contents = [
    tee-launcher
    (docker-client.override { buildxSupport = false; })
    bashInteractive
    coreutils
    dockerTools.fakeNss
  ];

  extraCommands = ''
    mkdir app
    ln -s ${lib.getExe tee-launcher} app/tee-launcher
  '';

  config = {
    Cmd = [ "/app/tee-launcher" ];
    Env = [ "PATH=/bin" ];
  };
}
