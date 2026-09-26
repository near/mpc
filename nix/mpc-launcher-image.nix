{
  lib,
  dockerTools,
  tee-launcher,
  docker-client,
  bashInteractive,
  coreutils,
}:

# Not buildLayeredImage: it records every layer's store paths in the image
# config, and the launcher's store path moves with any workspace change even
# when its binary does not. Copying the binary into a single layer keeps the
# voted digest tied to the image contents
dockerTools.buildImage {
  name = "mpc-launcher";
  tag = "latest";
  compressor = "none";

  copyToRoot = [
    docker-client
    bashInteractive
    coreutils
    dockerTools.fakeNss
  ];

  extraCommands = "install -D ${lib.getExe tee-launcher} app/tee-launcher";

  config = {
    Cmd = [ "/app/tee-launcher" ];
    Env = [ "PATH=/bin" ];
  };
}
