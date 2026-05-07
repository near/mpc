{
  dockerTools,
  bash,
  coreutils,
  gnused,
  python3,
  cacert,
  runCommand,
  mpc-node,
}:

let
  # The runtime layout `start.sh` expects: a writable-looking `/app` directory
  # holding the entry script, the embedded localnet genesis, and the binary
  # (referenced as both `./mpc-node` and `/app/mpc-node`).
  appFiles = runCommand "mpc-node-app-files" { } ''
    mkdir -p $out/app
    install -m 0755 ${../deployment/start.sh} $out/app/start.sh
    install -m 0644 ${../deployment/localnet/genesis.json} $out/app/localnet-genesis.json
    ln -s ${mpc-node}/bin/mpc-node $out/app/mpc-node
  '';
in
dockerTools.buildLayeredImage {
  name = "mpc-node";
  tag = "latest";
  # Fixed creation time for repro; image manifest digests must not depend on
  # wall clock at build time.
  created = "1970-01-01T00:00:00Z";

  # `bash` provides /bin/bash for the start.sh shebang.
  # `coreutils` and `gnused` provide the `cp`, `rm`, `sed -i` calls in start.sh.
  # `python3` is used by start.sh for JSON manipulation.
  # `cacert` provides the CA bundle for SSL_CERT_FILE.
  # `mpc-node` is included transitively via the symlink in `appFiles`; the
  # closure scanner picks up its store path and dockerTools pulls in the full
  # runtime closure (libssl, glibc, ...).
  contents = [
    bash
    coreutils
    gnused
    python3
    cacert
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
