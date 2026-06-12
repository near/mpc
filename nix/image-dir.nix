{
  runCommand,
  skopeo,
  image,
}:

# Convert a `dockerTools.buildLayeredImage` docker-archive tarball into
# skopeo's `dir:` layout — manifest.json plus gzip-compressed layer blobs —
# by running skopeo entirely inside the Nix sandbox. Both source
# (`docker-archive:`) and destination (`dir:`) are local formats, so no
# network is touched; the skopeo doing the compression is the one pinned by
# flake.lock, making the output bit-identical across builders.
#
# This is the artifact that gets pushed to the registry. `skopeo copy
# --preserve-digests dir:<this> docker://...` uploads these exact blobs and
# manifest, so the digest the registry reports is by construction
# `sha256(manifest.json)` — it cannot drift with whatever skopeo version
# happens to be installed on the pushing machine.

runCommand "${image.imageName}-image-dir"
  {
    nativeBuildInputs = [ skopeo ];
  }
  ''
    workdir=$(mktemp -d)
    mkdir "$workdir/skopeo-tmp"

    # Two flags to make skopeo work in the Nix sandbox:
    #
    # `--insecure-policy` skips the signature-trust policy check. Inside the
    # sandbox $HOME is `/homeless-shelter` and /etc/containers/policy.json
    # doesn't exist, so the default policy lookup fails. The check is also
    # meaningless here: we're converting a local docker-archive tarball to a
    # local dir layout, no registry signatures involved.
    #
    # `--tmpdir` overrides containers/image's hardcoded /var/tmp big-files
    # temp dir. The Nix sandbox root is read-only so we can't create
    # /var/tmp; point skopeo at our writable workdir instead.
    skopeo \
      --insecure-policy \
      --tmpdir "$workdir/skopeo-tmp" \
      copy --all --dest-compress \
      "docker-archive:${image}" \
      "dir:$out"
  ''
