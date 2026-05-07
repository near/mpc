{
  runCommand,
  skopeo,
  image,
}:

# Compute the manifest digest of `image` (a `dockerTools.buildLayeredImage`
# tarball derivation) by running skopeo entirely inside the Nix sandbox.
# Both source (`docker-archive:`) and destination (`dir:`) are local
# formats, so no network is touched — purely deterministic, reproducible
# across builders.
#
# The digest emitted here is the same one skopeo would compute when pushing
# the image to a registry; this is the value operators vote for.

runCommand "${image.imageName}-manifest-digest"
  {
    nativeBuildInputs = [ skopeo ];
  }
  ''
    workdir=$(mktemp -d)
    mkdir "$workdir/skopeo-tmp" "$workdir/out"

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
      "dir:$workdir/out"

    printf 'sha256:%s\n' "$(sha256sum < "$workdir/out/manifest.json" | cut -d' ' -f1)" > $out
  ''
