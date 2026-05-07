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
    td=$(mktemp -d)
    # `--insecure-policy` skips the signature-trust policy check. Inside the
    # Nix sandbox $HOME is `/homeless-shelter` and /etc/containers/policy.json
    # doesn't exist, so the default policy lookup fails. The check is also
    # meaningless here: we're converting a local docker-archive tarball to a
    # local dir layout, no registry signatures involved.
    skopeo --insecure-policy copy --all --dest-compress "docker-archive:${image}" "dir:$td"
    printf 'sha256:%s\n' "$(sha256sum < "$td/manifest.json" | cut -d' ' -f1)" > $out
  ''
