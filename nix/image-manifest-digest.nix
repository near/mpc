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
    skopeo copy --all --dest-compress "docker-archive:${image}" "dir:$td"
    printf 'sha256:%s\n' "$(sha256sum < "$td/manifest.json" | cut -d' ' -f1)" > $out
  ''
