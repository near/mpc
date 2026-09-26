{ runCommand, skopeo }:

# The image exactly as pushed to a registry: the layers are compressed here, so
# the SHA-256 of manifest.json is the manifest digest that operators vote on,
# and a digest-preserving copy publishes it unchanged
image:
runCommand "${image.imageName}-registry" { nativeBuildInputs = [ skopeo ]; } ''
  # No signature policy is installed in the sandbox
  skopeo --insecure-policy copy --dest-compress docker-archive:${image} dir:$out
''
