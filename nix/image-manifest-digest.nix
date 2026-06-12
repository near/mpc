{
  runCommand,
  imageDir,
}:

# The registry manifest digest of an image — the value operators vote for.
#
# `imageDir` (see image-dir.nix) holds the exact manifest and compressed
# blobs that get pushed, so hashing its manifest.json yields — by
# construction, not by coincidence — the digest the registry will report
# after `skopeo copy --preserve-digests dir:<imageDir> docker://...`.

runCommand "${imageDir.name}-manifest-digest" { } ''
  printf 'sha256:%s\n' "$(sha256sum < ${imageDir}/manifest.json | cut -d' ' -f1)" > $out
''
