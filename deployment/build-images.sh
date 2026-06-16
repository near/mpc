#! /usr/bin/env bash
# Script to reproducibly build the docker images for the node and launcher
#
# Requirements: docker, docker-buildx, git, find, touch, skopeo
# Extra requirements if using --node or --rust-launcher: repro-env, podman
# Extra requirements if using --push: docker must be logged in to registry
#
# Usage:
#   ./deployment/build-images.sh [--node] [--node-gcp] [--rust-launcher] [--push]
# If no image flags are used, all images are built
# Manifest digests are always computed and printed (skopeo required)


set -euo pipefail

USE_RUST_LAUNCHER=false
USE_NODE=false
USE_NODE_GCP=false
USE_PUSH=false

for arg in "$@"
do
  case "$arg" in
    --node)
      USE_NODE=true
      ;;
    --node-gcp)
      USE_NODE_GCP=true
      ;;
    --rust-launcher)
      USE_RUST_LAUNCHER=true
      ;;
    --push)
      USE_PUSH=true
      ;;
    *)
      echo "Unknown parameter: $arg"
      echo "Usage: $0 [--node] [--rust-launcher] [--push]"
      exit 1
      ;;
  esac
done

if ! $USE_RUST_LAUNCHER && ! $USE_NODE && ! $USE_NODE_GCP; then
    USE_RUST_LAUNCHER=true
    USE_NODE=true
    USE_NODE_GCP=true
fi

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmds() {
  local missing=0
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || { printf 'Missing dependency: %s\n' "$cmd" >&2; missing=1; }
  done
  [[ "${missing}" -eq 0 ]] || die "Please install the missing dependencies above."
}

require_cmds docker git find touch skopeo

if $USE_NODE || $USE_RUST_LAUNCHER; then
    require_cmds repro-env podman
fi

if ! docker buildx &>/dev/null; then
  die "Please install docker-buildx"
fi

if [ ! "$(pwd)" = "$(git rev-parse --show-toplevel)" ]; then
    echo "Must be called from project root!"
    exit 1
fi

DOCKERFILE_NODE=deployment/Dockerfile-node
: "${NODE_IMAGE_NAME:=mpc-node}"

DOCKERFILE_NODE_GCP=deployment/Dockerfile-node-gcp
: "${NODE_GCP_IMAGE_NAME:=mpc-node-gcp}"

DOCKERFILE_RUST_LAUNCHER=deployment/Dockerfile-rust-launcher
: "${RUST_LAUNCHER_IMAGE_NAME:=mpc-rust-launcher}"


SOURCE_DATE_EPOCH=0
GIT_COMMIT_HASH=$(git rev-parse HEAD)

# This might be necessary to fix reproducibility with old docker versions where
# rewrite-timestamp is not working as expected
# https://github.com/moby/buildkit/issues/4986
find . \( -type f -o -type d \) -exec touch -d @"$SOURCE_DATE_EPOCH" {} +

# Create our own builder (build env) to enable reproducible images

buildkit_version="0.27.1"
buildkit_image_name="buildkit_${buildkit_version}"

if ! docker buildx inspect ${buildkit_image_name} &>/dev/null; then
    docker buildx create --use --driver-opt image=moby/buildkit:v${buildkit_version} --name ${buildkit_image_name}
else
    # A reused builder may hold a stale local-context cache: buildkit keys
    # context changes on (size, mtime), but the touch above resets mtime, so a
    # changed file with unchanged size looks identical and the stale copy is
    # reused. Prune only type=source.local to force a fresh read (base-image and
    # apt caches are kept). A freshly created builder has no cache, so we only
    # prune when reusing one. `|| true`: the builder's container is bootstrapped
    # lazily on first build and may not exist yet, leaving nothing to prune.
    docker buildx prune --builder "${buildkit_image_name}" --filter type=source.local -f >/dev/null 2>&1 || true
fi


# Build a reproducible image to a docker-archive tar, then load it into the
# docker daemon. skopeo computes the manifest digest from the tar (not via the
# docker-daemon transport), so a host daemon whose API is incompatible with the
# skopeo version can't affect reproducibility. The daemon load is only for
# downstream consumers (`docker run`, runtime checks) that need the image there.
build_reproducible_image() {
  local image_name=$1
  local dockerfile_path=$2
  local tar_path=$3
  docker buildx build --builder "${buildkit_image_name}" --no-cache \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    --output "type=docker,name=$image_name,dest=$tar_path,rewrite-timestamp=true" \
    --progress plain -f "$dockerfile_path" .
  docker load -i "$tar_path"
}

# Compress a built image tar via skopeo to a temp directory.
# Prints the temp dir path to stdout. The manifest digest can be
# computed from $dir/manifest.json.
skopeo_compress() {
    local tar_path="$1"
    local td
    td=$(mktemp -d)
    # Compress the image to a local directory, which implicitly computes
    # the manifest digest in $td/manifest.json
    skopeo copy --all --dest-compress "docker-archive:${tar_path}" "dir:$td" >&2
    echo "$td"
}

manifest_digest_from_dir() {
    echo "sha256:$(sha256sum "$1/manifest.json" | cut -d' ' -f1)"
}

if $USE_RUST_LAUNCHER; then
    SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH repro-env build --env SOURCE_DATE_EPOCH -- cargo build -p tee-launcher --profile reproducible --locked
    rust_launcher_binary_hash=$(sha256sum target/reproducible/tee-launcher | cut -d' ' -f1)

    rust_launcher_tar="$(mktemp --suffix=.tar)"
    build_reproducible_image "$RUST_LAUNCHER_IMAGE_NAME" "$DOCKERFILE_RUST_LAUNCHER" "$rust_launcher_tar"
    rust_launcher_skopeo_dir="$(skopeo_compress "$rust_launcher_tar")"
    rust_launcher_manifest_digest="$(manifest_digest_from_dir "$rust_launcher_skopeo_dir")"
fi

if $USE_NODE || $USE_NODE_GCP; then
    # Pin jemalloc's `./configure` auto-detected values so tikv-jemalloc-sys
    # produces identical bytes across builders. See nix/mpc-node.nix for the
    # full rationale; values match the standard x86_64 Linux ABI.
    #
    # GIT_CEILING_DIRECTORIES stops jemalloc's `./configure` from walking out
    # of `target/` and finding the surrounding mpc repo's `.git/` — without
    # it, `git describe HEAD` returns mpc's commit SHA, which is then baked
    # into jemalloc's VERSION file (and the linked binary's `.rodata` and
    # `smallocx_<sha>` exported symbol). The path is the in-container
    # workspace mount (`/build`), not the host path.
    # Pin the C/C++ ISA for cc-crate dependencies (rocksdb, snappy, zstd,
    # jemalloc, ...) to match the rustc target-cpu set in .cargo/config.toml.
    # Without this, the cc crate uses the container's default `-march`, which
    # would diverge from the Rust code's ISA expectations.
    #
    # PCLMUL and AES are not part of the v3 micro-arch level (per System V
    # psABI) but are universally available on v3-capable hardware. Adding
    # them explicitly keeps rocksdb's PCLMUL-accelerated CRC32C path
    # compiled in. Match nix/mpc-node.nix and flake.nix.
    # BUILT_OVERRIDE_mpc_node_GIT_VERSION pins built's GIT_VERSION so local git
    # tags aren't embedded in the binary (which would break reproducibility).
    SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
    JEMALLOC_SYS_WITH_LG_VADDR=48 \
    JEMALLOC_SYS_WITH_LG_PAGE=12 \
    JEMALLOC_SYS_WITH_LG_HUGEPAGE=21 \
    GIT_CEILING_DIRECTORIES=/build/target \
    BUILT_OVERRIDE_mpc_node_GIT_VERSION="${GIT_COMMIT_HASH:0:7}" \
    CFLAGS="-march=x86-64-v3 -mpclmul -maes" \
    CXXFLAGS="-march=x86-64-v3 -mpclmul -maes" \
    repro-env build \
      --env SOURCE_DATE_EPOCH \
      --env JEMALLOC_SYS_WITH_LG_VADDR \
      --env JEMALLOC_SYS_WITH_LG_PAGE \
      --env JEMALLOC_SYS_WITH_LG_HUGEPAGE \
      --env GIT_CEILING_DIRECTORIES \
      --env BUILT_OVERRIDE_mpc_node_GIT_VERSION \
      --env CFLAGS \
      --env CXXFLAGS \
      -- cargo build -p mpc-node --profile reproducible --locked
    node_binary_hash=$(sha256sum target/reproducible/mpc-node | cut -d' ' -f1)
fi

if $USE_NODE; then
    node_tar="$(mktemp --suffix=.tar)"
    build_reproducible_image "$NODE_IMAGE_NAME" "$DOCKERFILE_NODE" "$node_tar"
    node_skopeo_dir="$(skopeo_compress "$node_tar")"
    node_manifest_digest="$(manifest_digest_from_dir "$node_skopeo_dir")"
fi

if $USE_NODE_GCP; then
    node_gcp_tar="$(mktemp --suffix=.tar)"
    build_reproducible_image "$NODE_GCP_IMAGE_NAME" "$DOCKERFILE_NODE_GCP" "$node_gcp_tar"
    node_gcp_skopeo_dir="$(skopeo_compress "$node_gcp_tar")"
    node_gcp_manifest_digest="$(manifest_digest_from_dir "$node_gcp_skopeo_dir")"
fi

if $USE_PUSH; then
    # This assumes that docker is logged-in dockerhub registry with nearone user

    branch_name=$(git branch --show-current)
    if [ -z "$branch_name" ]; then
        branch_name="detached"
    fi
    sanitized_branch_name="${branch_name//\//-}"

    # Fixed 7-char truncation (not `git rev-parse --short`) so the tag is a
    # pure function of the SHA — the Release workflow computes the same
    # string via `${SHA::7}` when looking up the image to retag.
    short_hash="${GIT_COMMIT_HASH:0:7}"
    image_tag="$sanitized_branch_name-$short_hash"
    echo "Using branch-hash tag: $image_tag"

    # Push from the already-compressed local directory, preserving the manifest digest.
    if $USE_NODE; then
        skopeo copy --preserve-digests "dir:$node_skopeo_dir" "docker://docker.io/nearone/$NODE_IMAGE_NAME:$image_tag"
    fi

    if $USE_NODE_GCP; then
        skopeo copy --preserve-digests "dir:$node_gcp_skopeo_dir" "docker://docker.io/nearone/$NODE_GCP_IMAGE_NAME:$image_tag"
    fi

    if $USE_RUST_LAUNCHER; then
        skopeo copy --preserve-digests "dir:$rust_launcher_skopeo_dir" "docker://docker.io/nearone/$RUST_LAUNCHER_IMAGE_NAME:$image_tag"
    fi
fi

echo "commit hash: $GIT_COMMIT_HASH"
echo "SOURCE_DATE_EPOCH used: $SOURCE_DATE_EPOCH"
if $USE_NODE || $USE_NODE_GCP; then
    echo "node binary hash: $node_binary_hash"
fi
if $USE_NODE; then
    echo "node manifest digest: $node_manifest_digest"
fi
if $USE_NODE_GCP; then
    echo "node gcp manifest digest: $node_gcp_manifest_digest"
fi
if $USE_RUST_LAUNCHER; then
    echo "rust launcher binary hash: $rust_launcher_binary_hash"
    echo "rust launcher manifest digest: $rust_launcher_manifest_digest"
fi
