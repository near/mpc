# Reproducible Builds

This project supports reproducible builds for both the node and launcher Docker images. Reproducible builds ensure that the same source code always produces identical binaries, which is important for security and verification purposes.

## Prerequisites

**Common requirements** (for both node and launcher):

- `docker` with buildx support
- `jq`
- `git`

**Additional requirements for building the node image**:

- `repro-env` - Tool for reproducible build environments ([install here](https://github.com/kpcyrd/repro-env))
- `podman`

## Building Images

The build script is located at `deployment/build-images.sh` and must be run from the project root directory.

**Build both node and launcher images** (default behavior):

```bash
./deployment/build-images.sh
```

**Build only the node image**:

```bash
./deployment/build-images.sh --node
```

**Build only the launcher image**:

```bash
./deployment/build-images.sh --launcher
```

The script will output the image hashes and other build information, which can be used to verify the reproducibility of the build.
