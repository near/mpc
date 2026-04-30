# Reproducible-build image for the MPC contract.
#
# Extends the upstream sourcescan/cargo-near image with the standalone
# `wasm-opt` binary (binaryen). cargo-near's bundled wasm-opt only exposes
# a `--no-wasmopt` toggle and is hard-coded to `-O`; we want `-Oz` for
# maximum size reduction, which requires invoking wasm-opt ourselves from
# `container_build_command`. The base image has no wasm-opt on PATH, so we
# install binaryen here and pin both the base digest and the apt version
# so the image is deterministic.

FROM sourcescan/cargo-near@sha256:1784ca6310f3496f0048356ce420921c8f5fdf71ee8124d43a2e1ceb1f70db8a

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends binaryen=120-4 \
 && rm -rf /var/lib/apt/lists/*
USER near
