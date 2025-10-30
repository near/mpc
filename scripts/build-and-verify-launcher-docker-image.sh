#! /usr/bin/env bash

./deployment/build-images.sh --launcher
# notice that any change to crates/contract/assets/launcher_docker_compose.yaml.template needs to be reflected here
published_manifest_hash=$(sed -n '5p' crates/contract/assets/launcher_docker_compose.yaml.template | grep -o '@sha256:.*' | cut -c 9-)
temp_dir=$(mktemp -d)
echo "using $temp_dir"
skopeo copy --all --dest-compress docker-daemon:mpc-launcher:latest dir:$temp_dir
expected_manifest_hash=$(sha256sum $temp_dir/manifest.json | cut -d' ' -f1)
if [ "${published_manifest_hash}" == "${expected_manifest_hash}" ]; then
    echo "Launcher docker image hash verified"
else
    echo "Launcher docker image hash verification failed"
    echo "Got: ${published_manifest_hash}"
    echo "Expected: ${expected_manifest_hash}"
    exit 1
fi