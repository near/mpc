# MPC localnet in docker

Brain dump right now, might clean this up for reproducibility.

# Step 1: Build docker images

```shell
deployment/build-images.sh
```

# Step 2: Start localnet
```shell
neard --home ~/.near/mpc-localnet init --chain-id mpc-localnet
```

```shell
cp -rf $(pwd)/deployment/localnet/. ~/.near/mpc-localnet
```

# Step 3:
Creating frodo and sam accounts as per localnet guide. Now going directly to starting their nodes.

Frodo's node:

```shell
docker run -v /tmp/frodo:/data --env-file docs/localnet/docker_envs/frodo.env mpc-node
```
