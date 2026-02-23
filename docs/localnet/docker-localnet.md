# MPC localnet in docker

Brain dump right now, might clean this up for reproducibility.

# Step 1: Build docker images

```shell
deployment/build-images.sh --node
```

# Step 2: Start localnet
Follow the normal localnet guide to start a neard instance,
create the relevant accounts and deoploy the contract.

Note: Make sure to copy the checked-in localnet configuration before starting neard.
Otherwise the neard node will have a different genesis configuration.
```shell
cp -rf $(pwd)/deployment/localnet/. ~/.near/mpc-localnet
```

# Step 3:
Assuming you've created the frodo and sam accounts as per localnet guide.
We can now start their nodes in docker.

Frodo's node:

```shell
docker run --name frodo-mpc-node -v /tmp/frodo:/data -p 3000:3000 -p 8081:8080 --env-file docs/localnet/docker-envs/frodo.env mpc-node
```

```shell
docker run --name sam-mpc-node -v /tmp/sam:/data -p 3001:3001 -p 8082:8080 --env-file docs/localnet/docker-envs/sam.env mpc-node
```

Great success!!! The dockerfiles seems have connected :)

# Step 4:
Add access keys and initialize the contract as per the localnet guide.
Before creating the initialize args, make sure to set the following
MPC host instead of localhost.

```shell
export MPC_HOST=172.17.0.1
```

Now you should be able to add a domain and request a signature as per the original localnet guide.
