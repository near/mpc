# 2025-11-24 mainnet upgrade guide
These are the commands we need to run to upgrade nodes running `2.2.1` to `3.0.3`.


# Prerequisites
The `nearone/mpc-node-gcp:mainnet-release` image must point to the `3.0.4` release.
All nodes must be running the `2.2.1` release.


# Step 1: Verify the right versions are running
Verify the image ID of the `mpc-node-gcp` image.
```shell
docker images
```

Which should output roughly the following
```
REPOSITORY              TAG               IMAGE ID       CREATED       SIZE
nearone/mpc-node-gcp    mainnet-release   3fb7ddd28233   6 days ago    3.82GB
```

Next, ensure you have the `secrets.json` file set.

First, exec into the docker container:
```shell
docker exec -it mpc-node bash
```

Then in the container run
```shell
ls /data/ | grep secrets.json
```

and verify the file is being outputted.

# Step 2: Update the config
Same as in testnet, `3.0.4` requires a few new config values:

* `near_responder_account_id` must be set to the same as `my_near_account_id`.
* `number_of_responder_keys` should be set to 1.
* `migration_web_ui` should be set with the same parameters as `web_ui` and port `8081`.
* `ckd` should be set with the same parameters as `signature`.

```shell
curl -LO https://github.com/near/mpc/releases/download/3.0.3/update_config.sh
```

```shell
bash update_config.sh /data/config.yaml
```

Now you should be able to veirfy the updated config
```shell
cat /data/config.yaml
```

it should look something like this:

```
# Configuration File
my_near_account_id: n1-multichain.testnet
web_ui:
  host: 0.0.0.0
  port: 8080
triple:
  concurrency: 2
  desired_triples_to_buffer: 1000000
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 16
  desired_presignatures_to_buffer: 8192
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: v1.signer-prod.testnet
  port_override: 80
  finality: optimistic
cores: 12
near_responder_account_id: n1-multichain.testnet
number_of_responder_keys: 1
ckd:
  timeout_sec: 60
migration_web_ui:
  host: 0.0.0.0
  port: 8081
```

# Step 3: Update the MPC node
⚠️WARNING ⚠️: This needs to be done in sync. Wait until everone is ready,
then run:

```
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    containrrr/watchtower \
    --run-once
```

# Step 4: Verify the new image is running
Check the `3.0.4` version is running from the metrics

```
curl localhost:8080/metrics | grep mpc_node_build_info
```

Also check if the network is connected and processing signatures:
```
curl localhost:8080/debug/signatures | head -n 20
```

Fingers crossed 🤞.

