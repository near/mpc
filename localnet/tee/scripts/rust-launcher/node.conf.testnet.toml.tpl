[launcher_config]
image_reference = "${MPC_IMAGE}"
pull_max_retries = 5
pull_retry_interval_secs = 2
pull_max_delay_secs = 60
port_mappings = [
${PORTS_TOML}]

[mpc_node_config]
home_dir = "/data"

[mpc_node_config.log]
format = "plain"
filter = "info"

[mpc_node_config.near_init]
chain_id = "testnet"
boot_nodes = "${NEAR_BOOT_NODES}"
download_genesis = true
download_config = "rpc"
tier3_public_addr = "${TIER3_PUBLIC_ADDR:?TIER3_PUBLIC_ADDR must be set; deploy-tee-cluster.sh sets it from MODE=testnet}"
external_storage_fallback_threshold = ${EXTERNAL_STORAGE_FALLBACK_THRESHOLD:?EXTERNAL_STORAGE_FALLBACK_THRESHOLD must be set; deploy-tee-cluster.sh defaults it to 100}

[mpc_node_config.secrets]
secret_store_key_hex = "${MPC_SECRET_STORE_KEY}"
backup_encryption_key_hex = "0000000000000000000000000000000000000000000000000000000000000000"

[mpc_node_config.node]
my_near_account_id = "${MPC_ACCOUNT_ID}"
near_responder_account_id = "${MPC_ACCOUNT_ID}"
number_of_responder_keys = 1
web_ui = "0.0.0.0:8080"
migration_web_ui = "0.0.0.0:8078"
cores = 4

[mpc_node_config.node.indexer]
validate_genesis = false
sync_mode = "Latest"
concurrency = 1
mpc_contract_id = "${MPC_CONTRACT_ID}"
finality = "optimistic"

[mpc_node_config.node.triple]
concurrency = 2
desired_triples_to_buffer = 128
timeout_sec = 60
parallel_triple_generation_stagger_time_sec = 1

[mpc_node_config.node.presignature]
concurrency = 4
desired_presignatures_to_buffer = 64
timeout_sec = 60

[mpc_node_config.node.signature]
timeout_sec = 60

[mpc_node_config.node.ckd]
timeout_sec = 60
