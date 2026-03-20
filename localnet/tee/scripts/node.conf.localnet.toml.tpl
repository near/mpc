[launcher_config]
image_tags = ["${MPC_IMAGE_TAGS}"]
image_name = "${MPC_IMAGE_NAME}"
registry = "${MPC_REGISTRY}"
rpc_request_timeout_secs = 10
rpc_request_interval_secs = 1
rpc_max_attempts = 20

[docker_command_config.port_mappings]
ports = [
${PORTS_TOML}]

[mpc_config]
home_dir = "/data"

[mpc_config.secrets]
secret_store_key_hex = "${MPC_SECRET_STORE_KEY}"
backup_encryption_key_hex = "0000000000000000000000000000000000000000000000000000000000000000"

[mpc_config.tee.authority]
type = "local"

[mpc_config.node]
my_near_account_id = "${MPC_ACCOUNT_ID}"
near_responder_account_id = "${MPC_ACCOUNT_ID}"
number_of_responder_keys = 1
web_ui = "0.0.0.0:8080"
migration_web_ui = "0.0.0.0:8078"
cores = 4

[mpc_config.node.indexer]
validate_genesis = false
sync_mode = "Latest"
concurrency = 1
mpc_contract_id = "${MPC_CONTRACT_ID}"
finality = "optimistic"

[mpc_config.node.triple]
concurrency = 2
desired_triples_to_buffer = 128
timeout_sec = 60
parallel_triple_generation_stagger_time_sec = 1

[mpc_config.node.presignature]
concurrency = 4
desired_presignatures_to_buffer = 64
timeout_sec = 60

[mpc_config.node.signature]
timeout_sec = 60

[mpc_config.node.ckd]
timeout_sec = 60
