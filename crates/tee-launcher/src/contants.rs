pub(crate) const MPC_CONTAINER_NAME: &str = "mpc-node";
pub(crate) const IMAGE_DIGEST_FILE: &str = "/mnt/shared/image-digest.bin";
pub(crate) const DSTACK_UNIX_SOCKET: &str = "/var/run/dstack.sock";
pub(crate) const DSTACK_USER_CONFIG_FILE: &str = "/tapp/user_config";

pub(crate) const SHA256_PREFIX: &str = "sha256:";

// Docker Hub defaults
pub(crate) const DEFAULT_RPC_REQUEST_TIMEOUT_SECS: f64 = 10.0;
pub(crate) const DEFAULT_RPC_REQUEST_INTERVAL_SECS: f64 = 1.0;
pub(crate) const DEFAULT_RPC_MAX_ATTEMPTS: u32 = 20;

pub(crate) const DEFAULT_MPC_IMAGE_NAME: &str = "nearone/mpc-node";
pub(crate) const DEFAULT_MPC_REGISTRY: &str = "registry.hub.docker.com";
pub(crate) const DEFAULT_MPC_IMAGE_TAG: &str = "latest";

// Env var names
pub(crate) const ENV_VAR_PLATFORM: &str = "PLATFORM";
pub(crate) const ENV_VAR_DEFAULT_IMAGE_DIGEST: &str = "DEFAULT_IMAGE_DIGEST";
pub(crate) const ENV_VAR_DOCKER_CONTENT_TRUST: &str = "DOCKER_CONTENT_TRUST";
pub(crate) const ENV_VAR_MPC_HASH_OVERRIDE: &str = "MPC_HASH_OVERRIDE";
pub(crate) const ENV_VAR_RPC_REQUEST_TIMEOUT_SECS: &str = "RPC_REQUEST_TIMEOUT_SECS";
pub(crate) const ENV_VAR_RPC_REQUEST_INTERVAL_SECS: &str = "RPC_REQUEST_INTERVAL_SECS";
pub(crate) const ENV_VAR_RPC_MAX_ATTEMPTS: &str = "RPC_MAX_ATTEMPTS";

pub(crate) const DSTACK_USER_CONFIG_MPC_IMAGE_TAGS: &str = "MPC_IMAGE_TAGS";
pub(crate) const DSTACK_USER_CONFIG_MPC_IMAGE_NAME: &str = "MPC_IMAGE_NAME";
pub(crate) const DSTACK_USER_CONFIG_MPC_IMAGE_REGISTRY: &str = "MPC_REGISTRY";

// Security limits
pub(crate) const MAX_PASSTHROUGH_ENV_VARS: usize = 64;
pub(crate) const MAX_ENV_VALUE_LEN: usize = 1024;
pub(crate) const MAX_TOTAL_ENV_BYTES: usize = 32 * 1024;
