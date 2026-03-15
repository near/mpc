pub(crate) const MPC_CONTAINER_NAME: &str = "mpc-node";
pub(crate) const IMAGE_DIGEST_FILE: &str = "/mnt/shared/image-digest.bin";
pub(crate) const DSTACK_UNIX_SOCKET: &str = "/var/run/dstack.sock";
pub(crate) const DSTACK_USER_CONFIG_FILE: &str = "/tapp/user_config";

/// Path inside the container where the MPC config file is bind-mounted.
pub(crate) const MPC_CONFIG_CONTAINER_PATH: &str = "/tmp/mpc-config.toml";
