pub(crate) const MPC_CONTAINER_NAME: &str = "mpc-node";
pub(crate) const IMAGE_DIGEST_FILE: &str = "/mnt/shared/image-digest.bin";
pub(crate) const DSTACK_UNIX_SOCKET: &str = "/var/run/dstack.sock";
pub(crate) const DSTACK_USER_CONFIG_FILE: &str = "/tapp/user_config";

/// Path on the shared volume where the launcher writes the MPC config and the
/// MPC container reads it.  Both containers mount `shared-volume` at `/mnt/shared`.
pub(crate) const MPC_CONFIG_SHARED_PATH: &str = "/mnt/shared/mpc-config.toml";
