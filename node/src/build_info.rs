use std::sync::LazyLock;

pub static MPC_VERSION: &str = env!("MPC_VERSION");
pub static MPC_BUILD_TIME: &str = env!("MPC_BUILD_TIME");
pub static MPC_COMMIT: &str = env!("MPC_COMMIT");
pub static RUSTC_VERSION: &str = env!("MPC_RUSTC_VERSION");

pub static MPC_VERSION_STRING: LazyLock<String> = LazyLock::new(|| {
    format!(
        "mpc-node {}\n(release {}) (build_time {}) (commit {}) (rustc {})",
        MPC_VERSION, MPC_VERSION, MPC_BUILD_TIME, MPC_COMMIT, RUSTC_VERSION,
    )
}); 