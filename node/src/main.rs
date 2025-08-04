use clap::Parser;
use std::sync::LazyLock;
use mpc_node::cli;

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

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    mpc_node::tracing::init_logging(cli.log_format);
    // Initialize build info metric
    mpc_node::metrics::init_build_info_metric();
    // Handle version flags before parsing CLI
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        println!("{}", *MPC_VERSION_STRING);
        return Ok(());
    }
    futures::executor::block_on(cli.run())
}
