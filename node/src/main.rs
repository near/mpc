use clap::Parser;
use mpc_node::build_info::MPC_VERSION_STRING;
use mpc_node::cli;

fn main() -> anyhow::Result<()> {
    // Handle version flags before parsing CLI
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        println!("{}", *MPC_VERSION_STRING);
        return Ok(());
    }

    let cli = cli::Cli::parse();
    mpc_node::tracing::init_logging(cli.log_format);
    // Initialize build info metric
    mpc_node::metrics::init_build_info_metric();
    futures::executor::block_on(cli.run())
}
