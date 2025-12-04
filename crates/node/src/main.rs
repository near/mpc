use clap::Parser;
use mpc_node::cli;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL_ALLOCATOR: Jemalloc = Jemalloc;

fn main() -> anyhow::Result<()> {
    // Handle version flags before parsing CLI
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        println!("{}", *mpc_node::MPC_VERSION_STRING);
        return Ok(());
    }

    let cli = cli::Cli::parse();

    mpc_node::metrics::init_build_info_metric();
    mpc_node::tracing::init_logging(cli.log_format);
    futures::executor::block_on(cli.run())
}
