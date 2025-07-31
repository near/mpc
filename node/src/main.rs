use clap::Parser;
use mpc_node::cli;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    mpc_node::tracing::init_logging(cli.log_format);
    futures::executor::block_on(cli.run())
}
