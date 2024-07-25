use clap::Parser;
use mpc_node::cli::Cli;

fn main() -> anyhow::Result<()> {
    mpc_node::cli::run(Cli::parse())
}
