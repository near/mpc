use ckd_example_cli::{ckd::run, cli};
use clap::Parser as _;

fn main() {
    let args = cli::Args::parse();
    run(args).unwrap();
}
