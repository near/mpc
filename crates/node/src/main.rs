use clap::Parser;
use mpc_node::cli;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL_ALLOCATOR: Jemalloc = Jemalloc;

fn main() -> anyhow::Result<()> {
    // Install the default rustls crypto provider before any TLS usage.
    // Required because rustls is configured with default-features=false,
    // and indirect consumers like hyper-rustls (via reqwest) call
    // ClientConfig::builder() without an explicit provider.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install default rustls CryptoProvider"))?;

    // Handle version flags before parsing CLI
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        println!("{}", *mpc_node::MPC_VERSION_STRING);
        return Ok(());
    }

    let cli = cli::Cli::parse();

    mpc_node::metrics::init_build_info_metric();
    futures::executor::block_on(cli.run())
}
