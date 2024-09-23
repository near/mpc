use clap::Parser;
use integration_tests_chain_signatures::containers::DockerClient;
use integration_tests_chain_signatures::{run, setup, utils, MultichainConfig};
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
enum Cli {
    /// Spin up dependent services and mpc nodes
    SetupEnv {
        #[arg(short, long, default_value_t = 3)]
        nodes: usize,
        #[arg(short, long, default_value_t = 2)]
        threshold: usize,
    },
    /// Spin up dependent services but not mpc nodes
    DepServices,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(EnvFilter::from_default_env());
    subscriber.init();
    let docker_client = DockerClient::default();

    match Cli::parse() {
        Cli::SetupEnv { nodes, threshold } => {
            println!(
                "Setting up an environment with {} nodes, {} threshold ...",
                nodes, threshold
            );
            let config = MultichainConfig {
                nodes,
                threshold,
                ..Default::default()
            };
            println!("Full config: {:?}", config);
            let nodes = run(config.clone(), &docker_client).await?;
            let ctx = nodes.ctx();
            let urls: Vec<_> = (0..config.nodes).map(|i| nodes.url(i)).collect();
            let near_accounts = nodes.near_accounts();
            let sk_local_path = nodes.ctx().storage_options.sk_share_local_path.clone();

            println!("\nEnvironment is ready:");
            println!("  docker-network: {}", ctx.docker_network);
            println!("  release:        {}", ctx.release);

            println!("\nExternal services:");
            println!("  datastore:     {}", ctx.datastore.local_address);
            println!("  lake_indexer:  {}", ctx.lake_indexer.rpc_host_address);

            println!("\nNodes:");
            for i in 0..urls.len() {
                println!("  Node {}", i);
                println!("    Url: {}", urls[i]);
                let account_id = near_accounts[i].id();
                println!("    Account: {}", account_id);
                let sk = near_accounts[i].secret_key();
                println!("    Secret Key: {}", sk);
                let pk = sk.public_key();
                println!("    Public Key: {}", pk);
            }

            signal::ctrl_c().await.expect("Failed to listen for event");
            println!("Received Ctrl-C");
            utils::clear_local_sk_shares(sk_local_path).await?;
            println!("Clean up finished");
        }
        Cli::DepServices => {
            println!("Settting up dependency services");
            let _ctx = setup(&docker_client).await?;
        }
    }

    Ok(())
}
