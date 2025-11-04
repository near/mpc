use near_primitives::types::AccountId;

#[derive(clap::Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    /// Home directory for storing backup service secrets and configuration.
    #[arg(long, env("BACKUP_HOME_DIR"))]
    pub home_dir: String,
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Generate new backup service keys (p2p_private_key and near_signer_key) and save to secrets.json.
    GenerateKeys(GenerateKeysArgs),
    /// Print the NEAR CLI command to register the backup service on the MPC contract.
    Register(RegisterArgs),
    /// Get keyshares from an MPC node and save them locally.
    GetKeyshares(GetKeysharesArgs),
    /// Put keyshares to an MPC node from local storage.
    PutKeyshares(PutKeysharesArgs),
}

#[derive(clap::Args, Debug)]
pub struct GenerateKeysArgs {}

#[derive(clap::Args, Debug)]
pub struct RegisterArgs {
    /// MPC contract account ID.
    #[arg(long, env)]
    pub mpc_contract_account_id: AccountId,

    /// NEAR network config name (e.g., testnet, mainnet, mpc-localnet).
    /// This will be used directly in the NEAR CLI command.
    #[arg(long, env)]
    pub near_network: String,

    /// Named account that will sign the registration transaction (e.g., sam.test.near).
    /// This is the operator's account that has permission to register backup services.
    #[arg(long, env)]
    pub signer_account_id: AccountId,
}

#[derive(clap::Args, Debug)]
pub struct GetKeysharesArgs {
    /// URL of the MPC node to retrieve keyshares from.
    #[arg(long, env)]
    pub mpc_node_url: String,
    /// P2P public key of the MPC node for authentication.
    #[arg(long, env)]
    pub mpc_node_p2p_key: String,

    #[arg(long, env)]
    pub backup_encryption_key: String,
}

#[derive(clap::Args, Debug)]
pub struct PutKeysharesArgs {
    /// URL of the MPC node to upload keyshares to.
    #[arg(long, env)]
    pub mpc_node_url: String,
    /// P2P public key of the MPC node for authentication.
    #[arg(long, env)]
    pub mpc_node_p2p_key: String,
    #[arg(long, env)]
    pub backup_encryption_key: String,
}
