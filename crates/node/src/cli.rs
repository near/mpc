use crate::{
    config::{load_config_file, start::NearInitConfigExt},
    run::run_mpc_node,
};
use clap::{Args, Parser, Subcommand};
use launcher_interface::types::{TeeAuthorityConfig, TeeConfig};
use mpc_node_config::{
    ChainId, ConfigFile, DownloadConfigType, LogConfig, LogFormat, NearInitConfig,
    SecretsStartConfig, StartConfig,
};
use mpc_primitives::hash::NodeImageHash;
use std::path::PathBuf;

const DUMMY_ALLOWED_HASH: NodeImageHash = NodeImageHash::new([0; 32]);
const ALLOWED_IMAGE_HASHES_FILE_PATH: &str = "/tmp/allowed_image_hashes.json";
#[derive(Parser, Debug)]
#[command(name = "mpc-node")]
#[command(about = "MPC Node for Near Protocol")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Cli {
    #[arg(long, value_enum, env("MPC_LOG_FORMAT"), default_value = "plain")]
    pub log_format: LogFormat,
    #[clap(subcommand)]
    pub command: CliCommand,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    /// Starts the MPC node using a single TOML configuration file instead of
    /// environment variables and CLI flags.
    StartWithConfigFile {
        /// Path to a TOML configuration file containing all settings needed to
        /// start the MPC node.
        config_path: PathBuf,
    },
    Start(StartCmd),
    /// Generates/downloads required files for Near node to run
    Init(InitConfigArgs),
}
#[derive(Args, Debug)]
pub struct StartCmd {
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: PathBuf,
    /// Hex-encoded 16 byte AES key for local storage encryption.
    /// This key should come from a secure secret storage.
    #[arg(env("MPC_SECRET_STORE_KEY"))]
    pub secret_store_key_hex: String,
    /// TEE related configuration settings.
    #[command(flatten)]
    pub image_hash_config: CliImageHashConfig,
    /// Hex-encoded 32 byte AES key for backup encryption.
    #[arg(env("MPC_BACKUP_ENCRYPTION_KEY_HEX"))]
    pub backup_encryption_key_hex: Option<String>,
}

#[derive(Args, Debug)]
pub struct CliImageHashConfig {
    #[arg(
        long,
        env("MPC_IMAGE_HASH"),
        help_heading = "Hex representation of the hash of the image running. Only required if running in TEE."
    )]
    pub image_hash: Option<String>,
    #[arg(
        long,
        env("MPC_LATEST_ALLOWED_HASH_FILE"),
        help_heading = "Path to the file which the mpc node will write the latest allowed hash to. If not set, assumes running outside of TEE and skips image hash monitoring."
    )]
    pub latest_allowed_hash_file: Option<PathBuf>,
}

impl StartCmd {
    fn into_start_config(self, config: ConfigFile, log_format: LogFormat) -> StartConfig {
        StartConfig {
            home_dir: self.home_dir,
            secrets: SecretsStartConfig {
                secret_store_key_hex: self.secret_store_key_hex,
                backup_encryption_key_hex: self.backup_encryption_key_hex,
            },
            near_init: None,
            node: config,
            // dstack and TEE is not supported with StartCmd, as it will be removed
            // in #2334, and not used by the rust launcher.
            tee: TeeConfig {
                authority: TeeAuthorityConfig::Local,
                // Use dummy values as we don't want a breaking change, and
                // this start command will be deprecated in #2334
                image_hash: DUMMY_ALLOWED_HASH.into(),
                latest_allowed_hash_file_path: ALLOWED_IMAGE_HASHES_FILE_PATH
                    .parse()
                    .expect("dummy allowed image hashes is valid path"),
            },

            log: LogConfig {
                format: log_format,
                filter: std::env::var("RUST_LOG").ok(),
            },
            pccs_endpoints: mpc_node_config::default_pccs_endpoints(),
        }
    }
}
#[derive(Args, Debug)]
pub struct InitConfigArgs {
    #[arg(long, env("MPC_HOME_DIR"))]
    pub dir: std::path::PathBuf,
    /// chain/network id (localnet, testnet, devnet, betanet)
    #[arg(long)]
    pub chain_id: Option<String>,
    /// Genesis file to use when initialize testnet (including downloading)
    #[arg(long)]
    pub genesis: Option<String>,
    /// Download the verified NEAR config file automatically.
    #[arg(long)]
    pub download_config: bool,
    #[arg(long)]
    pub download_config_url: Option<String>,
    /// Download the verified NEAR genesis file automatically.
    #[arg(long)]
    pub download_genesis: bool,
    /// Specify a custom download URL for the genesis-file.
    #[arg(long)]
    pub download_genesis_url: Option<String>,
    #[arg(long)]
    pub download_genesis_records_url: Option<String>,
    #[arg(long)]
    pub boot_nodes: Option<String>,
}

impl InitConfigArgs {
    pub fn into_near_init_config(self) -> NearInitConfig {
        NearInitConfig {
            chain_id: match self.chain_id.as_deref() {
                Some("mainnet") => ChainId::Mainnet,
                Some("testnet") => ChainId::Testnet,
                Some("mpc-localnet") => ChainId::Localnet,
                Some(other) => ChainId::Custom(other.to_string()),
                None => ChainId::Custom(String::new()),
            },
            boot_nodes: self.boot_nodes,
            genesis_path: self.genesis.map(PathBuf::from),
            download_config: if self.download_config {
                Some(DownloadConfigType::RPC)
            } else {
                None
            },
            download_config_url: if self.download_config {
                self.download_config_url
            } else {
                None
            },
            download_genesis: self.download_genesis,
            download_genesis_url: self.download_genesis_url,
            download_genesis_records_url: self.download_genesis_records_url,
            rpc_addr: None,
            network_addr: None,
            tier3_public_addr: None,
        }
    }
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self.command {
            CliCommand::StartWithConfigFile { config_path } => {
                let node_configuration = StartConfig::from_toml_file(&config_path)?;
                run_mpc_node(node_configuration).await
            }
            // TODO(#2334): deprecate this
            CliCommand::Start(start) => {
                let home_dir = std::path::Path::new(&start.home_dir);
                let config_file = load_config_file(home_dir)?;

                let node_configuration = start.into_start_config(config_file, self.log_format);
                run_mpc_node(node_configuration).await
            }
            CliCommand::Init(config) => {
                let dir = config.dir.clone();
                let near_init = config.into_near_init_config();
                near_init.run_init(&dir)
            }
        }
    }
}
