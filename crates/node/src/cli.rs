use crate::{
    config::start::NearInitConfigExt,
    keyshare::{
        compat::legacy_ecdsa_key_from_keyshares,
        local::LocalPermanentKeyStorageBackend,
        permanent::{PermanentKeyStorage, PermanentKeyStorageBackend, PermanentKeyshareData},
    },
    run::run_mpc_node,
};
use clap::{Args, Parser, Subcommand};
use hex::FromHex;
use launcher_interface::types::{TeeAuthorityConfig, TeeConfig};
use mpc_node_config::{
    ChainId, ConfigFile, DownloadConfigType, GcpStartConfig, LogConfig, LogFormat, NearInitConfig,
    SecretsStartConfig, StartConfig, load_config_file,
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
    /// Imports a keyshare from JSON and stores it in the local encrypted storage
    ImportKeyshare(ImportKeyshareCmd),
    /// Exports a keyshare from local encrypted storage and prints it to the console
    ExportKeyshare(ExportKeyshareCmd),
}
#[derive(Args, Debug)]
pub struct StartCmd {
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: PathBuf,
    /// Hex-encoded 16 byte AES key for local storage encryption.
    /// This key should come from a secure secret storage.
    #[arg(env("MPC_SECRET_STORE_KEY"))]
    pub secret_store_key_hex: String,
    /// If provided, the root keyshare is stored on GCP.
    /// This requires GCP_PROJECT_ID to be set as well.
    #[arg(env("GCP_KEYSHARE_SECRET_ID"))]
    pub gcp_keyshare_secret_id: Option<String>,
    #[arg(env("GCP_PROJECT_ID"))]
    pub gcp_project_id: Option<String>,
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
        let gcp = match (self.gcp_keyshare_secret_id, self.gcp_project_id) {
            (Some(keyshare_secret_id), Some(project_id)) => Some(GcpStartConfig {
                keyshare_secret_id,
                project_id,
            }),
            _ => None,
        };
        StartConfig {
            home_dir: self.home_dir.clone(),
            secrets: SecretsStartConfig {
                secret_store_key_hex: self.secret_store_key_hex,
                backup_encryption_key_hex: self.backup_encryption_key_hex,
            },
            near_init: None,
            gcp,
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
                log_dir: Some(self.home_dir),
                max_log_files: Some(100),
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

#[derive(Args, Debug)]
pub struct ImportKeyshareCmd {
    /// Path to home directory
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: String,

    /// JSON string containing the keyshare to import
    #[arg(
        help = "JSON string with the keyshare in format: {\"epoch\":1,\"private_share\":\"...\",\"public_key\":\"...\"}"
    )]
    pub keyshare_json: String,

    /// Hex-encoded 16 byte AES key for local storage encryption
    #[arg(help = "Hex-encoded 16 byte AES key for local storage encryption")]
    pub local_encryption_key_hex: String,
}

#[derive(Args, Debug)]
pub struct ExportKeyshareCmd {
    /// Path to home directory
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: String,

    /// Hex-encoded 16 byte AES key for local storage encryption
    #[arg(help = "Hex-encoded 16 byte AES key for local storage encryption")]
    pub local_encryption_key_hex: String,
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
            CliCommand::ImportKeyshare(cmd) => cmd.run().await,
            CliCommand::ExportKeyshare(cmd) => cmd.run().await,
        }
    }
}
impl ImportKeyshareCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            println!("Importing keyshare to local storage...");

            // Parse the encryption key
            let encryption_key_bytes = <[u8; 16]>::from_hex(&self.local_encryption_key_hex)
                .map_err(|_| {
                    anyhow::anyhow!("Invalid encryption key: must be 32 hex characters (16 bytes)")
                })?;

            let keyshare: PermanentKeyshareData = serde_json::from_str(&self.keyshare_json)
                .map_err(|e| anyhow::anyhow!("Failed to parse keyshare JSON: {}", e))?;

            println!("Parsed keyshare for epoch {}", keyshare.epoch_id());

            // Create the local storage and store the keyshare
            let home_dir = PathBuf::from(&self.home_dir);

            // Ensure the directory exists
            if !home_dir.exists() {
                std::fs::create_dir_all(&home_dir).map_err(|e| {
                    anyhow::anyhow!("Failed to create directory {}: {}", home_dir.display(), e)
                })?;
            }

            let storage =
                LocalPermanentKeyStorageBackend::new(home_dir.clone(), encryption_key_bytes)
                    .await?;

            // Check for existing keyshare
            if storage.load().await?.is_some() {
                anyhow::bail!("Refusing to overwrite existing local keyshare");
            }

            // Store the keyshare
            storage
                .store(&serde_json::to_vec(&keyshare)?, "imported")
                .await?;
            println!("Successfully imported keyshare to {}", home_dir.display());

            Ok(())
        })
    }
}

impl ExportKeyshareCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            println!("Exporting keyshare from local storage...");

            let encryption_key_bytes = <[u8; 16]>::from_hex(&self.local_encryption_key_hex)
                .map_err(|_| {
                    anyhow::anyhow!("Invalid encryption key: must be 32 hex characters (16 bytes)")
                })?;

            // Create the local storage
            let home_dir = PathBuf::from(&self.home_dir);

            // Check if directory exists
            if !home_dir.exists() {
                return Err(anyhow::anyhow!(
                    "Directory {} does not exist",
                    home_dir.display()
                ));
            }

            let storage = PermanentKeyStorage::new(Box::new(
                LocalPermanentKeyStorageBackend::new(home_dir.clone(), encryption_key_bytes)
                    .await?,
            ))
            .await?;

            // Load the keyshare
            let keyshare = storage
                .load()
                .await?
                .ok_or_else(|| anyhow::anyhow!("No keyshare found in {}", home_dir.display()))?;
            let keyshare = legacy_ecdsa_key_from_keyshares(&keyshare.keyshares_vec())?;

            // Print the keyshare to console
            let json = serde_json::to_string_pretty(&keyshare)
                .map_err(|e| anyhow::anyhow!("Failed to serialize keyshare: {}", e))?;

            println!("{}", json);
            println!(
                "\nKeyshare for epoch {} successfully exported.",
                keyshare.epoch
            );

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyshare::permanent::LegacyRootKeyshareData;
    use k256::{AffinePoint, Scalar};
    use tempfile::TempDir;

    // Mock keyshare data for testing
    fn create_test_keyshare_with_epoch(epoch: u64) -> PermanentKeyshareData {
        // Create a dummy private key - this is only for testing
        let private_share = Scalar::ONE;
        // Do some computation to get non-identity public key
        let public_key = AffinePoint::GENERATOR * private_share;

        PermanentKeyshareData::from_legacy(&LegacyRootKeyshareData {
            epoch,
            private_share,
            public_key: public_key.to_affine(),
        })
    }

    fn create_test_keyshare() -> PermanentKeyshareData {
        create_test_keyshare_with_epoch(1)
    }

    #[test]
    fn test_keyshare_import_export() {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new().unwrap();
        let home_dir = temp_dir.path().to_string_lossy().to_string();

        // Create test data
        let keyshare = create_test_keyshare();
        let keyshare_json = serde_json::to_string(&keyshare).unwrap();
        let encryption_key = "0123456789ABCDEF0123456789ABCDEF";

        // Test import functionality
        let import_cmd = ImportKeyshareCmd {
            home_dir: home_dir.clone(),
            keyshare_json,
            local_encryption_key_hex: encryption_key.to_string(),
        };

        let result = futures::executor::block_on(import_cmd.run());
        result.expect("Import command should succeed for valid input");

        // Test export functionality
        let export_cmd = ExportKeyshareCmd {
            home_dir: home_dir.clone(),
            local_encryption_key_hex: encryption_key.to_string(),
        };

        let result = futures::executor::block_on(export_cmd.run());
        result.expect("Export command should succeed after import");

        // Verify the exported data matches what we imported
        // For a more thorough test, we could capture stdout and verify the JSON content
    }

    #[test]
    fn test_import_existing_keyshare_with_lower_epoch() {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new().unwrap();
        let home_dir = temp_dir.path().to_string_lossy().to_string();

        // Create two keyshares with different epochs
        let keyshare1 = create_test_keyshare_with_epoch(2); // Higher epoch
        let keyshare2 = create_test_keyshare_with_epoch(1); // Lower epoch

        let keyshare1_json = serde_json::to_string(&keyshare1).unwrap();
        let keyshare2_json = serde_json::to_string(&keyshare2).unwrap();
        let encryption_key = "0123456789ABCDEF0123456789ABCDEF";

        // Import the first keyshare
        let import_cmd1 = ImportKeyshareCmd {
            home_dir: home_dir.clone(),
            keyshare_json: keyshare1_json,
            local_encryption_key_hex: encryption_key.to_string(),
        };

        let result = futures::executor::block_on(import_cmd1.run());
        assert!(
            result.is_ok(),
            "First import command failed: {:?}",
            result.err()
        );

        // Try to import the second keyshare with lower epoch
        let import_cmd2 = ImportKeyshareCmd {
            home_dir: home_dir.clone(),
            keyshare_json: keyshare2_json,
            local_encryption_key_hex: encryption_key.to_string(),
        };

        let result = futures::executor::block_on(import_cmd2.run());
        assert!(
            result.is_err(),
            "Import command with lower epoch should fail"
        );
    }

    #[test]
    fn test_export_nonexistent_keyshare() {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new().unwrap();
        let home_dir = temp_dir.path().to_string_lossy().to_string();
        let encryption_key = "0123456789ABCDEF0123456789ABCDEF";

        // Parse the export command on an empty directory
        let export_cmd = ExportKeyshareCmd {
            home_dir,
            local_encryption_key_hex: encryption_key.to_string(),
        };

        let result = futures::executor::block_on(export_cmd.run());
        assert!(
            result.is_err(),
            "Export command should fail on nonexistent keyshare"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No keyshare found")
        );
    }
}
