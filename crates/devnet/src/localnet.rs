use anyhow::{anyhow, Context, Result};
use std::env;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
// TODO: do not use Document
use toml_edit::{Document, Item, Table};

use crate::cli::{MpcDeployContractCmd, NewMpcNetworkCmd};
use crate::types::ParsedConfig;

fn near_home_dir() -> Result<PathBuf> {
    let home = env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| anyhow!("HOME environment variable not set"))?;

    Ok(home.join(".near/mpc-localnet"))
}
#[derive(clap::Parser)]
pub struct RunLocalnet {}

impl RunLocalnet {
    pub async fn run(&self, name: &str, config: ParsedConfig) -> Result<()> {
        let near_home = near_home_dir()?;

        if !config_exists(&near_home) {
            println!("No localnet config found, initializing…");
            init_localnet(&near_home)?;
            copy_localnet_config(&near_home)?;
        } else {
            println!(
                "Existing localnet config found at {}, skipping init",
                near_home.display()
            );
        }
        let _localnet = start_localnet(&near_home)?;

        // Optional: wait until RPC is up
        wait_for_neard()?;

        println!("Local NEAR network is running.");
        println!("Press Ctrl-C to stop.");

        ensure_mpc_localnet_network_config()?;
        // TODO: remove "SSD" flag?
        let new_network_cmd = NewMpcNetworkCmd {
            num_participants: 3,
            near_per_account: 1,
            num_responding_access_keys: 0,
            near_per_responding_account: 0,
            ssd: false,
        };
        new_network_cmd.run(name, config).await;
        // Block until Ctrl-C
        wait_for_ctrl_c();

        Ok(())
    }
}

use std::time::{Duration, Instant};

fn wait_for_neard() -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);

    while Instant::now() < deadline {
        if std::net::TcpStream::connect("127.0.0.1:3030").is_ok() {
            println!("NEAR localnet is up and responding");
            // TODO: print response
            return Ok(());
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    Err(anyhow::anyhow!(
        "Timed out waiting for NEAR localnet to become ready"
    ))
}

fn wait_for_ctrl_c() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn config_exists(near_home: &Path) -> bool {
    near_home.join("config.json").exists()
}

fn init_localnet(near_home: &Path) -> Result<()> {
    let status = Command::new("neard")
        .args([
            "--home",
            path_str(near_home)?,
            "init",
            "--chain-id",
            "mpc-localnet",
        ])
        .status()
        .context("Failed to run `neard init`")?;

    if !status.success() {
        return Err(anyhow!("`neard init` failed"));
    }

    Ok(())
}

fn copy_localnet_config(near_home: &Path) -> Result<()> {
    let deployment_localnet = Path::new("deployment/localnet");

    if !deployment_localnet.exists() {
        return Err(anyhow!("deployment/localnet directory does not exist"));
    }

    let status = Command::new("cp")
        .args([
            "-rf",
            path_str(&deployment_localnet.join("."))?,
            path_str(near_home)?,
        ])
        .status()
        .context("Failed to copy localnet configuration")?;

    if !status.success() {
        return Err(anyhow!("Failed to copy localnet config"));
    }

    Ok(())
}

pub struct Localnet {
    child: Child,
}

impl Drop for Localnet {
    fn drop(&mut self) {
        println!("Shutting down NEAR localnet…");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_localnet(near_home: &Path) -> Result<Localnet> {
    let child = start_neard(near_home)?;
    Ok(Localnet { child })
}
fn start_neard(near_home: &Path) -> Result<Child> {
    let log_path = near_home.join("neard.log");

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("Failed to open log file {}", log_path.display()))?;

    println!("Starting NEAR localnet node…");
    println!("Logs: {}", log_path.display());
    println!("Status endpoint: http://localhost:3030/status");

    let child = Command::new("neard")
        .env("NEAR_ENV", "mpc-localnet")
        .args(["--home", path_str(near_home)?, "run"])
        .stdout(Stdio::from(log_file.try_clone()?))
        .stderr(Stdio::from(log_file))
        .spawn()
        .context("Failed to spawn `neard run`")?;

    Ok(child)
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("Invalid UTF-8 path: {}", path.display()))
}

// toml logic
pub fn ensure_mpc_localnet_network_config() -> Result<()> {
    let config_path = cli_config_path()?;

    let mut doc = load_or_create_toml(&config_path)?;

    if network_config_exists(&doc, "mpc-localnet") {
        return Ok(());
    }

    insert_mpc_localnet_config(&mut doc);

    fs::write(&config_path, doc.to_string())
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    Ok(())
}

fn cli_config_path() -> Result<PathBuf> {
    let base = if cfg!(target_os = "macos") {
        dirs::home_dir()
            .context("Could not determine home directory")?
            .join("Library/Application Support")
    } else {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg)
        } else {
            dirs::home_dir()
                .context("Could not determine home directory")?
                .join(".config")
        }
    };

    Ok(base.join("near-cli").join("config.toml"))
}

fn load_or_create_toml(path: &PathBuf) -> Result<Document> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    if path.exists() {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        Ok(contents.parse::<Document>()?)
    } else {
        Ok(Document::new())
    }
}

fn network_config_exists(doc: &Document, network: &str) -> bool {
    doc.get("network_connection")
        .and_then(|n| n.get(network))
        .is_some()
}

fn insert_mpc_localnet_config(doc: &mut Document) {
    let network_table = doc
        .entry("network_connection")
        .or_insert(Item::Table(Table::new()))
        .as_table_mut()
        .expect("network_connection must be a table");

    let mut mpc = Table::new();
    mpc["network_name"] = "mpc-localnet".into();
    mpc["rpc_url"] = "http://localhost:3030/".into();
    mpc["wallet_url"] = "http://localhost:3030/".into();
    mpc["explorer_transaction_url"] = "http://localhost:3030/".into();
    mpc["linkdrop_account_id"] = "test.near".into();

    network_table["mpc-localnet"] = Item::Table(mpc);
}

/* key logic */

use serde::Deserialize;

#[derive(Deserialize)]
struct ValidatorKeyFile {
    account_id: String,
    secret_key: String,
}

use near_crypto::SecretKey;
use near_primitives::types::AccountId;

fn load_localnet_validator_identity() -> Result<(AccountId, SecretKey)> {
    let path = localnet_validator_key_path()?;

    let contents =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;

    let key_file: ValidatorKeyFile =
        serde_json::from_str(&contents).context("Invalid validator_key.json")?;

    let account_id: AccountId = key_file
        .account_id
        .parse()
        .context("Invalid account_id in validator_key.json")?;

    let secret_key: SecretKey = key_file
        .secret_key
        .parse()
        .context("Invalid secret_key in validator_key.json")?;

    Ok((account_id, secret_key))
}

fn localnet_validator_key_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;

    Ok(home.join(".near/mpc-localnet/validator_key.json"))
}

async fn bootstrap_localnet_funding_account(
    client: JsonRpcClient,
    recent_block_hash: CryptoHash,
) -> Result<OperatingAccount> {
    let (account_id, secret_key) = load_localnet_validator_identity()?;

    let signer = InMemorySigner::from_secret_key(account_id.clone(), secret_key);

    Ok(OperatingAccount::new(
        signer.account_id.clone(),
        recent_block_hash,
        client,
    ))
}
