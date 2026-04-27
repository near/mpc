use anyhow::Context;
use launcher_interface::types::{PccsTlsTrust, TeeAuthorityConfig, TeeConfig};
use mpc_node_config::{ConfigFile, DownloadConfigType, NearInitConfig, StartConfig};
use std::path::Path;
use tee_authority::tee_authority::{
    validate_pccs_tls_config, DstackTeeAuthorityConfig, LocalTeeAuthorityConfig, TeeAuthority,
};

pub trait TeeAuthorityImpl {
    fn into_tee_authority(
        self,
        pccs_url: url::Url,
        pccs_tls: Option<PccsTlsTrust>,
    ) -> anyhow::Result<TeeAuthority>;
}

impl TeeAuthorityImpl for TeeConfig {
    fn into_tee_authority(
        self,
        pccs_url: url::Url,
        pccs_tls: Option<PccsTlsTrust>,
    ) -> anyhow::Result<TeeAuthority> {
        validate_pccs_tls_config(&pccs_url, pccs_tls.as_ref())?;
        Ok(match self.authority {
            TeeAuthorityConfig::Local => LocalTeeAuthorityConfig::default().into(),
            TeeAuthorityConfig::Dstack { dstack_endpoint } => {
                DstackTeeAuthorityConfig::new(dstack_endpoint, pccs_url, pccs_tls).into()
            }
        })
    }
}

pub trait NearInitConfigExt {
    /// Runs `near_indexer::init_configs` to create the NEAR data directory.
    fn run_init(&self, home_dir: &Path) -> anyhow::Result<()>;
}

impl NearInitConfigExt for NearInitConfig {
    fn run_init(&self, home_dir: &Path) -> anyhow::Result<()> {
        run_near_init(self, home_dir)
    }
}

pub trait StartConfigExt {
    /// Ensures the NEAR node data directory is initialized.
    fn ensure_near_initialized(&self) -> anyhow::Result<()>;
}

impl StartConfigExt for StartConfig {
    fn ensure_near_initialized(&self) -> anyhow::Result<()> {
        let Some(near_init) = &self.near_init else {
            return Ok(());
        };

        let near_config_path = self.home_dir.join("config.json");
        if near_config_path.exists() {
            tracing::info!("NEAR node already initialized, skipping init");
            return Ok(());
        }

        tracing::info!(chain_id = %near_init.chain_id, "initializing NEAR node");
        run_near_init(near_init, &self.home_dir)?;

        // Patch the NEAR node config the same way start.sh does.
        patch_near_config(&near_config_path, near_init, &self.node)?;

        Ok(())
    }
}

/// Runs `near_indexer::init_configs` to create the NEAR data directory.
fn run_near_init(config: &NearInitConfig, home_dir: &Path) -> anyhow::Result<()> {
    let is_localnet = config.chain_id.is_localnet();
    let genesis_arg = config.genesis_path.as_deref().and_then(Path::to_str);
    let chain_id_arg = config.chain_id.to_init_arg();
    let boot_nodes = config.boot_nodes.as_deref();
    let download_config = config.download_config.clone().map(convert_download_config);

    near_indexer::init_configs(
        home_dir,
        chain_id_arg,
        None,
        None,
        1,
        false,
        genesis_arg,
        config.download_genesis,
        config.download_genesis_url.as_deref(),
        config.download_genesis_records_url.as_deref(),
        download_config,
        config.download_config_url.as_deref(),
        boot_nodes,
        None,
        None,
    )
    .context("failed to initialize NEAR node")?;

    // For localnet, overwrite the genesis file with the original (init
    // modifies it) and remove the unnecessary validator_key.json.
    if is_localnet {
        if let Some(genesis_src) = &config.genesis_path {
            let genesis_dst = home_dir.join("genesis.json");
            std::fs::copy(genesis_src, &genesis_dst).with_context(|| {
                format!(
                    "failed to copy genesis from {} to {}",
                    genesis_src.display(),
                    genesis_dst.display()
                )
            })?;
        }
        let validator_key = home_dir.join("validator_key.json");
        if validator_key.exists() {
            std::fs::remove_file(&validator_key).ok();
        }
    }

    Ok(())
}

fn convert_download_config(dt: DownloadConfigType) -> near_config_utils::DownloadConfigType {
    match dt {
        DownloadConfigType::Validator => near_config_utils::DownloadConfigType::Validator,
        DownloadConfigType::RPC => near_config_utils::DownloadConfigType::RPC,
        DownloadConfigType::Archival => near_config_utils::DownloadConfigType::Archival,
    }
}

/// Applies post-init patches to the NEAR node `config.json`, matching the
/// behaviour of `update_near_node_config()` in `start.sh`.
fn patch_near_config(
    config_path: &Path,
    near_init: &NearInitConfig,
    node_config: &ConfigFile,
) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

    // TODO(#2453): Deserialize into the `near_core::Config` type (currently not exported)
    let mut config: serde_json::Value =
        serde_json::from_str(&raw).context("failed to parse NEAR config.json")?;

    config["store"]["load_mem_tries_for_tracked_shards"] = serde_json::Value::Bool(true);

    let is_localnet = near_init.chain_id.is_localnet();
    if is_localnet {
        config["state_sync_enabled"] = serde_json::Value::Bool(false);
    } else {
        config["state_sync"]["sync"]["ExternalStorage"]["external_storage_fallback_threshold"] =
            serde_json::json!(0);
    }

    // Track the shard that hosts the MPC contract.
    let contract_id = node_config.indexer.mpc_contract_id.to_string();
    config["tracked_shards_config"] = serde_json::json!({ "Accounts": [contract_id] });

    // Override listen addresses when running multiple nodes on one machine.
    if let Some(rpc_addr) = &near_init.rpc_addr {
        config["rpc"]["addr"] = serde_json::Value::String(rpc_addr.clone());
    }
    if let Some(network_addr) = &near_init.network_addr {
        config["network"]["addr"] = serde_json::Value::String(network_addr.clone());
    }

    let patched =
        serde_json::to_string_pretty(&config).context("failed to re-serialize NEAR config.json")?;
    std::fs::write(config_path, patched)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    tracing::info!("NEAR node config.json patched successfully");
    Ok(())
}
