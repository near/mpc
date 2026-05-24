use anyhow::Context;
use launcher_interface::types::{PccsEndpointConfig, TeeAuthorityConfig, TeeConfig};
use mpc_node_config::{ConfigFile, DownloadConfigType, NearInitConfig, StartConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use std::path::Path;
use tee_authority::tee_authority::{
    validate_pccs_endpoints, DstackTeeAuthorityConfig, LocalTeeAuthorityConfig, TeeAuthority,
};

pub trait TeeAuthorityImpl {
    fn into_tee_authority(
        self,
        pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
    ) -> anyhow::Result<TeeAuthority>;
}

impl TeeAuthorityImpl for TeeConfig {
    fn into_tee_authority(
        self,
        pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
    ) -> anyhow::Result<TeeAuthority> {
        validate_pccs_endpoints(&pccs_endpoints)?;
        Ok(match self.authority {
            TeeAuthorityConfig::Local => LocalTeeAuthorityConfig::default().into(),
            TeeAuthorityConfig::Dstack { dstack_endpoint } => {
                DstackTeeAuthorityConfig::new(dstack_endpoint, pccs_endpoints).into()
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

    let contract_id = node_config.indexer.mpc_contract_id.to_string();
    apply_near_config_patches(&mut config, near_init, &contract_id);

    let patched =
        serde_json::to_string_pretty(&config).context("failed to re-serialize NEAR config.json")?;
    std::fs::write(config_path, patched)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    tracing::info!("NEAR node config.json patched successfully");
    Ok(())
}

/// Pure JSON-manipulation half of [`patch_near_config`], extracted so it can
/// be unit-tested without filesystem I/O or constructing a full `ConfigFile`.
fn apply_near_config_patches(
    config: &mut serde_json::Value,
    near_init: &NearInitConfig,
    mpc_contract_id: &str,
) {
    config["store"]["load_mem_tries_for_tracked_shards"] = serde_json::Value::Bool(true);

    if near_init.chain_id.is_localnet() {
        config["state_sync_enabled"] = serde_json::Value::Bool(false);
    } else {
        let storage_fallback_threshold = near_init.external_storage_fallback_threshold.unwrap_or(0);
        config["state_sync"]["sync"]["ExternalStorage"]["external_storage_fallback_threshold"] =
            serde_json::json!(storage_fallback_threshold);
    }

    // Track the shard that hosts the MPC contract.
    config["tracked_shards_config"] = serde_json::json!({ "Accounts": [mpc_contract_id] });

    // Override listen addresses when running multiple nodes on one machine.
    if let Some(rpc_addr) = &near_init.rpc_addr {
        config["rpc"]["addr"] = serde_json::Value::String(rpc_addr.to_string());
    }
    if let Some(network_addr) = &near_init.network_addr {
        config["network"]["addr"] = serde_json::Value::String(network_addr.to_string());
    }
    if let Some(tier3) = &near_init.tier3_public_addr {
        config["network"]["experimental"]["tier3_public_addr"] =
            serde_json::Value::String(tier3.to_string());
    }
}

#[cfg(test)]
#[expect(non_snake_case)] // tests follow `<system_under_test>__should_<assertion>` convention
mod tests {
    use super::*;
    use mpc_node_config::ChainId;

    fn near_init(chain_id: ChainId) -> NearInitConfig {
        NearInitConfig {
            chain_id,
            boot_nodes: None,
            genesis_path: None,
            download_config: None,
            download_config_url: None,
            download_genesis: false,
            download_genesis_url: None,
            download_genesis_records_url: None,
            rpc_addr: None,
            network_addr: None,
            tier3_public_addr: None,
            external_storage_fallback_threshold: None,
        }
    }

    fn empty_config_json() -> serde_json::Value {
        serde_json::json!({
            "store": {},
            "network": {},
            "rpc": {},
            "state_sync": { "sync": { "ExternalStorage": {} } }
        })
    }

    #[test]
    fn apply_near_config_patches__should_set_load_mem_tries() {
        // Given
        let mut config = empty_config_json();
        let init = near_init(ChainId::Testnet);

        // When
        apply_near_config_patches(&mut config, &init, "v1.signer-prod.testnet");

        // Then
        assert_eq!(
            config["store"]["load_mem_tries_for_tracked_shards"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn apply_near_config_patches__should_set_tracked_shards_to_contract_account() {
        // Given
        let mut config = empty_config_json();
        let init = near_init(ChainId::Testnet);

        // When
        apply_near_config_patches(&mut config, &init, "v1.signer-prod.testnet");

        // Then
        assert_eq!(
            config["tracked_shards_config"],
            serde_json::json!({ "Accounts": ["v1.signer-prod.testnet"] })
        );
    }

    #[test]
    fn apply_near_config_patches__should_set_network_and_rpc_addr_when_provided() {
        // Given
        let mut config = empty_config_json();
        let mut init = near_init(ChainId::Testnet);
        init.network_addr = Some("51.68.219.13:24567".parse().unwrap());
        init.rpc_addr = Some("0.0.0.0:13030".parse().unwrap());

        // When
        apply_near_config_patches(&mut config, &init, "v1.signer-prod.testnet");

        // Then
        assert_eq!(
            config["network"]["addr"],
            serde_json::json!("51.68.219.13:24567")
        );
        assert_eq!(config["rpc"]["addr"], serde_json::json!("0.0.0.0:13030"));
    }

    #[test]
    fn apply_near_config_patches__should_preserve_existing_network_and_rpc_addr_when_unset() {
        // Given — pre-populate network/rpc addr so we can prove the function
        // leaves them alone when the operator hasn't set the override.
        let mut config = empty_config_json();
        config["network"]["addr"] = serde_json::json!("downloaded-network-addr:24567");
        config["rpc"]["addr"] = serde_json::json!("downloaded-rpc-addr:3030");
        let init = near_init(ChainId::Testnet);

        // When
        apply_near_config_patches(&mut config, &init, "v1.signer-prod.testnet");

        // Then — sentinels survive (don't-clobber-downloaded-config contract).
        assert_eq!(
            config["network"]["addr"],
            serde_json::json!("downloaded-network-addr:24567")
        );
        assert_eq!(
            config["rpc"]["addr"],
            serde_json::json!("downloaded-rpc-addr:3030")
        );
    }

    #[test]
    fn apply_near_config_patches__should_disable_state_sync_for_localnet() {
        // is_localnet() returns true for both Localnet and Sandbox; cover both
        // so a future split of the variants doesn't silently regress one arm.
        for chain_id in [ChainId::Localnet, ChainId::Sandbox] {
            // Given — pre-populate the threshold with a sentinel so the negative
            // assertion below is meaningful (otherwise the test passes even if
            // the function does nothing).
            let mut config = empty_config_json();
            config["state_sync"]["sync"]["ExternalStorage"]
                ["external_storage_fallback_threshold"] = serde_json::json!(999);
            let init = near_init(chain_id);

            // When
            apply_near_config_patches(&mut config, &init, "mpc-contract.test.near");

            // Then
            assert_eq!(config["state_sync_enabled"], serde_json::json!(false));
            // Localnet branch must not touch the threshold — sentinel survives.
            assert_eq!(
                config["state_sync"]["sync"]["ExternalStorage"]
                    ["external_storage_fallback_threshold"],
                serde_json::json!(999)
            );
        }
    }

    #[test]
    fn apply_near_config_patches__should_set_external_storage_fallback_threshold_for_non_localnet()
    {
        // Given
        let mut config = empty_config_json();
        let init = near_init(ChainId::Testnet);

        // When
        apply_near_config_patches(&mut config, &init, "v1.signer-prod.testnet");

        // Then — non-localnet path writes the historical hardcoded 0.
        assert_eq!(
            config["state_sync"]["sync"]["ExternalStorage"]["external_storage_fallback_threshold"],
            serde_json::json!(0)
        );
    }

    #[test]
    fn apply_near_config_patches__should_set_tier3_public_addr_when_provided() {
        // Given
        let mut config = empty_config_json();
        let mut init = near_init(ChainId::Testnet);
        init.tier3_public_addr = Some("46.105.87.136:24567".parse().unwrap());

        // When
        apply_near_config_patches(&mut config, &init, "v1.signer-prod.testnet");

        // Then
        assert_eq!(
            config["network"]["experimental"]["tier3_public_addr"],
            serde_json::json!("46.105.87.136:24567")
        );
    }

    #[test]
    fn apply_near_config_patches__should_omit_tier3_public_addr_when_unset() {
        // Given
        let mut config = empty_config_json();
        let init = near_init(ChainId::Testnet);

        // When
        apply_near_config_patches(&mut config, &init, "v1.signer-prod.testnet");

        // Then
        assert!(config["network"]["experimental"]
            .get("tier3_public_addr")
            .is_none());
    }

    #[test]
    fn apply_near_config_patches__should_use_configured_fallback_threshold() {
        // Given
        let mut config = empty_config_json();
        let mut init = near_init(ChainId::Testnet);
        init.external_storage_fallback_threshold = Some(1000);

        // When
        apply_near_config_patches(&mut config, &init, "v1.signer-prod.testnet");

        // Then
        assert_eq!(
            config["state_sync"]["sync"]["ExternalStorage"]["external_storage_fallback_threshold"],
            serde_json::json!(1000)
        );
    }
}
