use crate::home_paths::near_config_file;
use anyhow::Context;
use launcher_interface::types::{PccsEndpointConfig, TeeAuthorityConfig, TeeConfig};
use mpc_node_config::{ConfigFile, DownloadConfigType, NearInitConfig, StartConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use std::path::Path;
use tee_authority::tee_authority::{
    DstackTeeAuthorityConfig, LocalTeeAuthorityConfig, TeeAuthority, validate_pccs_endpoints,
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

        let near_config_path = near_config_file(&self.home_dir);
        if near_config_path.exists() {
            tracing::info!("NEAR node already initialized, skipping init");
            // TODO(#3801): remove once the fleet is off ExternalStorage state
            // sync (post-3.13.2); this migrates existing configs in place.
            migrate_near_config_state_sync(&near_config_path, near_init)?;
            return Ok(());
        }

        require_tier3_public_addr(near_init)?;

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

/// Decentralized state sync requires the node to advertise a reachable
/// address; without it the node may advertise an unreachable (e.g.
/// NAT/SLIRP-internal) address and state sync stalls silently. Enforced at
/// first init only — existing nodes (whose `config.json` already exists) are
/// grandfathered.
fn require_tier3_public_addr(near_init: &NearInitConfig) -> anyhow::Result<()> {
    if !near_init.chain_id.is_localnet() && near_init.tier3_public_addr.is_none() {
        anyhow::bail!(
            "tier3_public_addr must be set for {} state sync: decentralized state \
             sync needs a reachable advertised IP:24567. Set tier3_public_addr in \
             [mpc_node_config.near_init].",
            near_init.chain_id
        );
    }
    Ok(())
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

    write_near_config_atomic(config_path, &config)?;

    tracing::info!("NEAR node config.json patched successfully");
    Ok(())
}

/// Migrates an existing NEAR `config.json` to decentralized state sync in place:
/// rewrites `state_sync.sync` to `Peers` and (re)applies `tier3_public_addr`,
/// touching only those fields. Runs on every start because nearcore 2.13 rejects
/// the old `ExternalStorage` value on load (the node exits); fresh inits instead
/// get it via [`apply_near_config_patches`]. A no-op once the config carries both.
fn migrate_near_config_state_sync(
    config_path: &Path,
    near_init: &NearInitConfig,
) -> anyhow::Result<()> {
    // Localnet disables state sync entirely, so there is nothing to migrate.
    if near_init.chain_id.is_localnet() {
        return Ok(());
    }

    // Symmetric to start.sh: `Peers` sync stalls silently without a reachable
    // advertised address, so surface when one isn't configured.
    if near_init.tier3_public_addr.is_none() {
        tracing::info!(
            "tier3_public_addr not set; decentralized state sync will rely on auto-detected addresses"
        );
    }

    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let mut config: serde_json::Value =
        serde_json::from_str(&raw).context("failed to parse NEAR config.json")?;

    // Evaluate both so the tier3 fix is not skipped when `state_sync.sync` is
    // already `Peers`.
    let sync_changed = set_decentralized_state_sync(&mut config);
    let tier3_changed = set_tier3_public_addr(&mut config, near_init);
    if !(sync_changed || tier3_changed) {
        return Ok(());
    }

    write_near_config_atomic(config_path, &config)?;

    if sync_changed {
        tracing::info!("migrated NEAR config.json state_sync to decentralized (Peers)");
    }
    if tier3_changed {
        tracing::info!("set NEAR config.json network.experimental.tier3_public_addr");
    }
    Ok(())
}

/// Writes `config` to `config_path` atomically: serialize to a sibling temp file,
/// then rename over the target. The migration runs fleet-wide on the 3.13.2
/// upgrade, and a crash mid-write with a plain `write` could leave a truncated
/// `config.json` that the next start fails to parse.
fn write_near_config_atomic(config_path: &Path, config: &serde_json::Value) -> anyhow::Result<()> {
    let serialized =
        serde_json::to_string_pretty(config).context("failed to re-serialize NEAR config.json")?;
    let file_name = config_path
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("config path has no file name: {}", config_path.display()))?;
    let tmp_path = config_path.with_file_name(format!("{file_name}.tmp"));
    std::fs::write(&tmp_path, serialized)
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, config_path)
        .with_context(|| format!("failed to replace {}", config_path.display()))?;
    Ok(())
}

/// Sets `state_sync.sync` to decentralized (`Peers`), replacing any inherited
/// value. Returns whether the config was changed.
fn set_decentralized_state_sync(config: &mut serde_json::Value) -> bool {
    let peers = serde_json::json!("Peers");
    if config["state_sync"]["sync"] == peers {
        return false;
    }
    config["state_sync"]["sync"] = peers;
    true
}

/// Sets the advertised `tier3_public_addr` when `near_init` provides one (it is
/// required for decentralized state sync to be reachable). No-op when unset.
/// Returns whether the config was changed.
fn set_tier3_public_addr(config: &mut serde_json::Value, near_init: &NearInitConfig) -> bool {
    let Some(tier3) = &near_init.tier3_public_addr else {
        return false;
    };
    let tier3 = serde_json::Value::String(tier3.to_string());
    if config["network"]["experimental"]["tier3_public_addr"] == tier3 {
        return false;
    }
    config["network"]["experimental"]["tier3_public_addr"] = tier3;
    true
}

/// Reads and parses the NEAR node `config.json` under `home_dir`, for serving
/// via the `/debug/nearcore_config` endpoint.
///
/// Panics if the file is missing or malformed: the embedded indexer loads the
/// same file at startup, so it is guaranteed present here.
pub(crate) fn read_near_config_json(home_dir: &Path) -> serde_json::Value {
    let path = near_config_file(home_dir);
    let raw = std::fs::read_to_string(&path).expect("NEAR config.json must be readable");
    serde_json::from_str(&raw).expect("NEAR config.json must be valid JSON")
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
        // Decentralized (peer-to-peer) state sync; replaces any inherited ExternalStorage block.
        set_decentralized_state_sync(config);
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
    set_tier3_public_addr(config, near_init);
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
            // Given — pre-populate sync with a sentinel so the negative
            // assertion below is meaningful (otherwise the test passes even if
            // the function does nothing).
            let mut config = empty_config_json();
            config["state_sync"]["sync"] = serde_json::json!("SENTINEL");
            let init = near_init(chain_id);

            // When
            apply_near_config_patches(&mut config, &init, "mpc-contract.test.near");

            // Then
            assert_eq!(config["state_sync_enabled"], serde_json::json!(false));
            // Localnet branch must not touch sync — sentinel survives.
            assert_eq!(config["state_sync"]["sync"], serde_json::json!("SENTINEL"));
        }
    }

    #[test]
    fn apply_near_config_patches__should_set_sync_to_peers_for_non_localnet() {
        // Given
        let mut config = empty_config_json();
        let init = near_init(ChainId::Testnet);

        // When
        apply_near_config_patches(&mut config, &init, "v1.signer-prod.testnet");

        // Then — non-localnet uses decentralized (peer-to-peer) state sync.
        assert_eq!(config["state_sync"]["sync"], serde_json::json!("Peers"));
    }

    #[test]
    fn apply_near_config_patches__should_replace_external_storage_block_with_peers() {
        // Given — a downloaded config that ships an ExternalStorage block.
        let mut config = empty_config_json();
        config["state_sync"]["sync"] = serde_json::json!({
            "ExternalStorage": {
                "location": { "GCS": { "bucket": "near-state-parts" } },
                "external_storage_fallback_threshold": 3
            }
        });
        let init = near_init(ChainId::Mainnet);

        // When
        apply_near_config_patches(&mut config, &init, "v1.signer");

        // Then — the whole block is replaced by the `Peers` variant.
        assert_eq!(config["state_sync"]["sync"], serde_json::json!("Peers"));
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
        assert!(
            config["network"]["experimental"]
                .get("tier3_public_addr")
                .is_none()
        );
    }

    #[test]
    fn require_tier3_public_addr__should_err_for_non_localnet_when_unset() {
        // Given
        let init = near_init(ChainId::Testnet);

        // When
        let result = require_tier3_public_addr(&init);

        // Then
        let err = result.expect_err("non-localnet without tier3_public_addr must fail");
        assert!(err.to_string().contains("tier3_public_addr"));
    }

    #[test]
    fn require_tier3_public_addr__should_ok_for_non_localnet_when_set() {
        // Given
        let mut init = near_init(ChainId::Mainnet);
        init.tier3_public_addr = Some("203.0.113.10:24567".parse().unwrap());

        // When / Then
        require_tier3_public_addr(&init).expect("set tier3_public_addr must pass");
    }

    #[test]
    fn require_tier3_public_addr__should_ok_for_localnet_when_unset() {
        // Given — localnet disables state sync, so tier3 is irrelevant.
        for chain_id in [ChainId::Localnet, ChainId::Sandbox] {
            let init = near_init(chain_id);

            // When / Then
            require_tier3_public_addr(&init).expect("localnet must not require tier3_public_addr");
        }
    }

    #[test]
    fn set_decentralized_state_sync__should_replace_external_storage_block() {
        // Given — an existing config still on centralized (ExternalStorage) sync.
        let mut config = serde_json::json!({
            "state_sync": { "sync": { "ExternalStorage": { "external_storage_fallback_threshold": 0 } } }
        });

        // When
        let changed = set_decentralized_state_sync(&mut config);

        // Then
        assert!(changed);
        assert_eq!(config["state_sync"]["sync"], serde_json::json!("Peers"));
    }

    #[test]
    fn set_decentralized_state_sync__should_report_no_change_when_already_peers() {
        // Given
        let mut config = serde_json::json!({ "state_sync": { "sync": "Peers" } });

        // When
        let changed = set_decentralized_state_sync(&mut config);

        // Then — idempotent: nothing to migrate.
        assert!(!changed);
        assert_eq!(config["state_sync"]["sync"], serde_json::json!("Peers"));
    }

    // Real ExternalStorage block captured from a production node
    // (n1-multichain.testnet, /debug/nearcore_config, 2026-07-14). Kept verbatim so the
    // migration is tested against the shape nodes actually carry, not a simplified stand-in.
    fn real_external_storage_config() -> serde_json::Value {
        serde_json::json!({
            "state_sync": {
                "sync": {
                    "ExternalStorage": {
                        "location": { "GCS": { "bucket": "state-parts" } },
                        "num_concurrent_requests": 25,
                        "num_concurrent_requests_during_catchup": 5,
                        "external_storage_fallback_threshold": 100
                    }
                },
                "parts_compression_lvl": 1
            }
        })
    }

    #[test]
    fn set_decentralized_state_sync__should_migrate_real_config_and_preserve_siblings() {
        // Given — the real production ExternalStorage config.
        let mut config = real_external_storage_config();

        // When
        let changed = set_decentralized_state_sync(&mut config);

        // Then — sync flips to Peers and the sibling field is left intact.
        assert!(changed);
        assert_eq!(config["state_sync"]["sync"], serde_json::json!("Peers"));
        assert_eq!(
            config["state_sync"]["parts_compression_lvl"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn set_decentralized_state_sync__should_set_peers_when_state_sync_is_null() {
        // Given — state_sync present but null (defensive edge case).
        let mut config = serde_json::json!({ "state_sync": serde_json::Value::Null });

        // When
        let changed = set_decentralized_state_sync(&mut config);

        // Then
        assert!(changed);
        assert_eq!(config["state_sync"]["sync"], serde_json::json!("Peers"));
    }

    #[test]
    fn set_decentralized_state_sync__should_set_peers_when_state_sync_absent() {
        // Given — no state_sync block at all (current downloaded-config default).
        let mut config = serde_json::json!({});

        // When
        let changed = set_decentralized_state_sync(&mut config);

        // Then
        assert!(changed);
        assert_eq!(config["state_sync"]["sync"], serde_json::json!("Peers"));
    }

    #[test]
    fn set_tier3_public_addr__should_set_and_report_change_when_provided() {
        // Given
        let mut config = serde_json::json!({ "network": {} });
        let mut init = near_init(ChainId::Mainnet);
        init.tier3_public_addr = Some("203.0.113.10:24567".parse().unwrap());

        // When
        let changed = set_tier3_public_addr(&mut config, &init);

        // Then
        assert!(changed);
        assert_eq!(
            config["network"]["experimental"]["tier3_public_addr"],
            serde_json::json!("203.0.113.10:24567")
        );
    }

    #[test]
    fn set_tier3_public_addr__should_report_no_change_when_unset() {
        // Given — no tier3 configured (e.g. a node initialized before #3533).
        let mut config = serde_json::json!({ "network": {} });
        let init = near_init(ChainId::Mainnet);

        // When
        let changed = set_tier3_public_addr(&mut config, &init);

        // Then
        assert!(!changed);
        assert!(
            config["network"]["experimental"]
                .get("tier3_public_addr")
                .is_none()
        );
    }

    #[test]
    fn migrate_near_config_state_sync__should_rewrite_existing_config_on_disk() {
        // Given — a config on disk with the deprecated ExternalStorage block.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&real_external_storage_config()).unwrap(),
        )
        .unwrap();
        let mut init = near_init(ChainId::Mainnet);
        init.tier3_public_addr = Some("203.0.113.10:24567".parse().unwrap());

        // When
        migrate_near_config_state_sync(&path, &init).unwrap();

        // Then — sync migrated, sibling preserved, tier3 applied, all persisted.
        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(on_disk["state_sync"]["sync"], serde_json::json!("Peers"));
        assert_eq!(
            on_disk["state_sync"]["parts_compression_lvl"],
            serde_json::json!(1)
        );
        assert_eq!(
            on_disk["network"]["experimental"]["tier3_public_addr"],
            serde_json::json!("203.0.113.10:24567")
        );

        // And — a second call is an idempotent no-op that leaves valid JSON.
        migrate_near_config_state_sync(&path, &init).unwrap();
        let again: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(again["state_sync"]["sync"], serde_json::json!("Peers"));
    }

    #[test]
    fn migrate_near_config_state_sync__should_leave_localnet_config_untouched() {
        // Given — localnet, whose config the migration must not touch.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&real_external_storage_config()).unwrap(),
        )
        .unwrap();

        // When
        migrate_near_config_state_sync(&path, &near_init(ChainId::Localnet)).unwrap();

        // Then — untouched: still on ExternalStorage.
        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(on_disk["state_sync"]["sync"]["ExternalStorage"].is_object());
    }

    #[test]
    fn read_near_config_json__should_return_parsed_config_when_present() {
        // Given
        let home_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            near_config_file(home_dir.path()),
            r#"{ "genesis_file": "genesis.json" }"#,
        )
        .unwrap();

        // When
        let config = read_near_config_json(home_dir.path());

        // Then
        assert_eq!(
            config,
            serde_json::json!({ "genesis_file": "genesis.json" })
        );
    }
}
