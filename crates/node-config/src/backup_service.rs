use std::{net::SocketAddr, path::Path};

use launcher_interface::types::{PccsEndpointConfig, TeeConfig};
use near_account_id::AccountId;
use near_indexer_primitives::CryptoHash;
use near_mpc_bounded_collections::NonEmptyVec;
use serde::{Deserialize, Serialize};

use crate::start::{NearInitConfig, SecretsStartConfig, default_pccs_endpoints, read_toml_file};

/// Configuration a launcher writes for a backup service. The launcher sets the `tee` section,
/// the contract id and the genesis hash itself, the latter two from its measured compose file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupServiceStartConfig {
    pub tee: TeeConfig,
    /// The operator's account. The service registers under it with the account key it generates,
    /// which the operator adds to this account.
    pub account_id: AccountId,
    pub mpc_contract_id: AccountId,
    /// Genesis hash of the chain the MPC contract runs on. The embedded NEAR node must follow
    /// this chain.
    pub genesis_hash: CryptoHash,
    pub near_init: NearInitConfig,
    /// [`SecretsStartConfig::backup_encryption_key_hex`] is required: it must be the key of the
    /// account's MPC node, which encrypts keyshares in transit.
    pub secrets: SecretsStartConfig,
    /// Port the MPC nodes serve keyshares on. Their hosts and TLS keys come from the contract.
    pub mpc_node_migration_port: u16,
    /// Address to serve `/health`, `/status`, `/metrics` and `/public_data` on.
    pub listen_address: SocketAddr,
    /// PCCS servers used to fetch TDX attestation collateral, as in
    /// [`crate::StartConfig::pccs_endpoints`].
    #[serde(default = "default_pccs_endpoints")]
    pub pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
}

impl BackupServiceStartConfig {
    pub fn from_toml_file(path: &Path) -> anyhow::Result<Self> {
        read_toml_file(path)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::{assert_matches, path::PathBuf};

    use launcher_interface::types::TeeAuthorityConfig;

    use super::*;
    use crate::ChainId;

    const MPC_CONTRACT_ID: &str = "v1.signer";
    const GENESIS_HASH: CryptoHash = CryptoHash([1; 32]);
    const TIER3_PUBLIC_ADDR: &str = "203.0.113.5:24567";

    fn launcher_tee_config(authority: TeeAuthorityConfig) -> TeeConfig {
        TeeConfig {
            authority,
            image_hash: format!("sha256:{}", "ab".repeat(32)).parse().unwrap(),
            latest_allowed_hash_file_path: PathBuf::from("/mnt/shared/image-digest.bin"),
        }
    }

    #[test]
    fn backup_service_start_config__should_parse_the_config_the_launcher_writes() {
        // Given
        let dstack_endpoint = PathBuf::from("/var/run/dstack.sock");
        let tee = launcher_tee_config(TeeAuthorityConfig::Dstack {
            dstack_endpoint: dstack_endpoint.clone(),
        });
        let account_id: AccountId = "operator.near".parse().unwrap();
        let mpc_contract_id: AccountId = MPC_CONTRACT_ID.parse().unwrap();
        let tier3_public_addr: SocketAddr = TIER3_PUBLIC_ADDR.parse().unwrap();
        let secret_store_key_hex = "11".repeat(16);
        let backup_encryption_key_hex = "22".repeat(32);
        let mpc_node_migration_port = 8079;
        let listen_address: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let launcher_config = format!(
            r#"
                account_id = "{account_id}"
                mpc_contract_id = "{mpc_contract_id}"
                genesis_hash = "{GENESIS_HASH}"
                mpc_node_migration_port = {mpc_node_migration_port}
                listen_address = "{listen_address}"

                [near_init]
                chain_id = "mainnet"
                download_genesis = true
                tier3_public_addr = "{tier3_public_addr}"

                [secrets]
                secret_store_key_hex = "{secret_store_key_hex}"
                backup_encryption_key_hex = "{backup_encryption_key_hex}"

                [tee]
                image_hash = "{}"
                latest_allowed_hash_file_path = "{}"

                [tee.authority]
                type = "dstack"
                dstack_endpoint = "{}"
            "#,
            tee.image_hash,
            tee.latest_allowed_hash_file_path.display(),
            dstack_endpoint.display(),
        );

        // When
        let config: BackupServiceStartConfig = toml::from_str(&launcher_config).unwrap();

        // Then
        let expected = BackupServiceStartConfig {
            tee,
            account_id,
            mpc_contract_id,
            genesis_hash: GENESIS_HASH,
            near_init: NearInitConfig {
                chain_id: ChainId::Mainnet,
                boot_nodes: None,
                genesis_path: None,
                download_config: None,
                download_config_url: None,
                download_genesis: true,
                download_genesis_url: None,
                download_genesis_records_url: None,
                rpc_addr: None,
                network_addr: None,
                tier3_public_addr: Some(tier3_public_addr),
            },
            secrets: SecretsStartConfig {
                secret_store_key_hex,
                backup_encryption_key_hex: Some(backup_encryption_key_hex),
            },
            mpc_node_migration_port,
            listen_address,
            pccs_endpoints: default_pccs_endpoints(),
        };
        assert_eq!(config, expected);
    }

    #[test]
    fn backup_service_start_config__should_parse_the_operator_template() {
        // Given
        let user_config: toml::Table = toml::from_str(include_str!(
            "../../../deployment/cvm-deployment/backup-service-user-config.toml"
        ))
        .unwrap();
        let mut backup_service_config = user_config["backup_service_config"]
            .as_table()
            .unwrap()
            .clone();
        backup_service_config["near_init"]["tier3_public_addr"] = TIER3_PUBLIC_ADDR.into();
        let tee = launcher_tee_config(TeeAuthorityConfig::Local);
        backup_service_config.insert("tee".into(), toml::Value::try_from(tee).unwrap());
        backup_service_config.insert("mpc_contract_id".into(), MPC_CONTRACT_ID.into());
        backup_service_config.insert("genesis_hash".into(), GENESIS_HASH.to_string().into());

        // When
        let result = backup_service_config.try_into::<BackupServiceStartConfig>();

        // Then
        assert_matches!(result, Ok(_));
    }
}
