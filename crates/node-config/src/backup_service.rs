use std::{net::SocketAddr, path::Path};

use launcher_interface::types::{PccsEndpointConfig, TeeConfig};
use near_account_id::AccountId;
use near_indexer_primitives::CryptoHash;
use near_mpc_bounded_collections::NonEmptyVec;
use serde::{Deserialize, Serialize};

use crate::start::{NearInitConfig, default_pccs_endpoints, read_toml_file};

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
    use std::path::PathBuf;

    use launcher_interface::types::{DockerSha256Digest, TeeAuthorityConfig};

    use super::*;
    use crate::ChainId;

    #[test]
    fn backup_service_start_config__should_parse_the_config_the_launcher_writes() {
        // Given
        let dstack_endpoint = PathBuf::from("/var/run/dstack.sock");
        let image_hash: DockerSha256Digest = format!("sha256:{}", "ab".repeat(32)).parse().unwrap();
        let latest_allowed_hash_file_path = PathBuf::from("/mnt/shared/image-digest.bin");
        let account_id: AccountId = "operator.near".parse().unwrap();
        let mpc_contract_id: AccountId = "v1.signer".parse().unwrap();
        let genesis_hash = CryptoHash([1; 32]);
        let tier3_public_addr: SocketAddr = "203.0.113.5:24567".parse().unwrap();
        let listen_address: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let launcher_config = format!(
            r#"
                account_id = "{account_id}"
                mpc_contract_id = "{mpc_contract_id}"
                genesis_hash = "{genesis_hash}"
                listen_address = "{listen_address}"

                [near_init]
                chain_id = "mainnet"
                download_genesis = true
                tier3_public_addr = "{tier3_public_addr}"

                [tee]
                image_hash = "{image_hash}"
                latest_allowed_hash_file_path = "{}"

                [tee.authority]
                type = "dstack"
                dstack_endpoint = "{}"
            "#,
            latest_allowed_hash_file_path.display(),
            dstack_endpoint.display(),
        );

        // When
        let config: BackupServiceStartConfig = toml::from_str(&launcher_config).unwrap();

        // Then
        let expected = BackupServiceStartConfig {
            tee: TeeConfig {
                authority: TeeAuthorityConfig::Dstack { dstack_endpoint },
                image_hash,
                latest_allowed_hash_file_path,
            },
            account_id,
            mpc_contract_id,
            genesis_hash,
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
            listen_address,
            pccs_endpoints: default_pccs_endpoints(),
        };
        assert_eq!(config, expected);
    }
}
