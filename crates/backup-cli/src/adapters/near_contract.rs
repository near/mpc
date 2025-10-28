use contract_interface::types as contract_types;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mpc_contract::node_migrations::BackupServiceInfo;
use near_crypto::{ED25519SecretKey, SecretKey as NearSecretKey};
use near_primitives::{types::AccountId, utils::derive_near_implicit_account_id};
use near_workspaces::types::SecretKey;
use std::str::FromStr;

use crate::{cli::Network, ports::RegisterBackupData};

#[derive(thiserror::Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[error("failed to connect to NEAR network: {0}")]
    NetworkConnection(#[from] near_workspaces::error::Error),

    #[error("failed to register backup data: {0}")]
    RegistrationFailed(near_workspaces::error::Error),

    #[error("transaction execution failed: {0}")]
    TransactionFailed(near_workspaces::result::ExecutionFailure),
}

pub struct NearContractAdapter {
    contract_account_id: AccountId,
    network: Network,
    signer_key: SigningKey,
}

impl NearContractAdapter {
    pub fn new(contract_account_id: AccountId, network: Network, signer_key: SigningKey) -> Self {
        Self {
            contract_account_id,
            network,
            signer_key,
        }
    }
}

impl RegisterBackupData for NearContractAdapter {
    type Error = Error;

    async fn register_backup_data(&self, public_key: &VerifyingKey) -> Result<(), Self::Error> {
        let backup_service_info = BackupServiceInfo {
            public_key: contract_types::Ed25519PublicKey::from(*public_key.as_bytes()),
        };

        let signer = signing_key_to_near_secret_key(&self.signer_key);
        let signer_account_id = derive_implicit_account_id(&self.signer_key);

        macro_rules! register_on_network {
            ($network:expr) => {
                call_register_on_network(
                    $network.await?,
                    signer_account_id,
                    signer,
                    &self.contract_account_id,
                    backup_service_info,
                )
                .await
            };
        }

        match &self.network {
            Network::Testnet => register_on_network!(near_workspaces::testnet()),
            Network::Mainnet => register_on_network!(near_workspaces::mainnet()),
            Network::Sandbox => register_on_network!(near_workspaces::sandbox()),
            Network::Localnet(rpc_url) => {
                register_on_network!(near_workspaces::custom(rpc_url.as_str()))
            }
        }
    }
}

async fn call_register_on_network<T: near_workspaces::Network + 'static>(
    worker: near_workspaces::Worker<T>,
    signer_account_id: AccountId,
    signer: SecretKey,
    contract_account_id: &AccountId,
    backup_service_info: BackupServiceInfo,
) -> Result<(), Error> {
    let account = near_workspaces::Account::from_secret_key(signer_account_id, signer, &worker);
    account
        .call(contract_account_id, "register_backup_service")
        .args_json(serde_json::json!({
            "backup_service_info": backup_service_info,
        }))
        .max_gas()
        .transact()
        .await
        .map_err(Error::RegistrationFailed)?
        .into_result()
        .map_err(Error::TransactionFailed)?;

    Ok(())
}

fn signing_key_to_near_secret_key(signer_key: &SigningKey) -> SecretKey {
    SecretKey::from_str(
        &NearSecretKey::ED25519(ED25519SecretKey(signer_key.to_keypair_bytes())).to_string(),
    )
    .expect("failed to create secret key")
}

fn derive_implicit_account_id(signer_key: &SigningKey) -> AccountId {
    derive_near_implicit_account_id(&(*signer_key.verifying_key().as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_derive_implicit_account_id() {
        // Given
        let signing_key = SigningKey::from_bytes(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]);

        // When
        let account_id = derive_implicit_account_id(&signing_key);

        // Then
        let expected_public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        assert_eq!(account_id.as_str(), expected_public_key_hex);
        assert_eq!(account_id.as_str().len(), 64);
    }

    #[test]
    fn test_signing_key_to_near_secret_key() {
        // Given
        let signing_key = SigningKey::from_bytes(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]);

        // When
        let near_secret_key = signing_key_to_near_secret_key(&signing_key);

        // Then
        let secret_key_str = near_secret_key.to_string();
        assert!(secret_key_str.starts_with("ed25519:"));
        let parsed = SecretKey::from_str(&secret_key_str).unwrap();
        assert_eq!(parsed, near_secret_key);
    }
}
