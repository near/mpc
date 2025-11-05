use std::sync::Arc;

use ed25519_dalek::SigningKey;
use near_sdk::AccountId;
use onboarding::onboard;
use tokio::sync::{watch, RwLock};
use types::MigrationInfo;

use crate::{
    config::{AesKey256, SecretsConfig, WebUIConfig},
    indexer::{participants::ContractState, tx_sender::TransactionSender},
    keyshare::KeyshareStorage,
};

pub mod onboarding;
pub mod types;
pub mod web;

pub struct MigrationSecrets {
    pub backup_encryption_key: AesKey256,
    pub p2p_private_key: SigningKey,
}

impl From<&SecretsConfig> for MigrationSecrets {
    fn from(value: &SecretsConfig) -> Self {
        Self {
            backup_encryption_key: value.backup_encryption_key,
            p2p_private_key: value.persistent_secrets.p2p_private_key.clone(),
        }
    }
}

pub async fn spawn_recovery_server_and_run_onboarding(
    migration_web_ui: WebUIConfig,
    migration_secrets: MigrationSecrets,
    my_near_account_id: AccountId,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    my_migration_info_receiver: watch::Receiver<MigrationInfo>,
    contract_state_receiver: watch::Receiver<ContractState>,
    tx_sender: impl TransactionSender,
) -> anyhow::Result<()> {
    let (import_keyshares_sender, import_keyshares_receiver) = tokio::sync::watch::channel(vec![]);
    let web_server_state = web::types::WebServerState {
        import_keyshares_sender,
        keyshare_storage: keyshare_storage.clone(),
        backup_encryption_key: migration_secrets.backup_encryption_key,
    };

    web::server::start_web_server(
        web_server_state.into(),
        migration_web_ui.clone(),
        my_migration_info_receiver.clone(),
        &migration_secrets.p2p_private_key,
    )
    .await?;
    onboard(
        contract_state_receiver,
        my_migration_info_receiver.clone(),
        my_near_account_id.clone(),
        migration_secrets.p2p_private_key.verifying_key(),
        tx_sender,
        keyshare_storage.clone(),
        import_keyshares_receiver,
    )
    .await?;
    Ok(())
}
