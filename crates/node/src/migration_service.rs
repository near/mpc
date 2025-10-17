use std::sync::Arc;

use ed25519_dalek::SigningKey;
use near_sdk::AccountId;
use onboarding::onboard;
use tokio::sync::{watch, RwLock};
use types::MigrationInfo;

use crate::{
    config::WebUIConfig,
    indexer::{participants::ContractState, tx_sender::TransactionSender},
    keyshare::KeyshareStorage,
};

pub mod onboarding;
pub mod types;
pub mod web;

pub async fn spawn_recovery_server_run_onboarding(
    migration_web_ui: WebUIConfig,
    p2p_private_key: &SigningKey,
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
    };

    web::server::start_web_server(
        web_server_state.into(),
        migration_web_ui.clone(),
        my_migration_info_receiver.clone(),
        p2p_private_key,
    )
    .await?;
    onboard(
        contract_state_receiver,
        my_migration_info_receiver.clone(),
        my_near_account_id.clone(),
        p2p_private_key.verifying_key(),
        tx_sender,
        keyshare_storage.clone(),
        import_keyshares_receiver,
    )
    .await?;
    Ok(())
}
