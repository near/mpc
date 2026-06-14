use std::{net::SocketAddr, sync::Arc};

use ed25519_dalek::SigningKey;
use near_account_id::AccountId;
use onboarding::onboard;
use tokio::sync::{RwLock, oneshot, watch};
use types::MigrationInfo;

use crate::{
    config::{AesKey256, SecretsConfig},
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

/// Spawns the migration web server and the onboarding state machine,
/// then awaits the first `OnboardingJob::Done` before returning. The
/// onboarding loop keeps running in the background past that point so
/// future migrations can re-enter `Onboard(keyset)` without a restart.
/// See `docs/design/migration-onboarding-reentry.md`.
pub async fn spawn_recovery_server_and_run_onboarding(
    migration_web_ui: SocketAddr,
    migration_secrets: MigrationSecrets,
    my_near_account_id: AccountId,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    my_migration_info_receiver: watch::Receiver<MigrationInfo>,
    contract_state_receiver: watch::Receiver<ContractState>,
    tx_sender: impl TransactionSender + 'static,
) -> anyhow::Result<()> {
    let (import_keyshares_sender, import_keyshares_receiver) = tokio::sync::watch::channel(vec![]);
    let web_server_state = web::types::WebServerState {
        import_keyshares_sender,
        keyshare_storage: keyshare_storage.clone(),
        backup_encryption_key: migration_secrets.backup_encryption_key,
    };

    web::server::start_web_server(
        web_server_state.into(),
        migration_web_ui,
        my_migration_info_receiver.clone(),
        &migration_secrets.p2p_private_key,
    )
    .await?;

    let (first_done_tx, first_done_rx) = oneshot::channel();
    let tls_public_key = migration_secrets.p2p_private_key.verifying_key();
    tokio::spawn(async move {
        if let Err(err) = onboard(
            contract_state_receiver,
            my_migration_info_receiver,
            my_near_account_id,
            tls_public_key,
            tx_sender,
            keyshare_storage,
            import_keyshares_receiver,
            Some(first_done_tx),
        )
        .await
        {
            tracing::error!(?err, "onboarding state machine exited unexpectedly");
        }
    });

    // Err here = the spawned task dropped the sender; the panic/error is
    // already logged above. Either way, startup proceeds.
    let _ = first_done_rx.await;
    Ok(())
}
