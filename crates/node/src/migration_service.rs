use std::{net::SocketAddr, sync::Arc};

use ed25519_dalek::{SigningKey, VerifyingKey};
use near_account_id::AccountId;
use tokio::sync::{RwLock, watch};
use types::MigrationInfo;

use crate::{
    config::{AesKey256, SecretsConfig},
    indexer::participants::ContractState,
    keyshare::{Keyshare, KeyshareStorage},
    migration_service::types::OnboardingJob,
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

/// Binds the migration web server on `migration_web_ui` and returns the
/// receiver side of the keyshare-import channel. The sender lives inside the
/// web server's state, so the channel stays alive for as long as the server
/// task does — i.e. the lifetime of the node process.
///
/// The dispatcher in `run.rs` clones this receiver into each invocation of
/// `onboarding::onboard` so back-migrations can be served without a process
/// restart. See `docs/design/migration-onboarding-dispatcher.md`.
pub async fn start_migration_web_server(
    migration_web_ui: SocketAddr,
    migration_secrets: &MigrationSecrets,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    my_migration_info_receiver: watch::Receiver<MigrationInfo>,
) -> anyhow::Result<watch::Receiver<Vec<Keyshare>>> {
    let (import_keyshares_sender, import_keyshares_receiver) = watch::channel(vec![]);
    let web_server_state = web::types::WebServerState {
        import_keyshares_sender,
        keyshare_storage,
        backup_encryption_key: migration_secrets.backup_encryption_key,
    };
    web::server::start_web_server(
        web_server_state.into(),
        migration_web_ui,
        my_migration_info_receiver,
        &migration_secrets.p2p_private_key,
    )
    .await?;
    Ok(import_keyshares_receiver)
}

/// Waits until the onboarding role implied by `(contract_state, migration_info,
/// my_id, tls_pub_key)` changes away from `current`, then returns the new
/// role. Used by the dispatcher to detect when the active subsystem
/// (coordinator vs onboarding) must be swapped.
pub(crate) async fn wait_until_role_change(
    mut contract_state_receiver: watch::Receiver<ContractState>,
    mut my_migration_info_receiver: watch::Receiver<MigrationInfo>,
    my_near_account_id: &AccountId,
    tls_public_key: &VerifyingKey,
    current: OnboardingJob,
) -> OnboardingJob {
    loop {
        let contract = contract_state_receiver.borrow_and_update().clone();
        let migration_info = my_migration_info_receiver.borrow_and_update().clone();
        let job = OnboardingJob::new(migration_info, contract, my_near_account_id, tls_public_key);
        if job != current {
            return job;
        }
        tokio::select! {
            _ = contract_state_receiver.changed() => {}
            _ = my_migration_info_receiver.changed() => {}
        }
    }
}
