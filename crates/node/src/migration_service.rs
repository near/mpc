use std::{net::SocketAddr, sync::Arc};

use anyhow::Context as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use near_account_id::AccountId;
use tokio::sync::{RwLock, watch};
use tokio_util::sync::CancellationToken;
use types::{MigrationInfo, NodeJob};

use crate::{
    config::{AesKey256, SecretsConfig},
    indexer::participants::ContractState,
    keyshare::{Keyshare, KeyshareStorage},
};

pub mod onboarding;
pub mod types;
pub mod web;

#[derive(Clone)]
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

/// Spawn the recovery web server; returns the receiver downstream consumers
/// (the coordinator's onboarding arm) use to pick up incoming keyshares.
/// The server stays alive for the lifetime of the process so back-migrations
/// can be served without a restart.
pub async fn spawn_recovery_server(
    migration_web_ui: SocketAddr,
    migration_secrets: &MigrationSecrets,
    keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    my_migration_info_receiver: watch::Receiver<MigrationInfo>,
) -> anyhow::Result<watch::Receiver<Vec<Keyshare>>> {
    let (import_keyshares_sender, import_keyshares_receiver) = tokio::sync::watch::channel(vec![]);
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

/// Spawn a background task that classifies the node's current job from
/// contract + migration state and publishes it on a `watch::Receiver<NodeJob>`.
/// Returns the receiver plus a cancellation token for shutdown.
///
/// This is the *single* source of role classification for the node — both the
/// coordinator's outer dispatch loop and the per-arm handlers (onboarding,
/// run_initialization, run_mpc, run_key_resharing) consume the receiver and
/// self-terminate when their job variant changes.
pub(crate) fn decide_current_job(
    mut contract_state_receiver: watch::Receiver<ContractState>,
    mut my_migration_info_receiver: watch::Receiver<MigrationInfo>,
    my_near_account_id: AccountId,
    tls_public_key: VerifyingKey,
) -> (CancellationToken, watch::Receiver<NodeJob>) {
    let cancel = CancellationToken::new();
    let init = NodeJob::new(
        my_migration_info_receiver.borrow_and_update().clone(),
        contract_state_receiver.borrow_and_update().clone(),
        &my_near_account_id,
        &tls_public_key,
    );
    let (sender, receiver) = watch::channel(init);
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = contract_state_receiver.changed() => {}
                _ = my_migration_info_receiver.changed() => {}
                _ = cancel_clone.cancelled() => return,
            }
            let next = NodeJob::new(
                my_migration_info_receiver.borrow_and_update().clone(),
                contract_state_receiver.borrow_and_update().clone(),
                &my_near_account_id,
                &tls_public_key,
            );
            sender.send_if_modified(|current| {
                if *current == next {
                    false
                } else {
                    *current = next;
                    true
                }
            });
        }
    });
    (cancel, receiver)
}

/// Wait until the `NodeJob` receiver's value no longer satisfies the
/// caller's "still my job?" predicate. Used by the per-arm handlers in the
/// coordinator loop to self-terminate on role change.
pub(crate) async fn wait_until_job_changes<P>(
    receiver: &mut watch::Receiver<NodeJob>,
    still_my_job: P,
) -> anyhow::Result<()>
where
    P: Fn(&NodeJob) -> bool,
{
    loop {
        if !still_my_job(&receiver.borrow_and_update()) {
            return Ok(());
        }
        receiver
            .changed()
            .await
            .context("current-job channel closed")?;
    }
}
