use std::{net::SocketAddr, sync::Arc};

use anyhow::Context as _;
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
/// (coordinator vs onboarding) must be swapped. Returns `Err` if either
/// underlying watch channel closes — without surfacing the error the loop
/// would spin reading stale state.
pub(crate) async fn wait_until_role_change(
    mut contract_state_receiver: watch::Receiver<ContractState>,
    mut my_migration_info_receiver: watch::Receiver<MigrationInfo>,
    my_near_account_id: &AccountId,
    tls_public_key: &VerifyingKey,
    current: OnboardingJob,
) -> anyhow::Result<OnboardingJob> {
    loop {
        let contract = contract_state_receiver.borrow_and_update().clone();
        let migration_info = my_migration_info_receiver.borrow_and_update().clone();
        let job = OnboardingJob::new(migration_info, contract, my_near_account_id, tls_public_key);
        if job != current {
            return Ok(job);
        }
        tokio::select! {
            res = contract_state_receiver.changed() => {
                res.context("contract state receiver closed")?;
            }
            res = my_migration_info_receiver.changed() => {
                res.context("migration info receiver closed")?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration_service::types::tests::make_running_contract_case;

    /// Returns when the contract state transitions away from a state in which
    /// the test node is an active participant. The function must surface the
    /// new role to the dispatcher so it can swap the coordinator out.
    #[tokio::test]
    #[expect(non_snake_case)]
    async fn wait_until_role_change__should_return_new_role_when_contract_state_changes() {
        // Given: a Running contract where the test node IS an active participant
        // (initial role = Done).
        let (case, _keyset) = make_running_contract_case(
            ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key(),
        );
        let my_account_id = case.participant_node.account_id.clone();
        let my_pk = case.participant_node.p2p_public_key;
        let initial_contract = case.contract;
        let migration_info = MigrationInfo {
            backup_service_info: None,
            active_migration: false,
        };
        assert_eq!(
            OnboardingJob::new(
                migration_info.clone(),
                initial_contract.clone(),
                &my_account_id,
                &my_pk,
            ),
            OnboardingJob::Done,
            "test precondition: initial role must be Done"
        );
        let (contract_tx, contract_rx) = watch::channel(initial_contract.clone());
        let (_migration_tx, migration_rx) = watch::channel(migration_info.clone());

        // When: start waiting with current = Done, then mutate the contract
        // so the same node is no longer a participant (role diverges from Done).
        let my_account_id_clone = my_account_id.clone();
        let handle = tokio::spawn(async move {
            wait_until_role_change(
                contract_rx,
                migration_rx,
                &my_account_id_clone,
                &my_pk,
                OnboardingJob::Done,
            )
            .await
        });
        let other_pk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]).verifying_key();
        let mut mutated = initial_contract.clone();
        mutated.change_participant_pk(&my_account_id, other_pk);
        contract_tx
            .send(mutated)
            .expect("send mutated contract state");

        // Then: the function returns WaitForStateChange (this node is no
        // longer a participant under the mutated contract).
        let new_role = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("wait_until_role_change did not return within 2s")
            .expect("task panicked")
            .expect("wait_until_role_change returned Err");
        assert_eq!(new_role, OnboardingJob::WaitForStateChange);
    }
}
