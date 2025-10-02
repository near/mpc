use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use mpc_contract::primitives::key_state::Keyset;
use near_sdk::AccountId;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::{
    config::NodeStatus,
    indexer::{
        participants::ContractState,
        tx_sender::{TransactionSender, TransactionStatus},
        types::{ChainSendTransactionRequest, ConcludeNodeMigrationArgs},
    },
    keyshare::{Keyshare, KeyshareStorage},
    migration_service::types::MigrationInfo,
};

async fn wait_for_onboarding(
    mut migration_info: watch::Receiver<MigrationInfo>,
) -> anyhow::Result<()> {
    loop {
        let res = migration_info.borrow_and_update().clone();
        if res.active_migration {
            return Ok(());
        }
        migration_info.changed().await?;
    }
}

async fn cancel_on_change(
    to_cancel: CancellationToken,
    mut migration_info: watch::Receiver<MigrationInfo>,
    mut contract_state_receiver: watch::Receiver<ContractState>,
) -> anyhow::Result<()> {
    let res = tokio::select! {
        res = migration_info.changed() => res,
        res = contract_state_receiver.changed() => res
    };
    to_cancel.cancel();
    res.context("channel closed")
}

fn node_status(
    contract_state: &ContractState,
    account_id: &AccountId,
    p2p_public_key: &VerifyingKey,
) -> NodeStatus {
    match contract_state {
        ContractState::Invalid => NodeStatus::Inactive,
        ContractState::Initializing(initializing) => initializing
            .participants
            .get_node_status(account_id, p2p_public_key),
        ContractState::Running(running) => {
            if let Some(resharing) = &running.resharing_state {
                resharing
                    .new_participants
                    .get_node_status(account_id, p2p_public_key)
            } else {
                running
                    .participants
                    .get_node_status(account_id, p2p_public_key)
            }
        }
    }
}

/// returns true if we need to onbard. Returns false if we are a participant.
/// Idles if we are neither.
async fn need_to_onboard(
    mut contract_state_receiver: watch::Receiver<ContractState>,
    tls_public_key: VerifyingKey,
    my_near_account_id: &AccountId,
) -> anyhow::Result<bool> {
    loop {
        let contract = contract_state_receiver.borrow_and_update().clone();
        match node_status(&contract, my_near_account_id, &tls_public_key) {
            NodeStatus::Active => {
                return Ok(false);
            }
            NodeStatus::Inactive => {}
            NodeStatus::Onboarding => {
                return Ok(true);
            }
        }
        tracing::info!(target: "Onboarding", "Our AccountId is not participating in the protocol. Waiting for state change.");
        contract_state_receiver
            .changed()
            .await
            .context("Channel closed")?;
    }
}

// todo: rename to migration_node_receiver
pub async fn onboard(
    my_near_account_id: &AccountId,
    tls_public_key: VerifyingKey,
    mut contract_state_receiver: watch::Receiver<ContractState>,
    migration_info: watch::Receiver<MigrationInfo>,
    tx_sender: impl TransactionSender,
    keyshare_storage: &mut KeyshareStorage,
    keyshare_receiver: watch::Receiver<Vec<Keyshare>>,
) -> anyhow::Result<()> {
    loop {
        if !need_to_onboard(
            contract_state_receiver.clone(),
            tls_public_key,
            my_near_account_id,
        )
        .await?
        {
            tracing::info!("We are already a participant, skipping onboarding.");
            return Ok(());
        }
        // we wait for the contract to greenlight our onboarding
        tokio::select! {
            res = contract_state_receiver.changed() => {res.context("channel closed")?; tracing::info!("contract state change, restarting the loop."); continue},
            res = wait_for_onboarding(migration_info.clone()) =>  {res.context("channel closed")?; tracing::info!("Found migration on chain.")}
        }

        let cancel_onboarding = CancellationToken::new();

        // we abort the onboarding if:
        //  - the contract state changes
        //  - we are suddenly no longer migrating
        tokio::spawn(cancel_on_change(
            cancel_onboarding.clone(),
            migration_info.clone(),
            contract_state_receiver.clone(),
        ));

        let res = onboard_inner(
            contract_state_receiver.clone(),
            keyshare_storage,
            keyshare_receiver.clone(),
            tx_sender.clone(),
            cancel_onboarding,
        )
        .await;

        match res {
            Ok(()) => {
                tracing::info!("concluded onboarding");
                return Ok(());
            }
            err => {
                tracing::info!("onboarding failed: {:?}. Retrying.", err);
            }
        }
    }
}

/// Waits for keyshares and retries import until success.
/// Returns `Ok(())` once import succeeds.
/// Returns `Err` only if the channel closed.
/// Import failures are logged but do not exit early.
/// Note: this function *should be cancelled* in case the keyset on the contract changes.
/// This function is **not** cancellation safe
async fn wait_for_and_import_keyshares(
    contract_keyset: &Keyset,
    keyshare_storage: &mut KeyshareStorage,
    mut keyshare_receiver: watch::Receiver<Vec<Keyshare>>,
    cancel_import: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        let received_keyshares = keyshare_receiver.borrow_and_update().clone();
        if !received_keyshares.is_empty() {
            match keyshare_storage
                .import_backup(received_keyshares, contract_keyset)
                .await
            {
                Ok(_) => {
                    tracing::info!(target: "Onboarding", "Successfully imported keyshares.");
                    return Ok(());
                }
                Err(err) => {
                    tracing::error!(target: "Onboarding", "Failed to import keyshares: {:?}", err)
                }
            }
        }
        let changed = tokio::select! {
            changed = keyshare_receiver.changed() => {changed},
            _ = cancel_import.cancelled() => {anyhow::bail!("Keyshare import was cancelled.");},

        };
        changed.context("Keyshare sender closed")?;
    }
}

/// Returns Error if the channel closed
async fn indef_wait_for_running_keyset(
    contract_state_receiver: &mut watch::Receiver<ContractState>,
) -> anyhow::Result<Keyset> {
    loop {
        let contract = contract_state_receiver.borrow_and_update().clone();
        match contract {
            ContractState::Invalid => {}
            ContractState::Initializing(_) => {}
            ContractState::Running(running_state) => {
                if running_state.resharing_state.is_none() {
                    return Ok(running_state.keyset);
                }
            }
        }
        contract_state_receiver.changed().await?;
    }
}

// note:

/// Returns Ok(()) if it successfully imported a keyset,
/// Returns Err(()) if the channel closed or if it was cancelled.
/// **not** cancellation safe. use the `cancel_import` token instead.
async fn ensure_keyset_is_imported(
    //mut contract_state_receiver: watch::Receiver<ContractState>,
    importing_keyset: Keyset,
    keyshare_storage: &mut KeyshareStorage,
    keyshare_receiver: watch::Receiver<Vec<Keyshare>>,
    cancel_import: CancellationToken, // this is probably not needed!
) -> anyhow::Result<()> {
    //loop {
    //let importing_keyset = tokio::select!{
    //    res = indef_wait_for_running_keyset(&mut contract_state_receiver) => res?,
    //    cancelled = cancel_import.cancelled() => anyhow::bail!("import cancelled"),
    //};

    if keyshare_storage
        .load_keyset(&importing_keyset)
        .await
        .is_ok()
    {
        return Ok(());
    } else {
        wait_for_and_import_keyshares(
            &importing_keyset,
            keyshare_storage,
            keyshare_receiver.clone(),
            cancel_import,
        )
        .await
    }
    //}
}

async fn send_conclude_onboarding(
    imported_keyset: Keyset,
    tx_sender: impl TransactionSender,
) -> anyhow::Result<()> {
    let transaction =
        ChainSendTransactionRequest::ConcludeNodeMigration(ConcludeNodeMigrationArgs {
            keyset: imported_keyset,
        });
    let res = tx_sender.send_and_wait(transaction).await?;
    match res {
        TransactionStatus::Unknown => {
            anyhow::bail!("Failed to send conclude resharing transaction.");
        }
        TransactionStatus::Executed => {
            tracing::info!("Conclude resharing transaction submitted successfully.");
            Ok(())
        }
        TransactionStatus::NotExecuted => {
            anyhow::bail!("Failed to send conclude resharing transaction.");
        }
    }
}

async fn cancel_on_keyset_change(
    mut contract_state_receiver: watch::Receiver<ContractState>,
    importing_keyset: Keyset,
    to_cancel: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        let contract = contract_state_receiver.borrow_and_update().clone();
        match contract {
            ContractState::Invalid => {}
            ContractState::Initializing(_) => {}
            ContractState::Running(running_state) => {
                if running_state.resharing_state.is_none() {
                    if importing_keyset != running_state.keyset {
                        to_cancel.cancel();
                        return Ok(());
                    }
                }
            }
        }
        contract_state_receiver.changed().await?;
    }
}

// NOT cancellation safe! Needs to be cancelled via `cancel_import_token`
async fn import_inner(
    importing_keyset: Keyset,
    keyshare_storage: &mut KeyshareStorage,
    keyshare_receiver: watch::Receiver<Vec<Keyshare>>,
    tx_sender: impl TransactionSender,
    cancel_import_token: CancellationToken,
) -> anyhow::Result<()> {
    ensure_keyset_is_imported(
        importing_keyset.clone(),
        keyshare_storage,
        keyshare_receiver,
        cancel_import_token.clone(),
    )
    .await
    .context("Unsuccessful importing keyset. Import Cancelled or channel closed")?;

    tokio::select! {
        res = send_conclude_onboarding(importing_keyset.clone(), tx_sender) => res?,
        _ = cancel_import_token.cancelled() => {
            anyhow::bail!("import cancelled due to key change");
        },
    };
    tracing::info!("Import concluded");
    Ok(())
}

async fn onboard_inner(
    mut contract_state_receiver: watch::Receiver<ContractState>,
    keyshare_storage: &mut KeyshareStorage,
    keyshare_receiver: watch::Receiver<Vec<Keyshare>>,
    tx_sender: impl TransactionSender,
    cancel_onboarding: CancellationToken,
) -> anyhow::Result<()> {
    let importing_keyset = tokio::select! {
        res = indef_wait_for_running_keyset(&mut contract_state_receiver) => res?,
        _ = cancel_onboarding.cancelled() => anyhow::bail!("onboarding cancelled"),
    };
    let cancel_import_token = cancel_onboarding.child_token();
    let monitoring_handle = tokio::spawn(cancel_on_keyset_change(
        contract_state_receiver.clone(),
        importing_keyset.clone(),
        cancel_import_token.clone(),
    ));

    let result = import_inner(
        importing_keyset,
        keyshare_storage,
        keyshare_receiver,
        tx_sender,
        cancel_import_token,
    )
    .await;
    monitoring_handle.abort();
    result
}
