use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use near_sdk::AccountId;
use tokio::sync::watch;

use crate::{
    config::NodeStatus,
    indexer::{
        participants::ContractState,
        tx_sender::{TransactionSender, TransactionStatus},
        types::{ChainSendTransactionRequest, ConcludeNodeMigrationArgs},
    },
    keyshare::{Keyshare, KeyshareStorage},
};

async fn wait_for_state_change(
    contract_state_receiver: &mut watch::Receiver<ContractState>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = contract_state_receiver.changed() => {return Ok(());},
            _ = tokio::time::sleep(Duration::from_secs(60)) => {
                tracing::info!(target: "Onboarding", "Waiting for state change");
            },
        };
    }
}

enum ChangeResult {
    Contract,
    Keyshares,
}

async fn wait_for_state_change_or_keyset(
    contract_state_receiver: &mut watch::Receiver<ContractState>,
    keyshare_receiver: &mut watch::Receiver<Vec<Keyshare>>,
) -> anyhow::Result<ChangeResult> {
    loop {
        tokio::select! {
            _ = contract_state_receiver.changed() => {return Ok(ChangeResult::Contract);},
            _ = keyshare_receiver.changed() => {return Ok(ChangeResult::Keyshares);},
            _ = tokio::time::sleep(Duration::from_secs(60)) => {
                tracing::info!(target: "Onboarding", "Waiting for keyshares or state change");
            },
        };
    }
}

pub async fn onboard(
    my_near_account_id: &AccountId,
    mut contract_state_receiver: watch::Receiver<ContractState>,
    tx_sender: impl TransactionSender,
    tls_public_key: VerifyingKey,
    keyshare_storage: &mut KeyshareStorage,
    mut keyshare_receiver: watch::Receiver<Vec<Keyshare>>,
) -> anyhow::Result<()> {
    // we loop until we are onboarded or a participant.
    loop {
        let contract = contract_state_receiver.borrow_and_update().clone();
        match contract.node_status(my_near_account_id, &tls_public_key) {
            NodeStatus::Active => {
                // we should probably also check if we have the keyshares and wait for onboarding
                // otherwise.
                break;
            }
            NodeStatus::Inactive => {
                wait_for_state_change(&mut contract_state_receiver).await?;
                continue;
            }
            NodeStatus::Onboarding => {
                // first, see if you have the necessary secrets
                let Some(contract_keyset) = contract.get_keyset_if_running() else {
                    tracing::info!(target: "Onboarding", "Onboarding not allowed while contract is not in running state. Waiting for state change");
                    wait_for_state_change(&mut contract_state_receiver).await?;
                    //indefinitely_wait_for_state_change(&mut contract_state_receiver).await?;
                    continue;
                };
                // now, we know we are in a running state. Lets see if we have the keyshares
                if keyshare_storage
                    .load_keyset(&contract_keyset)
                    .await
                    .is_err()
                {
                    // todo: probably cleaner, use a cancellation token.
                    // Cancel the token whenever the state changes in a monitoring function.
                    // in here, we make it cancel safe, i.e. we don't mess when importing the
                    // keyshares, just before or after
                    // wait and import keyshares
                    let ChangeResult::Keyshares = wait_for_state_change_or_keyset(
                        &mut contract_state_receiver,
                        &mut keyshare_receiver,
                    )
                    .await?
                    else {
                        tracing::info!(target: "Onboarding", "Contract state changed, need to restart onboarding.");
                        continue;
                    };
                    let received_keyshares = keyshare_receiver.borrow_and_update().clone();
                    tracing::info!(target: "Onboarding", "Received keyshares.");
                    match keyshare_storage
                        .import_backup(received_keyshares, contract_keyset)
                        .await
                    {
                        Ok(_) => {
                            tracing::info!(target: "Onboarding", "Successfully imported keyshares");
                        }
                        Err(err) => {
                            tracing::error!(target: "Onboarding", "Error importing keyshares: {}.", err);
                            continue;
                        }
                    }
                };

                tracing::info!("Have the keyshares, conclude onboarding");
                // todo: check that you have an ongoing migration. Or, just repeat

                let transaction =
                    ChainSendTransactionRequest::ConcludeNodeMigration(ConcludeNodeMigrationArgs {
                        keyset: contract_keyset.clone(),
                    });
                let res = tx_sender.send_and_wait(transaction).await?;
                match res {
                    TransactionStatus::Unknown => {
                        tracing::info!("unknown outcome");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    TransactionStatus::Executed => tracing::info!("we are good"),
                    TransactionStatus::NotExecuted => {
                        tracing::error!("unexpected error.");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
                continue;
            }
        }
    }
    Ok(())
}
