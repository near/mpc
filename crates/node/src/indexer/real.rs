use super::handler::listen_blocks;
use super::participants::{monitor_contract_state, ContractState};
use super::stats::indexer_logger;
use super::{IndexerAPI, IndexerState};
#[cfg(feature = "network-hardship-simulation")]
use crate::config::load_listening_blocks_file;
use crate::config::{IndexerConfig, RespondConfig};
use crate::indexer::balances::monitor_balance;
use crate::indexer::tee::monitor_allowed_docker_images;
use crate::indexer::tx_sender::{TransactionProcessorHandle, TransactionSender};
use ed25519_dalek::SigningKey;
use mpc_contract::state::ProtocolContractState;
use near_sdk::AccountId;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "network-hardship-simulation")]
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch, Mutex};

#[cfg(feature = "network-hardship-simulation")]
pub async fn check_block_processing(process_blocks_sender: watch::Sender<bool>, home_dir: PathBuf) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let new_val = match load_listening_blocks_file(&home_dir) {
            Ok(new_val) => {
                tracing::info!("flag file found, setting to {}", new_val);
                new_val
            }
            Err(e) => {
                tracing::info!("flag file not found, setting to {}. Error: {}", true, e);
                true
            }
        };
        if process_blocks_sender.send(new_val).is_err() {
            tracing::info!("channel closed");
            return;
        }
    }
}

/// Spawns a real indexer, returning a handle to the indexer, [`IndexerApi`].
///
/// If an unrecoverable error occurs, the spawned indexer will terminate, and the provided [`oneshot::Sender`]
/// will be used to propagate the error.
pub fn spawn_real_indexer(
    home_dir: PathBuf,
    indexer_config: IndexerConfig,
    my_near_account_id: AccountId,
    node_signing_key: SigningKey,
    respond_config: RespondConfig,
    protocol_state_sender: watch::Sender<ProtocolContractState>,
    indexer_exit_sender: oneshot::Sender<anyhow::Result<()>>,
) -> IndexerAPI<impl TransactionSender> {
    let (chain_config_sender, chain_config_receiver) =
        tokio::sync::watch::channel::<ContractState>(ContractState::WaitingForSync);
    let (block_update_sender, block_update_receiver) = mpsc::unbounded_channel();
    let (allowed_docker_images_sender, allowed_docker_images_receiver) = watch::channel(vec![]);

    let my_near_account_id_clone = my_near_account_id.clone();
    let respond_config_clone = respond_config.clone();

    let (txn_sender_sender, txn_sender_receiver) = oneshot::channel();

    // TODO(#156): replace actix with tokio
    std::thread::spawn(move || {
        actix::System::new().block_on(async {
            // We have this indirection of using a oneshot for sending the indexer state,
            // as we can't block the main thread for waiting on the `txn_sender`.
            // Thus we instead initialize a `txn_sender`, which runs as a spawned task, to await on the indexer state being ready.
            let indexer =
                near_indexer::Indexer::new(indexer_config.to_near_indexer_config(home_dir.clone()))
                    .expect("Failed to initialize the Indexer");
            let stream = indexer.streamer();
            let (view_client, client, tx_processor) = indexer.client_actors();
            let indexer_state = Arc::new(IndexerState::new(
                view_client,
                client,
                tx_processor,
                indexer_config.mpc_contract_id.clone(),
            ));

            let txn_sender_result = TransactionProcessorHandle::start_transaction_processor(
                my_near_account_id_clone,
                node_signing_key.clone(),
                respond_config_clone,
                Arc::clone(&indexer_state),
            );

            let Ok(txn_sender) = txn_sender_result else {
                tracing::error!("Failed to start transaction processor. Exiting indexer.");
                let _ = indexer_exit_sender.send(txn_sender_result.map(|_| ()));
                return;
            };

            if txn_sender_sender.send(txn_sender).is_err() {
                tracing::error!("Failed to send txn_sender back to main thread.")
            };

            #[cfg(feature = "network-hardship-simulation")]
            let process_blocks_receiver = {
                let (process_blocks_sender, process_blocks_receiver) = watch::channel(true);
                actix::spawn(check_block_processing(process_blocks_sender, home_dir));
                process_blocks_receiver
            };

            actix::spawn(monitor_contract_state(
                indexer_state.clone(),
                indexer_config.port_override,
                chain_config_sender,
                protocol_state_sender,
            ));

            actix::spawn(indexer_logger(
                Arc::clone(&indexer_state.stats),
                indexer_state.view_client.clone(),
            ));

            actix::spawn(monitor_balance(
                my_near_account_id.clone(),
                respond_config.account_id.clone(),
                indexer_state.client.clone(),
                indexer_state.view_client.clone(),
            ));

            actix::spawn(monitor_allowed_docker_images(
                allowed_docker_images_sender,
                indexer_state.clone(),
            ));

            // below function runs indefinitely and only returns in case of an error.
            #[cfg(feature = "network-hardship-simulation")]
            let indexer_result = listen_blocks(
                stream,
                indexer_config.concurrency,
                Arc::clone(&indexer_state.stats),
                indexer_config.mpc_contract_id,
                block_update_sender,
                process_blocks_receiver,
            )
            .await;

            #[cfg(not(feature = "network-hardship-simulation"))]
            let indexer_result = listen_blocks(
                stream,
                indexer_config.concurrency,
                Arc::clone(&indexer_state.stats),
                indexer_config.mpc_contract_id,
                block_update_sender,
            )
            .await;

            if indexer_exit_sender.send(indexer_result).is_err() {
                tracing::error!("Indexer thread could not send result back to main driver.")
            };
        });
    });

    let txn_sender = txn_sender_receiver
        .blocking_recv()
        .expect("txn_sender is returned from the `block_on` expression above.");

    IndexerAPI {
        contract_state_receiver: chain_config_receiver,
        block_update_receiver: Arc::new(Mutex::new(block_update_receiver)),
        txn_sender,
        allowed_docker_images_receiver,
    }
}
