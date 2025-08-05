use super::handler::listen_blocks;
use super::participants::{monitor_contract_state, ContractState};
use super::stats::indexer_logger;
use super::tx_sender::handle_txn_requests;
use super::{IndexerAPI, IndexerState};
#[cfg(feature = "network-hardship-simulation")]
use crate::config::load_listening_blocks_file;
use crate::config::{IndexerConfig, RespondConfig};
use crate::indexer::balances::monitor_balance;
#[cfg(feature = "tee")]
use crate::indexer::tee::monitor_allowed_docker_images;
use mpc_contract::state::ProtocolContractState;
use near_crypto::SecretKey;
use near_sdk::AccountId;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "network-hardship-simulation")]
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio_util::sync::CancellationToken;

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
    account_secret_key: SecretKey,
    respond_config: RespondConfig,
    protocol_state_sender: watch::Sender<ProtocolContractState>,
    indexer_exit_sender: oneshot::Sender<anyhow::Result<()>>,
) -> IndexerAPI {
    let (chain_config_sender, chain_config_receiver) =
        tokio::sync::watch::channel::<ContractState>(ContractState::WaitingForSync);
    let (block_update_sender, block_update_receiver) = mpsc::unbounded_channel();
    let (chain_txn_sender, chain_txn_receiver) = mpsc::channel(10000);
    #[cfg(feature = "tee")]
    let (allowed_docker_images_sender, allowed_docker_images_receiver) = watch::channel(vec![]);

    // TODO(#156): replace actix with tokio
    std::thread::spawn(move || {
        actix::System::new().block_on(async {
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

            actix::spawn(handle_txn_requests(
                chain_txn_receiver,
                my_near_account_id.clone(),
                account_secret_key.clone(),
                respond_config.clone(),
                indexer_state.clone(),
            ));
            let monitor_balance_cancellation_token = CancellationToken::new();
            actix::spawn(monitor_balance(
                my_near_account_id.clone(),
                respond_config.account_id.clone(),
                indexer_state.view_client.clone(),
                monitor_balance_cancellation_token.clone(),
            ));

            #[cfg(feature = "tee")]
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

            monitor_balance_cancellation_token.cancel();
            if indexer_exit_sender.send(indexer_result).is_err() {
                tracing::error!("Indexer thread could not send result back to main driver.")
            };
        });
    });

    IndexerAPI {
        contract_state_receiver: chain_config_receiver,
        block_update_receiver: Arc::new(Mutex::new(block_update_receiver)),
        txn_sender: chain_txn_sender,
        #[cfg(feature = "tee")]
        allowed_docker_images_receiver,
    }
}
