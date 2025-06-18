use super::handler::listen_blocks;
use super::participants::{monitor_contract_state, ContractState};
use super::stats::{indexer_logger, IndexerStats};
use super::tx_sender::handle_txn_requests;
use super::{IndexerAPI, IndexerState};
use crate::config::{IndexerConfig, RespondConfig};
use mpc_contract::state::ProtocolContractState;
use near_crypto::SecretKey;
use near_sdk::AccountId;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch, Mutex};

#[cfg(feature = "tee")]
use crate::indexer::tee::monitor_allowed_docker_images;

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
    let (tee_sender, tee_receiver) = oneshot::channel();

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
            // TODO: migrate this into IndexerState
            let stats: Arc<Mutex<IndexerStats>> = Arc::new(Mutex::new(IndexerStats::new()));
            actix::spawn(monitor_contract_state(
                indexer_state.clone(),
                indexer_config.port_override,
                chain_config_sender,
                protocol_state_sender,
            ));
            actix::spawn(indexer_logger(
                Arc::clone(&stats),
                indexer_state.view_client.clone(),
            ));
            actix::spawn(handle_txn_requests(
                chain_txn_receiver,
                my_near_account_id,
                account_secret_key.clone(),
                respond_config,
                indexer_state.clone(),
            ));

            #[cfg(feature = "tee")] {
                let allowed_docker_images_receiver = monitor_allowed_docker_images(indexer_state.clone()).await;
                tee_sender.send(allowed_docker_images_receiver).expect("Receiver for watcher must be alive");
            }

            let indexer_result = listen_blocks(
                stream,
                indexer_config.concurrency,
                Arc::clone(&stats),
                indexer_config.mpc_contract_id,
                block_update_sender,
            )
            .await;

            if indexer_exit_sender.send(indexer_result).is_err() {
                tracing::error!("Indexer thread could not send result back to main driver.")
            };
        });
    });

    #[cfg(feature = "tee")]
    let allowed_docker_images_receiver = tee_receiver
        .blocking_recv()
        .expect("monitor_allowed_docker_images must be called.");

    IndexerAPI {
        contract_state_receiver: chain_config_receiver,
        block_update_receiver: Arc::new(Mutex::new(block_update_receiver)),
        txn_sender: chain_txn_sender,
        #[cfg(feature = "tee")]
        allowed_docker_images_receiver,
    }
}
