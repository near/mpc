use super::handler::listen_blocks;
use super::participants::{monitor_chain_state, ContractState};
use super::stats::{indexer_logger, IndexerStats};
use super::tx_sender::handle_txn_requests;
use super::{IndexerAPI, IndexerState};
use crate::config::{
    load_listening_blocks_file, load_respond_config_file, IndexerConfig, RespondConfigFile,
};
use near_crypto::SecretKey;
use near_sdk::AccountId;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::sync::CancellationToken;
pub async fn check_block_processing(
    cancellation_token: CancellationToken,
    process_blocks: Arc<AtomicBool>,
    home_dir: PathBuf,
) {
    loop {
        tokio::select! {
            _ = cancellation_token.cancelled() => {
                println!("File watcher task received cancellation signal.");
                return;
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                match load_listening_blocks_file(&home_dir) {
                    Ok(new_val) => {
                        tracing::info!("flag file found, setting to {}", new_val);
                        process_blocks.store(new_val, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::info!("flag file not found, setting to {}. Error: {}", true, e);
                        process_blocks.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
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
    indexer_exit_sender: oneshot::Sender<anyhow::Result<()>>,
) -> IndexerAPI {
    let (chain_config_sender, chain_config_receiver) =
        tokio::sync::watch::channel::<ContractState>(ContractState::WaitingForSync);
    let (block_update_sender, block_update_receiver) = mpsc::unbounded_channel();
    let (chain_txn_sender, chain_txn_receiver) = mpsc::channel(10000);

    // TODO(#156): replace actix with tokio
    std::thread::spawn(move || {
        actix::System::new().block_on(async {
            let indexer =
                near_indexer::Indexer::new(indexer_config.to_near_indexer_config(home_dir.clone()))
                    .expect("Failed to initialize the Indexer");
            let respond_config = match load_respond_config_file(&home_dir) {
                Ok(Some(respond_config)) => respond_config,
                Ok(None) => {
                    tracing::warn!("No respond.yaml provided. Using the node's main account to send respond transactions.");
                    RespondConfigFile {
                        account_id: my_near_account_id.clone(),
                        access_keys: vec![account_secret_key.clone()],
                    }
                }
                Err(err) => {
                    panic!("respond.yaml is provided but failed to parse: {err:?}");
                }
            };
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

            let process_blocks = Arc::new(AtomicBool::new(true));
            let cancel_token_blocks_processing = CancellationToken::new();
            actix::spawn(check_block_processing(cancel_token_blocks_processing.clone(), process_blocks.clone(), home_dir));
            actix::spawn(monitor_chain_state(
                indexer_state.clone(),
                indexer_config.port_override,
                chain_config_sender,
            ));
            actix::spawn(indexer_logger(Arc::clone(&stats), indexer_state.view_client.clone()));
            actix::spawn(handle_txn_requests(
                chain_txn_receiver,
                my_near_account_id,
                account_secret_key.clone(),
                respond_config,
                indexer_state.clone(),
            ));
            let indexer_result = listen_blocks(
                stream,
                indexer_config.concurrency,
                Arc::clone(&stats),
                indexer_config.mpc_contract_id,
                block_update_sender,
                process_blocks,
            )
            .await;

            if indexer_exit_sender.send(indexer_result).is_err() {
                tracing::error!("Indexer thread could not send result back to main driver.")
            };
        });
    });

    IndexerAPI {
        contract_state_receiver: chain_config_receiver,
        block_update_receiver: Arc::new(Mutex::new(block_update_receiver)),
        txn_sender: chain_txn_sender,
    }
}
