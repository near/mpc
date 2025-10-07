use super::handler::listen_blocks;
use super::migrations::monitor_migrations;
use super::participants::{monitor_contract_state, ContractState};
use super::stats::indexer_logger;
use super::{IndexerAPI, IndexerState};
#[cfg(feature = "network-hardship-simulation")]
use crate::config::load_listening_blocks_file;
use crate::config::{IndexerConfig, RespondConfig};
use crate::indexer::balances::monitor_balance;
use crate::indexer::tee::monitor_allowed_docker_images;
use crate::indexer::tx_sender::{TransactionProcessorHandle, TransactionSender};
use crate::migration_service::types::MigrationInfo;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mpc_contract::node_migrations::{BackupServiceInfo, DestinationNodeInfo};
use mpc_contract::state::ProtocolContractState;
use near_sdk::AccountId;
use std::collections::BTreeMap;
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

// below function should return tuple: (IndexerAPI, RawContractState)
pub struct RawContractView {
    raw_protocol_state_receiver: watch::Receiver<(u64, ProtocolContractState)>,
    raw_migration_state_receiver: watch::Receiver<(
        u64,
        BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)>,
    )>,
}

pub struct RawContractSend {
    raw_protocol_state_sender: watch::Sender<(u64, ProtocolContractState)>,
    raw_migration_state_sender: watch::Sender<(
        u64,
        BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)>,
    )>,
}

// the information the MPC node needs to know.
pub struct ProcessedMpcContractView {
    contract_state: watch::Receiver<ContractState>,
    migration_state: watch::Receiver<MigrationInfo>,
}

pub struct MpcContractView {
    raw_view: RawContractView,
    // anything that deviates from `RawContractView` and is processed for the MPC node
    processed_view: ProcessedMpcContractView,
}

async fn process_protocol_state(
    mut raw_receiver: watch::Receiver<(u64, ProtocolContractState)>,
    raw_sender: watch::Sender<(u64, ProtocolContractState)>,
    processed_sender: watch::Sender<ContractState>,
    port_override: Option<u16>,
) {
    loop {
        // is there a performance penalty to this?
        let state = raw_receiver.borrow_and_update().clone();
        // if it changed for us, then it also changed for the receiver
        raw_sender.send(state.clone());
        match ContractState::from_contract_state(&state.1, state.0, port_override) {
            Ok(processed_state) => {
                processed_sender.send_if_modified(|watched_state| {
                    if *watched_state != processed_state {
                        *watched_state = processed_state.clone();
                        true
                    } else {
                        false
                    }
                });
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading config from chain: {:?}", e);
            }
        }
        raw_receiver.changed().await;
    }
}

async fn process_migration_state(
    mut raw_receiver: watch::Receiver<(
        u64,
        BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)>,
    )>,
    raw_sender: watch::Sender<(
        u64,
        BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)>,
    )>,
    processed_sender: watch::Sender<MigrationInfo>,
    my_near_account_id: AccountId,
    my_p2p_tls_key: VerifyingKey,
) {
    loop {
        let last_state = raw_receiver.borrow_and_update().clone();
        // if it changed for us, then it also changed for the receiver
        raw_sender.send(last_state.clone());
        let processed =
            MigrationInfo::from_raw_contract(&my_near_account_id, &my_p2p_tls_key, last_state.1);
        processed_sender.send_if_modified(|watched_state| {
            if *watched_state != processed {
                *watched_state = processed;
                true
            } else {
                false
            }
        });
        raw_receiver.changed().await;
    }
}

async fn spawn_processors(
    indexer_state: Arc<IndexerState>,
    raw_contract_sender: RawContractSend,
    port_override: Option<u16>,
    my_near_account_id: AccountId,
    my_p2p_tls_key: VerifyingKey,
) -> ProcessedMpcContractView {
    let raw_protocol_state_receiver = monitor_contract_state(indexer_state.clone()).await;
    let (processed_contract_state_sender, processed_contract_state_receiver) =
        watch::channel(ContractState::Invalid);
    tokio::spawn(process_protocol_state(
        raw_protocol_state_receiver,
        raw_contract_sender.raw_protocol_state_sender,
        processed_contract_state_sender,
        port_override,
    ));

    let raw_migration_state_receiver = monitor_migrations(indexer_state.clone()).await;
    let (processed_migration_satate_sender, processed_migration_state_receiver) =
        watch::channel(MigrationInfo {
            backup_service_info: None,
            active_migration: false,
        });
    tokio::spawn(process_migration_state(
        raw_migration_state_receiver,
        raw_contract_sender.raw_migration_state_sender,
        processed_migration_satate_sender,
        my_near_account_id,
        my_p2p_tls_key,
    ));
    ProcessedMpcContractView {
        contract_state: processed_contract_state_receiver,
        migration_state: processed_migration_state_receiver,
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
    account_secret_key: SigningKey,
    respond_config: RespondConfig,
    indexer_exit_sender: oneshot::Sender<anyhow::Result<()>>,
    raw_contract_sender: RawContractSend,
    //protocol_state_sender: watch::Sender<ProtocolContractState>,
    //migration_state_sender: watch::Sender<BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)>>,
    tls_public_key: VerifyingKey,
) -> IndexerAPI<impl TransactionSender> {
    let (raw_contract_state_sender_oneshot, raw_conrtact_state_receiver_oneshot) =
        oneshot::channel();
    //let (contract_state_sender_oneshot, contract_state_receiver_oneshot) = oneshot::channel();
    //let (migration_info_sender_oneshot, migration_info_receiver_oneshot) = oneshot::channel();

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

            // akin to `write` on the MPC contract
            let txn_sender_result = TransactionProcessorHandle::start_transaction_processor(
                my_near_account_id_clone,
                account_secret_key.clone(),
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

            // note: below functions use tokio::spawn. We are mixing up actix and tokio here. Not
            // sure that's the best thing to do.
            // Returns once the contract state is available.
            let raw_protocol_state_receiver = monitor_contract_state(
                indexer_state.clone(),
                //indexer_config.port_override,
                //protocol_state_sender,
            )
            .await;

            // This feels akward. Like, really akward.
            let raw_migration_state_receiver = monitor_migrations(indexer_state.clone()).await;

            let raw_contract_view = RawContractView{raw_protocol_state_receiver, raw_migration_state_receiver};
            // spawn the processor
            let contract_view = process_contract_view(raw_contract_view).await;
            //actix::spawn(process_contract_view)
            if raw_contract_state_sender_oneshot.send(RawContractView {
                raw_protocol_state_receiver,
                raw_migration_state_receiver,
            }).is_err() {
                tracing::error!(
                    "Indexer thread could not send raw contract state receivers back to main driver."
                )

            };
            //if contract_state_sender_oneshot
            //    .send(contract_state_receiver)
            //    .is_err()
            //{
            //    tracing::error!(
            //        "Indexer thread could not send contract state receiver back to main driver."
            //    )
            //};

            //if migration_info_sender_oneshot
            //    .send(my_migration_info_receiver)
            //    .is_err()
            //{
            //    tracing::error!(
            //        "Indexer thread could not send migration info receiver back to main driver."
            //    )
            //};

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

    let raw_receivers = raw_conrtact_state_receiver_oneshot
        .blocking_recv()
        .expect("Raw contract state receivers must be returned by indexer.");
    //let contract_state_receiver = contract_state_receiver_oneshot
    //    .blocking_recv()
    //    .expect("Contract state receiver must be returned by indexer.");

    //let my_migration_info_receiver = migration_info_receiver_oneshot
    //    .blocking_recv()
    //    .expect("Migraration info receiver must be returned by indexer.");

    IndexerAPI {
        contract_state_receiver,
        block_update_receiver: Arc::new(Mutex::new(block_update_receiver)),
        txn_sender,
        allowed_docker_images_receiver,
        my_migration_info_receiver,
    }
}
