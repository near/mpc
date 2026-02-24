use super::contract_state_viewer::{spawn_subscriber, MpcContractStateViewer};
use super::handler::listen_blocks;
use super::migrations::{monitor_migrations, ContractMigrationInfo};
use super::participants::monitor_contract_state;
use super::{IndexerAPI, IndexerState, RealForeignChainPolicyReader};
#[cfg(feature = "network-hardship-simulation")]
use crate::config::load_listening_blocks_file;
use crate::config::{IndexerConfig, RespondConfig};
use crate::indexer::tee::{
    monitor_allowed_docker_images, monitor_allowed_launcher_compose_hashes, monitor_tee_accounts,
};
use crate::indexer::tx_sender::{TransactionProcessorHandle, TransactionSender};
use chain_gateway::chain_gateway::{start_with_streamer, NoArgs};
use ed25519_dalek::{SigningKey, VerifyingKey};
use mpc_contract::state::ProtocolContractState;
use near_account_id::AccountId;
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
#[allow(clippy::too_many_arguments)]
pub fn spawn_real_indexer(
    home_dir: PathBuf,
    mpc_indexer_config: IndexerConfig,
    my_near_account_id: AccountId,
    account_secret_key: SigningKey,
    respond_config: RespondConfig,
    indexer_exit_sender: oneshot::Sender<anyhow::Result<()>>,
    protocol_state_sender: watch::Sender<ProtocolContractState>,
    migration_state_sender: watch::Sender<(u64, ContractMigrationInfo)>,
    tls_public_key: VerifyingKey,
) -> IndexerAPI<impl TransactionSender, RealForeignChainPolicyReader> {
    let (contract_state_sender_oneshot, contract_state_receiver_oneshot) = oneshot::channel();
    let (migration_info_sender_oneshot, migration_info_receiver_oneshot) = oneshot::channel();
    let (foreign_chain_policy_reader_sender, foreign_chain_policy_reader_receiver) =
        oneshot::channel();

    let (block_update_sender, block_update_receiver) = mpsc::unbounded_channel();
    let (allowed_docker_images_sender, allowed_docker_images_receiver) = watch::channel(vec![]);
    let (allowed_launcher_compose_sender, allowed_launcher_compose_receiver) =
        watch::channel(vec![]);
    let (tee_accounts_sender, tee_accounts_receiver) = watch::channel(vec![]);

    let my_near_account_id_clone = my_near_account_id.clone();
    let respond_config_clone = respond_config.clone();

    let (txn_sender_sender, txn_sender_receiver) = oneshot::channel();

    std::thread::spawn(move || {
        // TODO(#1515): limit number of worker threads? Assume not as we don't want the node to fall behind
        let indexer_tokio_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime must be constructable on startup");

        // TODO(#1515): Clean this entire function up eventually.
        // We have this indirection of using a oneshot for sending the indexer state,
        // as we can't block the main thread for waiting on the `txn_sender`.
        // Thus we instead initialize a `txn_sender`, which runs as a spawned task, to await on the indexer state being ready.
        indexer_tokio_runtime.block_on(async {
            let near_indexer_config = mpc_indexer_config.to_near_indexer_config(home_dir.clone());
            let (chain_gateway, stream) = start_with_streamer(near_indexer_config)
                .await
                .expect("indexer startup must succeed");

            let state_viewer = chain_gateway.viewer();
            let mpc_contract_id = mpc_indexer_config.mpc_contract_id.clone();
            let mpc_contract_state_viewer =
                MpcContractStateViewer::new(mpc_contract_id.clone(), state_viewer);
            let transaction_sender = chain_gateway.transaction_sender();

            let indexer_state = Arc::new(IndexerState::new(chain_gateway, mpc_contract_id.clone()));

            let txn_sender_result = TransactionProcessorHandle::start_transaction_processor(
                my_near_account_id_clone,
                account_secret_key.clone(),
                respond_config_clone,
                indexer_state.mpc_contract_id.clone(),
                mpc_contract_state_viewer.clone(),
                transaction_sender.into(),
            );

            let Ok(txn_sender) = txn_sender_result else {
                tracing::error!("Failed to start transaction processor. Exiting indexer.");
                let _ = indexer_exit_sender.send(txn_sender_result.map(|_| ()));
                return;
            };

            if txn_sender_sender.send(txn_sender).is_err() {
                tracing::error!("Failed to send txn_sender back to main thread.")
            };

            let foreign_chain_policy_reader =
                RealForeignChainPolicyReader::new(mpc_contract_state_viewer.clone());
            if foreign_chain_policy_reader_sender
                .send(foreign_chain_policy_reader)
                .is_err()
            {
                tracing::error!("failed to send foreign chain policy reader back to main thread")
            };

            #[cfg(feature = "network-hardship-simulation")]
            let process_blocks_receiver = {
                let (process_blocks_sender, process_blocks_receiver) = watch::channel(true);
                tokio::spawn(check_block_processing(process_blocks_sender, home_dir));
                process_blocks_receiver
            };

            //tokio::spawn(indexer_logger(Arc::clone(&indexer_state)));

            // mpc_contract_state_viewer.monitor_allowed_docker_images(allowed_docker_images_sender);
            spawn_subscriber(
                allowed_docker_images_sender,
                indexer_state.clone(),
                contract_interface::method_names::ALLOWED_DOCKER_IMAGE_HASHES,
                &NoArgs {},
            );
            //tokio::spawn(monitor_allowed_docker_images(
            //    allowed_docker_images_sender,
            //    indexer_state.clone(),
            //));

            // mpc_contract_state_viewer.monitor_allowed_launcher_compose_hashes(allowed_launcher_compose_sender);
            spawn_subscriber(
                allowed_launcher_compose_sender,
                indexer_state.clone(),
                contract_interface::method_names::ALLOWED_LAUNCHER_COMPOSE_HASHES,
                &NoArgs {},
            );
            //tokio::spawn(monitor_allowed_launcher_compose_hashes(
            //    allowed_launcher_compose_sender,
            //    mpc_contract_state_viewer.clone(),
            //));

            // mpc_contract_state_viewer.monitor_tee_accounts(tee_accounts_sender);
            // underneath the hood, you can have a generic method to avoid code duplication
            spawn_subscriber(
                tee_accounts_sender,
                indexer_state.clone(),
                contract_interface::method_names::GET_TEE_ACCOUNTS,
                &NoArgs {},
            );
            //tokio::spawn(monitor_tee_accounts(
            //    tee_accounts_sender,
            //    mpc_contract_state_viewer.clone(),
            //));

            //  let contract_state_receiver = mpc_contract_state_viewer.monitor_contract_state(protocol_state_sender).await;
            // Returns once the contract state is available.
            // todo
            let contract_state_receiver = monitor_contract_state(
                mpc_contract_state_viewer.clone(),
                mpc_indexer_config.port_override,
                protocol_state_sender,
            )
            .await;

            if contract_state_sender_oneshot
                .send(contract_state_receiver)
                .is_err()
            {
                tracing::error!(
                    "Indexer thread could not send contract state receiver back to main driver."
                )
            };

            // todo
            // let my_migration_info_receiver = mpc_contract_state_viewer.monitor_migrations().await;
            let my_migration_info_receiver = monitor_migrations(
                mpc_contract_state_viewer.clone(),
                migration_state_sender,
                my_near_account_id,
                tls_public_key,
            )
            .await;

            if migration_info_sender_oneshot
                .send(my_migration_info_receiver)
                .is_err()
            {
                tracing::error!(
                    "Indexer thread could not send migration info receiver back to main driver."
                )
            };

            // below function runs indefinitely and only returns in case of an error.
            #[cfg(feature = "network-hardship-simulation")]
            let indexer_result = listen_blocks(
                stream,
                mpc_indexer_config.concurrency,
                Arc::clone(&indexer_state.chain_gateway.stats()),
                mpc_indexer_config.mpc_contract_id,
                block_update_sender,
                process_blocks_receiver,
            )
            .await;

            #[cfg(not(feature = "network-hardship-simulation"))]
            let indexer_result = listen_blocks(
                stream,
                mpc_indexer_config.concurrency,
                Arc::clone(&indexer_state.chain_gateway.stats()),
                mpc_indexer_config.mpc_contract_id,
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

    let contract_state_receiver = contract_state_receiver_oneshot
        .blocking_recv()
        .expect("Contract state receiver must be returned by indexer.");

    let my_migration_info_receiver = migration_info_receiver_oneshot
        .blocking_recv()
        .expect("Migraration info receiver must be returned by indexer.");

    let foreign_chain_policy_reader = foreign_chain_policy_reader_receiver
        .blocking_recv()
        .expect("foreign chain policy reader must be returned by indexer");

    IndexerAPI {
        contract_state_receiver,
        block_update_receiver: Arc::new(Mutex::new(block_update_receiver)),
        txn_sender,
        allowed_docker_images_receiver,
        allowed_launcher_compose_receiver,
        attested_nodes_receiver: tee_accounts_receiver,
        my_migration_info_receiver,
        foreign_chain_policy_reader,
    }
}
