mod client;
mod errors;
mod rpc;
mod view_client;

pub(crate) use client::ClientWrapper;
pub(crate) use rpc::RpcHandlerWrapper;
pub(crate) use view_client::ViewClientWrapper;
pub(crate) use view_client::ViewFunctionCall;

//use near_account_id::AccountId;
//use near_indexer::{self};
//use std::sync::Arc;
//use tokio::sync::{Mutex, mpsc};
//
//use crate::errors::{self};
//use crate::near_internals_wrapper::client::ClientWrapper;
//use crate::near_internals_wrapper::rpc::RpcHandlerWrapper;
//use crate::near_internals_wrapper::view_client::ViewClientWrapper;
//use crate::near_internals_wrapper::view_client::ViewFunctionCall;
//use crate::stats::IndexerStats;
//
//pub(crate) struct ChainGateway {
//    /// For querying blockchain state.
//    view_client: ViewClientWrapper,
//    /// For querying blockchain sync status.
//    client: ClientWrapper,
//    /// For sending txs to the chain.
//    rpc_handler: RpcHandlerWrapper,
//    /// Stores runtime indexing statistics.
//    stats: Arc<Mutex<IndexerStats>>,
//}
//
//impl ChainGateway {
//    // todo: remove this method soon. Stats should be internal to this crate
//    pub fn stats(&self) -> Arc<Mutex<IndexerStats>> {
//        self.stats.clone()
//    }
//    pub async fn wait_for_full_sync(&self) {
//        self.client.wait_for_full_sync().await
//    }
//
//    pub async fn latest_final_block(
//        &self,
//    ) -> Result<near_indexer_primitives::views::BlockView, errors::ChainGatewayError> {
//        self.view_client.latest_final_block().await.map_err(|err| {
//            errors::ChainGatewayError::ViewClient {
//                op: errors::ChainGatewayOp::FetchFinalBlock,
//                source: Box::new(err),
//            }
//        })
//    }
//
//    pub async fn submit_tx(
//        &self,
//        transaction: near_indexer::near_primitives::transaction::SignedTransaction,
//    ) -> Result<(), errors::ChainGatewayError> {
//        self.rpc_handler
//            .submit_tx(transaction)
//            .await
//            .map_err(|err| errors::ChainGatewayError::RpcClient {
//                source: Box::new(err),
//            })
//    }
//
//    pub async fn function_query(
//        &self,
//        account_id: &AccountId,
//        method_name: &str,
//        args: Vec<u8>,
//    ) -> Result<(u64, Vec<u8>), errors::ChainGatewayError> {
//        self.view_client
//            .view_function_query(&ViewFunctionCall {
//                account_id: account_id.clone(),
//                method_name: method_name.to_string(),
//                args,
//            })
//            .await
//            .map_err(|err| errors::ChainGatewayError::ViewClient {
//                // note: not sure we need to log account_id and method name here. It can be read in                // the boxed error
//                // todo: no crate::errors
//                op: errors::ChainGatewayOp::ViewCall {
//                    account_id: account_id.to_string(),
//                    method_name: method_name.to_string(),
//                },
//                source: Box::new(err),
//            })
//    }
//}
//
///// todo: return error
//pub async fn start_with_streamer(
//    config: near_indexer::IndexerConfig,
//) -> Result<(ChainGateway, mpsc::Receiver<near_indexer::StreamerMessage>), errors::ChainGatewayError>
//{
//    let near_config = config.load_near_config().map_err(|err| {
//        errors::ChainGatewayError::FailureLoadingConfig {
//            msg: err.to_string(),
//        }
//    })?;
//
//    let near_node = near_indexer::Indexer::start_near_node(&config, near_config.clone())
//        .await
//        .map_err(|err| errors::ChainGatewayError::StartupFailed {
//            msg: err.to_string(),
//        })?;
//
//    let indexer = near_indexer::Indexer::from_near_node(config, near_config, &near_node);
//
//    let stream = indexer.streamer();
//
//    Ok((
//        ChainGateway {
//            view_client: ViewClientWrapper::new(near_node.view_client),
//            client: ClientWrapper::new(near_node.client),
//            rpc_handler: RpcHandlerWrapper::new(near_node.rpc_handler),
//            stats: Arc::new(Mutex::new(IndexerStats::new())),
//        },
//        stream,
//    ))
//}
