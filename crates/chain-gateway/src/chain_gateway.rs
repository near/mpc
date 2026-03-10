use near_account_id::AccountId;

use crate::errors::{ChainGatewayError, NearClientError, NearViewClientError};
use crate::near_internals_wrapper::{ClientWrapper, ViewClientWrapper};
use crate::primitives::{SyncChecker, ViewFunctionQuerySubmitter};
use crate::state_viewer::{ContractStateSubscriber, ContractViewer, MethodViewer};
use crate::types::RawObservedState;

#[derive(Clone)]
pub struct ChainGateway {
    /// For querying blockchain state.
    view_client: ViewClientWrapper,
    /// For querying blockchain sync status.
    client: ClientWrapper,
}

impl ContractViewer for ChainGateway {}
impl ContractStateSubscriber for ChainGateway {}
impl MethodViewer for ChainGateway {}

impl SyncChecker for ChainGateway {
    type Error = NearClientError;
    async fn is_syncing(&self) -> Result<bool, Self::Error> {
        self.client.is_syncing().await
    }
}

impl ViewFunctionQuerySubmitter for ChainGateway {
    type Error = NearViewClientError;
    async fn view_function_query(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<RawObservedState, Self::Error> {
        self.view_client
            .view_function_query(contract_id, method_name, args)
            .await
    }
}

pub async fn start(config: near_indexer::IndexerConfig) -> Result<ChainGateway, ChainGatewayError> {
    let near_config =
        config
            .load_near_config()
            .map_err(|err| ChainGatewayError::FailureLoadingConfig {
                msg: err.to_string(),
            })?;

    let near_node = near_indexer::Indexer::start_near_node(&config, near_config)
        .await
        .map_err(|err| ChainGatewayError::StartupFailed {
            msg: err.to_string(),
        })?;

    let view_client = ViewClientWrapper::new(near_node.view_client);
    let client = ClientWrapper::new(near_node.client);

    Ok(ChainGateway {
        view_client,
        client,
    })
}
