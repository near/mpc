use near_account_id::AccountId;

use crate::errors::{ChainGatewayError, NearClientError, NearViewClientError};
use crate::near_internals_wrapper::{ClientWrapper, ViewClientWrapper};
use crate::primitives::{IsSyncing, QueryViewFunction};
use crate::state_viewer::{SubscribeContractState, ViewContract, ViewMethod};
use crate::types::ObservedState;

#[derive(Clone)]
pub struct ChainGateway {
    /// For querying blockchain state.
    view_client: ViewClientWrapper,
    /// For querying blockchain sync status.
    client: ClientWrapper,
}

impl ViewContract for ChainGateway {}
impl SubscribeContractState for ChainGateway {}
impl ViewMethod for ChainGateway {}

impl IsSyncing for ChainGateway {
    type Error = NearClientError;
    async fn is_syncing(&self) -> Result<bool, Self::Error> {
        self.client.is_syncing().await
    }
}

impl QueryViewFunction for ChainGateway {
    type Error = NearViewClientError;
    async fn query_view_function(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ObservedState, Self::Error> {
        self.view_client
            .query_view_function(contract_id, method_name, args)
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
