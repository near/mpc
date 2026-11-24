use std::sync::Arc;

use near_async::messaging::CanSendAsync as _;
use near_indexer::near_primitives::views::{StatusResponse, StatusSyncInfo};
use near_indexer_primitives::CryptoHash;

use crate::{errors::NearClientError, primitives::IsSyncing};

/// Arc-wrapper around near-internal struct
#[derive(Clone)]
pub(crate) struct NearClientActorHandle {
    client: Arc<near_async::tokio::TokioRuntimeHandle<near_client::client_actor::ClientActor>>,
}

impl NearClientActorHandle {
    pub(crate) fn new(
        client: near_async::tokio::TokioRuntimeHandle<near_client::client_actor::ClientActor>,
    ) -> Self {
        Self {
            client: Arc::new(client),
        }
    }
}

/// Implement IsSyncing for our near client
impl IsSyncing for NearClientActorHandle {
    type Error = NearClientError;
    async fn is_syncing(&self) -> Result<bool, Self::Error> {
        Ok(self.sync_info().await?.syncing)
    }
}

impl NearClientActorHandle {
    pub(crate) async fn genesis_hash(&self) -> Result<CryptoHash, NearClientError> {
        Ok(self.status().await?.genesis_hash)
    }

    /// Part of the [`crate::nearcore_workarounds`]: can be merged back into
    /// [`IsSyncing::is_syncing`] once <https://github.com/near/nearcore/issues/16004> is resolved.
    pub(crate) async fn sync_info(&self) -> Result<StatusSyncInfo, NearClientError> {
        Ok(self.status().await?.sync_info)
    }

    async fn status(&self) -> Result<StatusResponse, NearClientError> {
        let status_request = near_client::Status {
            is_health_check: false,
            detailed: false,
        };
        self.client
            .send_async(
                near_o11y::span_wrapped_msg::SpanWrappedMessageExt::span_wrap(status_request),
            )
            .await
            .map_err(|err| NearClientError::AsyncSendError {
                message: err.to_string(),
            })?
            .map_err(|err| NearClientError::ResponseError {
                message: err.to_string(),
            })
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl NearClientActorHandle {
    pub(crate) async fn knows_producer(
        &self,
        account_id: &near_indexer::near_primitives::types::AccountId,
    ) -> Result<bool, NearClientError> {
        let network_info = self
            .client
            .send_async(
                near_o11y::span_wrapped_msg::SpanWrappedMessageExt::span_wrap(
                    near_client::GetNetworkInfo {},
                ),
            )
            .await
            .map_err(|err| NearClientError::AsyncSendError {
                message: err.to_string(),
            })?
            .map_err(|message| NearClientError::ResponseError { message })?;
        Ok(network_info
            .known_producers
            .iter()
            .any(|producer| &producer.account_id == account_id))
    }
}
