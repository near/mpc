use std::sync::Arc;

use near_async::messaging::CanSendAsync as _;

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
        let status_request = near_client::Status {
            is_health_check: false,
            detailed: false,
        };
        let status = &self
            .client
            .send_async(
                near_o11y::span_wrapped_msg::SpanWrappedMessageExt::span_wrap(status_request),
            )
            .await
            .map_err(|err| NearClientError::AsyncSendError {
                message: err.to_string(),
            })?
            .map_err(|err| NearClientError::ResponseError {
                message: err.to_string(),
            })?;
        Ok(status.sync_info.syncing)
    }
}
