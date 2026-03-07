use std::sync::Arc;

use async_trait::async_trait;
use near_async::messaging::CanSendAsync;

use crate::{near_internals_wrapper::errors::ClientError, primitives::SyncChecker};

#[derive(Clone)]
pub(crate) struct ClientWrapper {
    client: Arc<near_async::tokio::TokioRuntimeHandle<near_client::client_actor::ClientActorInner>>,
}

impl ClientWrapper {
    pub(crate) fn new(
        client: near_async::tokio::TokioRuntimeHandle<near_client::client_actor::ClientActorInner>,
    ) -> Self {
        Self {
            client: Arc::new(client),
        }
    }
}

#[async_trait]
impl SyncChecker for ClientWrapper {
    type Error = ClientError;
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
            .map_err(|err| ClientError::AsyncSendError {
                source: Arc::new(err),
            })?
            .map_err(|err| ClientError::ResponseError {
                source: Arc::new(err),
            })?;
        Ok(status.sync_info.syncing)
    }
}
