use std::sync::Arc;

use super::errors::ClientError;

#[derive(Clone)]
pub(crate) struct ClientWrapper {
    client: near_async::tokio::TokioRuntimeHandle<near_client::client_actor::ClientActorInner>,
}

impl ClientWrapper {
    pub(crate) fn new(
        client: near_async::tokio::TokioRuntimeHandle<near_client::client_actor::ClientActorInner>,
    ) -> Self {
        Self { client }
    }

    pub(crate) async fn is_syncing(&self) -> Result<bool, ClientError> {
        let status_request = near_client::Status {
            is_health_check: false,
            detailed: false,
        };
        // todo: log errors
        let status = near_async::messaging::CanSendAsync::send_async(
            &self.client,
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

    pub(crate) async fn wait_for_full_sync(&self) {
        const INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
        loop {
            tokio::time::sleep(INTERVAL).await;
            match self.is_syncing().await {
                Ok(is_syncing) => {
                    if !is_syncing {
                        return;
                    }
                    tracing::info!("wating for full sync");
                }
                Err(err) => {
                    tracing::warn!(err = %err, "error while waiting for sync");
                }
            }
        }
    }
}
