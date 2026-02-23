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
            source: Box::new(err),
        })?
        .map_err(|err| ClientError::ResponseError {
            source: Box::new(err),
        })?;
        Ok(status.sync_info.syncing)
    }
}
