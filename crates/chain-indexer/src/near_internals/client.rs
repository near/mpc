use near_async::{messaging::CanSendAsync, tokio::TokioRuntimeHandle};
use near_client::{Status, client_actor::ClientActorInner};

use std::time::Duration;

const INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone)]
pub struct IndexerClient {
    pub client: TokioRuntimeHandle<ClientActorInner>,
}

impl IndexerClient {
    pub async fn wait_for_full_sync(&self) {
        loop {
            tokio::time::sleep(INTERVAL).await;

            let status_request = Status {
                is_health_check: false,
                detailed: false,
            };
            let status_response = self
                .client
                .send_async(
                    near_o11y::span_wrapped_msg::SpanWrappedMessageExt::span_wrap(status_request),
                )
                .await;

            let Ok(Ok(status)) = status_response else {
                continue;
            };

            if !status.sync_info.syncing {
                return;
            }
        }
    }
}
