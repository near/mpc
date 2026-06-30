use std::sync::Arc;

use near_async::messaging::CanSendAsync as _;

use crate::{
    errors::NearClientError,
    primitives::{IsSyncing, SyncStatus},
};

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
    async fn sync_status(&self) -> Result<SyncStatus, Self::Error> {
        // `detailed: true` so the response carries connected-peer heights, which
        // we use to confirm the head has actually caught up.
        let status_request = near_client::Status {
            is_health_check: false,
            detailed: true,
        };
        let status = self
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
        let max_peer_height = status.detailed_debug_status.as_ref().and_then(|detailed| {
            detailed
                .network_info
                .connected_peers
                .iter()
                .filter_map(|peer| peer.height)
                .max()
        });
        Ok(SyncStatus {
            syncing: status.sync_info.syncing,
            head_height: status.sync_info.latest_block_height,
            max_peer_height,
        })
    }
}
