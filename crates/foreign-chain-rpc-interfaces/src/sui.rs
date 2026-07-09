use std::future::Future;
use std::time::Duration;

use http::{HeaderName, HeaderValue};
use sui_rpc::field::{FieldMask, FieldMaskUtil as _};
use sui_rpc::proto::sui::rpc::v2::{
    Checkpoint, ExecutedTransaction, GetCheckpointRequest, GetCheckpointResponse,
    GetServiceInfoRequest, GetServiceInfoResponse, GetTransactionRequest, GetTransactionResponse,
    get_checkpoint_request::CheckpointId,
};

pub use sui_rpc::proto::sui::rpc::v2 as proto;
pub use tonic::{Code, Status};

fn transaction_read_mask() -> FieldMask {
    FieldMask::from_paths([
        ExecutedTransaction::path_builder().digest(),
        ExecutedTransaction::path_builder().checkpoint(),
        ExecutedTransaction::path_builder()
            .effects()
            .status()
            .finish(),
        ExecutedTransaction::path_builder()
            .events()
            .events()
            .package_id(),
        ExecutedTransaction::path_builder()
            .events()
            .events()
            .module(),
        ExecutedTransaction::path_builder()
            .events()
            .events()
            .sender(),
        ExecutedTransaction::path_builder()
            .events()
            .events()
            .event_type(),
        ExecutedTransaction::path_builder()
            .events()
            .events()
            .contents()
            .finish(),
    ])
}

fn checkpoint_read_mask() -> FieldMask {
    FieldMask::from_paths([
        Checkpoint::path_builder().sequence_number(),
        Checkpoint::path_builder().transactions().digest(),
    ])
}

/// Client interface for the Sui gRPC API (`sui.rpc.v2.LedgerService`).
pub trait SuiRpcClient: Send + Sync {
    /// `digest` is the base58-encoded transaction digest.
    fn get_transaction(
        &self,
        digest: &str,
    ) -> impl Future<Output = Result<GetTransactionResponse, Status>> + Send;

    fn get_service_info(
        &self,
    ) -> impl Future<Output = Result<GetServiceInfoResponse, Status>> + Send;

    fn get_checkpoint(
        &self,
        sequence_number: u64,
    ) -> impl Future<Output = Result<GetCheckpointResponse, Status>> + Send;
}

#[derive(Clone)]
pub struct GrpcSuiClient {
    client: sui_rpc::Client,
    timeout: Duration,
}

impl GrpcSuiClient {
    /// `auth_header` is sent with every request (for `Header` auth). gRPC has no notion of
    /// auth in the URL path or query, so header auth is the only supported scheme.
    ///
    /// Must be called within a tokio runtime: the (lazy) channel captures the runtime handle.
    pub fn new(
        url: String,
        auth_header: Option<(HeaderName, HeaderValue)>,
        timeout: Duration,
    ) -> Result<Self, Status> {
        let mut client = sui_rpc::Client::new(url)?;
        if let Some((name, value)) = auth_header {
            let mut header_map = http::HeaderMap::new();
            header_map.insert(name, value);
            let mut headers = sui_rpc::client::HeadersInterceptor::new();
            *headers.headers_mut() = tonic::metadata::MetadataMap::from_headers(header_map);
            client = client.with_headers(headers);
        }
        Ok(Self { client, timeout })
    }

    fn request_with_timeout<T>(&self, message: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(message);
        request.set_timeout(self.timeout);
        request
    }
}

impl SuiRpcClient for GrpcSuiClient {
    fn get_transaction(
        &self,
        digest: &str,
    ) -> impl Future<Output = Result<GetTransactionResponse, Status>> + Send {
        let mut client = self.client.clone();
        let request = self.request_with_timeout(
            GetTransactionRequest::default()
                .with_digest(digest)
                .with_read_mask(transaction_read_mask()),
        );
        async move {
            let response = client.ledger_client().get_transaction(request).await?;
            Ok(response.into_inner())
        }
    }

    fn get_service_info(
        &self,
    ) -> impl Future<Output = Result<GetServiceInfoResponse, Status>> + Send {
        let mut client = self.client.clone();
        let request = self.request_with_timeout(GetServiceInfoRequest::default());
        async move {
            let response = client.ledger_client().get_service_info(request).await?;
            Ok(response.into_inner())
        }
    }

    fn get_checkpoint(
        &self,
        sequence_number: u64,
    ) -> impl Future<Output = Result<GetCheckpointResponse, Status>> + Send {
        let mut client = self.client.clone();
        let mut message = GetCheckpointRequest::default().with_read_mask(checkpoint_read_mask());
        message.checkpoint_id = Some(CheckpointId::SequenceNumber(sequence_number));
        let request = self.request_with_timeout(message);
        async move {
            let response = client.ledger_client().get_checkpoint(request).await?;
            Ok(response.into_inner())
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn grpc_sui_client_new__should_accept_https_url() {
        // Given / When / Then — the channel is lazy, so no connection is made here.
        GrpcSuiClient::new(
            "https://fullnode.mainnet.sui.io".to_string(),
            None,
            Duration::from_secs(5),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn grpc_sui_client_new__should_accept_auth_header() {
        // Given
        let auth_header = Some((
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("secret-token"),
        ));

        // When / Then
        GrpcSuiClient::new(
            "https://sui.example.com".to_string(),
            auth_header,
            Duration::from_secs(5),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn grpc_sui_client_new__should_reject_invalid_url() {
        // Given / When
        let result = GrpcSuiClient::new("not a url".to_string(), None, Duration::from_secs(5));

        // Then
        assert!(result.is_err());
    }

    #[test]
    fn transaction_read_mask__should_request_only_verified_sections() {
        // Then — pins that the typed path builders produce exactly the wire paths the server
        // honors (the live manual test proves those paths return the expected fields), and that
        // the events' `json` rendering is not among them.
        assert_eq!(
            transaction_read_mask().paths,
            vec![
                "digest",
                "checkpoint",
                "effects.status",
                "events.events.package_id",
                "events.events.module",
                "events.events.sender",
                "events.events.event_type",
                "events.events.contents",
            ]
        );
    }

    #[test]
    fn checkpoint_read_mask__should_request_only_probe_sections() {
        // Then
        assert_eq!(
            checkpoint_read_mask().paths,
            vec!["sequence_number", "transactions.digest"]
        );
    }
}
