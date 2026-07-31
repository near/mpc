#![allow(non_snake_case)]

//! Integration tests for [`ForeignChainInspectionError::classify_rpc_client_error`], which decides
//! whether a provider failed to answer, answered and refused, or answered unusably.

use assert_matches::assert_matches;
use foreign_chain_inspector::{BlockConfirmations, ForeignChainInspectionError, ProviderFailure};
use jsonrpsee::core::client::error::Error as RpcClientError;
use jsonrpsee::core::http_helpers::HttpError;
use jsonrpsee::http_client::transport::Error as TransportError;
use rstest::rstest;

fn transport(error: TransportError) -> RpcClientError {
    RpcClientError::Transport(Box::new(error))
}

#[rstest]
#[case(400)]
#[case(401)]
#[case(403)]
#[case(404)]
fn classify_rpc_client_error__should_report_a_deterministic_status_as_a_refusal(
    #[case] status_code: u16,
) {
    // Given
    let error = transport(TransportError::Rejected { status_code });

    // When
    let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

    // Then
    assert_matches!(
        &classified,
        ForeignChainInspectionError::RpcRequestRejected(_)
    );
    assert!(!classified.is_transient());
}

#[rstest]
#[case(408)]
#[case(429)]
#[case(500)]
#[case(503)]
fn classify_rpc_client_error__should_report_a_retryable_status_as_a_transient_failure(
    #[case] status_code: u16,
) {
    // Given
    let error = transport(TransportError::Rejected { status_code });

    // When
    let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

    // Then
    assert_matches!(
        &classified,
        ForeignChainInspectionError::RpcRequestFailed(_)
    );
    assert!(classified.is_transient());
}

#[test]
fn classify_rpc_client_error__should_report_a_jsonrpc_error_object_as_a_refusal() {
    // Given the answer an authenticated provider gives to a request it will not serve
    let error = RpcClientError::Call(jsonrpsee::types::ErrorObject::owned(
        -32600,
        "Must be authenticated!",
        None::<()>,
    ));

    // When
    let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

    // Then
    assert_matches!(
        &classified,
        ForeignChainInspectionError::RpcRequestRejected(_)
    );
    assert!(!classified.is_transient());
}

#[test]
fn classify_rpc_client_error__should_report_an_unparseable_result_as_malformed() {
    // Given
    let parse_error = serde_json::from_str::<String>("7").expect_err("a number is not a string");
    let error = RpcClientError::ParseError(parse_error);

    // When
    let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

    // Then
    assert_matches!(
        classified,
        ForeignChainInspectionError::MalformedRpcResponse(_)
    );
}

#[test]
fn classify_rpc_client_error__should_report_a_body_that_is_not_jsonrpc_as_malformed() {
    // Given
    let error = transport(TransportError::Http(HttpError::Malformed));

    // When
    let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

    // Then
    assert_matches!(
        classified,
        ForeignChainInspectionError::MalformedRpcResponse(_)
    );
}

#[test]
fn classify_rpc_client_error__should_report_a_connection_failure_as_transient() {
    // Given
    let error = transport(TransportError::Http(HttpError::Stream(Box::new(
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused"),
    ))));

    // When
    let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

    // Then
    assert_matches!(
        &classified,
        ForeignChainInspectionError::RpcRequestFailed(_)
    );
    assert!(classified.is_transient());
}

#[test]
fn classify_rpc_client_error__should_keep_the_rpc_url_out_of_the_message() {
    // Given a URL a client cannot be built for, as jsonrpsee reports it: with the URL in the text
    let error = transport(TransportError::Url(
        "http://provider.example/v2/super-secret".to_string(),
    ));

    // When
    let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

    // Then the API key spliced into the URL by `Path`/`Query` auth cannot travel with the error
    let rendered = classified.to_string();
    assert!(!rendered.contains("super-secret"), "{rendered}");
}

#[test]
fn classify_rpc_client_error__should_report_a_client_side_timeout_as_a_timeout() {
    // Given
    let error = RpcClientError::RequestTimeout;

    // When
    let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

    // Then
    assert_matches!(classified, ForeignChainInspectionError::Timeout);
}

#[rstest]
#[case(-32005)]
#[case(-32029)]
fn classify_rpc_client_error__should_report_a_rate_limit_code_as_a_transient_failure(
    #[case] code: i32,
) {
    // Given a provider signalling throttling in the error object rather than with a 429
    let error = RpcClientError::Call(jsonrpsee::types::ErrorObject::owned(
        code,
        "limit exceeded",
        None::<()>,
    ));

    // When
    let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

    // Then
    assert_matches!(
        &classified,
        ForeignChainInspectionError::RpcRequestFailed(_)
    );
    assert!(classified.is_transient());
}

#[rstest]
#[case(ForeignChainInspectionError::RpcRequestFailed("_".to_string()), Some(ProviderFailure::Unreachable))]
#[case(ForeignChainInspectionError::RpcRequestRejected("_".to_string()), Some(ProviderFailure::Rejected))]
#[case(ForeignChainInspectionError::Timeout, Some(ProviderFailure::TimedOut))]
#[case(ForeignChainInspectionError::MalformedRpcResponse("_".to_string()), Some(ProviderFailure::Malformed))]
#[case(
    ForeignChainInspectionError::InspectorResponseMismatch,
    Some(ProviderFailure::Malformed)
)]
// The transaction's own state is an answer, not a fault of the provider that reported it.
#[case(ForeignChainInspectionError::TransactionNotFound, None)]
#[case(ForeignChainInspectionError::TransactionFailed, None)]
#[case(ForeignChainInspectionError::NotFinalized, None)]
#[case(ForeignChainInspectionError::NotEnoughBlockConfirmations {
    expected: BlockConfirmations::from(6),
    got: BlockConfirmations::from(1),
}, None)]
fn provider_failure__should_name_only_the_failures_the_provider_owns(
    #[case] error: ForeignChainInspectionError,
    #[case] expected: Option<ProviderFailure>,
) {
    // When
    let failure = error.provider_failure();

    // Then
    assert_eq!(failure, expected);
}
