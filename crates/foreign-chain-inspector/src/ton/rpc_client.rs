use crate::RpcAuthentication;
use crate::ton::types::{TonAccountHash, TonTransactionHash, TonWorkchain};
use foreign_chain_rpc_interfaces::ton::{GetTransactionsResponse, TonRawAddress};
use reqwest::Client;
use std::future::Future;
use thiserror::Error;

const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Cap on the bytes buffered from a response body, so a misbehaving provider
/// cannot make the node buffer an arbitrarily large payload. Matches the
/// default maximum response size of the `jsonrpsee` clients used by the other
/// chain inspectors.
const MAX_RESPONSE_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Cap on the error-body excerpt embedded in [`TonRpcError::BadStatus`];
/// these end up in logs, so keep them short.
const MAX_ERROR_BODY_BYTES: usize = 1024;

pub trait TonRpcClient: Send + Sync {
    /// Fetch the transaction identified by `tx_hash` on `account` (within
    /// `workchain`) from the TON HTTP API v3 `/transactions` endpoint.
    fn get_transaction(
        &self,
        workchain: TonWorkchain,
        account: TonAccountHash,
        tx_hash: TonTransactionHash,
    ) -> impl Future<Output = Result<GetTransactionsResponse, TonRpcError>> + Send;
}

/// Errors raised by [`ReqwestTonClient`].
#[derive(Debug, Error)]
pub enum TonRpcError {
    #[error("failed to build TON RPC request URL: {0}")]
    InvalidUrl(url::ParseError),

    #[error("TON RPC HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("TON RPC returned non-success HTTP status {status}: {body}")]
    BadStatus { status: u16, body: String },

    #[error("failed to parse TON RPC JSON response: {0}")]
    Parse(serde_json::Error),

    #[error("TON RPC response body exceeds the {limit}-byte limit")]
    ResponseTooLarge { limit: usize },
}

/// `reqwest`-based [`TonRpcClient`] implementation.
#[derive(Clone)]
pub struct ReqwestTonClient {
    transactions_url: url::Url,
    client: Client,
}

impl ReqwestTonClient {
    /// Construct from a configured base URL (the `/api/v3/` root) and auth kind.
    pub fn new(base_url: String, auth: RpcAuthentication) -> Result<Self, TonRpcError> {
        let client = Client::builder()
            .default_headers(auth.into_header_map())
            .timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .map_err(TonRpcError::Http)?;

        Ok(Self {
            transactions_url: transactions_url(&base_url)?,
            client,
        })
    }

    /// The `GET /api/v3/transactions?...` URL for one transaction lookup.
    ///
    /// The v3 API treats `account` and `hash` case-insensitively; both are sent
    /// in a canonical lowercase-hex form so every node issues a byte-identical
    /// request and providers/caches behave deterministically.
    fn request_url(&self, account: &TonRawAddress, tx_hash: TonTransactionHash) -> url::Url {
        let mut url = self.transactions_url.clone();
        url.query_pairs_mut()
            .append_pair("account", &account.to_string())
            .append_pair("hash", &tx_hash.to_string())
            // We need the message bodies (the ext-out log payloads).
            .append_pair("include_msgs", "true")
            // `account` + `hash` uniquely identify the transaction, so a single
            // result is all we ever expect or need.
            .append_pair("limit", "1");
        url
    }
}

/// Join the `transactions` path segment onto the base URL.
///
/// Appends to the path directly rather than via `Url::join`, which would both
/// clear any pre-existing query string (e.g. `?api_key=...` for query-param
/// auth flows) per RFC 3986 §5.3 and drop the last path segment when the base
/// lacks a trailing slash (`/api/v3` + `transactions` = `/api/transactions`).
fn transactions_url(base_url: &str) -> Result<url::Url, TonRpcError> {
    let mut url = url::Url::parse(base_url).map_err(TonRpcError::InvalidUrl)?;
    let path = if url.path().ends_with('/') {
        format!("{}transactions", url.path())
    } else {
        format!("{}/transactions", url.path())
    };
    url.set_path(&path);
    Ok(url)
}

impl TonRpcClient for ReqwestTonClient {
    async fn get_transaction(
        &self,
        workchain: TonWorkchain,
        account: TonAccountHash,
        tx_hash: TonTransactionHash,
    ) -> Result<GetTransactionsResponse, TonRpcError> {
        let account = TonRawAddress {
            workchain: workchain as i8,
            hash: account.into(),
        };
        let url = self.request_url(&account, tx_hash);

        let response = self.client.get(url).send().await?;
        let status = response.status();
        if !status.is_success() {
            // Truncated and lossy: this is a log-friendly excerpt for triage,
            // not data we act on.
            let body = match read_body_limited(response, MAX_ERROR_BODY_BYTES).await {
                Ok(LimitedBody::Complete(bytes) | LimitedBody::Truncated(bytes)) => {
                    String::from_utf8_lossy(&bytes).into_owned()
                }
                Err(_) => String::new(),
            };
            return Err(TonRpcError::BadStatus {
                status: status.as_u16(),
                body,
            });
        }

        match read_body_limited(response, MAX_RESPONSE_SIZE_BYTES).await? {
            // A truncated JSON document must not be parsed.
            LimitedBody::Truncated(_) => Err(TonRpcError::ResponseTooLarge {
                limit: MAX_RESPONSE_SIZE_BYTES,
            }),
            LimitedBody::Complete(bytes) => {
                serde_json::from_slice::<GetTransactionsResponse>(&bytes)
                    .map_err(TonRpcError::Parse)
            }
        }
    }
}

/// A response body buffered up to a byte limit.
enum LimitedBody {
    Complete(Vec<u8>),
    /// The body exceeded the limit; carries the prefix read so far and the
    /// rest of the stream was dropped.
    Truncated(Vec<u8>),
}

/// Buffer at most `limit` bytes of the response body, never holding more than
/// that in memory regardless of what the provider streams.
async fn read_body_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<LimitedBody, reqwest::Error> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let remaining = limit.saturating_sub(bytes.len());
        if chunk.len() > remaining {
            bytes.extend(chunk.iter().take(remaining));
            return Ok(LimitedBody::Truncated(bytes));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(LimitedBody::Complete(bytes))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn transactions_url__should_insert_path_separator_when_trailing_slash_is_missing() {
        // Without the separator, path concatenation would produce
        // `/api/v3transactions`.
        let url = transactions_url("https://example.invalid/api/v3").unwrap();
        assert_eq!(url.path(), "/api/v3/transactions");
    }

    #[test]
    fn transactions_url__should_preserve_existing_trailing_slash() {
        let url = transactions_url("https://example.invalid/api/v3/").unwrap();
        assert_eq!(url.path(), "/api/v3/transactions");
    }

    #[test]
    fn request_url__should_append_canonical_query_parameters() {
        let client = ReqwestTonClient::new(
            "https://example.invalid/api/v3/".to_string(),
            RpcAuthentication::KeyInUrl,
        )
        .expect("valid base url");

        let url = client.request_url(
            &TonRawAddress {
                workchain: 0,
                hash: [0xab; 32],
            },
            TonTransactionHash::new([0xde; 32]),
        );

        let pairs: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
        assert_eq!(
            pairs.get("account").map(|v| v.as_ref()),
            Some("0:abababababababababababababababababababababababababababababababab")
        );
        let expected_hash = "de".repeat(32);
        assert_eq!(
            pairs.get("hash").map(|v| v.as_ref()),
            Some(expected_hash.as_str())
        );
        assert_eq!(pairs.get("include_msgs").map(|v| v.as_ref()), Some("true"));
        assert_eq!(pairs.get("limit").map(|v| v.as_ref()), Some("1"));
    }

    #[test]
    fn request_url__should_preserve_pre_existing_query_string() {
        // Operators may embed query-param auth (e.g. `?api_key=...`) on the
        // base URL when configuring `KeyInUrl`; it must survive the request's
        // own query parameters.
        let client = ReqwestTonClient::new(
            "https://example.invalid/api/v3/?api_key=secret".to_string(),
            RpcAuthentication::KeyInUrl,
        )
        .expect("valid base url");

        let url = client.request_url(
            &TonRawAddress {
                workchain: 0,
                hash: [0xaa; 32],
            },
            TonTransactionHash::new([0xde; 32]),
        );

        let pairs: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
        assert_eq!(pairs.get("api_key").map(|v| v.as_ref()), Some("secret"));
        assert!(pairs.contains_key("account"));
        assert!(pairs.contains_key("hash"));
    }
}
