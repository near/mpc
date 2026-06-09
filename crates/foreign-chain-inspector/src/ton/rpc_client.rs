use crate::{RpcAuthentication, ton::types::TonWorkchain};
use foreign_chain_rpc_interfaces::ton::GetTransactionsResponse;
use http::HeaderMap;
use reqwest::Client;
use std::future::Future;
use thiserror::Error;

const GET_TRANSACTIONS_PATH: &str = "transactions";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Query-parameter names for the v3 `/transactions` endpoint.
const ACCOUNT_QUERY_PARAM: &str = "account";
const HASH_QUERY_PARAM: &str = "hash";
const INCLUDE_MSGS_QUERY_PARAM: &str = "include_msgs";
const LIMIT_QUERY_PARAM: &str = "limit";

/// We need the message bodies (the ext-out log payloads), so request them.
const INCLUDE_MSGS_VALUE: &str = "true";
/// A transaction is uniquely identified by `account` + `hash`, so a single
/// result is all we ever expect or need.
const LIMIT_VALUE: &str = "1";

pub trait TonRpcClient: Send + Sync {
    /// Fetch the transaction identified by `tx_hash_hex` on `account_hash`
    /// (within `workchain`) from the TON HTTP API v3 `/transactions` endpoint.
    fn get_transaction(
        &self,
        workchain: TonWorkchain,
        account_hash: &[u8; 32],
        tx_hash_hex: &str,
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
}

/// `reqwest`-based [`TonRpcClient`] implementation.
pub struct ReqwestTonClient {
    base_url: url::Url,
    client: Client,
}

impl ReqwestTonClient {
    /// Construct from a configured base URL and auth kind.
    ///
    /// `base_url` should be the `/api/v3/` root. A trailing slash is appended
    /// if missing — without it, `Url::join("transactions")` would drop the
    /// last path segment (`/api/v3` + `transactions` = `/api/transactions`).
    pub fn new(base_url: String, auth: RpcAuthentication) -> Result<Self, TonRpcError> {
        let mut headers = HeaderMap::new();
        match auth {
            RpcAuthentication::KeyInUrl => {}
            RpcAuthentication::CustomHeader {
                header_name,
                header_value,
            } => {
                headers.insert(header_name, header_value);
            }
        }

        let client = Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .map_err(TonRpcError::Http)?;

        let mut base_url = url::Url::parse(&base_url).map_err(TonRpcError::InvalidUrl)?;
        if !base_url.path().ends_with('/') {
            let normalized = format!("{}/", base_url.path());
            base_url.set_path(&normalized);
        }

        Ok(Self { base_url, client })
    }
}

impl TonRpcClient for ReqwestTonClient {
    async fn get_transaction(
        &self,
        workchain: TonWorkchain,
        account_hash: &[u8; 32],
        tx_hash_hex: &str,
    ) -> Result<GetTransactionsResponse, TonRpcError> {
        // The v3 API treats `account` and `hash` case-insensitively. We build a
        // canonical lowercase form (hex of the raw bytes) so every node issues
        // a byte-identical request and providers/caches behave deterministically.
        // Cross-node consensus itself is reached on the extracted `TonLog`
        // (canonicalized via `normalize_body_boc`), not on the raw response.
        let account = format_ton_account(workchain, account_hash);
        let url = build_get_transactions_url(&self.base_url, &account, tx_hash_hex);

        let response = self.client.get(url).send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(TonRpcError::BadStatus {
                status: status.as_u16(),
                body,
            });
        }

        let bytes = response.bytes().await?;
        serde_json::from_slice::<GetTransactionsResponse>(&bytes).map_err(TonRpcError::Parse)
    }
}

/// Format a basechain/workchain address as `"<workchain>:<lowercase-hex>"` —
/// the canonical on-chain representation the v3 API accepts in its query
/// parameters.
pub(crate) fn format_ton_account(workchain: TonWorkchain, account_hash: &[u8; 32]) -> String {
    format!("{workchain}:{}", hex::encode(account_hash))
}

/// Build the `GET /api/v3/transactions?...` URL.
///
/// Uses `set_path` rather than `Url::join` so any pre-existing query string
/// on the base URL (e.g. `?api_key=...` for query-param auth flows) is
/// preserved — `Url::join` clears the base's query per RFC 3986 §5.3.
fn build_get_transactions_url(base_url: &url::Url, account: &str, tx_hash_hex: &str) -> url::Url {
    let mut url = base_url.clone();
    let new_path = format!("{}{}", url.path(), GET_TRANSACTIONS_PATH);
    url.set_path(&new_path);
    url.query_pairs_mut()
        .append_pair(ACCOUNT_QUERY_PARAM, account)
        .append_pair(HASH_QUERY_PARAM, tx_hash_hex)
        .append_pair(INCLUDE_MSGS_QUERY_PARAM, INCLUDE_MSGS_VALUE)
        .append_pair(LIMIT_QUERY_PARAM, LIMIT_VALUE);
    url
}

/// Build a [`ReqwestTonClient`] — the TON analog of
/// [`crate::build_http_client`] for jsonrpsee chains.
pub fn build_ton_http_client(
    base_url: String,
    auth: RpcAuthentication,
) -> Result<ReqwestTonClient, TonRpcError> {
    ReqwestTonClient::new(base_url, auth)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn format_ton_account__should_emit_lowercase_hex_for_workchain_0() {
        let hash = [0xab; 32];
        let got = format_ton_account(TonWorkchain::Basechain, &hash);
        assert_eq!(
            got,
            "0:abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn build_get_transactions_url__should_append_trailing_slash_when_missing() {
        // Without normalization in `new()`, path concatenation would produce
        // `/api/v3transactions` (no separator).
        let client = ReqwestTonClient::new(
            "https://example.invalid/api/v3".to_string(),
            RpcAuthentication::KeyInUrl,
        )
        .expect("valid base url");
        let url = build_get_transactions_url(&client.base_url, "0:aa", "deadbeef");
        assert_eq!(url.path(), "/api/v3/transactions");
    }

    #[test]
    fn build_get_transactions_url__should_preserve_existing_trailing_slash() {
        let client = ReqwestTonClient::new(
            "https://example.invalid/api/v3/".to_string(),
            RpcAuthentication::KeyInUrl,
        )
        .expect("valid base url");
        let url = build_get_transactions_url(&client.base_url, "0:aa", "deadbeef");
        assert_eq!(url.path(), "/api/v3/transactions");
    }

    #[test]
    fn build_get_transactions_url__should_preserve_pre_existing_query_string() {
        // Operators may embed query-param auth (e.g. `?api_key=...`) on the
        // base URL when configuring `KeyInUrl`. `Url::join` would drop it; we
        // must not.
        let client = ReqwestTonClient::new(
            "https://example.invalid/api/v3/?api_key=secret".to_string(),
            RpcAuthentication::KeyInUrl,
        )
        .expect("valid base url");
        let url = build_get_transactions_url(&client.base_url, "0:aa", "deadbeef");
        let pairs: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
        assert_eq!(pairs.get("api_key").map(|v| v.as_ref()), Some("secret"));
        assert_eq!(pairs.get("account").map(|v| v.as_ref()), Some("0:aa"));
        assert_eq!(pairs.get("hash").map(|v| v.as_ref()), Some("deadbeef"));
        assert_eq!(pairs.get("include_msgs").map(|v| v.as_ref()), Some("true"));
        assert_eq!(pairs.get("limit").map(|v| v.as_ref()), Some("1"));
    }
}
