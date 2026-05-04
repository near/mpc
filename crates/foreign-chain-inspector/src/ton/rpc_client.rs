use crate::RpcAuthentication;
use foreign_chain_rpc_interfaces::ton::GetTransactionsResponse;
use http::HeaderMap;
use reqwest::Client;
use std::future::Future;
use thiserror::Error;

const GET_TRANSACTIONS_PATH: &str = "transactions";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Trait hiding the concrete HTTP transport so tests can swap in mocks.
pub trait TonRpcClient: Send + Sync {
    /// Fetch a single transaction on a given account by hash, with outgoing
    /// messages included. The response always carries a `transactions` array;
    /// an empty array means no transaction matched the lookup.
    fn get_transaction(
        &self,
        workchain: i8,
        account_hash: &[u8; 32],
        tx_hash_hex: &str,
    ) -> impl Future<Output = Result<GetTransactionsResponse, TonRpcError>> + Send;
}

/// Errors raised by [`ReqwestTonClient`].
#[derive(Debug, Error)]
pub enum TonRpcError {
    #[error("failed to build toncenter request URL: {0}")]
    InvalidUrl(url::ParseError),

    #[error("toncenter HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("toncenter returned non-success HTTP status {status}: {body}")]
    BadStatus { status: u16, body: String },

    #[error("failed to parse toncenter JSON response: {0}")]
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
        workchain: i8,
        account_hash: &[u8; 32],
        tx_hash_hex: &str,
    ) -> Result<GetTransactionsResponse, TonRpcError> {
        let mut url = self
            .base_url
            .join(GET_TRANSACTIONS_PATH)
            .map_err(TonRpcError::InvalidUrl)?;
        // toncenter accepts `account=<workchain>:<hex>` and `hash=<hex>`.
        // We send lowercase hex for determinism across the node fleet (the
        // RPC treats case-insensitively but nodes compare response bytes).
        let account = format_ton_account(workchain, account_hash);
        url.query_pairs_mut()
            .append_pair("account", &account)
            .append_pair("hash", tx_hash_hex)
            .append_pair("include_msgs", "true")
            .append_pair("limit", "1");

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
/// the canonical on-chain representation toncenter v3 accepts in its query
/// parameters.
pub(crate) fn format_ton_account(workchain: i8, account_hash: &[u8; 32]) -> String {
    format!("{workchain}:{}", hex::encode(account_hash))
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
        let got = format_ton_account(0, &hash);
        assert_eq!(
            got,
            "0:abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn format_ton_account__should_emit_minus_1_for_masterchain() {
        let hash = [0x00; 32];
        let got = format_ton_account(-1, &hash);
        assert!(got.starts_with("-1:"));
    }

    #[test]
    fn new__should_append_trailing_slash_when_missing() {
        // Without normalization, `Url::join("transactions")` would replace the
        // last segment of `/api/v3` and produce `/api/transactions`.
        let client = ReqwestTonClient::new(
            "https://example.invalid/api/v3".to_string(),
            RpcAuthentication::KeyInUrl,
        )
        .expect("valid base url");
        let joined = client.base_url.join(GET_TRANSACTIONS_PATH).unwrap();
        assert_eq!(joined.path(), "/api/v3/transactions");
    }

    #[test]
    fn new__should_preserve_existing_trailing_slash() {
        let client = ReqwestTonClient::new(
            "https://example.invalid/api/v3/".to_string(),
            RpcAuthentication::KeyInUrl,
        )
        .expect("valid base url");
        let joined = client.base_url.join(GET_TRANSACTIONS_PATH).unwrap();
        assert_eq!(joined.path(), "/api/v3/transactions");
    }
}
