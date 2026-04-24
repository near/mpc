use crate::RpcAuthentication;
use async_trait::async_trait;
use foreign_chain_rpc_interfaces::ton::GetTransactionsResponse;
use http::HeaderMap;
use reqwest::Client;
use thiserror::Error;

const GET_TRANSACTIONS_PATH: &str = "transactions";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Trait hiding the concrete HTTP transport so tests can swap in mocks.
#[async_trait]
pub trait TonRpcClient: Send + Sync {
    /// Fetch a single transaction on a given account by hash, with outgoing
    /// messages included.
    ///
    /// toncenter v3 returns `{"transactions": [...]}` even when no transaction
    /// matches; the caller is responsible for interpreting an empty array.
    async fn get_transaction(
        &self,
        workchain: i8,
        account_hash: &[u8; 32],
        tx_hash_hex: &str,
    ) -> Result<GetTransactionsResponse, TonRpcError>;
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
///
/// One instance represents one configured upstream; the MPC node pre-builds
/// a pool of these so request handling only needs to index into the pool.
pub struct ReqwestTonClient {
    base_url: url::Url,
    client: Client,
}

impl ReqwestTonClient {
    /// Construct from a configured base URL and auth kind.
    ///
    /// `base_url` must be the `/api/v3/` root — the caller is responsible for
    /// the trailing slash (consistent with other adapters' config).
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

        let base_url = url::Url::parse(&base_url).map_err(TonRpcError::InvalidUrl)?;

        Ok(Self { base_url, client })
    }
}

#[async_trait]
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
    let mut out = String::with_capacity(4 + 2 * 32);
    out.push_str(&workchain.to_string());
    out.push(':');
    for byte in account_hash {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
}
