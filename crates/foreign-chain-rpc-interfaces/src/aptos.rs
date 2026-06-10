use reqwest::Url;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use std::future::Future;
use std::time::Duration;

/// Response from `GET /v1/transactions/by_hash/{txn_hash}`.
///
/// The Aptos `Transaction` payload is a union discriminated by `type`
/// (`pending_transaction`, `user_transaction`, `genesis_transaction`, …). We keep the
/// discriminant as a plain string (rather than a serde-tagged enum) plus only the fields we
/// verify, so every kind — including ones added to the API later — deserializes and the
/// inspector decides what to do with it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TransactionResponse {
    #[serde(rename = "type")]
    pub transaction_type: String,
    pub hash: String,
    /// `Some` iff committed; `None` for a pending tx.
    #[serde(default)]
    pub success: Option<bool>,
    /// Events in accumulator order; empty for a pending tx.
    #[serde(default)]
    pub events: Vec<AptosEventResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AptosEventResponse {
    pub guid: EventGuid,
    pub sequence_number: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: serde_json::Value,
}

/// For module events, `account_address` is `"0x0"` and `creation_number` is `"0"`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EventGuid {
    pub creation_number: String,
    pub account_address: String,
}

/// Error from the Aptos REST API client.
#[derive(Debug, thiserror::Error)]
pub enum AptosRpcError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Aptos API returned HTTP {status}: {body}")]
    ApiError { status: u16, body: String },
}

/// Client interface for the Aptos REST API v1.
pub trait AptosRpcClient: Send + Sync {
    fn get_transaction_by_hash(
        &self,
        tx_hash_hex: &str,
    ) -> impl Future<Output = Result<TransactionResponse, AptosRpcError>> + Send;
}

#[derive(Clone)]
pub struct ReqwestAptosClient {
    /// REST base including the `/v1` segment; the resource path is appended per request.
    base: Url,
    client: reqwest::Client,
}

impl ReqwestAptosClient {
    /// `auth_header` is installed as a default header (for `Header` auth); `Path`/`Query` auth is
    /// already baked into `base_url` by the caller.
    pub fn new(
        base_url: String,
        auth_header: Option<(HeaderName, HeaderValue)>,
        timeout: Duration,
    ) -> Self {
        let mut headers = HeaderMap::new();
        if let Some((name, value)) = auth_header {
            headers.insert(name, value);
        }
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .build()
            .expect("reqwest client construction with static config should not fail");
        let base = Url::parse(&base_url)
            .expect("Aptos rpc_url is validated as a URL by node-config before reaching here");
        Self { base, client }
    }
}

/// Appends `transactions/by_hash/{hash}` to `base`, preserving its path and query string (so a
/// `/v1` already in `base` isn't doubled, and a query-auth param survives).
fn build_request_url(base: &Url, tx_hash_hex: &str) -> Url {
    let mut url = base.clone();
    url.path_segments_mut()
        .expect("an http(s) base URL always supports path segments")
        .pop_if_empty()
        .extend(["transactions", "by_hash", tx_hash_hex]);
    url
}

impl AptosRpcClient for ReqwestAptosClient {
    fn get_transaction_by_hash(
        &self,
        tx_hash_hex: &str,
    ) -> impl Future<Output = Result<TransactionResponse, AptosRpcError>> + Send {
        let url = build_request_url(&self.base, tx_hash_hex);
        let client = self.client.clone();
        async move {
            let response = client.get(url).send().await?;
            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(AptosRpcError::ApiError {
                    status: status.as_u16(),
                    body,
                });
            }
            let parsed = response.json::<TransactionResponse>().await?;
            Ok(parsed)
        }
    }
}

/// Canonical string form of the event `data`: object keys sorted recursively so all nodes hash
/// identically regardless of provider key ordering.
///
/// TODO: migrate to BCS-encoded responses (via Accept: application/x-bcs) to drop this dependency.
pub fn normalize_event_data(value: &serde_json::Value) -> String {
    serde_json::to_string(&sort_keys(value.clone()))
        .expect("serde_json serialization of Value is infallible")
}

fn sort_keys(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_keys(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect();
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_keys).collect())
        }
        other => other,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn build_request_url__appends_resource_path_to_versioned_base() {
        // Given a base that already includes the `/v1` version segment (as the config provides).
        let base = Url::parse("https://fullnode.mainnet.aptoslabs.com/v1").unwrap();

        // When
        let url = build_request_url(&base, "0xabc");

        // Then — the version segment is not doubled.
        assert_eq!(
            url.as_str(),
            "https://fullnode.mainnet.aptoslabs.com/v1/transactions/by_hash/0xabc"
        );
    }

    #[test]
    fn build_request_url__handles_trailing_slash_in_base() {
        // Given a base with a trailing slash (as in the node-config fixtures).
        let base = Url::parse("https://aptos-mainnet.nodereal.io/v1/").unwrap();

        // When
        let url = build_request_url(&base, "0xabc");

        // Then — no empty path segment, no doubled `/v1`.
        assert_eq!(
            url.as_str(),
            "https://aptos-mainnet.nodereal.io/v1/transactions/by_hash/0xabc"
        );
    }

    #[test]
    fn build_request_url__preserves_query_auth_param() {
        // Given a base carrying a query-auth param (as produced by `auth_config_to_rpc_auth`).
        let base = Url::parse("https://host/v1?api_key=secret").unwrap();

        // When
        let url = build_request_url(&base, "0xabc");

        // Then — the resource path is inserted into the path, leaving the query intact.
        assert_eq!(
            url.as_str(),
            "https://host/v1/transactions/by_hash/0xabc?api_key=secret"
        );
    }

    #[test]
    fn deserialize_transaction__should_parse_committed_user_transaction_with_type_tag() {
        // Given — a vanilla fullnode response: tagged with `type`, full field set, plus
        // request/gas fields (sender, payload, …) which we ignore.
        let json = serde_json::json!({
            "type": "user_transaction",
            "hash": "0xabcdef1234",
            "sender": "0x1",
            "sequence_number": "7",
            "gas_used": "57",
            "success": true,
            "vm_status": "Executed successfully",
            "version": "12345",
            "events": [
                {
                    "guid": {
                        "creation_number": "0",
                        "account_address": "0x0"
                    },
                    "sequence_number": "0",
                    "type": "0x1::omni_bridge::InitTransfer",
                    "data": { "amount": "100" }
                }
            ]
        });

        // When
        let tx: TransactionResponse = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(tx.transaction_type, "user_transaction");
        assert_eq!(tx.success, Some(true));
        assert_eq!(tx.hash, "0xabcdef1234");
        assert_eq!(tx.events.len(), 1);
        assert_eq!(tx.events[0].event_type, "0x1::omni_bridge::InitTransfer");
    }

    #[test]
    fn deserialize_transaction__should_parse_non_user_transaction_kind() {
        // Given — a committed system transaction kind. It must deserialize like any other
        // committed kind rather than erroring on parse.
        let json = serde_json::json!({
            "type": "block_metadata_transaction",
            "hash": "0xbe9e71",
            "epoch": "7510",
            "round": "42",
            "success": true,
            "vm_status": "Executed successfully",
            "events": []
        });

        // When
        let tx: TransactionResponse = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(tx.transaction_type, "block_metadata_transaction");
    }

    #[test]
    fn deserialize_transaction__should_parse_pending_transaction_without_execution_fields() {
        // Given — a pending_transaction has no success/version/events, only the request fields.
        // The previous strict DTO would fail to deserialize this entirely.
        let json = serde_json::json!({
            "type": "pending_transaction",
            "hash": "0xabcdef1234",
            "sender": "0x1",
            "sequence_number": "7",
            "max_gas_amount": "100000",
            "gas_unit_price": "100",
            "expiration_timestamp_secs": "1700000000",
            "payload": { "type": "entry_function_payload" },
            "signature": { "type": "ed25519_signature" }
        });

        // When
        let tx: TransactionResponse = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(tx.transaction_type, "pending_transaction");
        assert_eq!(tx.success, None);
        assert!(tx.events.is_empty());
    }

    #[test]
    fn normalize_event_data__should_sort_object_keys() {
        // Given
        let value = serde_json::json!({ "z": 1, "a": 2, "m": 3 });

        // When
        let normalized = normalize_event_data(&value);

        // Then
        assert_eq!(normalized, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn normalize_event_data__should_sort_nested_object_keys() {
        // Given
        let value = serde_json::json!({ "outer_b": { "inner_z": 9, "inner_a": 1 }, "outer_a": 0 });

        // When
        let normalized = normalize_event_data(&value);

        // Then
        assert_eq!(
            normalized,
            r#"{"outer_a":0,"outer_b":{"inner_a":1,"inner_z":9}}"#
        );
    }
}
