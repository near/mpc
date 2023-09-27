pub mod error;
pub mod msg;

use anyhow::Context;
use hyper::{Body, Client, Method, Request};
use near_crypto::PublicKey;
use near_jsonrpc_client::JsonRpcClient;
use near_primitives::hash::CryptoHash;
use near_primitives::types::{AccountId, BlockHeight, Nonce};
use near_primitives::views::FinalExecutionStatus;

use self::error::RelayerError;
use self::msg::{
    CreateAccountAtomicRequest, RegisterAccountRequest, SendMetaTxRequest, SendMetaTxResponse,
};

use crate::firewall::allowed::DelegateActionRelayer;
use crate::nar::{self, CachedAccessKeyNonces};

pub struct NearRpcAndRelayerClient {
    rpc_client: JsonRpcClient,
    cached_nonces: CachedAccessKeyNonces,
}

impl NearRpcAndRelayerClient {
    pub fn connect(near_rpc: &str) -> Self {
        Self {
            rpc_client: JsonRpcClient::connect(near_rpc),
            cached_nonces: Default::default(),
        }
    }

    pub async fn access_key(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Result<(CryptoHash, BlockHeight, Nonce), RelayerError> {
        nar::fetch_tx_nonce(
            &self.cached_nonces,
            &self.rpc_client,
            &(account_id, public_key),
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(account_id = request.account_id.to_string()))]
    pub async fn register_account(
        &self,
        request: RegisterAccountRequest,
        relayer: DelegateActionRelayer,
    ) -> Result<(), RelayerError> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/register_account", relayer.url))
            .header("content-type", "application/json");

        if let Some(api_key) = relayer.api_key {
            req = req.header("x-api-key", api_key);
        };

        let request = req
            .body(Body::from(
                serde_json::to_vec(&request)
                    .map_err(|e| RelayerError::DataConversionFailure(e.into()))?,
            ))
            .map_err(|e| RelayerError::NetworkFailure(e.into()))?;

        tracing::debug!("constructed http request to {}", relayer.url);
        let client = Client::new();
        let response = client
            .request(request)
            .await
            .map_err(|e| RelayerError::NetworkFailure(e.into()))?;

        let status = response.status();
        let response_body = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|e| RelayerError::NetworkFailure(e.into()))?;
        let msg = std::str::from_utf8(&response_body)
            .map_err(|e| RelayerError::DataConversionFailure(e.into()))?;

        if status.is_success() {
            tracing::debug!("success: {msg}");
            Ok(())
        } else {
            Err(RelayerError::RequestFailure(status, msg.to_string()))
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(account_id = request.account_id.to_string()))]
    pub async fn create_account_atomic(
        &self,
        request: CreateAccountAtomicRequest,
        relayer: DelegateActionRelayer,
    ) -> Result<(), RelayerError> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/create_account_atomic", relayer.url))
            .header("content-type", "application/json");

        if let Some(api_key) = relayer.api_key {
            req = req.header("x-api-key", api_key);
        };

        let request = req
            .body(Body::from(
                serde_json::to_vec(&request)
                    .map_err(|e| RelayerError::DataConversionFailure(e.into()))?,
            ))
            .map_err(|e| RelayerError::NetworkFailure(e.into()))?;

        tracing::debug!("constructed http request to {}", relayer.url);
        let client = Client::new();
        let response = client
            .request(request)
            .await
            .map_err(|e| RelayerError::NetworkFailure(e.into()))?;

        let status = response.status();
        let response_body = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|e| RelayerError::NetworkFailure(e.into()))?;
        let msg = std::str::from_utf8(&response_body)
            .map_err(|e| RelayerError::DataConversionFailure(e.into()))?;

        if status.is_success() {
            tracing::debug!(response_body = msg, "got response");
            Ok(())
        } else {
            Err(RelayerError::RequestFailure(status, msg.to_string()))
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(receiver_id = request.delegate_action.receiver_id.to_string()))]
    pub async fn send_meta_tx(
        &self,
        request: SendMetaTxRequest,
        relayer: DelegateActionRelayer,
    ) -> Result<SendMetaTxResponse, RelayerError> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/send_meta_tx", relayer.url))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&request)
                    .map_err(|e| RelayerError::DataConversionFailure(e.into()))?,
            ))
            .context("failed to construct send_meta_tx request")
            .map_err(RelayerError::NetworkFailure)?;

        tracing::debug!("constructed http request to {}", relayer.url);
        let client = Client::new();
        let response = client
            .request(request)
            .await
            .context("failed to send send_meta_tx request to relayer")
            .map_err(RelayerError::NetworkFailure)?;
        let status = response.status();
        let response_body = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|e| RelayerError::NetworkFailure(e.into()))?;
        let msg = std::str::from_utf8(&response_body)
            .map_err(|e| RelayerError::DataConversionFailure(e.into()))?;

        if status.is_success() {
            tracing::debug!(response_body = msg, "got response");
            let response: SendMetaTxResponse = serde_json::from_slice(&response_body)
                .map_err(|e| RelayerError::DataConversionFailure(e.into()))?;
            match response.status {
                FinalExecutionStatus::NotStarted | FinalExecutionStatus::Started => {
                    Err(RelayerError::TxNotReady)
                }
                FinalExecutionStatus::Failure(e) => Err(RelayerError::TxExecutionFailure(e)),
                FinalExecutionStatus::SuccessValue(ref value) => {
                    tracing::debug!(
                        value = std::str::from_utf8(value)
                            .map_err(|e| RelayerError::DataConversionFailure(e.into()))?,
                        "success"
                    );
                    Ok(response)
                }
            }
        } else {
            Err(RelayerError::RequestFailure(status, msg.to_string()))
        }
    }

    pub(crate) async fn invalidate_cache_if_acc_creation_failed(
        &self,
        cache_key: &(AccountId, PublicKey),
        err_str: &str,
    ) {
        nar::invalidate_nonce_if_tx_failed(&self.cached_nonces, cache_key, err_str).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTNET_URL: &str = "https://rpc.testnet.near.org";

    #[tokio::test]
    async fn test_access_key() -> anyhow::Result<()> {
        let testnet = NearRpcAndRelayerClient::connect(TESTNET_URL);
        let (block_hash, block_height, nonce) = testnet
            .access_key(
                "dev-1636354824855-78504059330123".parse()?,
                "ed25519:8n5HXTibTDtXKAnEUPFUXXJoKqa5A1c2vWXt6LbRAcGn".parse()?,
            )
            .await?;

        assert_eq!(block_hash.0.len(), 32);
        assert!(block_height > 0);
        // Assuming no one will use this account ever again
        assert_eq!(nonce, 70526114000003);
        Ok(())
    }
}
