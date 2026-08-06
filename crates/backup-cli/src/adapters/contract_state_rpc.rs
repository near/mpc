use std::error::Error;

use near_account_id::AccountId;
use near_kit::{Error as NearKitError, Near, RpcError as NearKitRpcError};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::ProtocolContractState;

use crate::ports::ReadContractState;

/// Reads the MPC contract's `state` view method from a NEAR JSON-RPC endpoint.
pub struct RpcContractStateReader {
    client: Near,
    contract_id: AccountId,
}

impl RpcContractStateReader {
    pub fn new(rpc_url: &str, chain_id: &str, contract_id: AccountId) -> Self {
        Self {
            client: Near::custom(rpc_url, chain_id).build(),
            contract_id,
        }
    }
}

impl ReadContractState for RpcContractStateReader {
    type Error = RpcError;

    async fn get_contract_state(&self) -> Result<ProtocolContractState, Self::Error> {
        self.client
            .view::<ProtocolContractState>(&self.contract_id, method_names::STATE)
            .await
            .map_err(|err| RpcError(describe(&err)))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("contract state view call failed: {0}")]
pub struct RpcError(String);

/// `reqwest` writes the request url, which is where an api key lives, into both the [`Display`](std::fmt::Display) and
/// the [`Debug`] of its errors, so its own text is dropped in favour of the causes below it, which do
/// not know the url. Every other variant carries text `near_kit` authored itself.
fn describe(err: &NearKitError) -> String {
    match err {
        NearKitError::Rpc(rpc) if matches!(rpc.as_ref(), NearKitRpcError::Http(_)) => {
            let below_reqwest = Error::source(rpc.as_ref()).and_then(Error::source);
            match below_reqwest {
                Some(cause) => format!("http transport error: {cause:?}"),
                None => "http transport error".to_owned(),
            }
        }
        _ => err.to_string(),
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    use tokio::net::TcpListener;

    const API_KEY: &str = "d0n0tl0gme";

    #[tokio::test]
    async fn get_contract_state__should_not_report_the_api_key_of_a_failing_endpoint() {
        // Given
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let reader = RpcContractStateReader::new(
            &format!("http://127.0.0.1:{port}/?apikey={API_KEY}"),
            "mainnet",
            "v1.signer".parse().unwrap(),
        );

        // When
        let err = reader
            .get_contract_state()
            .await
            .expect_err("a hung up endpoint should fail the read");

        // Then
        assert!(
            !format!("{err}").contains(API_KEY),
            "api key must not be rendered: {err}"
        );
        assert!(
            !format!("{err:?}").contains(API_KEY),
            "api key must not be rendered: {err:?}"
        );
    }
}
