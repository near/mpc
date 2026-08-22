use std::error::Error;

use near_account_id::AccountId;
use near_contract_transport::{ObservedState, ViewContract};
use near_kit::{Near, RpcError as NearKitRpcError};
use near_mpc_contract_interface::client::{MpcContractHandle, MpcContractHandleError};
use near_mpc_contract_interface::types::ProtocolContractState;

use crate::ports::ReadContractState;

pub struct RpcStateReader(Near);

impl RpcStateReader {
    pub fn new(rpc_url: &str, near_chain_id: &str) -> Self {
        Self(Near::custom(rpc_url, near_chain_id).build())
    }
}

impl ViewContract for RpcStateReader {
    type Error = RpcError;
    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: near_contract_transport::ViewArgs,
    ) -> Result<near_contract_transport::ObservedState<Vec<u8>>, Self::Error> {
        match self
            .0
            .rpc()
            .view_function(
                contract_id,
                &view_args.method_name,
                &view_args.args,
                near_kit::BlockReference::Finality(near_kit::Finality::Final),
            )
            .await
        {
            Ok(res) => Ok(ObservedState {
                observed_at: res.block_height.into(),
                value: res.result,
            }),
            Err(err) => Err(RpcError(describe(&err))),
        }
    }
}

impl ReadContractState for MpcContractHandle<RpcStateReader> {
    type Error = MpcContractHandleError<RpcError>;
    async fn get_contract_state(&self) -> Result<ProtocolContractState, Self::Error> {
        self.state().await.map(|success| success.value)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("contract state view call failed: {0}")]
pub struct RpcError(String);

/// `reqwest` writes the request url, which is where an api key lives, into both the [`Display`](std::fmt::Display) and
/// the [`Debug`] of its errors, so its own text is dropped in favour of the causes below it, which do
/// not know the url. Every other variant carries text `near_kit` authored itself.
fn describe(err: &near_kit::RpcError) -> String {
    if matches!(err, NearKitRpcError::Http(_)) {
        let below_reqwest = Error::source(err).and_then(Error::source);
        match below_reqwest {
            Some(cause) => format!("http transport error: {cause:?}"),
            None => "http transport error".to_owned(),
        }
    } else {
        err.to_string()
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

        let reader = MpcContractHandle::new(
            RpcStateReader::new(
                &format!("http://127.0.0.1:{port}/?apikey={API_KEY}"),
                "mainnet",
            ),
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
