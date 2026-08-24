use std::error::Error;
use std::time::Duration;

use near_account_id::AccountId;
use near_contract_transport::{ObservedState, PollInterval, ViewArgs, ViewContract};
use near_kit::{Near, RpcError as NearKitRpcError};
use tokio::time::timeout;

#[derive(Clone)]
pub struct RpcStateReader {
    near: Near,
    poll_interval: Duration,
    request_timeout: Duration,
}

impl RpcStateReader {
    pub fn new(
        rpc_url: &str,
        near_chain_id: &str,
        poll_interval: Duration,
        request_timeout: Duration,
    ) -> Self {
        Self {
            near: Near::custom(rpc_url, near_chain_id).build(),
            poll_interval,
            request_timeout,
        }
    }
}

impl PollInterval for RpcStateReader {
    fn poll_interval(&self) -> Duration {
        self.poll_interval
    }
}

impl ViewContract for RpcStateReader {
    type Error = RpcError;
    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<ObservedState, Self::Error> {
        let call = self.near.rpc().view_function(
            contract_id,
            &view_args.method_name,
            &view_args.args,
            near_kit::BlockReference::Finality(near_kit::Finality::Final),
        );

        match timeout(self.request_timeout, call).await {
            Err(_elapsed) => Err(RpcError::Timeout(self.request_timeout)),
            Ok(Ok(res)) => Ok(ObservedState {
                observed_at: res.block_height.into(),
                value: res.result,
            }),
            Ok(Err(err)) => Err(RpcError::View(describe(&err))),
        }
    }
}

/// `Clone`, `PartialEq` and `Eq` are what let a subscription hold this in its
/// watch channel and notify once per distinct failure rather than once per read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    #[error("contract state view call failed: {0}")]
    View(String),
    #[error("contract state view call did not finish within {0:?}")]
    Timeout(Duration),
}

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

    use near_mpc_contract_interface::client::MpcContractHandle;
    use tokio::net::TcpListener;

    const API_KEY: &str = "d0n0tl0gme";
    const TEST_POLL_INTERVAL: Duration = Duration::from_secs(60);
    const TEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

    #[tokio::test]
    async fn view_contract__should_not_report_the_api_key_of_a_failing_endpoint() {
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
                TEST_POLL_INTERVAL,
                TEST_REQUEST_TIMEOUT,
            ),
            "v1.signer".parse().unwrap(),
        );

        // When
        let err = reader
            .state()
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
