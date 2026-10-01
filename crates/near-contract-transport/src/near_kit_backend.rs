use std::error::Error;
use std::marker::PhantomData;
use std::time::Duration;

use near_account_id::AccountId;
use near_kit::rpc::{BlockReference, RpcError};
use near_kit::transaction::WaitLevel;

use crate::{
    CallContract, FunctionCallArgs, HasPollInterval, ObservedState, PollInterval,
    SerializedObservation, ViewArgs, ViewContract,
};

/// [`near_kit::Near`] as a call and view backend. `W` is the wait level a call blocks on
/// before returning, which decides its [`CallContract::Output`]; `poll_interval` paces
/// subscriptions and `read_timeout` bounds each view.
pub struct NearKitCaller<W> {
    inner: near_kit::Near,
    poll_interval: PollInterval,
    read_timeout: Duration,
    _wait_level: PhantomData<fn() -> W>,
}

impl<W> NearKitCaller<W> {
    pub fn new(near: near_kit::Near, poll_interval: PollInterval, read_timeout: Duration) -> Self {
        Self {
            inner: near,
            poll_interval,
            read_timeout,
            _wait_level: PhantomData,
        }
    }

    pub fn with_wait_level<U: WaitLevel>(self) -> NearKitCaller<U> {
        NearKitCaller {
            inner: self.inner,
            poll_interval: self.poll_interval,
            read_timeout: self.read_timeout,
            _wait_level: PhantomData,
        }
    }
}

impl<W> Clone for NearKitCaller<W> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            poll_interval: self.poll_interval,
            read_timeout: self.read_timeout,
            _wait_level: PhantomData,
        }
    }
}

impl<W> HasPollInterval for NearKitCaller<W> {
    fn poll_interval(&self) -> PollInterval {
        self.poll_interval
    }
}

impl<W: WaitLevel> CallContract for NearKitCaller<W> {
    type Output = W::Response;
    type Error = near_kit::Error;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        self.inner
            .call(contract_id, &call_args.method_name)
            .args_raw(call_args.args)
            .gas(call_args.gas)
            .deposit(call_args.deposit)
            .finish()
            .wait_until::<W>()
            .await
    }
}

impl<W> ViewContract for NearKitCaller<W> {
    type Error = NearKitViewError;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<SerializedObservation, Self::Error> {
        tokio::time::timeout(
            self.read_timeout,
            self.inner.view_contract(contract_id, view_args),
        )
        .await
        .map_err(|_elapsed| NearKitViewError::Timeout(self.read_timeout))?
    }
}

impl ViewContract for near_kit::Near {
    type Error = NearKitViewError;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<SerializedObservation, Self::Error> {
        let result = self
            .rpc()
            .view_function(
                contract_id,
                &view_args.method_name,
                &view_args.args,
                BlockReference::default(),
            )
            .await?;
        Ok(ObservedState {
            observed_at: result.block_height.into(),
            value: result.result,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NearKitViewError {
    /// [`RpcError`] is neither [`Clone`] nor [`PartialEq`], so only its rendering is kept.
    #[error("{0}")]
    Rpc(String),
    #[error("view did not finish within {0:?}")]
    Timeout(Duration),
}

/// `reqwest` writes the request url, which is where an api key lives, into both the
/// [`Display`](std::fmt::Display) and the [`Debug`] of its errors, so its own text is dropped
/// in favour of the causes below it, which do not know the url. Every other variant carries
/// text `near_kit` authored itself.
impl From<RpcError> for NearKitViewError {
    fn from(err: RpcError) -> Self {
        let text = match &err {
            RpcError::Http(_) => match Error::source(&err).and_then(Error::source) {
                Some(cause) => format!("http transport error: {cause:?}"),
                None => "http transport error".to_owned(),
            },
            _ => err.to_string(),
        };
        Self::Rpc(text)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::time::Duration;

    use near_kit::Near;
    use near_kit::transaction::Final;
    use tokio::net::TcpListener;

    use crate::{PollInterval, ViewArgs, ViewContract};

    use super::{NearKitCaller, NearKitViewError};

    const API_KEY: &str = "d0n0tl0gme";
    const READ_TIMEOUT: Duration = Duration::from_millis(100);

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
        let near = Near::custom(
            format!("http://127.0.0.1:{port}/?apikey={API_KEY}"),
            "mainnet",
        )
        .build();

        // When
        let err = near
            .view_contract(&"v1.signer".parse().unwrap(), ViewArgs::no_args("state"))
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

    #[tokio::test]
    async fn view_contract__should_time_out_when_the_endpoint_never_answers() {
        // Given
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held_open = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held_open.push(stream);
            }
        });
        let caller = NearKitCaller::<Final>::new(
            Near::custom(format!("http://127.0.0.1:{port}"), "mainnet").build(),
            PollInterval::new(Duration::from_secs(1)).unwrap(),
            READ_TIMEOUT,
        );

        // When
        let err = caller
            .view_contract(&"v1.signer".parse().unwrap(), ViewArgs::no_args("state"))
            .await
            .expect_err("a silent endpoint should time out");

        // Then
        assert_eq!(err, NearKitViewError::Timeout(READ_TIMEOUT));
    }
}
