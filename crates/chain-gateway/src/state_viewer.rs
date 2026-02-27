use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::near_internals_wrapper::{
    BlockHeight, ClientWrapper, ViewClientWrapper, ViewFunctionCall, ViewOutput,
};
use async_trait::async_trait;
use near_account_id::AccountId;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct StateViewer {
    /// For querying blockchain sync status.
    pub(crate) client: Arc<ClientWrapper>,
    /// for viewing state
    pub(crate) view_client: Arc<ViewClientWrapper>,
}

impl StateViewer {
    pub async fn subscribe<Arg: Serialize, Res: DeserializeOwned + Send + Clone>(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> Result<impl ContractStateStream<Res>, ChainGatewayError> {
        ContractMethodSubscription::new::<Arg>(self.clone(), contract_id, method_name, args).await
    }

    pub(crate) async fn view_raw(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Result<ViewOutput, ChainGatewayError> {
        self.client.wait_for_full_sync().await;
        let response = self
            .view_client
            .view_function_query(&ViewFunctionCall {
                account_id: contract_id.clone(),
                method_name: method_name.to_string(),
                args,
            })
            .await
            .map_err(|err| ChainGatewayError::ViewClient {
                // note: not sure we need to log account_id and method name here. It can be read in the boxed error
                op: ChainGatewayOp::ViewCall {
                    account_id: contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Arc::new(err),
            })?;
        Ok(response)
    }

    pub async fn view<Arg, Res>(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> Result<(BlockHeight, Res), ChainGatewayError>
    where
        Arg: Serialize,
        Res: DeserializeOwned,
    {
        let args: Vec<u8> = serde_json::to_string(args)
            .map_err(|err| ChainGatewayError::Serialization {
                op: ChainGatewayOp::ViewCall {
                    account_id: contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Arc::new(err),
            })?
            .into_bytes();
        let res = self
            .view_raw(contract_id.clone(), method_name, args)
            .await?;
        let value = serde_json::from_slice::<Res>(&res.value).map_err(|err| {
            ChainGatewayError::Deserialization {
                source: Arc::new(err),
            }
        })?;
        Ok((res.block_height, value))
    }
}

#[async_trait]
pub trait ContractStateStream<Res> {
    /// returns the last value observed on chain [Res] and the block height at which it last changed
    /// labels the value as seen
    fn latest(&mut self) -> Result<(BlockHeight, Res), ChainGatewayError>;
    /// returns if the value of type `Res` has changed
    async fn changed(&mut self) -> Result<(), ChainGatewayError>;
}

pub(crate) struct ContractMethodSubscription<Res> {
    _task_handle: JoinHandle<()>,
    cancel_token: CancellationToken,
    cached: Result<(BlockHeight, Res), ChainGatewayError>,
    last_observed: tokio::sync::watch::Receiver<Result<ObservedState, ChainGatewayError>>,
}

#[async_trait]
impl<Res> ContractStateStream<Res> for ContractMethodSubscription<Res>
where
    Res: DeserializeOwned + Send + Clone,
{
    async fn changed(&mut self) -> Result<(), ChainGatewayError> {
        self.last_observed
            .changed()
            .await
            .map_err(|_| ChainGatewayError::MonitoringClosed)?;
        Ok(())
    }

    fn latest(&mut self) -> Result<(BlockHeight, Res), ChainGatewayError> {
        if self
            .last_observed
            .has_changed()
            .map_err(|_| ChainGatewayError::MonitoringClosed)?
        {
            let observed_or_error = self.last_observed.borrow_and_update().clone();
            let wrapped = match observed_or_error {
                Ok(value) => match serde_json::from_slice::<Res>(&value.value) {
                    Ok(res) => Ok((value.last_changed_height, res)),
                    Err(err) => Err(ChainGatewayError::Deserialization {
                        source: Arc::new(err),
                    }),
                },
                Err(err) => Err(err),
            };
            self.cached = wrapped;
        }
        self.cached.clone()
    }
}

impl<Res> Drop for ContractMethodSubscription<Res> {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl<Res> ContractMethodSubscription<Res>
where
    Res: DeserializeOwned,
{
    pub(crate) async fn new<Arg: Serialize>(
        state_viewer: StateViewer,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> Result<Self, ChainGatewayError> {
        tracing::debug!(contract_id=?contract_id, method_name=?method_name, "setting up snapshot");
        let args: Vec<u8> = serde_json::to_string(args)
            .map_err(|err| ChainGatewayError::Serialization {
                op: ChainGatewayOp::ViewCall {
                    account_id: contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Arc::new(err),
            })?
            .into_bytes();
        let val = state_viewer
            .view_raw(contract_id.clone(), method_name, args.clone())
            .await;
        let observed_state: Result<ObservedState, ChainGatewayError> = val.map(|val| val.into());
        let (sender, last_observed) = tokio::sync::watch::channel(observed_state.clone());
        // todo: this might be wrong?
        let cached: Result<(BlockHeight, Res), ChainGatewayError> =
            observed_state.and_then(|value| {
                let deser_value = serde_json::from_slice::<Res>(&value.value).map_err(|err| {
                    ChainGatewayError::Deserialization {
                        source: Arc::new(err),
                    }
                })?;
                Ok((value.last_changed_height, deser_value))
            });

        let cancel_token = CancellationToken::new();
        let _task_handle = tokio::spawn(monitor(
            state_viewer,
            contract_id,
            method_name.to_string(),
            args,
            sender,
            cancel_token.clone(),
        ));

        Ok(Self {
            _task_handle,
            cancel_token,
            cached,
            last_observed,
        })
    }
}

#[derive(Clone)]
struct ObservedState {
    pub last_changed_height: BlockHeight,
    pub value: Vec<u8>,
}

impl From<ViewOutput> for ObservedState {
    fn from(value: ViewOutput) -> Self {
        Self {
            last_changed_height: value.block_height,
            value: value.value,
        }
    }
}

async fn monitor(
    state_viewer: StateViewer,
    contract_id: AccountId,
    method_name: String,
    args: Vec<u8>,
    sender: tokio::sync::watch::Sender<Result<ObservedState, ChainGatewayError>>,
    cancel: CancellationToken,
) {
    const POLL_INTERVAL: Duration = Duration::from_millis(200);
    fn modify(
        existing: &mut Result<ObservedState, ChainGatewayError>,
        new: Result<ViewOutput, ChainGatewayError>,
    ) -> bool {
        let value_changed = match (&existing, &new) {
            (Ok(prev_res), Ok(curr_res)) => prev_res.value != curr_res.value,
            (Err(prev_err), Err(curr_err)) => prev_err.to_string() != curr_err.to_string(),
            _ => true,
        };
        if value_changed {
            *existing = new.map(|value| ObservedState {
                last_changed_height: value.block_height,
                value: value.value,
            });
        }
        value_changed
    }

    let mut ticker = tokio::time::interval(POLL_INTERVAL);

    ticker.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!(
                    contract_id = ?contract_id,
                    method_name = ?method_name,
                    "contract monitoring task cancelled"
                );
                break;
            }
            _ = ticker.tick() => {
                let val = state_viewer
                    .view_raw(contract_id.clone(), &method_name, args.clone())
                    .await;

                if sender.send_if_modified(|existing| modify(existing, val)) {
                    tracing::debug!(
                        contract_id = ?contract_id,
                        method_name = ?method_name,
                        "updated value"
                    );
                    //break;
                }
            }
        }
    }
}
