use crate::errors::ChainGatewayError;
use async_trait::async_trait;
use near_account_id::AccountId;
use serde::de::DeserializeOwned;

use super::monitoring::{MonitoringTask, make_monitoring_task};
use super::subscription_trait::{ContractStateStream, ObservedState};
use super::viewer_trait::ContractViewer;

/// Holds  a Monitoring task and the latest cached value.
/// This is useful such that we don't unnecessarily deserialze the same state multiple times.
pub(crate) struct ContractMethodSubscription<Res> {
    inner: MonitoringTask,
    cached: Result<ObservedState<Res>, ChainGatewayError>,
}

impl<Res> ContractMethodSubscription<Res>
where
    Res: DeserializeOwned,
{
    fn update_cache(&mut self) {
        let observed = self.inner.last_observed.borrow_and_update().clone();
        self.cached = observed.and_then(|value| value.deserialize());
    }
}

#[async_trait]
impl<Res> ContractStateStream<Res> for ContractMethodSubscription<Res>
where
    Res: DeserializeOwned + Send + Clone,
{
    async fn changed(&mut self) -> Result<(), ChainGatewayError> {
        self.inner
            .last_observed
            .changed()
            .await
            .map_err(|_| ChainGatewayError::MonitoringClosed)?;
        self.update_cache();
        Ok(())
    }

    fn latest(&mut self) -> Result<ObservedState<Res>, ChainGatewayError> {
        if self
            .inner
            .last_observed
            .has_changed()
            .map_err(|_| ChainGatewayError::MonitoringClosed)?
        {
            self.update_cache();
        }
        self.cached.clone()
    }
}

impl<Res> ContractMethodSubscription<Res>
where
    Res: DeserializeOwned,
{
    pub(super) async fn new<V: ContractViewer>(
        viewer: V,
        contract_id: AccountId,
        method_name: &str,
        args: Vec<u8>,
    ) -> Self {
        let mut task = make_monitoring_task(viewer, contract_id, method_name, args).await;
        let cached: Result<ObservedState<Res>, ChainGatewayError> = task
            .last_observed
            .borrow_and_update()
            .clone()
            .and_then(|value| value.deserialize());
        Self {
            inner: task,
            cached,
        }
    }
}
