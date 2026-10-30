use std::fmt::Debug;
use std::sync::Arc;

use near_contract_transport::watch::Observed;
use near_mpc_contract_interface::types::ProtocolContractState;
use tokio::sync::watch;
use tokio::sync::watch::error::RecvError;

use crate::ports;

impl<E: Debug + Send + Sync> ports::WatchContractState
    for watch::Receiver<Observed<ProtocolContractState, E>>
{
    type Error = Arc<E>;

    fn latest(&mut self) -> Result<ProtocolContractState, Arc<E>> {
        self.borrow_and_update()
            .clone()
            .map(|observed| observed.result)
    }

    async fn changed(&mut self) -> Result<(), RecvError> {
        watch::Receiver::changed(self).await
    }
}
