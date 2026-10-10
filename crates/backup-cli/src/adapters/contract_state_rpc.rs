use std::time::Duration;

use near_account_id::AccountId;
use near_contract_transport::{
    Json, NearKitCaller, NearKitViewError, PollInterval, TransportError, ViewArgs, ViewContract,
};
use near_kit::Near;
use near_kit::transaction::Final;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::ProtocolContractState;

use crate::ports::ReadContractState;

/// Reads the MPC contract's `state` view method from a NEAR JSON-RPC endpoint.
pub struct RpcContractStateReader {
    client: NearKitCaller<Final>,
    contract_id: AccountId,
}

impl RpcContractStateReader {
    pub fn new(
        rpc_url: &str,
        chain_id: &str,
        contract_id: AccountId,
        poll_interval: PollInterval,
        read_timeout: Duration,
    ) -> Self {
        let near = Near::custom(rpc_url, chain_id).build();
        Self {
            client: NearKitCaller::new(near, poll_interval, read_timeout),
            contract_id,
        }
    }
}

impl ReadContractState for RpcContractStateReader {
    type Error = TransportError<NearKitViewError>;
    async fn get_contract_state(&self) -> Result<ProtocolContractState, Self::Error> {
        let observed = self
            .client
            .view::<ProtocolContractState, Json>(
                self.contract_id.clone(),
                ViewArgs::no_args(method_names::STATE),
            )
            .await?;
        Ok(observed.value)
    }
}
