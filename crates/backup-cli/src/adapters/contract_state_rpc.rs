use near_account_id::AccountId;
use near_kit::Near;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::ProtocolContractState;

use crate::ports::ContractStateReader;

/// Reads the MPC contract's `state` view method from a NEAR JSON-RPC endpoint.
pub struct RpcContractStateReader {
    client: Near,
    contract_id: AccountId,
}

impl RpcContractStateReader {
    /// `rpc_url` may embed a provider api key as a query parameter; `chain_id` is only
    /// relevant for signed transactions, not the view calls made here.
    pub fn new(rpc_url: &str, chain_id: &str, contract_id: AccountId) -> Self {
        Self {
            client: Near::custom(rpc_url, chain_id).build(),
            contract_id,
        }
    }
}

impl ContractStateReader for RpcContractStateReader {
    type Error = anyhow::Error;

    async fn get_contract_state(&self) -> Result<ProtocolContractState, Self::Error> {
        self.client
            .view::<ProtocolContractState>(&self.contract_id, method_names::STATE)
            .await
            .map_err(|err| anyhow::anyhow!("state view call failed: {err}"))
    }
}
