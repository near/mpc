use chain_gateway::errors::NearViewClientError;
use near_contract_transport::{NearKitViewError, Subscription};
use near_mpc_contract_interface::types::ProtocolContractState;

use crate::ports;

impl ports::WatchContractState for Subscription<ProtocolContractState, NearViewClientError> {}
impl ports::WatchContractState for Subscription<ProtocolContractState, NearKitViewError> {}
