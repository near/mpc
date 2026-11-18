use chain_gateway::errors::NearViewClientError;
use near_contract_transport::{NearKitViewError, Subscription};
use near_mpc_contract_interface::types::Keyset;

use crate::ports;

impl ports::WatchCurrentKeyset for Subscription<Option<Keyset>, NearViewClientError> {}
impl ports::WatchCurrentKeyset for Subscription<Option<Keyset>, NearKitViewError> {}
