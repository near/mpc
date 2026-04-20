use near_sdk::near;

pub use near_mpc_contract_interface::types::{SignRequestArgs, SignatureRequest, YieldIndex};

#[derive(Clone, Debug)]
#[near(serializers=[borsh])]
pub enum SignatureResult<T, E> {
    Ok(T),
    Err(E),
}
