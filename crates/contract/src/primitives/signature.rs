use near_sdk::{near, CryptoHash};

pub use near_mpc_contract_interface::types::{SignRequestArgs, SignatureRequest};

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(Debug, Clone)]
#[near(serializers=[borsh, json])]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}

#[derive(Clone, Debug)]
#[near(serializers=[borsh])]
pub enum SignatureResult<T, E> {
    Ok(T),
    Err(E),
}
