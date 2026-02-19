use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct Metrics {
    pub sign_with_v1_payload_count: u64,
    pub sign_with_v2_payload_count: u64,
}
