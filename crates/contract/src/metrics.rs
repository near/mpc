use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Default, BorshSerialize, BorshDeserialize)]
pub(crate) struct Metrics {
    pub(crate) sign_with_v1_payload_count: u64,
    pub(crate) sign_with_v2_payload_count: u64,
}
