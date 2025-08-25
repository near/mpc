use borsh::{BorshDeserialize, BorshSerialize};

#[derive(BorshDeserialize, BorshSerialize)]
pub(crate) enum Messages {
    KEEPALIVE,
    Secrets(String),
}
