use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Messages {
    KEEPALIVE,
    Secrets(String),
}
