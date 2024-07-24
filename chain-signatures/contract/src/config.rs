use borsh::{self, BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct Config {
    /// Timeout for triple generation in milliseconds.
    pub triple_timeout: u64,
    /// Timeout for presignature generation in milliseconds.
    pub presignature_timeout: u64,
    /// Timeout for signature generation in milliseconds.
    pub signature_timeout: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            triple_timeout: min_to_ms(20),
            presignature_timeout: secs_to_ms(30),
            signature_timeout: secs_to_ms(30),
        }
    }
}

pub const fn secs_to_ms(secs: u64) -> u64 {
    secs * 1000
}

pub const fn min_to_ms(min: u64) -> u64 {
    min * 60 * 1000
}
