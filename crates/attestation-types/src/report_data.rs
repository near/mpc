use borsh::{BorshDeserialize, BorshSerialize};

// `BorshSchema` derive expands to `T::declaration().to_string()`, which is
// only in scope under no_std when `alloc::string::ToString` is imported.
#[cfg(feature = "borsh-schema")]
use alloc::string::ToString as _;

/// Number of bytes for the report data.
pub const REPORT_DATA_SIZE: usize = 64;

#[derive(Debug, Clone, derive_more::From, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct ReportData([u8; REPORT_DATA_SIZE]);

impl ReportData {
    pub fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE] {
        self.0
    }
}
