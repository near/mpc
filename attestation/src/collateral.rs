use alloc::string::String;
use derive_more::{Deref, From, Into};

/// Supplemental data for the TEE quote, including Intel certificates to verify it came from
/// genuine Intel hardware, along with details about the Trusted Computing Base (TCB)
/// versioning, status, and other relevant info.
#[derive(From, Deref, Into)]
pub(crate) struct Collateral(String);
