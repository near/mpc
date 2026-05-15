use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Deref, From, Into};
use serde::{Deserialize, Serialize};

// `BorshSchema` derive expands to `T::declaration().to_string()`, which is
// only in scope under no_std when `alloc::string::ToString` is imported.
#[cfg(feature = "borsh-schema")]
use alloc::string::ToString as _;

/// Raw bytes of an Intel TDX / SGX quote, as produced by the platform.
///
/// Borsh-encoded as a length-prefixed byte vector. Identical wire layout to
/// `dcap_qvl::verify::verify`'s first argument.
#[derive(
    Debug,
    Clone,
    From,
    Into,
    Deref,
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct QuoteBytes(Vec<u8>);
