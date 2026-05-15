//! `DstackAttestation` — the bundle a TDX node submits for verification.
//!
//! Holds the raw quote bytes, the Intel collateral required to verify
//! them, and the Dstack-supplied TCB info. This crate carries only the
//! data shape; the `dcap_qvl::verify::verify` call that consumes a
//! `(quote, collateral)` pair lives in the `attestation` crate (which is
//! the only crate that depends on `dcap-qvl`).

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use derive_more::Constructor;
use serde::{Deserialize, Serialize};

use alloc::{format, string::String};

use crate::{collateral::Collateral, quote::QuoteBytes, tcb_info::TcbInfo};

// `BorshSchema` derive expands to `T::declaration().to_string()`, which is
// only in scope under no_std when `alloc::string::ToString` is imported.
#[cfg(feature = "borsh-schema")]
use alloc::string::ToString as _;

#[derive(Clone, Constructor, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct DstackAttestation {
    pub quote: QuoteBytes,
    pub collateral: Collateral,
    pub tcb_info: TcbInfo,
}

impl fmt::Debug for DstackAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX_BYTES: usize = 2048;

        fn truncate_debug<T: fmt::Debug>(value: &T, max_bytes: usize) -> String {
            let debug_str = format!("{:?}", value);
            if debug_str.len() <= max_bytes {
                debug_str
            } else {
                format!(
                    "{}... (truncated {} bytes)",
                    &debug_str[..max_bytes],
                    debug_str.len() - max_bytes
                )
            }
        }

        f.debug_struct("DstackAttestation")
            .field("quote", &truncate_debug(&self.quote, MAX_BYTES))
            .field("collateral", &truncate_debug(&self.collateral, MAX_BYTES))
            .field("tcb_info", &truncate_debug(&self.tcb_info, MAX_BYTES))
            .finish()
    }
}
