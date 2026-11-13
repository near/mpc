//! Batch random OT from the DDH dual-mode cryptosystem of
//! \[[PVW08](https://eprint.iacr.org/2007/348)\], in messy mode.
//!
//! The protocol is specified in `docs/ecdsa/pvw08.md`.

mod crs;
mod receiver;

pub use crs::{Crs, HashToElement};
pub use receiver::{ReceiverPublicKey, ReceiverSecrets};
