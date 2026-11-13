//! Batch random OT from the DDH dual-mode cryptosystem of
//! \[[PVW08](https://eprint.iacr.org/2007/348)\], in messy mode.
//!
//! The protocol is specified in `docs/ecdsa/pvw08.md`.

mod crs;
mod kdf;
mod receiver;
mod sender;

pub use crs::{Crs, HashToElement};
pub use receiver::{ReceiverOutput, ReceiverPublicKey, ReceiverSecrets};
pub use sender::{SenderCiphertext, SenderOutput, SenderRandomness};
