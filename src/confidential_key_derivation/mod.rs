//! Confidential Key Derivation (CKD) protocol.
//!
//! This module provides the implementation of the Confidential Key Derivation (CKD) protocol,
//! which allows a client to derive a unique key for a specific application without revealing
//! the application identifier to the key derivation service.
//!
//! The protocol is based on a combination of Oblivious Transfer (OT) and Diffie-Hellman key exchange.
//!
//! For more details, refer to the `confidential_key_derivation.md` document in the `docs` folder.

pub mod app_id;
pub mod ciphersuite;
mod dkg;
pub mod protocol;

pub use app_id::AppId;
use serde::{Deserialize, Serialize};

use crate::confidential_key_derivation::ciphersuite::BLS12381SHA256;

pub type ElementG1 = blstrs::G1Projective;
pub type ElementG2 = blstrs::G2Projective;
pub type Scalar = blstrs::Scalar;
pub type KeygenOutput = crate::KeygenOutput<BLS12381SHA256>;
pub type SigningShare = crate::SigningShare<BLS12381SHA256>;

/// The output of the confidential key derivation protocol when run by the coordinator
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CKDCoordinatorOutput {
    big_y: ElementG1,
    big_c: ElementG1,
}

impl CKDCoordinatorOutput {
    pub fn new(big_y: ElementG1, big_c: ElementG1) -> Self {
        CKDCoordinatorOutput { big_y, big_c }
    }

    /// Outputs big_y
    pub fn big_y(&self) -> ElementG1 {
        self.big_y
    }

    /// Outputs big_c
    pub fn big_c(&self) -> ElementG1 {
        self.big_c
    }

    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( app_id )
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
}

/// None for participants and Some for coordinator
pub type CKDOutput = Option<CKDCoordinatorOutput>;
pub type VerifyingKey = crate::VerifyingKey<BLS12381SHA256>;
pub type PublicKey = ElementG1;
pub type Signature = ElementG1;
