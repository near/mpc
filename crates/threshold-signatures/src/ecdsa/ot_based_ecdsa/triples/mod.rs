//! This module contains the types and protocols related to triple generation.
//!
//! The cait-sith signing protocol makes use of *committed* Beaver Triples.
//! A triple is a value of the form `(a, b, c), (A, B, C)`, such that
//! `c = a * b`, and `A = a * G`, `B = b * G`, `C = c * G`. This is a beaver
//! triple along with commitments to its values in the form of group elements.
//!
//! The signing protocols make use of a triple where the scalar values `(a, b, c)`
//! are secret-shared, and the commitments are public. Each signature requires
//! two triples. These triples can be generated in advance without knowledge
//! of the secret key used to sign. It's important that the value of the underlying
//! scalars in the triple is kept secret, otherwise the private key used to create
//! a signature with that triple could be recovered.
//!
//! There are two ways of generating these triples.
//!
//! One way is to have
//! a trusted third party generate them. This is supported by the [deal] function.
//!
//! The other way is to run a protocol generating a secret shared triple without any party
//! learning the secret values. This is better because no party learns the value of the
//! triple, which needs to be kept secret. This method is supported by the [`generate_triple`]
//! protocol.
//!
//! This protocol requires a setup protocol to be done once beforehand.
//! After this setup protocol has been run, an arbitrary number of triples can
//! be generated.
mod batch_random_ot;
mod bits;

mod correlated_ot_extension;
mod generation;
mod mta;
mod multiplication;
mod random_ot_extension;

pub use generation::{generate_triple, generate_triple_many, TripleGenerationOutput};

#[cfg(test)]
pub(crate) mod test;

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{
    ecdsa::{AffinePoint, Scalar},
    participants::Participant,
    ReconstructionLowerBound,
};

/// Represents the public part of a triple.
///
/// This contains commitments to each part of the triple.
///
/// We also record who participated in the protocol,
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TriplePub {
    pub big_a: AffinePoint,
    pub big_b: AffinePoint,
    pub big_c: AffinePoint,
    /// The participants in generating this triple.
    pub participants: Vec<Participant>,
    /// The threshold which will be able to reconstruct it.
    pub threshold: ReconstructionLowerBound,
}

/// Represents a share of a triple.
///
/// This consists of shares of each individual part.
///
/// i.e. we have a share of a, b, and c such that a * b = c.
#[derive(Clone, Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct TripleShare {
    pub a: Scalar,
    pub b: Scalar,
    pub c: Scalar,
}
