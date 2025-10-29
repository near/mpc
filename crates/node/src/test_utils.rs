// TODO(#1318) this utilities should be moved to the threshold_signatures repo
/// Convenient test utilities to generate keys, triples, presignatures, and signatures.
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, Scalar};
use rand::rngs::OsRng;
use std::collections::HashMap;
use threshold_signatures::confidential_key_derivation as ckd;
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleGenerationOutput;
use threshold_signatures::ecdsa::ot_based_ecdsa::PresignOutput;
use threshold_signatures::ecdsa::ot_based_ecdsa::{PresignArguments, RerandomizedPresignOutput};
use threshold_signatures::ecdsa::{RerandomizationArguments, Signature};
use threshold_signatures::test::run_protocol;
use threshold_signatures::frost_ed25519::Ed25519Sha512;
use threshold_signatures::frost_secp256k1::{Secp256K1Sha256, VerifyingKey};
use threshold_signatures::participants::Participant;
use threshold_signatures::protocol::{Action, Protocol};
use threshold_signatures::{ecdsa, eddsa, keygen, ParticipantList};

use crate::primitives::ParticipantId;
