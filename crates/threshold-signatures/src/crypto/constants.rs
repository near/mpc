//! This module contains cryptographic constants that are used throughout the codebase.

use ecdsa::elliptic_curve::{Curve, bigint::Bounded};
use k256::Secp256k1;

// Commitment Scheme Constants
/// Commitment scheme domain separator.
pub const NEAR_COMMIT_LABEL: &[u8] = b"Near threshold signature commitment";
/// Length of the commitment.
pub const COMMIT_LEN: usize = 32;
/// Commitment scheme domain separator.
pub const START_LABEL: &[u8] = b"start data";

// Hashing Constants
/// Generic hash domain separator.
pub const NEAR_HASH_LABEL: &[u8] = b"Near threshold signature generic hash";
/// Length of the hash output.
pub const HASH_LEN: usize = 32;

// Randomness Constants
/// Length of the randomizer for commitments.
pub const RANDOMIZER_LEN: usize = 32;

// Confidential Key Derivation Constants
/// Confidential key derivation domain separator.
pub const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";

// Pedersen Commitment Constants
/// Domain separation tag for deriving the Pedersen generator `H` on secp256k1
/// via RFC 9380 hash-to-curve (suite `secp256k1_XMD:SHA-256_SSWU_RO_`).
/// Consensus-critical: changing it changes the generator.
pub const NEAR_PEDERSEN_GENERATOR_DST: &[u8] =
    b"NEAR secp256k1_XMD:SHA-256_SSWU_RO_ Pedersen generator";
/// The fixed message hashed to the curve to derive the Pedersen generator `H`.
pub const NEAR_PEDERSEN_GENERATOR_MSG: &[u8] =
    b"Near threshold signatures Pedersen commitment generator, 2026-09-28, NEAR/USD=5.10";

// DLOG Proof Constants
/// DLOG proof statement label.
pub const NEAR_DLOG_STATEMENT_LABEL: &[u8] = b"dlog proof statement";
/// DLOG proof commitment label.
pub const NEAR_DLOG_COMMITMENT_LABEL: &[u8] = b"dlog proof commitment";
/// DLOG proof challenge label.
pub const NEAR_DLOG_CHALLENGE_LABEL: &[u8] = b"dlog proof challenge";
/// A string used to extend an encoding
pub const NEAR_DLOG_ENCODE_LABEL_STATEMENT: &[u8] = b"statement:";
/// A string used to extend an encoding
pub const NEAR_DLOG_ENCODE_LABEL_PUBLIC: &[u8] = b"public:";

// DLOGEQ Proof Constants
/// DLOGEQ proof statement label.
pub const NEAR_DLOGEQ_STATEMENT_LABEL: &[u8] = b"dlogeq proof statement";
/// DLOGEQ proof commitment label.
pub const NEAR_DLOGEQ_COMMITMENT_LABEL: &[u8] = b"dlogeq proof commitment";
/// DLOGEQ proof challenge label.
pub const NEAR_DLOGEQ_CHALLENGE_LABEL: &[u8] = b"dlogeq proof challenge";
/// A string used to extend an encoding
pub const NEAR_DLOGEQ_ENCODE_LABEL_STATEMENT: &[u8] = b"statement:";
/// A string used to extend an encoding
pub const NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC0: &[u8] = b"public 0:";
/// A string used to extend an encoding
pub const NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC1: &[u8] = b"public 1:";
/// A string used to extend an encoding
pub const NEAR_DLOGEQ_ENCODE_LABEL_GENERATOR1: &[u8] = b"generator 1:";

// W-Opening Proof Constants
/// W-opening proof statement label.
pub const NEAR_W_OPENING_STATEMENT_LABEL: &[u8] = b"w opening proof statement";
/// W-opening proof commitment label.
pub const NEAR_W_OPENING_COMMITMENT_LABEL: &[u8] = b"w opening proof commitment";
/// W-opening proof challenge label.
pub const NEAR_W_OPENING_CHALLENGE_LABEL: &[u8] = b"w opening proof challenge";
/// A string used to extend an encoding
pub const NEAR_W_OPENING_ENCODE_LABEL_STATEMENT: &[u8] = b"statement:";
/// A string used to extend an encoding
pub const NEAR_W_OPENING_ENCODE_LABEL_BIG_W: &[u8] = b"big w:";
/// A string used to extend an encoding
pub const NEAR_W_OPENING_ENCODE_LABEL_BIG_R: &[u8] = b"big r:";
/// A string used to extend an encoding
pub const NEAR_W_OPENING_ENCODE_LABEL_COM_A: &[u8] = b"com a:";
/// A string used to extend an encoding
pub const NEAR_W_OPENING_ENCODE_LABEL_COM_B: &[u8] = b"com b:";
/// A string used to extend an encoding
pub const NEAR_W_OPENING_ENCODE_LABEL_H_PED: &[u8] = b"pedersen generator:";

// Keccak Constants
pub const KECCAK_STATE_BYTES: usize = 200;
pub const KECCAK_STATE_WORDS: usize = 25;

// Strobe Constants
/// Strobe R value; security level 128 is hardcoded
pub const STROBE_R: u8 = 166;

pub const FLAG_I: u8 = 1;
pub const FLAG_A: u8 = 1 << 1;
pub const FLAG_C: u8 = 1 << 2;
pub const FLAG_T: u8 = 1 << 3;
pub const FLAG_M: u8 = 1 << 4;
pub const FLAG_K: u8 = 1 << 5;

// Merlin Protocol Constants
pub const MERLIN_PROTOCOL_LABEL: &[u8] = b"Mini-Merlin";

// Batch Random OT Constants
/// Batch random OT hash domain separator.
pub const NEAR_BATCH_RANDOM_OT_HASH: &[u8] = b"Near threshold signatures batch ROT";

// Correlated OT PRG Constants
/// Correlated OT PRG context.
pub const NEAR_PRG_CTX: &[u8] = b"Near threshold signatures correlated OT PRG";

// Security Parameters
/// The security parameter we use for different constructions
pub const SECURITY_PARAMETER: usize = 128;
/// Field modulus
pub const BITS: usize = <<Secp256k1 as Curve>::Uint as Bounded>::BITS;

// Robust ECDSA Constants
/// Robust ECDSA signing transcript label.
pub const NEAR_ROBUST_ECDSA_SIGN_LABEL: &[u8] = b"Near threshold signatures robust ecdsa sign";

// Triple Generation Constants
/// Triple generation label.
pub const NEAR_TRIPLE_GENERATION_LABEL: &[u8] = b"Near threshold signatures triple generation";

// Random OT Extension Constants
/// Random OT extension hash context.
pub const NEAR_RANDOM_OT_EXTENSION_HASH_CTX: &[u8] = b"Random OT Extension Hash";

// Channel Tags Constants
/// Channel tags domain separator.
pub const NEAR_CHANNEL_TAGS_DOMAIN: &[u8] = b"Near threshold signatures channel tags";
