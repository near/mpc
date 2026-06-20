//! FROST ciphersuite for Nockchain's Cheetah curve + Tip5 challenge ("`SchnorrCheetah`").
//!
//! A hand-rolled `frost_core::{Field, Group, Ciphersuite}` over the pure-Rust
//! `cheetah-curve` primitives. Unlike `eddsa`/`redjubjub` (which reuse off-the-shelf
//! ciphersuite crates), Cheetah has none, so the group/field/hashes live here.
//!
//! `challenge()` is overridden to Nockchain's exact transcript
//! `c = trunc_g_order(Tip5(R.x‖R.y‖P.x‖P.y‖m))`, so frost-core's verification
//! equation `z·G == R + c·P` coincides with the on-chain `Spend1` verifier — i.e.
//! signatures produced here are accepted by Nockchain, with chain signature `(c, s=z)`.
//! The FROST `message` is the 5-belt sig-hash digest encoded as 40 LE bytes (see
//! [`message_from_digest`]).
//!
//! Hardening: the scalar field is backed by constant-time `crypto-bigint`
//! (`U256`) — modular add/sub/mul/inverse, wide-reduction nonce sampling, and
//! constant-time equality/range checks. The cheetah-curve point/field arithmetic
//! underneath (point add/double, projective scalar mul, Goldilocks reductions) is
//! constant time as well — see cheetah-curve's `SECURITY.md`.

use core::ops::{Add, Mul, Sub};

use frost_core::{
    Challenge, Element, Error, Field, FieldError, Group, GroupError, Signature, VerifyingKey,
};
use rand_core::{CryptoRng, RngCore};
use subtle::{ConstantTimeEq, ConstantTimeLess};

use cheetah::{
    A_GEN, A_ID, Belt, CheetahPoint, F6lt, G_ORDER, G_ORDER_NZ, U256, ch_add, ch_neg, ch_scal_big,
    digest_from_message, hash_varlen, tip5_to_bytes, trunc_g_order,
};
pub use cheetah::message_from_digest;
use crypto_bigint::U512;

use crate::crypto::ciphersuite::{BytesOrder, ScalarSerializationFormat};

mod presign;
pub mod sign;

pub use presign::{KeygenOutput, PresignArguments, PresignOutput, SignatureOption, presign};

// ---- scalar field GF(G_ORDER) ----------------------------------------------

/// A scalar in `[0, G_ORDER)`, backed by a constant-time `crypto_bigint::U256`.
#[derive(Copy, Clone, Debug)]
pub struct CheetahScalar(U256);

impl CheetahScalar {
    fn from_u256(v: &U256) -> Self {
        Self(v.rem(&G_ORDER_NZ))
    }
    fn to_u256(self) -> U256 {
        self.0
    }
}

impl PartialEq for CheetahScalar {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for CheetahScalar {}

impl Add for CheetahScalar {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0.add_mod(&rhs.0, &G_ORDER_NZ))
    }
}
impl Sub for CheetahScalar {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.sub_mod(&rhs.0, &G_ORDER_NZ))
    }
}
impl Mul for CheetahScalar {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(self.0.mul_mod(&rhs.0, &G_ORDER_NZ))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CheetahScalarField;

impl Field for CheetahScalarField {
    type Scalar = CheetahScalar;
    type Serialization = [u8; 32];

    fn zero() -> CheetahScalar {
        CheetahScalar(U256::ZERO)
    }
    fn one() -> CheetahScalar {
        CheetahScalar(U256::ONE)
    }
    fn invert(scalar: &CheetahScalar) -> Result<CheetahScalar, FieldError> {
        Option::<U256>::from(scalar.0.invert_mod(&G_ORDER_NZ))
            .map(CheetahScalar)
            .ok_or(FieldError::InvalidZeroScalar)
    }
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> CheetahScalar {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        CheetahScalar(U512::from_le_slice(&wide).rem(&G_ORDER_NZ))
    }
    fn serialize(scalar: &CheetahScalar) -> [u8; 32] {
        scalar.0.to_le_bytes().into()
    }
    fn little_endian_serialize(scalar: &CheetahScalar) -> [u8; 32] {
        scalar.0.to_le_bytes().into()
    }
    fn deserialize(buf: &[u8; 32]) -> Result<CheetahScalar, FieldError> {
        let v = U256::from_le_slice(buf);
        if bool::from(v.ct_lt(&G_ORDER)) {
            Ok(CheetahScalar(v))
        } else {
            Err(FieldError::MalformedScalar)
        }
    }
}

// ---- prime-order group (Cheetah) -------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CheetahElement(pub CheetahPoint);

impl Add for CheetahElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(ch_add(&self.0, &rhs.0).expect("cheetah point addition"))
    }
}
impl Sub for CheetahElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(ch_add(&self.0, &ch_neg(&rhs.0)).expect("cheetah point subtraction"))
    }
}
impl Mul<CheetahScalar> for CheetahElement {
    type Output = Self;
    fn mul(self, rhs: CheetahScalar) -> Self {
        Self(ch_scal_big(&rhs.to_u256(), &self.0).expect("cheetah scalar mul"))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CheetahGroup;

impl Group for CheetahGroup {
    type Field = CheetahScalarField;
    type Element = CheetahElement;
    type Serialization = [u8; 97];

    fn cofactor() -> CheetahScalar {
        <CheetahScalarField as Field>::one()
    }
    fn identity() -> CheetahElement {
        CheetahElement(A_ID)
    }
    fn generator() -> CheetahElement {
        CheetahElement(A_GEN)
    }
    fn serialize(element: &CheetahElement) -> Result<[u8; 97], GroupError> {
        if element.0.inf {
            return Err(GroupError::InvalidIdentityElement);
        }
        Ok(point_to_bytes(&element.0))
    }
    fn deserialize(buf: &[u8; 97]) -> Result<CheetahElement, GroupError> {
        let p = point_from_bytes(buf).ok_or(GroupError::MalformedElement)?;
        if p.inf {
            return Err(GroupError::InvalidIdentityElement);
        }
        if !p.in_curve() {
            return Err(GroupError::MalformedElement);
        }
        Ok(CheetahElement(p))
    }
}

fn point_to_bytes(p: &CheetahPoint) -> [u8; 97] {
    let mut o = [0u8; 97];
    o[0] = 0x01;
    let mut i = 1;
    for b in p.y.0.iter().rev() {
        o.get_mut(i..i + 8)
            .expect("point encoding fits in 97 bytes")
            .copy_from_slice(&b.0.to_be_bytes());
        i += 8;
    }
    for b in p.x.0.iter().rev() {
        o.get_mut(i..i + 8)
            .expect("point encoding fits in 97 bytes")
            .copy_from_slice(&b.0.to_be_bytes());
        i += 8;
    }
    o
}

fn point_from_bytes(buf: &[u8; 97]) -> Option<CheetahPoint> {
    if buf[0] != 0x01 {
        return None;
    }
    let mut limbs = [0u64; 12];
    for (k, limb) in limbs.iter_mut().enumerate() {
        let mut a = [0u8; 8];
        a.copy_from_slice(
            buf.get(1 + k * 8..9 + k * 8)
                .expect("point decoding from 97-byte buffer"),
        );
        *limb = u64::from_be_bytes(a);
    }
    let y = F6lt([
        Belt(limbs[5]),
        Belt(limbs[4]),
        Belt(limbs[3]),
        Belt(limbs[2]),
        Belt(limbs[1]),
        Belt(limbs[0]),
    ]);
    let x = F6lt([
        Belt(limbs[11]),
        Belt(limbs[10]),
        Belt(limbs[9]),
        Belt(limbs[8]),
        Belt(limbs[7]),
        Belt(limbs[6]),
    ]);
    Some(CheetahPoint { x, y, inf: false })
}

// ---- ciphersuite ------------------------------------------------------------

/// Reduce a little-endian byte string into a Cheetah scalar (chain-signatures
/// tweak / epsilon). Delegates to cheetah-curve's `tweak_from_le_bytes`.
pub fn tweak_scalar(bytes: &[u8]) -> CheetahScalar {
    CheetahScalar::from_u256(&cheetah::tweak_from_le_bytes(bytes))
}

/// Domain-separated Tip5 hash to a Cheetah scalar (FROST H1/H2/H3/HDKG/HID).
fn tip5_to_scalar(domain: &[u8], m: &[u8]) -> CheetahScalar {
    CheetahScalar::from_u256(&cheetah::tip5_to_scalar(domain, m))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CheetahTip5;

impl frost_core::Ciphersuite for CheetahTip5 {
    const ID: &'static str = "FROST-NOCKCHAIN-CHEETAH-TIP5-v1";
    type Group = CheetahGroup;
    type HashOutput = [u8; 32];
    /// `R` (97 bytes) ‖ `z` (32 bytes, little-endian).
    type SignatureSerialization = [u8; 129];

    fn H1(m: &[u8]) -> CheetahScalar {
        tip5_to_scalar(b"rho", m)
    }
    fn H2(m: &[u8]) -> CheetahScalar {
        tip5_to_scalar(b"chal", m)
    }
    fn H3(m: &[u8]) -> CheetahScalar {
        tip5_to_scalar(b"nonce", m)
    }
    fn H4(m: &[u8]) -> [u8; 32] {
        tip5_to_bytes(b"msg", m)
    }
    fn H5(m: &[u8]) -> [u8; 32] {
        tip5_to_bytes(b"com", m)
    }
    fn HDKG(m: &[u8]) -> Option<CheetahScalar> {
        Some(tip5_to_scalar(b"dkg", m))
    }
    fn HID(m: &[u8]) -> Option<CheetahScalar> {
        Some(tip5_to_scalar(b"id", m))
    }

    /// Nockchain challenge: `c = trunc_g_order(Tip5(R.x‖R.y‖P.x‖P.y‖m))`.
    #[allow(non_snake_case)]
    fn challenge(
        R: &Element<Self>,
        verifying_key: &VerifyingKey<Self>,
        message: &[u8],
    ) -> Result<Challenge<Self>, Error<Self>> {
        let r = R.0;
        let p = (*verifying_key).to_element().0;
        let m = digest_from_message(message);
        let mut t: Vec<Belt> = Vec::with_capacity(29);
        t.extend_from_slice(&r.x.0);
        t.extend_from_slice(&r.y.0);
        t.extend_from_slice(&p.x.0);
        t.extend_from_slice(&p.y.0);
        t.extend(m.iter().map(|&u| Belt(u)));
        let c = trunc_g_order(&hash_varlen(&t));
        Ok(Challenge::from_scalar(CheetahScalar::from_u256(&c)))
    }
}

impl ScalarSerializationFormat for CheetahTip5 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl crate::Ciphersuite for CheetahTip5 {}

/// (`0x01 ‖ y-limbs ‖ x-limbs`), matching rose-ts `publicKeyToBeBytes`.
pub fn verifying_key_to_bytes(key: &VerifyingKey<CheetahTip5>) -> [u8; 97] {
    point_to_bytes(&key.to_element().0)
}

/// Convert a FROST signature `(R, z)` into the Nockchain chain signature `c ‖ s`.
///
/// Output is two 32-byte little-endian scalars, where `c = challenge(R, P, m)` and `s = z`.
/// This is the `(c, s)` the contract relays and the Nockchain verifier accepts.
pub fn chain_signature_bytes(
    signature: &Signature<CheetahTip5>,
    verifying_key: &VerifyingKey<CheetahTip5>,
    message: &[u8],
) -> Result<[u8; 64], Error<CheetahTip5>> {
    let c =
        <CheetahTip5 as frost_core::Ciphersuite>::challenge(signature.R(), verifying_key, message)?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&<CheetahScalarField as Field>::serialize(&c.to_scalar()));
    out[32..].copy_from_slice(&<CheetahScalarField as Field>::serialize(signature.z()));
    Ok(out)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use frost_core::{SigningKey, VerifyingKey};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    /// Mirror of nockchain-types `Spend1::verify_pkh_signature`: accept iff
    /// `trunc_g_order(Tip5((s·G − c·P).x ‖ .y ‖ P.x ‖ P.y ‖ m)) == c`.
    fn chain_verify(pubkey: &CheetahPoint, c: &U256, s: &U256, m: &[u64; 5]) -> bool {
        let left = ch_scal_big(s, &A_GEN).expect("sG");
        let right = ch_neg(&ch_scal_big(c, pubkey).expect("cP"));
        let rprime = ch_add(&left, &right).expect("R'");
        let mut t: Vec<Belt> = Vec::with_capacity(29);
        t.extend_from_slice(&rprime.x.0);
        t.extend_from_slice(&rprime.y.0);
        t.extend_from_slice(&pubkey.x.0);
        t.extend_from_slice(&pubkey.y.0);
        t.extend(m.iter().map(|&u| Belt(u)));
        &trunc_g_order(&hash_varlen(&t)) == c
    }

    #[test]
    fn cheetah_tip5__single_sign_verifies_under_frost_and_chain() {
        // Given a keypair and a 5-belt digest message,
        let mut rng = StdRng::seed_from_u64(1);
        let sk = SigningKey::<CheetahTip5>::new(&mut rng);
        let vk = VerifyingKey::<CheetahTip5>::from(&sk);
        let digest = [1u64, 2, 3, 4, 5];
        let msg = message_from_digest(&digest);

        // When we sign,
        let sig = sk.sign(&mut rng, &msg);

        // Then frost-core verification (using our overridden Tip5 challenge) accepts,
        vk.verify(&msg, &sig).expect("frost-core verify");

        // and the Nockchain chain verifier accepts the (c, s=z) signature.
        let bytes = <CheetahTip5 as frost_core::Ciphersuite>::serialize_signature(&sig)
            .expect("serialize signature");
        assert_eq!(bytes.len(), 129);
        let mut rbuf = [0u8; 97];
        rbuf.copy_from_slice(&bytes[..97]);
        let rpt = point_from_bytes(&rbuf).expect("R point");
        let z = U256::from_le_slice(&bytes[97..129]);
        let p = vk.to_element().0;

        let mut t: Vec<Belt> = Vec::with_capacity(29);
        t.extend_from_slice(&rpt.x.0);
        t.extend_from_slice(&rpt.y.0);
        t.extend_from_slice(&p.x.0);
        t.extend_from_slice(&p.y.0);
        t.extend(digest.iter().map(|&u| Belt(u)));
        let c = trunc_g_order(&hash_varlen(&t));

        assert!(
            chain_verify(&p, &c, &z, &digest),
            "Nockchain verifier must accept"
        );
    }

    #[test]
    fn cheetah_tip5__frost_threshold_sign_verifies() {
        // Given a 3-of-5 dealer keygen,
        use crate::test_utils::build_frost_key_packages_with_dealer;
        use frost_core::{
            CheaterDetection, Identifier, SigningPackage, aggregate_custom,
            keys::{KeyPackage, PublicKeyPackage},
            round1, round2,
        };
        use std::collections::BTreeMap;

        let mut rng = StdRng::seed_from_u64(7);
        let (n, t): (u16, u16) = (5, 3);
        let keys = build_frost_key_packages_with_dealer::<CheetahTip5>(n, t, &mut rng);
        let vk = keys[0].1.public_key;

        // a t-subset signs,
        let signers: Vec<_> = keys.iter().take(t as usize).cloned().collect();

        // round 1: commitments + nonces
        let mut commitments: BTreeMap<
            Identifier<CheetahTip5>,
            round1::SigningCommitments<CheetahTip5>,
        > = BTreeMap::new();
        let mut nonces: BTreeMap<Identifier<CheetahTip5>, round1::SigningNonces<CheetahTip5>> =
            BTreeMap::new();
        for (p, kg) in &signers {
            let id = p.to_identifier::<CheetahTip5>().unwrap();
            let (no, com) = round1::commit(&kg.private_share, &mut rng);
            commitments.insert(id, com);
            nonces.insert(id, no);
        }

        let digest = [7u64, 8, 9, 10, 11];
        let msg = message_from_digest(&digest);
        let signing_package = SigningPackage::<CheetahTip5>::new(commitments, &msg);

        // round 2: signature shares
        let mut shares: BTreeMap<Identifier<CheetahTip5>, round2::SignatureShare<CheetahTip5>> =
            BTreeMap::new();
        for (p, kg) in &signers {
            let id = p.to_identifier::<CheetahTip5>().unwrap();
            let verifying_share = kg.private_share.into();
            let key_package = KeyPackage::new(id, kg.private_share, verifying_share, vk, t);
            let share = round2::sign(&signing_package, &nonces[&id], &key_package).unwrap();
            shares.insert(id, share);
        }

        // Then aggregation yields a signature that verifies (frost-core's check with
        // our Tip5 challenge == the Nockchain verifier).
        let pkp = PublicKeyPackage::new(BTreeMap::new(), vk, None);
        let signature =
            aggregate_custom(&signing_package, &shares, &pkp, CheaterDetection::Disabled).unwrap();
        vk.verify(&msg, &signature)
            .expect("threshold signature must verify");
    }
}
