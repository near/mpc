//! FROST ciphersuite for Nockchain's Cheetah curve + Tip5 challenge ("SchnorrCheetah").
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
//! Hardening: scalar equality is constant-time (`subtle::ct_eq`) and nonce
//! sampling uses wide reduction (negligible modulo bias). REMAINING: the scalar
//! field arithmetic routes through `ibig` (a variable-time bignum), so it is not
//! yet fully constant-time — a constant-time field backend is future work — and
//! the code is not yet clippy-clean (indexing / `expect`).

use core::ops::{Add, Mul, Sub};

use frost_core::{
    Challenge, Element, Error, Field, FieldError, Group, GroupError, Signature, VerifyingKey,
};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use cheetah::{
    ch_add, ch_neg, ch_scal_big, hash_varlen, trunc_g_order, Belt, CheetahPoint, F6lt, A_GEN,
    A_ID, G_ORDER, PRIME,
};
use ibig::modular::ModuloRing;
use ibig::UBig;

use crate::crypto::ciphersuite::{BytesOrder, ScalarSerializationFormat};

mod presign;
pub mod sign;

pub use presign::{KeygenOutput, PresignArguments, PresignOutput, SignatureOption, presign};

// ---- scalar field GF(G_ORDER) ----------------------------------------------

/// A scalar in `[0, G_ORDER)`, stored little-endian. `Copy` (required by frost-core),
/// so it cannot hold an `ibig::UBig` directly; arithmetic routes through `UBig`.
#[derive(Copy, Clone, Debug)]
pub struct CheetahScalar([u8; 32]);

impl CheetahScalar {
    fn from_ubig(v: &UBig) -> Self {
        let r = v.clone() % &*G_ORDER;
        let le = r.to_le_bytes();
        let mut b = [0u8; 32];
        b[..le.len()].copy_from_slice(&le);
        CheetahScalar(b)
    }
    fn to_ubig(self) -> UBig {
        UBig::from_le_bytes(&self.0)
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
        Self::from_ubig(&(self.to_ubig() + rhs.to_ubig()))
    }
}
impl Sub for CheetahScalar {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        // (a - b) mod n = a + (n - b), since b is canonical in [0, n).
        let n = (*G_ORDER).clone();
        Self::from_ubig(&(self.to_ubig() + (n - rhs.to_ubig())))
    }
}
impl Mul for CheetahScalar {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self::from_ubig(&(self.to_ubig() * rhs.to_ubig()))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CheetahScalarField;

impl Field for CheetahScalarField {
    type Scalar = CheetahScalar;
    type Serialization = [u8; 32];

    fn zero() -> CheetahScalar {
        CheetahScalar([0u8; 32])
    }
    fn one() -> CheetahScalar {
        CheetahScalar::from_ubig(&UBig::from(1u8))
    }
    fn invert(scalar: &CheetahScalar) -> Result<CheetahScalar, FieldError> {
        let v = scalar.to_ubig();
        if v == UBig::from(0u8) {
            return Err(FieldError::InvalidZeroScalar);
        }
        let ring = ModuloRing::new(&G_ORDER);
        let inv = ring.from(&v).inverse().ok_or(FieldError::InvalidZeroScalar)?;
        Ok(CheetahScalar::from_ubig(&inv.residue()))
    }
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> CheetahScalar {
        // Wide reduction: sample 512 bits and reduce mod n (`from_ubig`), so the
        // modulo bias is ~2^-257 (cryptographically negligible) instead of the
        // ~2^-255 a single 256-bit draw would give.
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        CheetahScalar::from_ubig(&UBig::from_le_bytes(&wide))
    }
    fn serialize(scalar: &CheetahScalar) -> [u8; 32] {
        scalar.0
    }
    fn little_endian_serialize(scalar: &CheetahScalar) -> [u8; 32] {
        scalar.0
    }
    fn deserialize(buf: &[u8; 32]) -> Result<CheetahScalar, FieldError> {
        let v = UBig::from_le_bytes(buf);
        if v >= *G_ORDER {
            return Err(FieldError::MalformedScalar);
        }
        Ok(CheetahScalar(*buf))
    }
}

// ---- prime-order group (Cheetah) -------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CheetahElement(pub CheetahPoint);

impl Add for CheetahElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        CheetahElement(ch_add(&self.0, &rhs.0).expect("cheetah point addition"))
    }
}
impl Sub for CheetahElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        CheetahElement(ch_add(&self.0, &ch_neg(&rhs.0)).expect("cheetah point subtraction"))
    }
}
impl Mul<CheetahScalar> for CheetahElement {
    type Output = Self;
    fn mul(self, rhs: CheetahScalar) -> Self {
        CheetahElement(ch_scal_big(&rhs.to_ubig(), &self.0).expect("cheetah scalar mul"))
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

/// 97-byte point wire form: `0x01 ‖ y-limbs(reversed, BE) ‖ x-limbs(reversed, BE)`.
/// Matches `cheetah-tip5`'s base58 byte order and rose-ts `publicKeyToBeBytes`.
fn point_to_bytes(p: &CheetahPoint) -> [u8; 97] {
    let mut o = [0u8; 97];
    o[0] = 0x01;
    let mut i = 1;
    for b in p.y.0.iter().rev() {
        o[i..i + 8].copy_from_slice(&b.0.to_be_bytes());
        i += 8;
    }
    for b in p.x.0.iter().rev() {
        o[i..i + 8].copy_from_slice(&b.0.to_be_bytes());
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
        a.copy_from_slice(&buf[1 + k * 8..9 + k * 8]);
        *limb = u64::from_be_bytes(a);
    }
    let y = F6lt([
        Belt(limbs[5]), Belt(limbs[4]), Belt(limbs[3]),
        Belt(limbs[2]), Belt(limbs[1]), Belt(limbs[0]),
    ]);
    let x = F6lt([
        Belt(limbs[11]), Belt(limbs[10]), Belt(limbs[9]),
        Belt(limbs[8]), Belt(limbs[7]), Belt(limbs[6]),
    ]);
    Some(CheetahPoint { x, y, inf: false })
}

// ---- ciphersuite ------------------------------------------------------------

/// Encode a 5-belt sig-hash digest as the 40 little-endian bytes that consumers
/// pass to FROST as the `message`.
pub fn message_from_digest(digest: &[u64; 5]) -> [u8; 40] {
    let mut m = [0u8; 40];
    for (i, &b) in digest.iter().enumerate() {
        m[i * 8..i * 8 + 8].copy_from_slice(&b.to_le_bytes());
    }
    m
}

/// Derive a Cheetah scalar from tweak bytes (little-endian, reduced mod the group
/// order) for chainsig-style key derivation via [`crate::Tweak`]. The same mapping
/// must be used by the chainsig.js adapter when deriving per-account child keys.
pub fn tweak_scalar(bytes: &[u8]) -> CheetahScalar {
    CheetahScalar::from_ubig(&UBig::from_le_bytes(bytes))
}

fn digest_from_message(message: &[u8]) -> [u64; 5] {
    let mut d = [0u64; 5];
    for (i, slot) in d.iter_mut().enumerate() {
        let s = i * 8;
        let mut a = [0u8; 8];
        if s + 8 <= message.len() {
            a.copy_from_slice(&message[s..s + 8]);
        }
        *slot = u64::from_le_bytes(a) % PRIME;
    }
    d
}

fn tip5_to_scalar(domain: &[u8], m: &[u8]) -> CheetahScalar {
    let mut t: Vec<Belt> = Vec::with_capacity(domain.len() + m.len());
    t.extend(domain.iter().map(|&b| Belt(b as u64)));
    t.extend(m.iter().map(|&b| Belt(b as u64)));
    CheetahScalar::from_ubig(&trunc_g_order(&hash_varlen(&mut t)))
}

fn tip5_to_bytes(domain: &[u8], m: &[u8]) -> [u8; 32] {
    let mut t: Vec<Belt> = Vec::with_capacity(domain.len() + m.len());
    t.extend(domain.iter().map(|&b| Belt(b as u64)));
    t.extend(m.iter().map(|&b| Belt(b as u64)));
    let d = hash_varlen(&mut t);
    let mut o = [0u8; 32];
    for i in 0..4 {
        o[i * 8..i * 8 + 8].copy_from_slice(&d[i].to_le_bytes());
    }
    o
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
        // Unused: challenge() is overridden below to match Nockchain exactly.
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
    #[allow(non_snake_case)] // `R` (nonce commitment) matches frost-core's trait/spec naming.
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
        let c = trunc_g_order(&hash_varlen(&mut t));
        Ok(Challenge::from_scalar(CheetahScalar::from_ubig(&c)))
    }
}

impl ScalarSerializationFormat for CheetahTip5 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl crate::Ciphersuite for CheetahTip5 {}

/// Serialize a Cheetah verifying key to its 97-byte chain wire form
/// (`0x01 ‖ y-limbs ‖ x-limbs`), matching rose-ts `publicKeyToBeBytes`. This is the
/// opaque bytes carried by `dtos::PublicKey::Cheetah`.
pub fn verifying_key_to_bytes(key: &VerifyingKey<CheetahTip5>) -> [u8; 97] {
    point_to_bytes(&key.to_element().0)
}

/// Convert a FROST signature `(R, z)` into the Nockchain chain signature `c ‖ s`
/// (two 32-byte little-endian scalars), where `c = challenge(R, P, m)` and `s = z`.
/// This is the `(c, s)` the contract relays and the Nockchain verifier accepts.
pub fn chain_signature_bytes(
    signature: &Signature<CheetahTip5>,
    verifying_key: &VerifyingKey<CheetahTip5>,
    message: &[u8],
) -> Result<[u8; 64], Error<CheetahTip5>> {
    let c = <CheetahTip5 as frost_core::Ciphersuite>::challenge(
        signature.R(),
        verifying_key,
        message,
    )?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&<CheetahScalarField as Field>::serialize(&c.to_scalar()));
    out[32..].copy_from_slice(&<CheetahScalarField as Field>::serialize(signature.z()));
    Ok(out)
}

#[cfg(test)]
#[allow(non_snake_case)] // repo test convention: <system_under_test>__should_<assertion>
mod tests {
    use super::*;
    use frost_core::{SigningKey, VerifyingKey};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Mirror of nockchain-types `Spend1::verify_pkh_signature`: accept iff
    /// `trunc_g_order(Tip5((s·G − c·P).x ‖ .y ‖ P.x ‖ P.y ‖ m)) == c`.
    fn chain_verify(pubkey: &CheetahPoint, c: &UBig, s: &UBig, m: &[u64; 5]) -> bool {
        let left = ch_scal_big(s, &A_GEN).expect("sG");
        let right = ch_neg(&ch_scal_big(c, pubkey).expect("cP"));
        let rprime = ch_add(&left, &right).expect("R'");
        let mut t: Vec<Belt> = Vec::with_capacity(29);
        t.extend_from_slice(&rprime.x.0);
        t.extend_from_slice(&rprime.y.0);
        t.extend_from_slice(&pubkey.x.0);
        t.extend_from_slice(&pubkey.y.0);
        t.extend(m.iter().map(|&u| Belt(u)));
        &trunc_g_order(&hash_varlen(&mut t)) == c
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
        let z = UBig::from_le_bytes(&bytes[97..129]);
        let p = vk.to_element().0;

        let mut t: Vec<Belt> = Vec::with_capacity(29);
        t.extend_from_slice(&rpt.x.0);
        t.extend_from_slice(&rpt.y.0);
        t.extend_from_slice(&p.x.0);
        t.extend_from_slice(&p.y.0);
        t.extend(digest.iter().map(|&u| Belt(u)));
        let c = trunc_g_order(&hash_varlen(&mut t));

        assert!(chain_verify(&p, &c, &z, &digest), "Nockchain verifier must accept");
    }

    #[test]
    fn cheetah_tip5__frost_threshold_sign_verifies() {
        // Given a 3-of-5 dealer keygen,
        use crate::test_utils::build_frost_key_packages_with_dealer;
        use frost_core::{
            aggregate_custom,
            keys::{KeyPackage, PublicKeyPackage},
            round1, round2, CheaterDetection, Identifier, SigningPackage,
        };
        use std::collections::BTreeMap;

        let mut rng = StdRng::seed_from_u64(7);
        let (n, t): (u16, u16) = (5, 3);
        let keys = build_frost_key_packages_with_dealer::<CheetahTip5>(n, t, &mut rng);
        let vk = keys[0].1.public_key;

        // a t-subset signs,
        let signers: Vec<_> = keys.iter().take(t as usize).cloned().collect();

        // round 1: commitments + nonces
        let mut commitments: BTreeMap<Identifier<CheetahTip5>, round1::SigningCommitments<CheetahTip5>> =
            BTreeMap::new();
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
        vk.verify(&msg, &signature).expect("threshold signature must verify");
    }
}
