use k256::{
    Secp256k1,
    elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest},
};
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable};

use crate::{
    Ciphersuite, Element, crypto::constants::NEAR_PVW08_CRS_DOMAIN, ecdsa::Secp256K1Sha256,
    errors::ProtocolError,
};

/// Common reference string `(g0, h0, g1, h1)` of the dual-mode cryptosystem.
///
/// The only constructor is [`Crs::derive`], so nobody knows the discrete
/// logarithms relating the four points and the string is in messy mode except
/// with negligible probability.
pub struct Crs<C: Ciphersuite> {
    g0: Element<C>,
    h0: Element<C>,
    g1: Element<C>,
    h1: Element<C>,
}

impl<C: HashToElement> Crs<C> {
    /// Derives the string from the session identifier.
    ///
    /// Both parties must use the same `sid`, and it must be unique to the run.
    pub fn derive(sid: &[u8]) -> Result<Self, ProtocolError> {
        let point = |index: u8| C::hash_to_element(NEAR_PVW08_CRS_DOMAIN, &[sid, &[index]]);
        Ok(Self {
            g0: point(0)?,
            h0: point(1)?,
            g1: point(2)?,
            h1: point(3)?,
        })
    }
}

impl<C: Ciphersuite> Crs<C>
where
    Element<C>: ConditionallySelectable,
{
    /// Returns `(g0, h0)` if `choice` is 0 and `(g1, h1)` otherwise, in constant time.
    pub fn branch(&self, choice: Choice) -> (Element<C>, Element<C>) {
        (
            <Element<C>>::conditional_select(&self.g0, &self.g1, choice),
            <Element<C>>::conditional_select(&self.h0, &self.h1, choice),
        )
    }
}

/// Hashing to a uniform group element of unknown discrete logarithm.
pub trait HashToElement: Ciphersuite {
    /// Hashes the concatenation of `msg` under the domain separation tag `domain`.
    fn hash_to_element(domain: &[u8], msg: &[&[u8]]) -> Result<Element<Self>, ProtocolError>;
}

/// RFC 9380 suite `secp256k1_XMD:SHA-256_SSWU_RO_`.
impl HashToElement for Secp256K1Sha256 {
    fn hash_to_element(domain: &[u8], msg: &[&[u8]]) -> Result<Element<Self>, ProtocolError> {
        Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(msg, &[domain])
            .map_err(|_| ProtocolError::HashingError)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use frost_core::Group;
    use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};

    use super::*;
    use crate::ecdsa::Secp256K1Group;

    type C = Secp256K1Sha256;

    fn points(crs: &Crs<C>) -> [ProjectivePoint; 4] {
        [crs.g0, crs.h0, crs.g1, crs.h1]
    }

    #[test]
    fn hash_to_element__should_match_rfc9380_test_vector() {
        // Given
        let domain = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

        // When
        let point = C::hash_to_element(domain, &[b""]).unwrap();

        // Then
        let encoded = point.to_affine().to_encoded_point(false);
        assert_eq!(
            hex::encode(encoded.x().unwrap()),
            "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346"
        );
        assert_eq!(
            hex::encode(encoded.y().unwrap()),
            "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067"
        );
    }

    #[test]
    fn hash_to_element__should_concatenate_message_parts() {
        // Given
        let domain = b"domain";

        // When
        let split = C::hash_to_element(domain, &[b"ab", b"c"]).unwrap();
        let joined = C::hash_to_element(domain, &[b"abc"]).unwrap();

        // Then
        assert_eq!(split, joined);
    }

    #[test]
    fn derive__should_be_deterministic() {
        // Given
        let sid = b"session";

        // When
        let first = Crs::<C>::derive(sid).unwrap();
        let second = Crs::<C>::derive(sid).unwrap();

        // Then
        assert_eq!(points(&first), points(&second));
    }

    #[test]
    fn derive__should_yield_distinct_non_identity_points() {
        // Given
        let sid = b"session";

        // When
        let crs = Crs::<C>::derive(sid).unwrap();

        // Then
        let points = points(&crs);
        for (i, point) in points.iter().enumerate() {
            assert_ne!(*point, Secp256K1Group::identity());
            for other in points.iter().skip(i + 1) {
                assert_ne!(point, other);
            }
        }
    }

    #[test]
    fn derive__should_yield_unrelated_strings_for_different_sids() {
        // Given
        let sid = b"session";
        let other_sid = b"session'";

        // When
        let crs = Crs::<C>::derive(sid).unwrap();
        let other_crs = Crs::<C>::derive(other_sid).unwrap();

        // Then
        for point in points(&crs) {
            assert!(!points(&other_crs).contains(&point));
        }
    }

    #[test]
    fn derive__should_match_snapshot() {
        // Given
        let sid = b"session";

        // When
        let crs = Crs::<C>::derive(sid).unwrap();

        // Then
        let serialized = points(&crs).map(|point| {
            let bytes = Secp256K1Group::serialize(&point).unwrap();
            hex::encode(bytes)
        });
        insta::assert_json_snapshot!(serialized);
    }

    #[test]
    fn branch__should_select_the_pair_of_the_choice_bit() {
        // Given
        let crs = Crs::<C>::derive(b"session").unwrap();

        // When
        let branch0 = crs.branch(Choice::from(0));
        let branch1 = crs.branch(Choice::from(1));

        // Then
        assert_eq!(branch0, (crs.g0, crs.h0));
        assert_eq!(branch1, (crs.g1, crs.h1));
    }
}
