use blstrs::{G1Projective, G2Projective};
use elliptic_curve::Group as _;
use near_account_id::AccountId;
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::kdf::derive_app_id;
use near_mpc_contract_interface::types::{CKDResponse, DomainId};
use near_sdk::{env, near};

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct CKDRequest {
    /// The app ephemeral public key
    pub app_public_key: dtos::CKDAppPublicKey,
    pub app_id: dtos::CkdAppId,
    pub domain_id: DomainId,
}

impl CKDRequest {
    pub fn new(
        app_public_key: dtos::CKDAppPublicKey,
        domain_id: DomainId,
        predecessor_id: &AccountId,
        derivation_path: &str,
    ) -> Self {
        let app_id = derive_app_id(predecessor_id, derivation_path);
        Self {
            app_public_key,
            app_id,
            domain_id,
        }
    }
}

/// Check that `e(app_pk1, g2) = e(g1, app_pk2)`.
///
/// Point validation is fully delegated to the host: the decompression
/// functions abort execution on malformed or off-curve encodings, and
/// `bls12381_pairing_check` returns `false` when a point is outside its
/// prime-order subgroup.
pub(crate) fn app_public_key_check(app_public_key: &dtos::CKDAppPublicKeyPV) -> bool {
    let pk1 = env::bls12381_p1_decompress(&app_public_key.pk1);
    let pk2 = env::bls12381_p2_decompress(&app_public_key.pk2);
    let g1 = G1Projective::generator().to_uncompressed();
    let minus_g2 = (-G2Projective::generator()).to_uncompressed();

    let pairing_input = [
        pk1.as_slice(),
        minus_g2.as_slice(),
        g1.as_slice(),
        pk2.as_slice(),
    ]
    .concat();
    env::bls12381_pairing_check(&pairing_input)
}

/// Check that `e(big_c, g2) = e(big_y, app_pk2) . e(hash_point, public_key)`.
///
/// Point validation is fully delegated to the host, as in
/// [`app_public_key_check`].
pub(crate) fn ckd_output_check(
    app_id: &dtos::CkdAppId,
    output: &CKDResponse,
    app_public_key: &dtos::CKDAppPublicKeyPV,
    public_key: &dtos::Bls12381G2PublicKey,
) -> bool {
    let big_c = env::bls12381_p1_decompress(&output.big_c);
    let big_y = env::bls12381_p1_decompress(&output.big_y);
    let pk2 = env::bls12381_p2_decompress(&app_public_key.pk2);
    let pk = env::bls12381_p2_decompress(public_key);
    let hash_point = hash_app_id_with_pk(public_key.as_slice(), app_id.as_ref());
    let minus_g2 = (-G2Projective::generator()).to_uncompressed();

    let pairing_input = [
        big_c.as_slice(),
        minus_g2.as_slice(),
        big_y.as_slice(),
        pk2.as_slice(),
        hash_point.as_slice(),
        pk.as_slice(),
    ]
    .concat();
    env::bls12381_pairing_check(&pairing_input)
}

/// Hashes the app id and the public key as `H(pk || app_id)` where `H` is a
/// random oracle, returning the resulting G1 point in uncompressed encoding.
fn hash_app_id_with_pk(pk: &[u8], app_id: &[u8]) -> Vec<u8> {
    let input = [pk, app_id].concat();
    hash_to_curve(&input)
}

/// Confidential key derivation domain separator.
const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_` hash-to-curve.
///
/// There is no host function for the full hash-to-curve — the host only
/// exposes the `map_fp_to_g1` step, not `expand_message_xmd` — so this
/// delegates to `blstrs`, returning the resulting G1 point in uncompressed
/// encoding.
fn hash_to_curve(bytes: &[u8]) -> Vec<u8> {
    G1Projective::hash_to_curve(bytes, NEAR_CKD_DOMAIN, &[])
        .to_uncompressed()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
    use elliptic_curve::Field as _;
    use elliptic_curve::group::Curve as _;
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;
    use threshold_signatures::confidential_key_derivation::{self as ckd, ElementG2, VerifyingKey};

    /// Finds a point on the G1 curve that is not in the prime-order subgroup
    /// by scanning x-coordinates: the subgroup has index ~2^125 in the curve
    /// group, so essentially every curve point qualifies.
    fn must_g1_point_outside_subgroup() -> G1Affine {
        let mut candidate = [0u8; 48];
        candidate[0] = 0x80; // compressed-encoding flag
        for x in 0u8..=255 {
            candidate[47] = x;
            let Some(point) = G1Affine::from_compressed_unchecked(&candidate).into_option() else {
                continue;
            };
            if !bool::from(point.is_torsion_free()) {
                return point;
            }
        }
        panic!("no G1 point outside the prime-order subgroup found");
    }

    /// G2 counterpart of [`must_g1_point_outside_subgroup`].
    fn must_g2_point_outside_subgroup() -> G2Affine {
        let mut candidate = [0u8; 96];
        candidate[0] = 0x80; // compressed-encoding flag
        for x in 0u8..=255 {
            candidate[95] = x;
            let Some(point) = G2Affine::from_compressed_unchecked(&candidate).into_option() else {
                continue;
            };
            if !bool::from(point.is_torsion_free()) {
                return point;
            }
        }
        panic!("no G2 point outside the prime-order subgroup found");
    }

    /// Finds a compressed G1 encoding whose x-coordinate is a valid field
    /// element but lies on no curve point (x^3 + 4 is a non-square).
    fn must_g1_x_not_on_curve() -> [u8; 48] {
        let mut candidate = [0u8; 48];
        candidate[0] = 0x80; // compressed-encoding flag
        for x in 0u8..=255 {
            candidate[47] = x;
            if G1Affine::from_compressed_unchecked(&candidate)
                .is_none()
                .into()
            {
                return candidate;
            }
        }
        panic!("no x-coordinate off the G1 curve found");
    }

    /// G2 counterpart of [`must_g1_x_not_on_curve`].
    fn must_g2_x_not_on_curve() -> [u8; 96] {
        let mut candidate = [0u8; 96];
        candidate[0] = 0x80; // compressed-encoding flag
        for x in 0u8..=255 {
            candidate[95] = x;
            if G2Affine::from_compressed_unchecked(&candidate)
                .is_none()
                .into()
            {
                return candidate;
            }
        }
        panic!("no x-coordinate off the G2 curve found");
    }

    fn make_app_public_key_pv(scalar: Scalar) -> dtos::CKDAppPublicKeyPV {
        dtos::CKDAppPublicKeyPV {
            pk1: dtos::Bls12381G1PublicKey((G1Projective::generator() * scalar).to_compressed()),
            pk2: dtos::Bls12381G2PublicKey((G2Projective::generator() * scalar).to_compressed()),
        }
    }

    #[test]
    fn hash_to_curve_is_deterministic() {
        let input = b"test input";
        let p1 = hash_to_curve(input);
        let p2 = hash_to_curve(input);
        assert_eq!(p1, p2);
    }

    #[test]
    fn hash_to_curve_produces_valid_point() {
        let p = hash_to_curve(b"some data");
        let point = G1Affine::from_uncompressed(p.as_slice().try_into().unwrap()).into_option();
        assert!(point.is_some());
    }

    #[test]
    fn hash_to_curve_different_inputs_produce_different_points() {
        let p1 = hash_to_curve(b"input a");
        let p2 = hash_to_curve(b"input b");
        assert_ne!(p1, p2);
    }

    #[test]
    fn hash_app_id_with_pk_is_deterministic() {
        let pk = G2Projective::generator().to_compressed();
        let app_id = [42u8; 32];
        let p1 = hash_app_id_with_pk(&pk, &app_id);
        let p2 = hash_app_id_with_pk(&pk, &app_id);
        assert_eq!(p1, p2);
    }

    #[test]
    fn hash_app_id_with_pk_produces_valid_point() {
        let pk = G2Projective::generator().to_compressed();
        let app_id = [1u8; 32];
        let p = hash_app_id_with_pk(&pk, &app_id);
        let point = G1Affine::from_uncompressed(p.as_slice().try_into().unwrap()).into_option();
        assert!(point.is_some());
    }

    /// The contract's `hash_app_id_with_pk` must produce the same output as
    /// `threshold_signatures::confidential_key_derivation::hash_app_id_with_pk`
    /// for the same inputs, since nodes and the contract must agree on the hash point.
    #[test]
    #[expect(non_snake_case)]
    fn hash_app_id_with_pk__should_match_threshold_signatures_crate() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let scalar = Scalar::random(&mut rng);
        let pk_element = ElementG2::generator() * scalar;
        let vk = VerifyingKey::new(pk_element);
        let app_id = [7u8; 32];

        // When: the contract version takes raw compressed pk bytes
        let contract_result = hash_app_id_with_pk(pk_element.to_compressed().as_slice(), &app_id);

        // Then
        let ts_result = ckd::hash_app_id_with_pk(&vk, &app_id);
        assert_eq!(
            contract_result,
            ts_result.to_affine().to_uncompressed().as_slice(),
            "contract and threshold-signatures hash_app_id_with_pk must agree"
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn hash_app_id_with_pk__should_produce_stable_output() {
        // Given
        let pk = G2Projective::generator().to_compressed();
        let app_id = [0u8; 32];

        // When
        let result = hash_app_id_with_pk(&pk, &app_id);

        // Then
        let point = G1Affine::from_uncompressed(
            result
                .as_slice()
                .try_into()
                .expect("hash point is 96 bytes"),
        )
        .into_option()
        .expect("hash point is a valid G1 point");
        let compressed = hex::encode(point.to_compressed());
        insta::assert_snapshot!(compressed);
    }

    #[test]
    #[expect(non_snake_case)]
    fn bls12381_pairing_check__should_reject_g1_point_outside_prime_order_subgroup() {
        // Given: a G1 point on the curve but outside the prime-order
        // subgroup, paired with the G2 identity. A host that skipped the
        // subgroup check would evaluate the pairing to the identity and
        // return true; the subgroup check is the only reason this fails.
        let rogue = must_g1_point_outside_subgroup();
        let g2_identity = G2Projective::identity().to_uncompressed();
        let pairing_input = [rogue.to_uncompressed().as_slice(), &g2_identity].concat();

        // When
        let accepted = env::bls12381_pairing_check(&pairing_input);

        // Then
        assert!(
            !accepted,
            "the host must reject G1 points outside the prime-order subgroup"
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn bls12381_pairing_check__should_reject_g2_point_outside_prime_order_subgroup() {
        // Given: a non-subgroup G2 point paired with the G1 identity
        let rogue = must_g2_point_outside_subgroup();
        let g1_identity = G1Projective::identity().to_uncompressed();
        let pairing_input = [g1_identity.as_slice(), &rogue.to_uncompressed()].concat();

        // When
        let accepted = env::bls12381_pairing_check(&pairing_input);

        // Then
        assert!(
            !accepted,
            "the host must reject G2 points outside the prime-order subgroup"
        );
    }

    /// Control for the two rejection tests above: identity points themselves
    /// are accepted, so the rejections are caused by the rogue points only.
    #[test]
    #[expect(non_snake_case)]
    fn bls12381_pairing_check__should_accept_pairs_containing_identity_points() {
        // Given: e(g1, identity) * e(identity, g2) = 1
        let g1 = G1Projective::generator().to_uncompressed();
        let g1_identity = G1Projective::identity().to_uncompressed();
        let g2 = G2Projective::generator().to_uncompressed();
        let g2_identity = G2Projective::identity().to_uncompressed();
        let pairing_input = [
            g1.as_slice(),
            g2_identity.as_slice(),
            g1_identity.as_slice(),
            g2.as_slice(),
        ]
        .concat();

        // When
        let accepted = env::bls12381_pairing_check(&pairing_input);

        // Then
        assert!(accepted);
    }

    #[test]
    #[should_panic(expected = "Register was expected to have data")]
    #[expect(non_snake_case)]
    fn bls12381_p1_decompress__should_abort_on_x_coordinate_not_on_curve() {
        // Given: a compressed encoding whose x-coordinate lies on no curve point
        let candidate = must_g1_x_not_on_curve();

        // When / Then: the host rejects it and the SDK wrapper aborts
        env::bls12381_p1_decompress(candidate);
    }

    #[test]
    #[should_panic(expected = "Register was expected to have data")]
    #[expect(non_snake_case)]
    fn bls12381_p1_decompress__should_abort_on_x_coordinate_overflowing_the_field() {
        // Given: a compressed encoding whose x-coordinate is >= p
        let mut candidate = [0xffu8; 48];
        candidate[0] = 0x9f; // compressed-encoding flag, x starts with 0x1ff...

        // When / Then: the host rejects it and the SDK wrapper aborts
        env::bls12381_p1_decompress(candidate);
    }

    #[test]
    #[should_panic(expected = "Register was expected to have data")]
    #[expect(non_snake_case)]
    fn bls12381_p2_decompress__should_abort_on_x_coordinate_not_on_curve() {
        // Given: a compressed encoding whose x-coordinate lies on no curve point
        let candidate = must_g2_x_not_on_curve();

        // When / Then: the host rejects it and the SDK wrapper aborts
        env::bls12381_p2_decompress(candidate);
    }

    #[test]
    #[should_panic(expected = "Register was expected to have data")]
    #[expect(non_snake_case)]
    fn bls12381_p2_decompress__should_abort_on_x_coordinate_overflowing_the_field() {
        // Given: a compressed encoding whose x-coordinate is >= p
        let mut candidate = [0xffu8; 96];
        candidate[0] = 0x9f; // compressed-encoding flag, x starts with 0x1ff...

        // When / Then: the host rejects it and the SDK wrapper aborts
        env::bls12381_p2_decompress(candidate);
    }

    #[test]
    #[expect(non_snake_case)]
    fn app_public_key_check__should_accept_key_pair_with_matching_scalar() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let app_pk = make_app_public_key_pv(Scalar::random(&mut rng));

        // When
        let accepted = app_public_key_check(&app_pk);

        // Then
        assert!(accepted);
    }

    #[test]
    #[expect(non_snake_case)]
    fn app_public_key_check__should_reject_key_pair_with_mismatched_scalars() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let pk1_scalar = Scalar::random(&mut rng);
        let pk2_scalar = Scalar::random(&mut rng);
        let app_pk = dtos::CKDAppPublicKeyPV {
            pk1: dtos::Bls12381G1PublicKey(
                (G1Projective::generator() * pk1_scalar).to_compressed(),
            ),
            pk2: dtos::Bls12381G2PublicKey(
                (G2Projective::generator() * pk2_scalar).to_compressed(),
            ),
        };

        // When
        let accepted = app_public_key_check(&app_pk);

        // Then
        assert!(!accepted);
    }

    #[test]
    #[expect(non_snake_case)]
    fn app_public_key_check__should_reject_pk1_outside_prime_order_subgroup() {
        // Given: pk1 on the curve but outside the subgroup, so decompression
        // alone accepts it and only the pairing-check subgroup validation can
        // reject it
        let app_pk = dtos::CKDAppPublicKeyPV {
            pk1: dtos::Bls12381G1PublicKey(must_g1_point_outside_subgroup().to_compressed()),
            pk2: dtos::Bls12381G2PublicKey(G2Projective::generator().to_compressed()),
        };

        // When
        let accepted = app_public_key_check(&app_pk);

        // Then
        assert!(!accepted);
    }

    /// Documents the pre-existing behavior that identity key pairs satisfy
    /// the pairing equation and are accepted.
    #[test]
    #[expect(non_snake_case)]
    fn app_public_key_check__should_accept_identity_key_pair() {
        // Given
        let app_pk = dtos::CKDAppPublicKeyPV {
            pk1: dtos::Bls12381G1PublicKey(G1Projective::identity().to_compressed()),
            pk2: dtos::Bls12381G2PublicKey(G2Projective::identity().to_compressed()),
        };

        // When
        let accepted = app_public_key_check(&app_pk);

        // Then
        assert!(accepted);
    }

    /// Builds a CKD output that satisfies
    /// `e(big_c, g2) = e(big_y, app_pk2) . e(hash_point, public_key)`.
    fn make_valid_ckd_output(
        rng: &mut StdRng,
    ) -> (
        dtos::CkdAppId,
        CKDResponse,
        dtos::CKDAppPublicKeyPV,
        dtos::Bls12381G2PublicKey,
    ) {
        let msk = Scalar::random(&mut *rng);
        let network_pk =
            dtos::Bls12381G2PublicKey((G2Projective::generator() * msk).to_compressed());

        let app_scalar = Scalar::random(&mut *rng);
        let app_pk1 = G1Projective::generator() * app_scalar;
        let app_pk = make_app_public_key_pv(app_scalar);

        let app_id = derive_app_id(&"alice.near".parse().unwrap(), "path");
        let hash_point = G1Projective::hash_to_curve(
            &[network_pk.0.as_slice(), app_id.as_ref()].concat(),
            NEAR_CKD_DOMAIN,
            &[],
        );

        let y = Scalar::random(&mut *rng);
        let big_y = G1Projective::generator() * y;
        let big_c = hash_point * msk + app_pk1 * y;
        let response = CKDResponse {
            big_y: dtos::Bls12381G1PublicKey(big_y.to_compressed()),
            big_c: dtos::Bls12381G1PublicKey(big_c.to_compressed()),
        };
        (app_id, response, app_pk, network_pk)
    }

    #[test]
    #[expect(non_snake_case)]
    fn ckd_output_check__should_accept_valid_protocol_output() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let (app_id, response, app_pk, network_pk) = make_valid_ckd_output(&mut rng);

        // When
        let accepted = ckd_output_check(&app_id, &response, &app_pk, &network_pk);

        // Then
        assert!(accepted);
    }

    #[test]
    #[expect(non_snake_case)]
    fn ckd_output_check__should_reject_tampered_big_c() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let (app_id, mut response, app_pk, network_pk) = make_valid_ckd_output(&mut rng);
        response.big_c = dtos::Bls12381G1PublicKey(
            (G1Projective::generator() * Scalar::random(&mut rng)).to_compressed(),
        );

        // When
        let accepted = ckd_output_check(&app_id, &response, &app_pk, &network_pk);

        // Then
        assert!(!accepted);
    }

    #[test]
    fn ckd_request_new_derives_app_id_deterministically() {
        let account_id: AccountId = "alice.near".parse().unwrap();
        let pk = dtos::CKDAppPublicKey::AppPublicKey(dtos::Bls12381G1PublicKey([1u8; 48]));
        let domain_id = DomainId(0);

        let r1 = CKDRequest::new(pk.clone(), domain_id, &account_id, "path/a");
        let r2 = CKDRequest::new(pk.clone(), domain_id, &account_id, "path/a");
        assert_eq!(r1.app_id, r2.app_id);

        let r3 = CKDRequest::new(pk, domain_id, &account_id, "path/b");
        assert_ne!(r1.app_id, r3.app_id);
    }
}
