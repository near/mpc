//! Test vectors for Confidential Key Derivation (CKD).
//!
//! The committed vectors live in `tests/vectors/ckd_test_vectors.json` (see its
//! `_encoding` block for the serialization conventions). Each fixes the scalars
//! `msk`, `a`, `y` and an `app_id`, and records every intermediate and final
//! value so an independent implementation can reproduce and check the scheme.
//!
//! `generate_ckd_test_vectors` (ignored) regenerates the JSON; the other tests
//! verify the committed values against the public crate API.

use blstrs::{Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar};
use digest::Digest as _;
use elliptic_curve::Group as _;
use hkdf::Hkdf;
use pairing::{MillerLoopResult as _, MultiMillerLoop as _};
use serde::Deserialize;
use sha2::Sha256;
use threshold_signatures::confidential_key_derivation::{
    self as ckd, CKDOutput, VerifyingKey, ciphersuite::verify_signature,
};

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/ckd_test_vectors.json"
);

/// Hash-to-curve domain separator, mirroring the crate-private constant of the
/// same name; used only to document the DST in the generated vectors file.
const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";

#[derive(Deserialize)]
struct TestVectors {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    // Inputs.
    msk: String,
    a: String,
    y: String,
    app_id: String,
    // Expected values.
    pk: String,
    app_pk1: String,
    app_pk2: String,
    hash_point: String,
    big_y: String,
    big_c: String,
    sig: String,
    s: String,
}

fn load_vectors() -> Vec<Vector> {
    let data = std::fs::read_to_string(VECTORS_PATH).expect("read test vectors file");
    let parsed: TestVectors = serde_json::from_str(&data).expect("parse test vectors file");
    parsed.vectors
}

/// Parses a 32-byte big-endian hex scalar, reduced mod the BLS12-381 scalar order.
fn scalar_from_be_hex(hex_be: &str) -> Scalar {
    let mut bytes: [u8; 32] = hex::decode(hex_be)
        .expect("scalar hex")
        .try_into()
        .expect("scalar is 32 bytes");
    bytes.reverse();
    Scalar::from_bytes_le(&bytes)
        .into_option()
        .expect("scalar below the group order")
}

fn g1_from_hex(hex_compressed: &str) -> G1Projective {
    let bytes: [u8; 48] = hex::decode(hex_compressed)
        .expect("g1 hex")
        .try_into()
        .expect("g1 point is 48 bytes");
    G1Projective::from_compressed(&bytes)
        .into_option()
        .expect("valid compressed G1 point")
}

fn g2_from_hex(hex_compressed: &str) -> G2Projective {
    let bytes: [u8; 96] = hex::decode(hex_compressed)
        .expect("g2 hex")
        .try_into()
        .expect("g2 point is 96 bytes");
    G2Projective::from_compressed(&bytes)
        .into_option()
        .expect("valid compressed G2 point")
}

fn hex_g1(point: &G1Projective) -> String {
    hex::encode(point.to_compressed())
}

fn hex_g2(point: &G2Projective) -> String {
    hex::encode(point.to_compressed())
}

/// `H(pk_compressed || app_id)` mapped to G1.
fn hash_point(pk: &G2Projective, app_id: &[u8]) -> G1Projective {
    ckd::hash_app_id_with_pk(&VerifyingKey::new(*pk), app_id)
}

/// HKDF-SHA256 with no salt and empty info over the 48-byte compressed signature.
fn derive_strong_key(sig: &G1Projective) -> [u8; 32] {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, &sig.to_compressed())
        .expand(b"", &mut okm)
        .expect("hkdf expand");
    okm
}

/// Returns true iff the product of pairings `e(a_i, b_i)` equals the identity.
fn pairing_product_is_identity(pairs: &[(G1Projective, G2Projective)]) -> bool {
    let prepared: Vec<(G1Affine, G2Prepared)> = pairs
        .iter()
        .map(|(a, b)| (G1Affine::from(a), G2Prepared::from(G2Affine::from(b))))
        .collect();
    let refs: Vec<(&G1Affine, &G2Prepared)> = prepared.iter().map(|(a, b)| (a, b)).collect();
    Bls12::multi_miller_loop(&refs)
        .final_exponentiation()
        .is_identity()
        .into()
}

#[test]
#[expect(non_snake_case)]
fn ckd_test_vectors__should_derive_expected_public_values() {
    // Given
    let vectors = load_vectors();

    for v in &vectors {
        let msk = scalar_from_be_hex(&v.msk);
        let a = scalar_from_be_hex(&v.a);
        let y = scalar_from_be_hex(&v.y);
        let app_id = hex::decode(&v.app_id).expect("app_id hex");

        // When
        let pk = G2Projective::generator() * msk;
        let app_pk1 = G1Projective::generator() * a;
        let app_pk2 = G2Projective::generator() * a;
        let h = hash_point(&pk, &app_id);
        let big_y = G1Projective::generator() * y;
        let big_c = h * msk + app_pk1 * y;

        // Then
        assert_eq!(hex_g2(&pk), v.pk);
        assert_eq!(hex_g1(&app_pk1), v.app_pk1);
        assert_eq!(hex_g2(&app_pk2), v.app_pk2);
        assert_eq!(hex_g1(&h), v.hash_point);
        assert_eq!(hex_g1(&big_y), v.big_y);
        assert_eq!(hex_g1(&big_c), v.big_c);
    }
}

/// Private-verifiability recovery: the app unmasks `(big_y, big_c)` with its
/// secret `a` and the resulting BLS signature verifies against the network key.
#[test]
#[expect(non_snake_case)]
fn ckd_test_vectors__should_recover_a_signature_that_verifies() {
    // Given
    let vectors = load_vectors();

    for v in &vectors {
        let a = scalar_from_be_hex(&v.a);
        let pk = g2_from_hex(&v.pk);
        let big_y = g1_from_hex(&v.big_y);
        let big_c = g1_from_hex(&v.big_c);
        let app_id = hex::decode(&v.app_id).expect("app_id hex");

        // When
        let sig = CKDOutput::new(big_y, big_c).unmask(a);

        // Then
        assert_eq!(hex_g1(&sig), v.sig);
        assert!(verify_signature(&VerifyingKey::new(pk), &app_id, &sig).is_ok());
    }
}

#[test]
#[expect(non_snake_case)]
fn ckd_test_vectors__should_derive_expected_hkdf_secret() {
    // Given
    let vectors = load_vectors();

    for v in &vectors {
        let sig = g1_from_hex(&v.sig);

        // When
        let s = derive_strong_key(&sig);

        // Then
        assert_eq!(hex::encode(s), v.s);
    }
}

/// Public-verifiability: the app key pair and the aggregated output satisfy the
/// pairing equations an observer checks without knowing the app secret `a`.
#[test]
#[expect(non_snake_case)]
fn ckd_test_vectors__should_satisfy_public_verifiability_pairings() {
    // Given
    let vectors = load_vectors();

    for v in &vectors {
        let pk = g2_from_hex(&v.pk);
        let app_pk1 = g1_from_hex(&v.app_pk1);
        let app_pk2 = g2_from_hex(&v.app_pk2);
        let h = g1_from_hex(&v.hash_point);
        let big_y = g1_from_hex(&v.big_y);
        let big_c = g1_from_hex(&v.big_c);
        let minus_g2 = -G2Projective::generator();

        // When: e(app_pk1, G2) = e(G1, app_pk2)
        let app_key_ok = pairing_product_is_identity(&[
            (app_pk1, minus_g2),
            (G1Projective::generator(), app_pk2),
        ]);
        // When: e(big_c, G2) = e(big_y, app_pk2) . e(hash_point, pk)
        let output_ok =
            pairing_product_is_identity(&[(big_c, minus_g2), (big_y, app_pk2), (h, pk)]);

        // Then
        assert!(app_key_ok, "app public key pairing check failed");
        assert!(output_ok, "aggregated output pairing check failed");
    }
}

/// Source for a generator scalar: a label to be hashed (top byte cleared so it
/// stays below the group order) or an explicit 32-byte big-endian hex value.
enum ScalarSpec {
    Label(&'static str),
    Hex(&'static str),
}

fn resolve_scalar(spec: &ScalarSpec) -> ([u8; 32], Scalar) {
    let be: [u8; 32] = match spec {
        ScalarSpec::Label(label) => {
            let mut be: [u8; 32] = Sha256::digest(label.as_bytes()).into();
            be[0] &= 0x3f;
            be
        }
        ScalarSpec::Hex(hex_be) => hex::decode(hex_be)
            .expect("scalar hex")
            .try_into()
            .expect("scalar is 32 bytes"),
    };
    let mut le = be;
    le.reverse();
    let scalar = Scalar::from_bytes_le(&le)
        .into_option()
        .expect("scalar below the group order");
    (be, scalar)
}

/// Computes a full vector (inputs echoed + all derived values) as JSON. The
/// `app_id` bytes are arbitrary; SHA-256 of a label is just a convenient
/// deterministic source.
fn compute_vector(
    app_id_label: &str,
    msk_spec: &ScalarSpec,
    a_spec: &ScalarSpec,
    y_spec: &ScalarSpec,
) -> serde_json::Value {
    let (msk_be, msk) = resolve_scalar(msk_spec);
    let (a_be, a) = resolve_scalar(a_spec);
    let (y_be, y) = resolve_scalar(y_spec);
    let app_id: [u8; 32] = Sha256::digest(app_id_label.as_bytes()).into();

    let pk = G2Projective::generator() * msk;
    let app_pk1 = G1Projective::generator() * a;
    let app_pk2 = G2Projective::generator() * a;
    let h = hash_point(&pk, &app_id);
    let big_y = G1Projective::generator() * y;
    let big_c = h * msk + app_pk1 * y;
    let sig = CKDOutput::new(big_y, big_c).unmask(a);
    let s = derive_strong_key(&sig);

    serde_json::json!({
        "msk": hex::encode(msk_be),
        "a": hex::encode(a_be),
        "y": hex::encode(y_be),
        "app_id": hex::encode(app_id),
        "pk": hex_g2(&pk),
        "app_pk1": hex_g1(&app_pk1),
        "app_pk2": hex_g2(&app_pk2),
        "hash_point": hex_g1(&h),
        "big_y": hex_g1(&big_y),
        "big_c": hex_g1(&big_c),
        "sig": hex_g1(&sig),
        "s": hex::encode(s),
    })
}

/// The self-describing `_encoding` / `_notes` header of the vectors file.
fn vectors_metadata() -> serde_json::Value {
    serde_json::json!({
        "_encoding": {
            "curve": "BLS12-381",
            "scalars": "32-byte big-endian hex, reduced mod the scalar field order",
            "g1_points": "48-byte compressed hex (blstrs/ZCash encoding)",
            "g2_points": "96-byte compressed hex (blstrs/ZCash encoding)",
            "pk_group": "G2 (network public key)",
            "signature_group": "G1",
            "app_id": "application identifier bytes",
            "hash_to_curve_dst": String::from_utf8_lossy(NEAR_CKD_DOMAIN),
            "hash_to_curve_input": "pk_compressed(96B) || app_id, RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_, empty aug",
            "s": "HKDF-SHA256(ikm = sig_compressed[48B], salt = none, info = \"\"), 32 bytes",
        },
        "_notes": {
            "derivation": "pk = msk.G2 ; A1 = a.G1 ; A2 = a.G2 ; hash_point = H(pk||app_id) ; big_y = y.G1 ; big_c = hash_point.msk + A1.y ; sig = big_c - a.big_y = msk.hash_point ; s = HKDF(sig)",
            "private_verifiability": "app recovers sig via unmask(a) and verifies e(hash_point, pk) = e(sig, G2)",
            "public_verifiability": "adds A2 and the checks e(A1, G2) = e(G1, A2) and e(big_c, G2) = e(big_y, A2) . e(hash_point, pk)",
        },
    })
}

/// Regenerates `tests/vectors/ckd_test_vectors.json`. Ignored so it never runs
/// in CI; run manually with `cargo nextest run -- --ignored generate_ckd_test_vectors`
/// (or `cargo test -- --ignored generate_ckd_test_vectors --nocapture`) and paste
/// the printed JSON into the file.
#[test]
#[ignore = "manual test-vector generator; prints JSON to stdout"]
fn generate_ckd_test_vectors() {
    // q - 1, the largest valid scalar; exercises little-endian encoding and
    // canonical reduction on the consuming side.
    const MAX_SCALAR: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000";

    // (app_id label, msk, app-secret a, blinding y)
    let inputs = [
        (
            "ckd-vector-1/app_id",
            ScalarSpec::Label("ckd-vector-1/msk"),
            ScalarSpec::Label("ckd-vector-1/a"),
            ScalarSpec::Label("ckd-vector-1/y"),
        ),
        (
            "ckd-vector-2/app_id",
            ScalarSpec::Label("ckd-vector-2/msk"),
            ScalarSpec::Label("ckd-vector-2/a"),
            ScalarSpec::Label("ckd-vector-2/y"),
        ),
        // Hand-checkable anchor: msk = a = y = 1, so pk and app_pk1 are the group
        // generators, big_y = G1, and sig = hash_point.
        (
            "ckd-vector-3/app_id",
            ScalarSpec::Hex("0000000000000000000000000000000000000000000000000000000000000001"),
            ScalarSpec::Hex("0000000000000000000000000000000000000000000000000000000000000001"),
            ScalarSpec::Hex("0000000000000000000000000000000000000000000000000000000000000001"),
        ),
        // High-bit scalars: exercises little-endian encoding and canonical
        // reduction (msk = q - 1, the largest valid scalar).
        (
            "ckd-vector-4/app_id",
            ScalarSpec::Hex(MAX_SCALAR),
            ScalarSpec::Hex("6fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            ScalarSpec::Hex("5abbccddeeff00112233445566778899aabbccddeeff00112233445566778899"),
        ),
    ];

    let vectors: Vec<serde_json::Value> = inputs
        .iter()
        .map(|(app_id_label, msk_spec, a_spec, y_spec)| {
            compute_vector(app_id_label, msk_spec, a_spec, y_spec)
        })
        .collect();

    let mut doc = vectors_metadata();
    doc["vectors"] = serde_json::Value::Array(vectors);

    println!(
        "{}",
        serde_json::to_string_pretty(&doc).expect("serialize vectors")
    );
}
