//! Test vectors for Confidential Key Derivation (CKD).
//!
//! The committed vectors live in `tests/vectors/ckd_test_vectors.json` (see its
//! `_encoding` block for the serialization conventions). Each fixes the scalars
//! `msk`, `a` and an `app_id`, and records every intermediate and final value so
//! an independent implementation can reproduce and check the scheme.
//!
//! `generate_ckd_test_vectors` (ignored) regenerates the JSON; the other tests
//! verify the committed values against the public crate API.

use blstrs::{Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar};
use digest::Digest as _;
use elliptic_curve::Group as _;
use hkdf::Hkdf;
use pairing::{MillerLoopResult as _, MultiMillerLoop as _};
use rand::SeedableRng as _;
use serde::Deserialize;
use sha2::Sha256;
use threshold_signatures::confidential_key_derivation::{
    self as ckd, AppId, BLS12381SHA256, CKDOutput, PublicVerificationKey, VerifyingKey,
    ciphersuite::verify_signature,
};
use threshold_signatures::test_utils::{
    MockCryptoRng, deal_keygen_outputs, generate_participants, run_ckd_pv,
};

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/ckd_test_vectors.json"
);

/// Mirror of the crate-private `crypto::constants::NEAR_CKD_DOMAIN` (the source
/// of truth); used only to document the DST in the generated vectors file.
const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// The threshold instance the vectors are generated from. All participants take
/// part, so the sharing reconstructs `msk` regardless of the threshold.
const NUM_PARTICIPANTS: usize = 3;
const THRESHOLD: usize = 2;

/// Base RNG seed; each vector uses `BASE_SEED + index` so the generator and the
/// regression check drive the protocol identically.
const BASE_SEED: u64 = 0xC0DE_0000;

#[derive(Deserialize)]
struct TestVectors {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    // Inputs.
    msk: String,
    a: String,
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

/// Parses a 32-byte big-endian hex scalar. The value must be canonical, i.e.
/// strictly less than the BLS12-381 scalar order (no reduction is performed).
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

fn hash_point(pk: &VerifyingKey, app_id: &[u8]) -> G1Projective {
    ckd::hash_app_id_with_pk(pk, app_id)
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

/// Every value a vector records, as hex strings.
struct DerivedVector {
    pk: String,
    app_pk1: String,
    app_pk2: String,
    hash_point: String,
    big_y: String,
    big_c: String,
    sig: String,
    s: String,
}

/// Derives a full vector by running the real threshold `ckd_pv` protocol.
///
/// `msk` is dealt to [`NUM_PARTICIPANTS`] participants and every participant runs
/// the protocol, so the coordinator's aggregated `(big_y, big_c)` is genuine
/// protocol output. All randomness is seeded from `seed`, so the result is
/// reproducible.
fn derive_vector(msk: Scalar, a: Scalar, app_id: &[u8], seed: u64) -> DerivedVector {
    let participants = generate_participants(NUM_PARTICIPANTS);
    let coordinator = *participants.first().expect("participant list is not empty");

    let pk = VerifyingKey::new(G2Projective::generator() * msk);
    let app_pk1 = G1Projective::generator() * a;
    let app_pk2 = G2Projective::generator() * a;
    let app_pk = PublicVerificationKey::new(app_pk1, app_pk2);
    let h = hash_point(&pk, app_id);
    let app_id = AppId::try_from(app_id).expect("valid app_id");

    let mut rng = MockCryptoRng::seed_from_u64(seed);
    let key_packages =
        deal_keygen_outputs::<BLS12381SHA256>(msk, &participants, THRESHOLD, &mut rng);
    let output = run_ckd_pv(&key_packages, coordinator, &app_id, &app_pk, &mut rng)
        .expect("run ckd protocol");

    let sig = output.unmask(a);
    let s = derive_strong_key(&sig);

    DerivedVector {
        pk: hex_g2(&pk.to_element()),
        app_pk1: hex_g1(&app_pk1),
        app_pk2: hex_g2(&app_pk2),
        hash_point: hex_g1(&h),
        big_y: hex_g1(&output.big_y()),
        big_c: hex_g1(&output.big_c()),
        sig: hex_g1(&sig),
        s: hex::encode(s),
    }
}

/// Re-runs the real protocol on the committed inputs and asserts every recorded
/// value matches. Fails if our implementation drifts from the committed vectors.
#[test]
#[expect(non_snake_case)]
fn ckd_test_vectors__should_match_real_protocol() {
    // Given
    let vectors = load_vectors();

    for (i, v) in vectors.iter().enumerate() {
        let msk = scalar_from_be_hex(&v.msk);
        let a = scalar_from_be_hex(&v.a);
        let app_id = hex::decode(&v.app_id).expect("app_id hex");

        // When
        let derived = derive_vector(msk, a, &app_id, BASE_SEED + i as u64);

        // Then
        assert_eq!(derived.pk, v.pk, "vector {i}: pk");
        assert_eq!(derived.app_pk1, v.app_pk1, "vector {i}: app_pk1");
        assert_eq!(derived.app_pk2, v.app_pk2, "vector {i}: app_pk2");
        assert_eq!(derived.hash_point, v.hash_point, "vector {i}: hash_point");
        assert_eq!(derived.big_y, v.big_y, "vector {i}: big_y");
        assert_eq!(derived.big_c, v.big_c, "vector {i}: big_c");
        assert_eq!(derived.sig, v.sig, "vector {i}: sig");
        assert_eq!(derived.s, v.s, "vector {i}: s");
    }
}

/// Private-verifiability recovery: the app unmasks `(big_y, big_c)` with its
/// secret `a` and the resulting BLS signature verifies against the network key.
#[test]
#[expect(non_snake_case)]
fn ckd_test_vectors__should_recover_a_signature_that_verifies() {
    // Given
    let vectors = load_vectors();

    for (i, v) in vectors.iter().enumerate() {
        let a = scalar_from_be_hex(&v.a);
        let pk = g2_from_hex(&v.pk);
        let big_y = g1_from_hex(&v.big_y);
        let big_c = g1_from_hex(&v.big_c);
        let app_id = hex::decode(&v.app_id).expect("app_id hex");

        // When
        let sig = CKDOutput::new(big_y, big_c).unmask(a);

        // Then
        assert_eq!(hex_g1(&sig), v.sig, "vector {i}: sig");
        assert!(
            verify_signature(&VerifyingKey::new(pk), &app_id, &sig).is_ok(),
            "vector {i}: signature verification"
        );
    }
}

#[test]
#[expect(non_snake_case)]
fn ckd_test_vectors__should_derive_expected_hkdf_secret() {
    // Given
    let vectors = load_vectors();

    for (i, v) in vectors.iter().enumerate() {
        let sig = g1_from_hex(&v.sig);

        // When
        let s = derive_strong_key(&sig);

        // Then
        assert_eq!(hex::encode(s), v.s, "vector {i}: s");
    }
}

/// Public-verifiability: the app key pair and the aggregated output satisfy the
/// pairing equations an observer checks without knowing the app secret `a`.
#[test]
#[expect(non_snake_case)]
fn ckd_test_vectors__should_satisfy_public_verifiability_pairings() {
    // Given
    let vectors = load_vectors();

    for (i, v) in vectors.iter().enumerate() {
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
        assert!(
            app_key_ok,
            "vector {i}: app public key pairing check failed"
        );
        assert!(
            output_ok,
            "vector {i}: aggregated output pairing check failed"
        );
    }
}

/// Source for a generator scalar: a label to be hashed (top two bits of the top
/// byte cleared so the result stays below the scalar order) or an explicit
/// 32-byte big-endian hex value.
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
    seed: u64,
) -> serde_json::Value {
    let (msk_be, msk) = resolve_scalar(msk_spec);
    let (a_be, a) = resolve_scalar(a_spec);
    let app_id: [u8; 32] = Sha256::digest(app_id_label.as_bytes()).into();

    let derived = derive_vector(msk, a, &app_id, seed);

    serde_json::json!({
        "msk": hex::encode(msk_be),
        "a": hex::encode(a_be),
        "app_id": hex::encode(app_id),
        "pk": derived.pk,
        "app_pk1": derived.app_pk1,
        "app_pk2": derived.app_pk2,
        "hash_point": derived.hash_point,
        "big_y": derived.big_y,
        "big_c": derived.big_c,
        "sig": derived.sig,
        "s": derived.s,
    })
}

/// The self-describing `_encoding` header of the vectors file.
fn vectors_metadata() -> serde_json::Value {
    serde_json::json!({
        "_encoding": {
            "curve": "BLS12-381",
            "scalars": "32-byte big-endian hex, canonical (strictly less than the scalar field order)",
            "g1_points": "48-byte compressed hex (blstrs/ZCash encoding)",
            "g2_points": "96-byte compressed hex (blstrs/ZCash encoding)",
            "pk_group": "G2 (network public key)",
            "signature_group": "G1",
            "app_id": "application identifier bytes",
            "hash_to_curve_dst": String::from_utf8_lossy(NEAR_CKD_DOMAIN),
            "hash_to_curve_input": "pk_compressed(96B) || app_id, RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_, empty aug",
            "s": "HKDF-SHA256(ikm = sig_compressed[48B], salt = none, info = \"\"), 32 bytes",
        },
    })
}

/// Rewrites `tests/vectors/ckd_test_vectors.json` in place. Ignored so it never
/// runs in CI; run manually with
/// `cargo nextest run -- --ignored generate_ckd_test_vectors` after changing the
/// scheme or the vector inputs, then commit the regenerated file.
#[test]
#[ignore = "manual test-vector generator; rewrites the committed vectors file"]
fn generate_ckd_test_vectors() {
    // q - 1, the largest valid scalar; exercises little-endian encoding and
    // canonical reduction on the consuming side.
    const MAX_SCALAR: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000";

    // (app_id label, msk, app-secret a)
    let inputs = [
        (
            "ckd-vector-1/app_id",
            ScalarSpec::Label("ckd-vector-1/msk"),
            ScalarSpec::Label("ckd-vector-1/a"),
        ),
        (
            "ckd-vector-2/app_id",
            ScalarSpec::Label("ckd-vector-2/msk"),
            ScalarSpec::Label("ckd-vector-2/a"),
        ),
        // Hand-checkable anchor: msk = a = 1, so pk and app_pk1 are the group
        // generators and sig = hash_point (unmask cancels the blinding).
        (
            "ckd-vector-3/app_id",
            ScalarSpec::Hex("0000000000000000000000000000000000000000000000000000000000000001"),
            ScalarSpec::Hex("0000000000000000000000000000000000000000000000000000000000000001"),
        ),
        // High-bit scalars: exercises little-endian encoding and canonical
        // reduction (msk = q - 1, the largest valid scalar).
        (
            "ckd-vector-4/app_id",
            ScalarSpec::Hex(MAX_SCALAR),
            ScalarSpec::Hex("6fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ),
    ];

    let vectors: Vec<serde_json::Value> = inputs
        .iter()
        .enumerate()
        .map(|(i, (app_id_label, msk_spec, a_spec))| {
            compute_vector(app_id_label, msk_spec, a_spec, BASE_SEED + i as u64)
        })
        .collect();

    let mut doc = vectors_metadata();
    doc["vectors"] = serde_json::Value::Array(vectors);

    let json = serde_json::to_string_pretty(&doc).expect("serialize vectors");
    std::fs::write(VECTORS_PATH, format!("{json}\n")).expect("write test vectors file");
    println!("wrote {VECTORS_PATH}");
}
