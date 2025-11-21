type C = crate::confidential_key_derivation::ciphersuite::BLS12381SHA256;

use rand::SeedableRng;

use crate::test_utils::{generate_participants, MockCryptoRng};

#[test]
fn test_keygen() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold = 2;
    crate::dkg::test::test_keygen::<C, _>(&participants, threshold, &mut rng);
}

#[test]
fn test_refresh() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold = 2;
    crate::dkg::test::test_refresh::<C, _>(&participants, threshold, &mut rng);
}

#[test]
fn test_reshare() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold0 = 2;
    let threshold1 = 3;
    crate::dkg::test::test_reshare::<C, _>(&participants, threshold0, threshold1, &mut rng);
}

#[test]
fn test_keygen_determinism() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold = 2;
    let result = crate::dkg::test::test_keygen::<C, _>(&participants, threshold, &mut rng);
    insta::assert_json_snapshot!(result);
}

#[test]
fn test_refresh_determinism() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold = 2;
    let result = crate::dkg::test::test_refresh::<C, _>(&participants, threshold, &mut rng);
    insta::assert_json_snapshot!(result);
}

#[test]
fn test_reshare_determinism() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold0 = 2;
    let threshold1 = 3;
    let result =
        crate::dkg::test::test_reshare::<C, _>(&participants, threshold0, threshold1, &mut rng);
    insta::assert_json_snapshot!(result);
}

#[test]
fn test_keygen_threshold_limits() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    crate::dkg::test::keygen__should_fail_if_threshold_is_below_limit::<C, _>(&mut rng);
}

#[test]
fn test_reshare_threshold_limits() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    crate::dkg::test::reshare__should_fail_if_threshold_is_below_limit::<C, _>(&mut rng);
}
