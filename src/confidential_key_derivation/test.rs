type C = crate::confidential_key_derivation::ciphersuite::BLS12381SHA256;

use crate::test_utils::generate_participants;

#[test]
fn test_keygen() {
    let participants = generate_participants(3);
    let threshold = 2;
    crate::dkg::test::test_keygen::<C>(&participants, threshold);
}

#[test]
fn test_refresh() {
    let participants = generate_participants(3);
    let threshold = 2;
    crate::dkg::test::test_refresh::<C>(&participants, threshold);
}

#[test]
fn test_reshare() {
    let participants = generate_participants(3);
    let threshold0 = 2;
    let threshold1 = 3;
    crate::dkg::test::test_reshare::<C>(&participants, threshold0, threshold1);
}
