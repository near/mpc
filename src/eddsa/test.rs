use crate::crypto::hash::HashOutput;
use crate::eddsa::{sign::sign, KeygenOutput, SignatureOption};
use crate::participants::{Participant, ParticipantList};
use crate::test::{generate_participants, run_protocol, GenOutput, GenProtocol, MockCryptoRng};

use frost_core::keys::SigningShare;
use frost_core::VerifyingKey as FrostVerifyingKey;
use frost_core::{Scalar as FrostScalar, SigningKey as FrostSigningKey};
use frost_ed25519::Ed25519Sha512;

type C = Ed25519Sha512;
use rand_core::{OsRng, RngCore};
use std::error::Error;

/// this is a centralized key generation
pub fn build_key_packages_with_dealer(max_signers: u16, min_signers: u16) -> GenOutput<C> {
    use std::collections::BTreeMap;

    let mut identifiers = Vec::with_capacity(max_signers.into());
    for _ in 0..max_signers {
        // from 1 to avoid assigning 0 to a ParticipantId
        identifiers.push(Participant::from(OsRng.next_u32()));
    }

    let from_frost_identifiers = identifiers
        .iter()
        .map(|&x| (x.to_identifier().unwrap(), x))
        .collect::<BTreeMap<_, _>>();

    let identifiers_list = from_frost_identifiers.keys().copied().collect::<Vec<_>>();

    let (shares, pubkey_package) = frost_ed25519::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost_ed25519::keys::IdentifierList::Custom(identifiers_list.as_slice()),
        OsRng,
    )
    .unwrap();

    shares
        .into_iter()
        .map(|(id, share)| {
            (
                from_frost_identifiers[&id],
                KeygenOutput {
                    private_share: *share.signing_share(),
                    public_key: *pubkey_package.verifying_key(),
                },
            )
        })
        .collect::<Vec<_>>()
}

pub fn test_run_signature_protocols(
    participants: &[(Participant, KeygenOutput)],
    actual_signers: usize,
    coordinators: &[Participant],
    threshold: usize,
    msg_hash: HashOutput,
) -> Result<Vec<(Participant, SignatureOption)>, Box<dyn Error>> {
    let mut protocols: GenProtocol<SignatureOption> = Vec::with_capacity(participants.len());

    let participants_list = participants
        .iter()
        .take(actual_signers)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    let coordinators = ParticipantList::new(coordinators).unwrap();
    for (participant, key_pair) in participants.iter().take(actual_signers) {
        let protocol = if coordinators.contains(*participant) {
            let protocol = sign(
                &participants_list,
                threshold,
                *participant,
                *participant,
                key_pair.clone(),
                msg_hash.as_ref().to_vec(),
                OsRng,
            )?;
            Box::new(protocol)
        } else {
            // pick any coordinator
            let mut rng = OsRng;
            let index = rng.next_u32() as usize % coordinators.len();
            let coordinator = coordinators.get_participant(index).unwrap();
            // run the signing scheme
            let protocol = sign(
                &participants_list,
                threshold,
                *participant,
                coordinator,
                key_pair.clone(),
                msg_hash.as_ref().to_vec(),
                OsRng,
            )?;
            Box::new(protocol)
        };
        protocols.push((*participant, protocol));
    }

    Ok(run_protocol(protocols)?)
}

#[test]
#[allow(non_snake_case)]
fn keygen_output__should_be_serializable() {
    // Given
    let mut rng = MockCryptoRng::new([1; 8]);
    let signing_key = FrostSigningKey::<C>::new(&mut rng);

    let keygen_output = KeygenOutput {
        private_share: SigningShare::<C>::new(FrostScalar::<C>::from(7_u32)),
        public_key: FrostVerifyingKey::<C>::from(signing_key),
    };

    // When
    let serialized_keygen_output =
        serde_json::to_string(&keygen_output).expect("should be able to serialize output");

    // Then
    assert_eq!(
        serialized_keygen_output,
        "{\"private_share\":\"0700000000000000000000000000000000000000000000000000000000000000\",\"public_key\":\"c6473159e19ed185b373e935081774e0c133b9416abdff319667187a71dff53e\"}"
    );
}

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
