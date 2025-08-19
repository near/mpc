use crate::eddsa::dkg_ed25519::{keygen, refresh, reshare};
use crate::eddsa::sign::{sign, SignatureOutput};
use crate::eddsa::KeygenOutput;
use crate::participants::ParticipantList;
use crate::protocol::{run_protocol, Participant, Protocol};

use crate::crypto::hash::HashOutput;
use frost_ed25519::VerifyingKey;
use rand_core::{OsRng, RngCore};
use std::error::Error;

/// this is a centralized key generation
pub(crate) fn build_key_packages_with_dealer(
    max_signers: usize,
    min_signers: usize,
) -> Vec<(Participant, KeygenOutput)> {
    use std::collections::BTreeMap;

    let mut identifiers = Vec::with_capacity(max_signers);
    for _ in 0..max_signers {
        // from 1 to avoid assigning 0 to a ParticipantId
        identifiers.push(Participant::from(OsRng.next_u32()))
    }

    let from_frost_identifiers = identifiers
        .iter()
        .map(|&x| (x.to_identifier(), x))
        .collect::<BTreeMap<_, _>>();

    let identifiers_list = from_frost_identifiers.keys().cloned().collect::<Vec<_>>();

    let (shares, pubkey_package) = frost_ed25519::keys::generate_with_dealer(
        max_signers as u16,
        min_signers as u16,
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

/// runs distributed keygen
pub(crate) fn run_keygen(
    participants: &[Participant],
    threshold: usize,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
        Vec::with_capacity(participants.len());

    for p in participants.iter() {
        let protocol = keygen(participants, *p, threshold)?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}

/// runs distributed refresh
pub(crate) fn run_refresh(
    participants: &[Participant],
    keys: Vec<(Participant, KeygenOutput)>,
    threshold: usize,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
        Vec::with_capacity(participants.len());

    for (p, out) in keys.iter() {
        let protocol = refresh(
            Some(out.private_share),
            out.public_key,
            participants,
            threshold,
            *p,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}

/// runs distributed reshare
pub(crate) fn run_reshare(
    participants: &[Participant],
    pub_key: &VerifyingKey,
    keys: Vec<(Participant, KeygenOutput)>,
    old_threshold: usize,
    new_threshold: usize,
    new_participants: Vec<Participant>,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    assert!(!new_participants.is_empty());
    let mut setup: Vec<_> = vec![];

    for new_participant in &new_participants {
        let mut is_break = false;
        for (p, k) in &keys {
            if p == new_participant {
                setup.push((*p, (Some(k.private_share), k.public_key)));
                is_break = true;
                break;
            }
        }
        if !is_break {
            setup.push((*new_participant, (None, *pub_key)));
        }
    }

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
        Vec::with_capacity(participants.len());

    for (p, out) in setup.iter() {
        let protocol = reshare(
            participants,
            old_threshold,
            out.0,
            out.1,
            &new_participants,
            new_threshold,
            *p,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}

pub(crate) fn test_run_signature_protocols(
    participants: &[(Participant, KeygenOutput)],
    actual_signers: usize,
    coordinators: &[Participant],
    threshold: usize,
    msg_hash: HashOutput,
) -> Result<Vec<(Participant, SignatureOutput)>, Box<dyn Error>> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOutput>>)> =
        Vec::with_capacity(participants.len());

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
            )?;
            Box::new(protocol)
        };
        protocols.push((*participant, protocol))
    }

    Ok(run_protocol(protocols)?)
}

/// Assert that each participant has the same view of the public key
pub(crate) fn assert_public_key_invariant(
    participants: &[(Participant, KeygenOutput)],
) -> Result<(), Box<dyn Error>> {
    let public_key_package = participants.first().unwrap().1.public_key;

    if participants
        .iter()
        .any(|(_, key_pair)| key_pair.public_key != public_key_package)
    {
        panic!("public key package is not the same for all participants");
    }

    Ok(())
}
