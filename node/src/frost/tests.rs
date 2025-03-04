#[cfg(test)]
use crate::frost::KeygenOutput;
#[cfg(test)]
use cait_sith::protocol::{make_protocol, Context, Participant, Protocol};
#[cfg(test)]
use frost_ed25519::{Identifier, Signature};

#[cfg(test)]
#[allow(dead_code)]
pub(crate) enum SignatureOutput {
    Coordinator(Signature),
    Participant,
}

#[cfg(test)]
pub(crate) fn build_key_packages_with_dealer(
    max_signers: usize,
    min_signers: usize,
) -> Vec<(Participant, KeygenOutput)> {
    use crate::frost::to_frost_identifier;
    use aes_gcm::aead::OsRng;
    use rand::RngCore;
    use std::collections::BTreeMap;

    let mut identifiers = Vec::with_capacity(max_signers);
    for _ in 0..max_signers {
        // from 1 to avoid assigning 0 to a ParticipantId
        identifiers.push(Participant::from(OsRng.next_u32()))
    }

    let from_frost_identifiers = identifiers
        .iter()
        .map(|&x| (to_frost_identifier(x), x))
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
                    key_package: frost_ed25519::keys::KeyPackage::try_from(share).unwrap(),
                    public_key_package: pubkey_package.clone(),
                },
            )
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
pub(crate) fn build_and_run_signature_protocols(
    participants: &[(Participant, KeygenOutput)],
    actual_signers: usize,
    coordinators_count: usize,
) -> anyhow::Result<Vec<(Participant, SignatureOutput)>> {
    use crate::frost::sign::{do_sign_coordinator, do_sign_participant};
    use cait_sith::participants::ParticipantList;
    use cait_sith::protocol::run_protocol;
    use futures::FutureExt;
    use near_indexer::near_primitives::hash::hash;
    use rand::prelude::StdRng;
    use rand::SeedableRng;

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOutput>>)> =
        Vec::with_capacity(participants.len());

    let participants_list = participants
        .iter()
        .take(actual_signers)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    let participants_list = ParticipantList::new(&participants_list).unwrap();

    let msg = "hello_near";
    let msg_hash = hash(msg.as_bytes());

    for (idx, (participant, key_pair)) in participants.iter().take(actual_signers).enumerate() {
        let rng: StdRng = StdRng::seed_from_u64(protocols.len() as u64);

        let ctx = Context::new();
        let protocol: Box<dyn Protocol<Output = SignatureOutput>> = if idx < coordinators_count {
            let fut = do_sign_coordinator(
                ctx.shared_channel(),
                rng,
                participants_list.clone(),
                *participant,
                key_pair.clone(),
                msg_hash.as_bytes().to_vec(),
            )
            .map(|x| x.map(SignatureOutput::Coordinator));
            let protocol = make_protocol(ctx, fut);
            Box::new(protocol)
        } else {
            let fut = do_sign_participant(
                ctx.shared_channel(),
                rng,
                key_pair.clone(),
                msg_hash.as_bytes().to_vec(),
            )
            .map(|x| x.map(|_| SignatureOutput::Participant));
            let protocol = make_protocol(ctx, fut);
            Box::new(protocol)
        };

        protocols.push((*participant, protocol))
    }

    Ok(run_protocol(protocols)?)
}

/// Extract group signin key from participants.
/// The caller is responsible for providing at least `min_signers` shares:
///  if less than that is provided, a different key will be returned.
#[cfg(test)]
pub(crate) fn reconstruct_signing_key(
    participants: &[(Participant, KeygenOutput)],
) -> anyhow::Result<frost_ed25519::SigningKey> {
    let key_packages = participants
        .iter()
        .map(|(_, key_pair)| key_pair.key_package.clone())
        .collect::<Vec<_>>();

    let signing_key = frost_ed25519::keys::reconstruct(&key_packages)?;

    Ok(signing_key)
}

#[test]
fn verify_stability_of_identifier_derivation() {
    let participant = Participant::from(1e9 as u32);
    let identifier = Identifier::derive(participant.bytes().as_slice()).unwrap();
    assert_eq!(
        identifier.serialize(),
        vec![
            96, 203, 29, 92, 230, 35, 120, 169, 19, 185, 45, 28, 48, 68, 84, 190, 12, 186, 169,
            192, 196, 21, 238, 181, 134, 181, 203, 236, 162, 68, 212, 4
        ]
    );
}
