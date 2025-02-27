#[cfg(test)]
use crate::frost::KeygenOutput;
#[cfg(test)]
use cait_sith::protocol::Participant;

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