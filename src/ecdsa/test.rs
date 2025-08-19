use frost_secp256k1::VerifyingKey;
use k256::{AffinePoint, Scalar};
use std::error::Error;

use crate::crypto::hash::test::scalar_hash;
use crate::ecdsa::{
    dkg_ecdsa::{keygen, refresh, reshare},
    FullSignature, KeygenOutput,
};
use crate::protocol::errors::InitializationError;
use crate::protocol::{run_protocol, Participant, Protocol};

/// runs distributed keygen
pub(crate) fn run_keygen(
    participants: &[Participant],
    threshold: usize,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
        Vec::with_capacity(participants.len());

    for p in participants {
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

#[allow(clippy::type_complexity)]
pub fn run_sign<PresignOutput, F>(
    participants_outs: Vec<(Participant, PresignOutput)>,
    public_key: AffinePoint,
    msg: &[u8],
    sign_box: F,
) -> Vec<(Participant, FullSignature)>
where
    F: Fn(
        &[Participant],
        Participant,
        AffinePoint,
        PresignOutput,
        Scalar,
    ) -> Result<Box<dyn Protocol<Output = FullSignature>>, InitializationError>,
{
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = FullSignature>>)> =
        Vec::with_capacity(participants_outs.len());

    let participant_list: Vec<Participant> = participants_outs.iter().map(|(p, _)| *p).collect();
    let participant_list = participant_list.as_slice();
    for (p, presign_out) in participants_outs.into_iter() {
        let protocol = sign_box(
            participant_list,
            p,
            public_key,
            presign_out,
            scalar_hash(msg),
        );
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((p, protocol));
    }

    run_protocol(protocols).unwrap()
}
