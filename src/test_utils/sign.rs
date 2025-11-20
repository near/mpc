use crate::errors::{InitializationError, ProtocolError};
use crate::participants::Participant;
use crate::protocol::Protocol;
use crate::test_utils::{run_protocol, GenProtocol};
use crate::{Ciphersuite, Element, Scalar};
use std::error::Error;

// +++++++++++++++++ Signing Functions +++++++++++++++++ //
/// Runs the signing algorithm for ECDSA.
/// The scheme must be asymmetric as in: there exists a coordinator that is different than participants.
/// Only used for unit tests.
pub fn run_sign<C: Ciphersuite, PresignOutput, Signature: Clone, F>(
    participants_presign: Vec<(Participant, PresignOutput)>,
    coordinator: Participant,
    public_key: Element<C>,
    msg_hash: Scalar<C>,
    sign: F,
) -> Result<Vec<(Participant, Signature)>, Box<dyn Error>>
where
    F: Fn(
        &[Participant],
        Participant,
        Participant,
        Element<C>,
        PresignOutput,
        Scalar<C>,
    ) -> Result<Box<dyn Protocol<Output = Signature>>, InitializationError>,
{
    let mut protocols: GenProtocol<Signature> = Vec::with_capacity(participants_presign.len());

    let participants: Vec<Participant> = participants_presign.iter().map(|(p, _)| *p).collect();
    let participants = participants.as_slice();
    for (p, presignature) in participants_presign {
        let protocol = sign(
            participants,
            coordinator,
            p,
            public_key,
            presignature,
            msg_hash,
        )?;

        protocols.push((p, protocol));
    }

    Ok(run_protocol(protocols)?)
}

/// Checks that the list contains all None but one element
/// and verifies such element belongs to the coordinator
pub fn check_one_coordinator_output<ProtocolOutput: Clone>(
    all_sigs: Vec<(Participant, Option<ProtocolOutput>)>,
    coordinator: Participant,
) -> Result<ProtocolOutput, ProtocolError> {
    let mut some_iter = all_sigs.into_iter().filter(|(_, sig)| sig.is_some());

    // test there is at least one not None element
    let (p, c_opt) = some_iter
        .next()
        .ok_or(ProtocolError::MismatchCoordinatorOutput)?;

    // test the coordinator is the one owning the output
    if coordinator != p {
        return Err(ProtocolError::MismatchCoordinatorOutput);
    }

    // test the participant is unique
    let out = c_opt.ok_or(ProtocolError::MismatchCoordinatorOutput)?;

    if some_iter.next().is_some() {
        return Err(ProtocolError::MismatchCoordinatorOutput);
    }
    Ok(out)
}
