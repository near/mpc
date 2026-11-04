use rand_core::CryptoRngCore;
use std::error::Error;

use crate::frost;
use crate::test_utils::{GenProtocol, run_protocol};
use crate::{Ciphersuite, Participant, ReconstructionThreshold};

// +++++++++++++++++ EdDSA Presignature +++++++++++++++++ //
type BoxErr = Box<dyn Error>;
pub fn frost_run_presignature<C>(
    participants: &[(Participant, crate::KeygenOutput<C>)],
    threshold: impl Into<ReconstructionThreshold> + Copy,
    actual_signers: usize,
    mut rng: impl CryptoRngCore + Send + Clone + 'static,
) -> Result<Vec<(Participant, frost::PresignOutput<C>)>, BoxErr>
where
    C: Ciphersuite,
{
    let mut protocols: GenProtocol<frost::PresignOutput<C>> =
        Vec::with_capacity(participants.len());

    let participants_list = participants
        .iter()
        .take(actual_signers)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();

    for (participant, keygen_out) in participants.iter().take(actual_signers) {
        let args = crate::frost::PresignArguments {
            private_share: keygen_out.private_share,
            threshold: threshold.into(),
        };
        rng.next_u64();
        // run the signing scheme
        let protocol =
            crate::frost::presign::<C, _>(&participants_list, *participant, &args, rng.clone())?;

        protocols.push((*participant, Box::new(protocol)));
    }

    Ok(run_protocol(protocols)?)
}
