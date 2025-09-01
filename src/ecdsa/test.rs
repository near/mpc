use crate::crypto::hash::test::scalar_hash;
use crate::ecdsa::FullSignature;
use crate::protocol::{errors::InitializationError, run_protocol, Participant, Protocol};
use k256::{AffinePoint, Scalar};

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
