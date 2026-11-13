use rand::SeedableRng;

use super::base::co15::{BatchRandomOTOutputReceiver, BatchRandomOTOutputSender};
use super::base::pvw08::{self, ReceiverOutput, ReceiverSecrets, SenderOutput, SenderRandomness};
use crate::ecdsa::Secp256K1Sha256;

use crate::test_utils::MockCryptoRng;

use crate::errors::ProtocolError;
use crate::participants::Participant;
use crate::protocol::internal::{Comms, make_protocol};
use crate::test_utils::run_two_party_protocol;

/// Run the batch random OT protocol between two parties.
pub fn run_batch_random_ot()
-> Result<(BatchRandomOTOutputSender, BatchRandomOTOutputReceiver), ProtocolError> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let s = Participant::from(0u32);
    let r = Participant::from(1u32);
    let comms_s = Comms::with_buffer_capacity(usize::MAX);
    let comms_r = Comms::with_buffer_capacity(usize::MAX);

    run_two_party_protocol(
        s,
        r,
        &mut make_protocol(comms_s.clone(), {
            let y = super::base::co15::batch_random_ot_sender_helper(&mut rng);
            super::base::co15::batch_random_ot_sender(comms_s.private_channel(s, r), y)
        }),
        &mut make_protocol(comms_r.clone(), {
            let (delta, x) = super::base::co15::batch_random_ot_receiver_random_helper(&mut rng);
            super::base::co15::batch_random_ot_receiver(comms_r.private_channel(r, s), delta, x)
        }),
    )
}

/// Run the PVW08 batch random OT protocol between two parties, each with its
/// own batch size and session identifier.
pub fn run_pvw08_batch_random_ot(
    sender_batch_size: usize,
    receiver_batch_size: usize,
    sender_sid: &[u8],
    receiver_sid: &[u8],
) -> Result<(SenderOutput, ReceiverOutput), ProtocolError> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let s = Participant::from(0u32);
    let r = Participant::from(1u32);
    let comms_s = Comms::with_buffer_capacity(usize::MAX);
    let comms_r = Comms::with_buffer_capacity(usize::MAX);
    let randomness = SenderRandomness::<Secp256K1Sha256>::random(sender_batch_size, &mut rng);
    let secrets = ReceiverSecrets::<Secp256K1Sha256>::random(receiver_batch_size, &mut rng);

    run_two_party_protocol(
        s,
        r,
        &mut make_protocol(
            comms_s.clone(),
            pvw08::batch_random_ot_sender(
                comms_s.private_channel(s, r),
                sender_sid.to_vec(),
                randomness,
            ),
        ),
        &mut make_protocol(
            comms_r.clone(),
            pvw08::batch_random_ot_receiver(
                comms_r.private_channel(r, s),
                receiver_sid.to_vec(),
                secrets,
            ),
        ),
    )
}
