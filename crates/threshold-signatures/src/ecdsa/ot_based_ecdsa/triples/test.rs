use rand::SeedableRng;

use super::batch_random_ot::{BatchRandomOTOutputReceiver, BatchRandomOTOutputSender};

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
            let y = super::batch_random_ot::batch_random_ot_sender_helper(&mut rng);
            super::batch_random_ot::batch_random_ot_sender(comms_s.private_channel(s, r), y)
        }),
        &mut make_protocol(comms_r.clone(), {
            let (delta, x) =
                super::batch_random_ot::batch_random_ot_receiver_random_helper(&mut rng);
            super::batch_random_ot::batch_random_ot_receiver(
                comms_r.private_channel(r, s),
                delta,
                x,
            )
        }),
    )
}
