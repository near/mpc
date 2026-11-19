//! Batch random OT from the DDH dual-mode cryptosystem of
//! \[[PVW08](https://eprint.iacr.org/2007/348)\], in messy mode.
//!
//! The protocol is specified in `docs/ecdsa/pvw08.md`.

mod crs;
mod kdf;
mod point_bytes;
mod receiver;
mod sender;

pub use crs::{Crs, HashToElement};
pub use receiver::{ReceiverOutput, ReceiverPublicKey, ReceiverSecrets};
pub use sender::{SenderCiphertext, SenderOutput, SenderRandomness};

use subtle::ConditionallySelectable;
use zeroize::Zeroize;

use crate::{Element, Scalar, errors::ProtocolError, protocol::internal::PrivateChannel};

/// Runs the receiver of a batch of random OTs, one per choice bit in `secrets`.
///
/// Both parties must pass the same `sid`, unique to this run.
pub async fn batch_random_ot_receiver<C: HashToElement>(
    mut chan: PrivateChannel,
    sid: Vec<u8>,
    secrets: ReceiverSecrets<C>,
) -> Result<ReceiverOutput, ProtocolError>
where
    Scalar<C>: Zeroize,
    Element<C>: ConditionallySelectable,
{
    let crs = Crs::<C>::derive(&sid)?;
    let public_keys = secrets.public_keys(&crs);
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &public_keys)?;

    let wait1 = chan.next_waitpoint();
    let ciphertexts: Vec<SenderCiphertext<C>> = chan.recv(wait1).await?;
    secrets.decapsulate(&sid, &public_keys, chan.to, &ciphertexts)
}

/// Runs the sender of a batch of random OTs, one per transfer in `randomness`.
///
/// Both parties must pass the same `sid`, unique to this run.
pub async fn batch_random_ot_sender<C: HashToElement>(
    mut chan: PrivateChannel,
    sid: Vec<u8>,
    randomness: SenderRandomness<C>,
) -> Result<SenderOutput, ProtocolError>
where
    Scalar<C>: Zeroize,
    Element<C>: ConditionallySelectable,
{
    let crs = Crs::<C>::derive(&sid)?;
    let wait0 = chan.next_waitpoint();
    let public_keys: Vec<ReceiverPublicKey<C>> = chan.recv(wait0).await?;

    let (ciphertexts, output) = randomness.encapsulate(&crs, &sid, chan.to, &public_keys)?;
    let wait1 = chan.next_waitpoint();
    chan.send(wait1, &ciphertexts)?;
    Ok(output)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use rstest::rstest;
    use subtle::ConditionallySelectable;

    use crate::{
        ecdsa::ot::{
            bits::BitVector,
            test::{run_pvw08_batch_random_ot, run_pvw08_batch_random_ot_with_traffic},
        },
        errors::ProtocolError,
    };

    #[rstest]
    #[case(1)]
    #[case(128)]
    #[case(1000)]
    fn batch_random_ot__should_give_the_receiver_the_chosen_keys(#[case] batch_size: usize) {
        // Given
        let sid = b"session";

        // When
        let (sender_output, receiver_output) =
            run_pvw08_batch_random_ot(batch_size, batch_size, sid, sid).unwrap();

        // Then
        assert_eq!(receiver_output.keys.height(), batch_size);
        let sender_keys = sender_output.k0.rows().zip(sender_output.k1.rows());
        let receiver_keys = receiver_output
            .choices
            .iter()
            .zip(receiver_output.keys.rows());
        for ((k0, k1), (&choice, key)) in sender_keys.zip(receiver_keys) {
            assert_eq!(*key, BitVector::conditional_select(k0, k1, choice));
        }
    }

    #[test]
    fn batch_random_ot__should_send_one_message_each_way() {
        // Given
        let sid = b"session";
        let batch_size = 128;
        // A point is 33 bytes compressed, behind a 2-byte MessagePack header.
        let point_len = 35;
        let points_per_message = 2 * batch_size;
        // Room for the message header and the framing of the batch.
        let overhead = 256;

        // When
        let (_, [sender, receiver]) =
            run_pvw08_batch_random_ot_with_traffic(batch_size, batch_size, sid, sid).unwrap();

        // Then
        assert_eq!(sender.messages, 1);
        assert_eq!(receiver.messages, 1);
        for traffic in [sender, receiver] {
            assert!(traffic.bytes >= points_per_message * point_len);
            assert!(traffic.bytes <= points_per_message * point_len + overhead);
        }
    }

    #[test]
    fn batch_random_ot__should_give_unrelated_keys_when_the_sids_differ() {
        // Given
        let sender_sid = b"session";
        let receiver_sid = b"another session";

        // When
        let (sender_output, receiver_output) =
            run_pvw08_batch_random_ot(16, 16, sender_sid, receiver_sid).unwrap();

        // Then
        let sender_keys = sender_output.k0.rows().zip(sender_output.k1.rows());
        for ((k0, k1), key) in sender_keys.zip(receiver_output.keys.rows()) {
            assert_ne!(key, k0);
            assert_ne!(key, k1);
        }
    }

    #[test]
    fn batch_random_ot__should_abort_when_the_batch_sizes_differ() {
        // Given
        let sid = b"session";

        // When
        let result = run_pvw08_batch_random_ot(8, 7, sid, sid);

        // Then
        assert!(matches!(
            result,
            Err(ProtocolError::UnexpectedLength {
                expected: 8,
                actual: 7,
                ..
            })
        ));
    }
}
