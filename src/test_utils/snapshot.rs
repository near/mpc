use std::collections::HashMap;

use crate::{participants::Participant, protocol::MessageData};

/// A single received message during a protocol run
#[derive(Debug, PartialEq, Clone)]
struct ReceivedMessageSnapshot {
    from: Participant,
    message: MessageData,
}

impl ReceivedMessageSnapshot {
    fn new(from: Participant, message: MessageData) -> Self {
        Self { from, message }
    }
}

/// Registers a particular participant's view of the received messages
#[derive(Debug, Default, Clone)]
struct ParticipantSnapshot {
    snaps: Vec<ReceivedMessageSnapshot>,
    read_index: usize,
}

impl ParticipantSnapshot {
    fn push_received_message_snapshot(&mut self, snap: ReceivedMessageSnapshot) {
        self.snaps.push(snap);
    }

    fn push_message(&mut self, from: Participant, message: MessageData) {
        let snap = ReceivedMessageSnapshot::new(from, message);
        self.push_received_message_snapshot(snap);
    }

    fn read_next_message(&mut self) -> Option<(Participant, MessageData)> {
        if self.read_index >= self.snaps.len() {
            return None;
        }
        let message_snap = &self.snaps[self.read_index];
        self.read_index += 1;
        Some((message_snap.from, message_snap.message.clone()))
    }

    fn read_all_messages(&self) -> Option<Vec<(Participant, MessageData)>> {
        if self.snaps.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        for snap in &self.snaps {
            out.push((snap.from, snap.message.clone()));
        }
        Some(out)
    }

    fn refresh_read_all(&mut self) {
        self.read_index = 0;
    }
}

/// Used to store the snapshot of all the messages sent during
/// the communication rounds of a certain protocol
pub struct ProtocolSnapshot {
    snapshots: HashMap<Participant, ParticipantSnapshot>,
}

impl ProtocolSnapshot {
    /// Creates an empty snapshot
    pub fn new_empty(participants: Vec<Participant>) -> Self {
        let snapshots = participants
            .into_iter()
            .map(|p| (p, ParticipantSnapshot::default()))
            .collect::<HashMap<_, _>>();
        Self { snapshots }
    }

    /// Adds a messages sent by a sender and to a receiver to the protocol snapshot
    pub fn push_message(
        &mut self,
        to: Participant,
        from: Participant,
        message: MessageData,
    ) -> Option<()> {
        self.snapshots
            .get_mut(&to)
            .map(|snapshot| snapshot.push_message(from, message))
    }

    /// Reads the next message stored in the snapshot of a particular participant given as input
    pub fn read_next_message_for_participant(
        &mut self,
        participant: Participant,
    ) -> Option<(Participant, MessageData)> {
        self.snapshots
            .get_mut(&participant)
            .and_then(ParticipantSnapshot::read_next_message)
    }

    /// Returns a vector of all received messages by a specific participant
    pub fn get_received_messages(
        self,
        participant: &Participant,
    ) -> Option<Vec<(Participant, MessageData)>> {
        self.snapshots
            .get(participant)
            .and_then(ParticipantSnapshot::read_all_messages)
    }

    /// Refreshes the snapshots allowing reading them from the beginning
    pub fn refresh_read_all(&mut self) {
        for snapshot in self.snapshots.values_mut() {
            snapshot.refresh_read_all();
        }
    }

    /// Gives the number of participants that the current struct snapshotted
    pub fn number_of_participants(&self) -> usize {
        self.snapshots.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ecdsa::{
        robust_ecdsa::{presign::presign, PresignArguments, PresignOutput},
        KeygenOutput, Polynomial,
    };
    use crate::test_utils::{
        generate_participants, run_protocol_and_take_snapshots, GenProtocol, MockCryptoRng,
    };
    use crate::SigningShare;
    use frost_secp256k1::VerifyingKey;
    use k256::ProjectivePoint;
    use rand_core::{CryptoRngCore, SeedableRng};

    fn generate_random_received_snap(rng: &mut impl CryptoRngCore) -> ReceivedMessageSnapshot {
        let from = Participant::from(rng.next_u32());
        let mut message: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut message);
        let message = message.to_vec();
        ReceivedMessageSnapshot::new(from, message)
    }

    #[test]
    fn test_read_next_message() {
        let mut psnap = ParticipantSnapshot::default();
        let mut rvec = Vec::new();
        let mut rng = MockCryptoRng::seed_from_u64(123_123);
        for _ in 0..50 {
            let received_snap = generate_random_received_snap(&mut rng);
            rvec.push(received_snap.clone());
            psnap.push_received_message_snapshot(received_snap);
        }
        for r in rvec {
            let (from, message) = psnap.read_next_message().unwrap();
            let read_message = ReceivedMessageSnapshot::new(from, message);
            assert_eq!(r, read_message);
        }
    }

    #[test]
    fn test_refresh_read_all() {
        let mut psnap = ParticipantSnapshot::default();
        let mut rng = MockCryptoRng::seed_from_u64(123_123);
        for _ in 0..50 {
            let received_snap = generate_random_received_snap(&mut rng);
            psnap.push_received_message_snapshot(received_snap);
        }

        let mut rvec = Vec::new();
        for _ in 0..50 {
            let (from, message) = psnap.read_next_message().unwrap();
            let read_message = ReceivedMessageSnapshot::new(from, message);
            rvec.push(read_message);
        }
        psnap.refresh_read_all();
        for r in rvec {
            let (from, message) = psnap.read_next_message().unwrap();
            let read_message = ReceivedMessageSnapshot::new(from, message);
            assert_eq!(r, read_message);
        }
    }

    fn prepare_keys(p: Participant, f: &Polynomial, big_x: ProjectivePoint) -> KeygenOutput {
        let private_share = f.eval_at_participant(p).unwrap();
        let verifying_key = VerifyingKey::new(big_x);
        KeygenOutput {
            private_share: SigningShare::new(private_share.0),
            public_key: verifying_key,
        }
    }

    #[test]
    fn ecdsa_presign_should_return_same_snapshot_when_executed_twice() {
        let max_malicious = 2;
        let num_participants = 5;
        let participants = generate_participants(num_participants);

        let mut rng = MockCryptoRng::seed_from_u64(42u64);
        let f = Polynomial::generate_polynomial(None, max_malicious, &mut rng).unwrap();
        let big_x = ProjectivePoint::GENERATOR * f.eval_at_zero().unwrap().0;

        // create rngs for first and second snapshots
        let rngs = crate::test_utils::mockrng::create_rngs(num_participants, &mut rng);

        let mut results = Vec::new();
        let mut snapshots = Vec::new();

        // Running the protocol twice
        for _ in 0..2 {
            let mut protocols: GenProtocol<PresignOutput> = Vec::with_capacity(participants.len());
            for (i, p) in participants.iter().enumerate() {
                // simulating the key packages for each participant
                let keygen_out = prepare_keys(*p, &f, big_x);
                let protocol = presign(
                    &participants[..],
                    *p,
                    PresignArguments {
                        keygen_out,
                        threshold: max_malicious,
                    },
                    rngs[i].clone(),
                )
                .unwrap();
                protocols.push((*p, Box::new(protocol)));
            }
            let (result, snapshot) = run_protocol_and_take_snapshots(protocols).unwrap();
            results.push(result);
            snapshots.push(snapshot);
        }

        // Check the results are the same
        assert!(results[0]
            .iter()
            .all(|(p1, o1)| { results[1].iter().any(|(p2, o2)| p1 == p2 && o1 == o2) }));

        // Check the messages sent per participants are the same
        for p in participants {
            while let Some((sender1, msg1)) = snapshots[0].read_next_message_for_participant(p) {
                let (sender2, msg2) = snapshots[1].read_next_message_for_participant(p).unwrap();
                assert!(sender1 == sender2 && msg1 == msg2);
            }
        }
    }
}
