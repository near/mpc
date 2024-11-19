use crate::metrics;
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use cait_sith::protocol::Participant;
use cait_sith::triples::TripleGenerationOutput;
use cait_sith::{FullSignature, KeygenOutput, PresignArguments, PresignOutput};
use k256::{Scalar, Secp256k1};
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::oneshot;

/// Performs an MPC presignature operation. This is the same for the initiator
/// and for passive participants.
pub async fn pre_sign(
    channel: NetworkTaskChannel,
    participants: Vec<ParticipantId>,
    me: ParticipantId,
    threshold: usize,
    triple0: TripleGenerationOutput<Secp256k1>,
    triple1: TripleGenerationOutput<Secp256k1>,
    keygen_out: KeygenOutput<Secp256k1>,
) -> anyhow::Result<PresignOutput<Secp256k1>> {
    let cs_participants = participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol = cait_sith::presign::<Secp256k1>(
        &cs_participants,
        me.into(),
        &cs_participants,
        me.into(),
        PresignArguments {
            triple0,
            triple1,
            keygen_out,
            threshold,
        },
    )?;
    let presignature = run_protocol("presign", channel, participants, me, protocol).await?;
    metrics::MPC_NUM_PRESIGNATURES_GENERATED.inc();
    Ok(presignature)
}

/// Performs an MPC signature operation. This is the same for the initiator
/// and for passive participants.
pub async fn sign(
    channel: NetworkTaskChannel,
    participants: Vec<ParticipantId>,
    me: ParticipantId,
    keygen_out: KeygenOutput<Secp256k1>,
    presign_out: PresignOutput<Secp256k1>,
    msg_hash: Scalar,
) -> anyhow::Result<FullSignature<Secp256k1>> {
    let cs_participants = participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol = cait_sith::sign::<Secp256k1>(
        &cs_participants,
        me.into(),
        keygen_out.public_key,
        presign_out,
        msg_hash,
    )?;
    let signature = run_protocol("sign", channel, participants, me, protocol).await?;
    metrics::MPC_NUM_SIGNATURES_GENERATED.inc();
    Ok(signature)
}

/// TODO(#10): is this a good way to generate IDs?
pub fn generate_presignature_id(me: ParticipantId) -> u64 {
    (rand::random::<u64>() >> 12) | ((me.0 as u64) << 52)
}

/// TODO(#10): is this a good way to generate IDs?
pub fn generate_signature_id(me: ParticipantId) -> u64 {
    (rand::random::<u64>() >> 12) | ((me.0 as u64) << 52)
}

/// Keeps track of presignatures that have been generated.
/// TODO(#12): Probably need to make this like the triple store.
pub struct SimplePresignatureStore {
    others_presignatures: Mutex<HashMap<u64, oneshot::Receiver<PresignOutput<Secp256k1>>>>,
}

impl SimplePresignatureStore {
    pub fn new() -> Self {
        Self {
            others_presignatures: Mutex::new(HashMap::new()),
        }
    }

    /// Removes a presignature we have helped someone else generate. This will asynchronously
    /// block if we know the result will be available but it is not yet. It will return error
    /// if we know we won't have the result.
    pub async fn take_their_presignature(
        &self,
        id: u64,
    ) -> anyhow::Result<PresignOutput<Secp256k1>> {
        let receiver = self
            .others_presignatures
            .lock()
            .unwrap()
            .remove(&id)
            .ok_or_else(|| anyhow::anyhow!("Presignature not found"))?;
        Ok(receiver.await?)
    }

    /// This is not a one-shot operation. It declares the ID as "will be available", and the
    /// caller should send the output when it's available using the returned sender.
    /// See #8 for details.
    pub fn add_their_presignature(&self, id: u64) -> oneshot::Sender<PresignOutput<Secp256k1>> {
        let (sender, receiver) = oneshot::channel();
        self.others_presignatures
            .lock()
            .unwrap()
            .insert(id, receiver);
        sender
    }
}
