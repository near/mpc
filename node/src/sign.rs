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

pub fn generate_presignature_id(me: ParticipantId) -> u64 {
    (rand::random::<u64>() >> 12) | ((me.0 as u64) << 52)
}

pub fn generate_signature_id(me: ParticipantId) -> u64 {
    (rand::random::<u64>() >> 12) | ((me.0 as u64) << 52)
}

pub struct SimplePresignatureStore {
    others_presignatures: Mutex<HashMap<u64, oneshot::Receiver<PresignOutput<Secp256k1>>>>,
}

impl SimplePresignatureStore {
    pub fn new() -> Self {
        Self {
            others_presignatures: Mutex::new(HashMap::new()),
        }
    }

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

    pub fn add_their_presignature(&self, id: u64) -> oneshot::Sender<PresignOutput<Secp256k1>> {
        let (sender, receiver) = oneshot::channel();
        self.others_presignatures
            .lock()
            .unwrap()
            .insert(id, receiver);
        sender
    }
}
