use crate::config::Config;
use crate::hkdf::derive_tweak;
use crate::indexer::handler::ChainSignatureRequest;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, PresignOutputWithParticipants};
use crate::sign::{
    pre_sign_unowned, run_background_presignature_generation, sign, PresignatureStorage,
    SignatureIdGenerator,
};
use crate::sign_request::{SignRequestStorage, SignatureRequest};
use crate::tracking::{self, AutoAbortTaskCollection};
use crate::triple::{
    run_background_triple_generation, run_many_triple_generation, TripleStorage,
    SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
};
use cait_sith::{FullSignature, KeygenOutput};
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, Scalar, Secp256k1};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Clone)]
pub struct MpcClient {
    config: Arc<Config>,
    client: Arc<MeshNetworkClient>,
    triple_store: Arc<TripleStorage>,
    presignature_store: Arc<PresignatureStorage>,
    sign_request_store: Arc<SignRequestStorage>,
    root_keyshare: KeygenOutput<Secp256k1>,
    signature_id_generator: Arc<SignatureIdGenerator>,
}

impl MpcClient {
    pub fn new(
        config: Arc<Config>,
        client: Arc<MeshNetworkClient>,
        triple_store: Arc<TripleStorage>,
        presignature_store: Arc<PresignatureStorage>,
        sign_request_store: Arc<SignRequestStorage>,
        root_keyshare: KeygenOutput<Secp256k1>,
    ) -> Self {
        let my_participant_id = client.my_participant_id();
        Self {
            config,
            client,
            triple_store,
            presignature_store,
            sign_request_store,
            root_keyshare,
            signature_id_generator: Arc::new(SignatureIdGenerator::new(my_participant_id)),
        }
    }

    /// Main entry point for the MPC node. Runs all the business logic for doing
    /// multiparty computation.
    pub async fn run(
        self,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
        mut sign_request_receiver: mpsc::Receiver<ChainSignatureRequest>,
    ) -> anyhow::Result<()> {
        let monitor_passive_channels = {
            let client = self.client.clone();
            let config = self.config.clone();
            let triple_store = self.triple_store.clone();
            let presignature_store = self.presignature_store.clone();
            let root_keyshare = self.root_keyshare.clone();
            tracking::spawn("monitor passive channels", async move {
                let mut tasks = AutoAbortTaskCollection::new();
                loop {
                    let channel = channel_receiver.recv().await.unwrap();
                    let client = client.clone();
                    let config = config.clone();
                    let triple_store = triple_store.clone();
                    let presignature_store = presignature_store.clone();
                    let root_keyshare = root_keyshare.clone();
                    tasks.spawn_checked(
                        &format!("passive task {:?}", channel.task_id),
                        async move {
                            match channel.task_id {
                                MpcTaskId::KeyGeneration => {
                                    anyhow::bail!(
                                        "Key generation rejected in normal node operation"
                                    );
                                }
                                MpcTaskId::ManyTriples { start, count } => {
                                    if count as usize != SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE {
                                        return Err(anyhow::anyhow!(
                                            "Unsupported batch size for triple generation"
                                        ));
                                    }
                                    let pending_paired_triples = (0..count / 2)
                                        .map(|i| {
                                            anyhow::Ok(
                                                triple_store
                                                    .prepare_unowned(start.add_to_counter(i)?),
                                            )
                                        })
                                        .collect::<anyhow::Result<Vec<_>>>()?;
                                    let triples = timeout(
                                        Duration::from_secs(config.triple.timeout_sec),
                                        run_many_triple_generation::<
                                            SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
                                        >(
                                            channel,
                                            client.my_participant_id(),
                                            config.mpc.participants.threshold as usize,
                                        ),
                                    )
                                    .await??;
                                    for (pending_triple, paired_triple) in
                                        pending_paired_triples.into_iter().zip(triples.into_iter())
                                    {
                                        pending_triple.commit(paired_triple);
                                    }
                                }
                                MpcTaskId::Presignature {
                                    id,
                                    paired_triple_id,
                                } => {
                                    let pending_asset = presignature_store.prepare_unowned(id);
                                    let participants = channel.participants.clone();
                                    let presignature = timeout(
                                        Duration::from_secs(config.presignature.timeout_sec),
                                        pre_sign_unowned(
                                            channel,
                                            client.my_participant_id(),
                                            config.mpc.participants.threshold as usize,
                                            root_keyshare,
                                            triple_store.clone(),
                                            paired_triple_id,
                                        ),
                                    )
                                    .await??;
                                    pending_asset.commit(PresignOutputWithParticipants {
                                        presignature,
                                        participants,
                                    });
                                }
                                MpcTaskId::Signature {
                                    presignature_id,
                                    msg_hash,
                                    tweak,
                                    entropy,
                                    ..
                                } => {
                                    let msg_hash =
                                        Scalar::from_repr(FieldBytes::clone_from_slice(&msg_hash))
                                            .into_option()
                                            .ok_or_else(|| {
                                                anyhow::anyhow!(
                                                    "Failed to convert msg_hash to Scalar"
                                                )
                                            })?;
                                    let tweak =
                                        Scalar::from_repr(FieldBytes::clone_from_slice(&tweak))
                                            .into_option()
                                            .ok_or_else(|| {
                                                anyhow::anyhow!("Failed to convert tweak to Scalar")
                                            })?;
                                    timeout(
                                        Duration::from_secs(config.signature.timeout_sec),
                                        sign(
                                            channel,
                                            client.my_participant_id(),
                                            root_keyshare,
                                            presignature_store
                                                .take_unowned(presignature_id)
                                                .await?
                                                .presignature,
                                            msg_hash,
                                            tweak,
                                            entropy,
                                        ),
                                    )
                                    .await??;
                                }
                            }
                            anyhow::Ok(())
                        },
                    );
                }
            })
        };

        let monitor_chain = {
            tracking::spawn("monitor chain", async move {
                loop {
                    let ChainSignatureRequest {
                        request_id,
                        request,
                        predecessor_id,
                        entropy,
                        timestamp_nanosec,
                    } = sign_request_receiver.recv().await.unwrap();

                    let request = SignatureRequest {
                        id: request_id,
                        msg_hash: request.payload,
                        tweak: derive_tweak(&predecessor_id, &request.path),
                        entropy,
                        timestamp_nanosec,
                    };

                    if self.sign_request_store.add(request) {
                        // TODO: decide if we are the leader for this request,
                        // and if so, initiate the signature computation
                    }
                }
            })
        };

        let generate_triples = tracking::spawn(
            "generate triples",
            run_background_triple_generation(
                self.client.clone(),
                self.config.mpc.participants.threshold as usize,
                self.config.triple.clone().into(),
                self.triple_store.clone(),
            ),
        );

        let generate_presignatures = tracking::spawn(
            "generate presignatures",
            run_background_presignature_generation(
                self.client.clone(),
                self.config.mpc.participants.threshold as usize,
                self.config.presignature.clone().into(),
                self.triple_store.clone(),
                self.presignature_store.clone(),
                self.root_keyshare.clone(),
            ),
        );

        monitor_passive_channels.await?;
        monitor_chain.await?;
        generate_triples.await??;
        generate_presignatures.await??;

        Ok(())
    }

    pub async fn make_signature(
        self,
        msg_hash: Scalar,
        tweak: Scalar,
        entropy: [u8; 32],
    ) -> anyhow::Result<FullSignature<Secp256k1>> {
        let (presignature_id, presignature) = self
            .presignature_store
            .take_owned(&self.client.all_alive_participant_ids())
            .await;
        let signature = sign(
            self.client.new_channel_for_task(
                MpcTaskId::Signature {
                    id: self.signature_id_generator.generate_signature_id(),
                    presignature_id,
                    msg_hash: msg_hash.to_repr().into(),
                    tweak: tweak.to_repr().into(),
                    entropy,
                },
                presignature.participants,
            )?,
            self.client.my_participant_id(),
            self.root_keyshare.clone(),
            presignature.presignature,
            msg_hash,
            tweak,
            entropy,
        )
        .await?;

        Ok(signature)
    }
}
