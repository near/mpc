use crate::config::Config;
use crate::key_generation::{run_key_generation, KeygenNeeded, KeygenStorage};
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, PresignOutputWithParticipants};
use crate::sign::{
    pre_sign_unowned, run_background_presignature_generation, sign, PresignatureStorage,
    SignatureIdGenerator,
};
use crate::tracking;
use crate::triple::{
    run_background_triple_generation, run_many_triple_generation, TripleStorage,
    SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
};
use cait_sith::FullSignature;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, Scalar, Secp256k1};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Clone)]
pub struct MpcClient {
    config: Arc<Config>,
    client: Arc<MeshNetworkClient>,
    triple_store: Arc<TripleStorage>,
    presignature_store: Arc<PresignatureStorage>,
    keygen_store: Arc<KeygenStorage>,
    signature_id_generator: Arc<SignatureIdGenerator>,
}

impl MpcClient {
    pub fn new(
        config: Arc<Config>,
        client: Arc<MeshNetworkClient>,
        triple_store: Arc<TripleStorage>,
        presignature_store: Arc<PresignatureStorage>,
        keygen_store: Arc<KeygenStorage>,
    ) -> Self {
        let my_participant_id = client.my_participant_id();
        Self {
            config,
            client,
            triple_store,
            presignature_store,
            keygen_store,
            signature_id_generator: Arc::new(SignatureIdGenerator::new(my_participant_id)),
        }
    }

    /// Main entry point for the MPC node. Runs all the business logic for doing
    /// multiparty computation.
    pub async fn run(
        self,
        keygen_needed: Option<KeygenNeeded>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<()> {
        let keygen_needed = Arc::new(Mutex::new(keygen_needed));
        {
            let client = self.client.clone();
            let config = self.config.clone();
            let triple_store = self.triple_store.clone();
            let presignature_store = self.presignature_store.clone();
            let keygen_store = self.keygen_store.clone();
            let keygen_needed = keygen_needed.clone();
            tracking::spawn("monitor passive channels", async move {
                loop {
                    let channel = channel_receiver.recv().await.unwrap();
                    let client = client.clone();
                    let config = config.clone();
                    let triple_store = triple_store.clone();
                    let presignature_store = presignature_store.clone();
                    let keygen_store = keygen_store.clone();
                    let keygen_needed = keygen_needed.clone();
                    tracking::spawn_checked(
                        &format!("passive task {:?}", channel.task_id),
                        async move {
                            match channel.task_id {
                                MpcTaskId::KeyGeneration => {
                                    let Some(keygen_needed) = keygen_needed.lock().unwrap().take()
                                    else {
                                        anyhow::bail!("Key already generated");
                                    };

                                    let key = timeout(
                                        Duration::from_secs(config.key_generation.timeout_sec),
                                        run_key_generation(
                                            channel,
                                            client.my_participant_id(),
                                            config.mpc.participants.threshold as usize,
                                        ),
                                    )
                                    .await??;
                                    keygen_needed.commit(key);
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
                                            keygen_store.get_generated_key().await,
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
                                    timeout(
                                        Duration::from_secs(config.signature.timeout_sec),
                                        sign(
                                            channel,
                                            client.my_participant_id(),
                                            keygen_store.get_generated_key().await,
                                            presignature_store
                                                .take_unowned(presignature_id)
                                                .await?
                                                .presignature,
                                            msg_hash,
                                        ),
                                    )
                                    .await??;
                                }
                            }
                            anyhow::Ok(())
                        },
                    );
                }
            });
        }

        // If we're the first participant, initiate key generation if there is no key.
        if self.client.my_participant_id() == self.client.all_participant_ids()[0] {
            let keygen_needed = keygen_needed.lock().unwrap().take();
            if let Some(keygen_needed) = keygen_needed {
                let generated_key = run_key_generation(
                    self.client.new_channel_for_task(
                        MpcTaskId::KeyGeneration,
                        self.client.all_participant_ids(),
                    )?,
                    self.client.my_participant_id(),
                    self.config.mpc.participants.threshold as usize,
                )
                .await?;
                keygen_needed.commit(generated_key);
            }
        }
        tracking::set_progress("Bootstrap complete");

        let background_triple_generation = tracking::spawn(
            "generate triples",
            run_background_triple_generation(
                self.client.clone(),
                self.config.mpc.participants.threshold as usize,
                self.config.triple.clone().into(),
                self.triple_store.clone(),
            ),
        );

        let background_presignature_generation = tracking::spawn(
            "generate presignatures",
            run_background_presignature_generation(
                self.client.clone(),
                self.config.mpc.participants.threshold as usize,
                self.config.presignature.clone().into(),
                self.triple_store.clone(),
                self.presignature_store.clone(),
                self.keygen_store.get_generated_key().await,
            ),
        );

        background_triple_generation.await??;
        background_presignature_generation.await??;

        Ok(())
    }

    pub async fn make_signature(
        self,
        msg_hash: Scalar,
    ) -> anyhow::Result<FullSignature<Secp256k1>> {
        let keygen_out = self.keygen_store.get_generated_key().await;
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
                },
                presignature.participants,
            )?,
            self.client.my_participant_id(),
            keygen_out,
            presignature.presignature,
            msg_hash,
        )
        .await?;

        Ok(signature)
    }
}
