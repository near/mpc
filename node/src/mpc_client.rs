use crate::config::Config;
use crate::key_generation::run_key_generation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::sign::{
    generate_presignature_id, generate_signature_id, pre_sign, sign, SimplePresignatureStore,
};
use crate::tracking;
use crate::triple::{
    run_background_triple_generation, run_many_triple_generation, SimpleTripleStore,
    SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
};
use anyhow::Context;
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
    triple_store: Arc<SimpleTripleStore>,
    presignature_store: Arc<SimplePresignatureStore>,
    keygen_out: Arc<tokio::sync::OnceCell<KeygenOutput<Secp256k1>>>,
}

impl MpcClient {
    pub fn new(
        config: Arc<Config>,
        client: Arc<MeshNetworkClient>,
        triple_store: Arc<SimpleTripleStore>,
        presignature_store: Arc<SimplePresignatureStore>,
        keygen_out: Arc<tokio::sync::OnceCell<KeygenOutput<Secp256k1>>>,
    ) -> Self {
        Self {
            config,
            client,
            triple_store,
            presignature_store,
            keygen_out,
        }
    }

    /// Main entry point for the MPC node. Runs all the business logic for doing
    /// multiparty computation.
    pub async fn run(
        self,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<()> {
        let (generated_key_sender, generated_key_receiver) = mpsc::channel(1);
        {
            let client = self.client.clone();
            let config = self.config.clone();
            let triple_store = self.triple_store.clone();
            let presignature_store = self.presignature_store.clone();
            let keygen_out = self.keygen_out.clone();
            tracking::spawn("monitor passive channels", async move {
                loop {
                    let channel = channel_receiver.recv().await.unwrap();
                    let client = client.clone();
                    let config = config.clone();
                    let generated_key_sender = generated_key_sender.clone();
                    let triple_store = triple_store.clone();
                    let presignature_store = presignature_store.clone();
                    let keygen_out = keygen_out.clone();
                    tracking::spawn_checked(
                        &format!("passive task {:?}", channel.task_id),
                        async move {
                            match channel.task_id {
                                MpcTaskId::KeyGeneration => {
                                    let key = timeout(
                                        Duration::from_secs(config.key_generation.timeout_sec),
                                        run_key_generation(
                                            channel,
                                            client.all_participant_ids(),
                                            client.my_participant_id(),
                                            config.mpc.participants.threshold as usize,
                                        ),
                                    )
                                    .await??;
                                    generated_key_sender
                                        .send(key)
                                        .await
                                        .context("Key generated twice")?;
                                }
                                MpcTaskId::ManyTriples { start, end } => {
                                    if end.checked_sub(start)
                                        != Some(SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE as u64)
                                    {
                                        tracing::error!(
                                            "Unsupported batch size for triple generation"
                                        );
                                        return Err(anyhow::anyhow!(
                                            "Unsupported batch size for triple generation"
                                        ));
                                    }
                                    let triples = timeout(
                                        Duration::from_secs(config.triple.timeout_sec),
                                        run_many_triple_generation::<
                                            SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
                                        >(
                                            channel,
                                            client.all_participant_ids(),
                                            client.my_participant_id(),
                                            config.mpc.participants.threshold as usize,
                                        ),
                                    )
                                    .await??;
                                    for (i, triple) in triples.into_iter().enumerate() {
                                        triple_store.add_their_triple(start + i as u64, triple);
                                    }
                                }
                                MpcTaskId::Presignature {
                                    id,
                                    triple0_id,
                                    triple1_id,
                                } => {
                                    let sender = presignature_store.add_their_presignature(id);
                                    let presignature = timeout(
                                        Duration::from_secs(config.presignature.timeout_sec),
                                        pre_sign(
                                            channel,
                                            client.all_participant_ids(),
                                            client.my_participant_id(),
                                            config.mpc.participants.threshold as usize,
                                            triple_store.take_their_triple(triple0_id)?,
                                            triple_store.take_their_triple(triple1_id)?,
                                            keygen_out
                                                .get()
                                                .ok_or_else(|| {
                                                    anyhow::anyhow!("Key not generated")
                                                })?
                                                .clone(),
                                        ),
                                    )
                                    .await??;
                                    sender.send(presignature).ok();
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
                                            client.all_participant_ids(),
                                            client.my_participant_id(),
                                            keygen_out
                                                .get()
                                                .ok_or_else(|| {
                                                    anyhow::anyhow!("Key not generated")
                                                })?
                                                .clone(),
                                            presignature_store
                                                .take_their_presignature(presignature_id)
                                                .await?,
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

        self.keygen_out
            .set(
                if self.client.my_participant_id() == self.client.all_participant_ids()[0] {
                    run_key_generation(
                        self.client.new_channel_for_task(MpcTaskId::KeyGeneration)?,
                        self.client.all_participant_ids(),
                        self.client.my_participant_id(),
                        self.config.mpc.participants.threshold as usize,
                    )
                    .await?
                } else {
                    tracking::set_progress("Waiting for key generation");
                    let mut generated_key_receiver = generated_key_receiver;
                    generated_key_receiver
                        .recv()
                        .await
                        .ok_or_else(|| anyhow::anyhow!("Key not generated"))?
                },
            )
            .unwrap();
        tracking::set_progress("Bootstrap complete");

        run_background_triple_generation(
            self.client.clone(),
            self.config.mpc.participants.threshold as usize,
            self.config.triple.clone().into(),
            self.triple_store.clone(),
        )
        .await?;

        Ok(())
    }

    pub async fn make_signature(
        self,
        msg_hash: Scalar,
    ) -> anyhow::Result<FullSignature<Secp256k1>> {
        let (triple0_id, triple0) = self.triple_store.take_my_triple().await?;
        let (triple1_id, triple1) = self.triple_store.take_my_triple().await?;
        let presignature_id = generate_presignature_id(self.client.my_participant_id());
        let key = self
            .keygen_out
            .get()
            .ok_or_else(|| anyhow::anyhow!("Key not generated"))?
            .clone();
        let presignature = pre_sign(
            self.client.new_channel_for_task(MpcTaskId::Presignature {
                id: presignature_id,
                triple0_id,
                triple1_id,
            })?,
            self.client.all_participant_ids(),
            self.client.my_participant_id(),
            self.config.mpc.participants.threshold as usize,
            triple0,
            triple1,
            key.clone(),
        )
        .await?;
        let signature = sign(
            self.client.new_channel_for_task(MpcTaskId::Signature {
                id: generate_signature_id(self.client.my_participant_id()),
                presignature_id,
                msg_hash: msg_hash.to_repr().into(),
            })?,
            self.client.all_participant_ids(),
            self.client.my_participant_id(),
            key,
            presignature,
            msg_hash,
        )
        .await?;

        Ok(signature)
    }
}
