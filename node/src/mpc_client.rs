use crate::cli::LeaderMode;
use crate::config::Config;
use crate::hkdf::derive_tweak;
use crate::indexer::handler::ChainSignatureRequest;
use crate::indexer::lib::has_success_value;
use crate::indexer::response::ChainRespondArgs;
use crate::key_generation::RootKeyshareData;
use crate::metrics;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, PresignOutputWithParticipants};
use crate::sign::{
    pre_sign_unowned, run_background_presignature_generation, sign, PresignatureStorage,
};
use crate::sign_request::{
    compute_leaders_for_signing, SignRequestStorage, SignatureId, SignatureRequest,
};
use crate::tracking::{self, AutoAbortTaskCollection};
use crate::triple::{
    run_background_triple_generation, run_many_triple_generation, TripleStorage,
    SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
};
use actix::Addr;
use cait_sith::FullSignature;
use k256::{AffinePoint, Secp256k1};
use lru::LruCache;
use near_client::ViewClientActor;
use near_indexer_primitives::types::AccountId;
use std::num::NonZero;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::{mpsc, OnceCell};
use tokio::time::{sleep, timeout};

const SECONDARY_LEADER_SIGNATURE_CACHE_SIZE: NonZero<usize> = NonZero::new(10000).unwrap();

type SignatureCache = LruCache<SignatureId, (FullSignature<Secp256k1>, AffinePoint)>;

#[derive(Clone)]
pub struct MpcClient {
    config: Arc<Config>,
    client: Arc<MeshNetworkClient>,
    triple_store: Arc<TripleStorage>,
    presignature_store: Arc<PresignatureStorage>,
    sign_request_store: Arc<SignRequestStorage>,
    root_keyshare: RootKeyshareData,
    secondary_leader_signature_cache: Arc<Mutex<SignatureCache>>,
}

impl MpcClient {
    pub fn new(
        config: Arc<Config>,
        client: Arc<MeshNetworkClient>,
        triple_store: Arc<TripleStorage>,
        presignature_store: Arc<PresignatureStorage>,
        sign_request_store: Arc<SignRequestStorage>,
        root_keyshare: RootKeyshareData,
    ) -> Self {
        Self {
            config,
            client,
            triple_store,
            presignature_store,
            sign_request_store,
            root_keyshare,
            secondary_leader_signature_cache: Arc::new(Mutex::new(LruCache::new(
                SECONDARY_LEADER_SIGNATURE_CACHE_SIZE,
            ))),
        }
    }

    /// Main entry point for the MPC node. Runs all the business logic for doing
    /// multiparty computation.
    pub async fn run(
        self,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
        mut sign_request_receiver: mpsc::Receiver<ChainSignatureRequest>,
        sign_response_sender: mpsc::Sender<ChainRespondArgs>,
        view_client: Arc<OnceCell<Addr<ViewClientActor>>>,
        mpc_contract_id: Option<AccountId>,
        leader_mode: LeaderMode,
    ) -> anyhow::Result<()> {
        let monitor_passive_channels = {
            let client = self.client.clone();
            let config = self.config.clone();
            let triple_store = self.triple_store.clone();
            let presignature_store = self.presignature_store.clone();
            let sign_request_store = self.sign_request_store.clone();
            let root_keyshare = self.root_keyshare.clone();
            let secondary_leader_signature_cache = self.secondary_leader_signature_cache.clone();
            tracking::spawn("monitor passive channels", async move {
                let mut tasks = AutoAbortTaskCollection::new();
                loop {
                    let channel = channel_receiver.recv().await.unwrap();
                    let client = client.clone();
                    let config = config.clone();
                    let triple_store = triple_store.clone();
                    let presignature_store = presignature_store.clone();
                    let sign_request_store = sign_request_store.clone();
                    let root_keyshare = root_keyshare.clone();
                    let secondary_leader_signature_cache = secondary_leader_signature_cache.clone();
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
                                            root_keyshare.keygen_output(),
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
                                    id,
                                    presignature_id,
                                } => {
                                    // TODO(#69): decide a better timeout for this
                                    let request = timeout(
                                        Duration::from_secs(config.signature.timeout_sec),
                                        sign_request_store.get(id),
                                    )
                                    .await??;

                                    let signature = timeout(
                                        Duration::from_secs(config.signature.timeout_sec),
                                        sign(
                                            channel,
                                            client.my_participant_id(),
                                            root_keyshare.keygen_output(),
                                            presignature_store
                                                .take_unowned(presignature_id)
                                                .await?
                                                .presignature,
                                            request.msg_hash,
                                            request.tweak,
                                            request.entropy,
                                        ),
                                    )
                                    .await??;

                                    // As the secondary leader, we store the full signature in case
                                    // we need to submit it ourselves due to lack of successful
                                    // response from the primary leader as observed on-chain.
                                    let (_, secondary_leader) =
                                        compute_leaders_for_signing(&config.mpc, &request);
                                    if config.mpc.my_participant_id == secondary_leader {
                                        secondary_leader_signature_cache
                                            .lock()
                                            .expect("poisoned lock")
                                            .push(request.id, signature);
                                    }
                                }
                            }
                            anyhow::Ok(())
                        },
                    );
                }
            })
        };

        let monitor_chain = {
            let this = Arc::new(self.clone());
            let config = self.config.clone();
            let network_client = self.client.clone();
            tracking::spawn("monitor chain", async move {
                let mut tasks = AutoAbortTaskCollection::new();
                loop {
                    let this = this.clone();
                    let config = config.clone();
                    let sign_request_store = self.sign_request_store.clone();
                    let sign_response_sender = sign_response_sender.clone();

                    let ChainSignatureRequest {
                        request_id,
                        request,
                        predecessor_id,
                        entropy,
                        timestamp_nanosec,
                    } = sign_request_receiver.recv().await.unwrap();

                    let alive_participants = network_client.all_alive_participant_ids();
                    let view_client = view_client.clone();
                    let mpc_contract_id = mpc_contract_id.clone();
                    let secondary_leader_signature_cache =
                        self.secondary_leader_signature_cache.clone();

                    tasks.spawn_checked(
                        &format!("indexed sign request {:?}", request_id),
                        async move {
                            let request = SignatureRequest {
                                id: request_id,
                                msg_hash: request.payload,
                                tweak: derive_tweak(&predecessor_id, &request.path),
                                entropy,
                                timestamp_nanosec,
                            };

                            // Check if we've already seen this request
                            if !sign_request_store.add(&request) {
                                return anyhow::Ok(());
                            }

                            let (primary_leader, secondary_leader) =
                                compute_leaders_for_signing(&config.mpc, &request);

                            let should_lead = async {
                                // primary leader
                                if config.mpc.my_participant_id == primary_leader {
                                    if leader_mode == LeaderMode::DisablePrimary {
                                        metrics::MPC_NUM_SIGN_REQUESTS_LEADER
                                            .with_label_values(&["ignored_as_primary"])
                                            .inc();
                                    } else {
                                        return Ok::<bool, anyhow::Error>(true);
                                    }
                                }
                                // secondary leader
                                if config.mpc.my_participant_id == secondary_leader {
                                    // primary leader is not alive
                                    if !alive_participants.contains(&primary_leader) {
                                        return Ok(true);
                                    }
                                    // primary leader has not responded on-chain
                                    if let Some(mpc_contract_id) = mpc_contract_id {
                                        sleep(Duration::from_secs(
                                            config.signature.secondary_leader_delay_sec,
                                        ))
                                        .await;
                                        // NB: if we have trouble reading the chain, we won't initiate
                                        if !has_success_value(
                                            near_indexer_primitives::CryptoHash(request_id),
                                            mpc_contract_id,
                                            view_client
                                                .get()
                                                .ok_or(anyhow::anyhow!("no view client addr"))?,
                                        )
                                        .await?
                                        {
                                            return Ok(true);
                                        }
                                    }
                                }
                                Ok(false)
                            }
                            .await?;

                            if should_lead {
                                // Check if we already have the signature cached. This can occur if
                                // the primary leader failed to submit the signature on-chain after
                                // successfully leading the computation.
                                if let Some((signature, public_key)) = {
                                    let mut cache = secondary_leader_signature_cache
                                        .lock()
                                        .expect("poisoned cache");
                                    cache.pop(&request.id)
                                } {
                                    metrics::MPC_NUM_SIGN_REQUESTS_LEADER
                                        .with_label_values(&["secondary_responded_from_cache"])
                                        .inc();
                                    let response =
                                        ChainRespondArgs::new(&request, &signature, &public_key)?;
                                    let _ = sign_response_sender.send(response).await;
                                    return anyhow::Ok(());
                                }

                                // Lead the signature computation
                                if config.mpc.my_participant_id == primary_leader {
                                    metrics::MPC_NUM_SIGN_REQUESTS_LEADER
                                        .with_label_values(&["initiated_as_primary"])
                                        .inc();
                                } else {
                                    metrics::MPC_NUM_SIGN_REQUESTS_LEADER
                                        .with_label_values(&["initiated_as_secondary"])
                                        .inc();
                                }
                                let (signature, public_key) = timeout(
                                    Duration::from_secs(config.signature.timeout_sec),
                                    this.clone().make_signature(request.id),
                                )
                                .await??;
                                metrics::MPC_NUM_SIGN_REQUESTS_LEADER
                                    .with_label_values(&["initiated_and_succeeded"])
                                    .inc();

                                if config.mpc.my_participant_id == primary_leader
                                    && leader_mode == LeaderMode::DropPrimaryResponse
                                {
                                    metrics::MPC_NUM_SIGN_REQUESTS_LEADER
                                        .with_label_values(&["primary_dropped_response"])
                                        .inc();
                                    return anyhow::Ok(());
                                }
                                let response =
                                    ChainRespondArgs::new(&request, &signature, &public_key)?;
                                let _ = sign_response_sender.send(response).await;
                            }

                            anyhow::Ok(())
                        },
                    );
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
                self.root_keyshare.keygen_output(),
            ),
        );

        monitor_passive_channels.await?;
        monitor_chain.await?;
        generate_triples.await??;
        generate_presignatures.await??;

        Ok(())
    }

    // TODO: this is testonly and needs to be protected
    pub fn add_sign_request(self, request: &SignatureRequest) {
        self.sign_request_store.add(request);
    }

    pub async fn make_signature(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<(FullSignature<Secp256k1>, AffinePoint)> {
        let (presignature_id, presignature) = self
            .presignature_store
            .take_owned(&self.client.all_alive_participant_ids())
            .await;
        let sign_request = self.sign_request_store.get(id).await?;
        let (signature, public_key) = sign(
            self.client.new_channel_for_task(
                MpcTaskId::Signature {
                    id,
                    presignature_id,
                },
                presignature.participants,
            )?,
            self.client.my_participant_id(),
            self.root_keyshare.keygen_output(),
            presignature.presignature,
            sign_request.msg_hash,
            sign_request.tweak,
            sign_request.entropy,
        )
        .await?;

        Ok((signature, public_key))
    }
}
