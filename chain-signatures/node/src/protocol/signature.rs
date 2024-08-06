use super::contract::primitives::Participants;
use super::message::SignatureMessage;
use super::presignature::{GenerationError, Presignature, PresignatureId, PresignatureManager};
use crate::indexer::ContractSignRequest;
use crate::kdf::into_eth_sig;
use crate::types::SignatureProtocol;
use crate::util::AffinePointExt;
use crate::web::StateView;

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::{FullSignature, PresignOutput};
use chrono::Utc;
use crypto_shared::SerializableScalar;
use crypto_shared::{derive_key, PublicKey};
use k256::{Scalar, Secp256k1};
use mpc_contract::config::ProtocolConfig;
use mpc_contract::primitives::SignatureRequest;
use rand::rngs::StdRng;
use rand::seq::{IteratorRandom, SliceRandom};
use rand::SeedableRng;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use near_account_id::AccountId;
use near_fetch::signer::SignerExt;

pub type ReceiptId = near_primitives::hash::CryptoHash;

pub struct SignRequest {
    pub receipt_id: ReceiptId,
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub entropy: [u8; 32],
    pub time_added: Instant,
}

/// Type that preserves the insertion order of requests.
#[derive(Default)]
pub struct ParticipantRequests {
    requests: HashMap<ReceiptId, SignRequest>,
    order: VecDeque<ReceiptId>,
}

impl ParticipantRequests {
    fn insert(&mut self, receipt_id: ReceiptId, request: SignRequest) {
        self.requests.insert(receipt_id, request);
        self.order.push_back(receipt_id);
    }

    fn contains_key(&self, receipt_id: &ReceiptId) -> bool {
        self.requests.contains_key(receipt_id)
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn pop_front(&mut self) -> Option<(ReceiptId, SignRequest)> {
        let receipt_id = self.order.pop_front()?;
        self.requests
            .remove(&receipt_id)
            .map(|req| (receipt_id, req))
    }
}

#[derive(Default)]
pub struct SignQueue {
    unorganized_requests: Vec<SignRequest>,
    requests: HashMap<Participant, ParticipantRequests>,
}

impl SignQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.unorganized_requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn add(&mut self, request: SignRequest) {
        tracing::info!(
            receipt_id = %request.receipt_id,
            payload = hex::encode(request.request.payload.to_bytes()),
            entropy = hex::encode(request.entropy),
            "new sign request"
        );
        self.unorganized_requests.push(request);
    }

    pub fn organize(
        &mut self,
        threshold: usize,
        stable: &Participants,
        me: Participant,
        my_account_id: &AccountId,
    ) {
        if stable.len() < threshold {
            tracing::info!(
                "Require at least {} stable participants to organize, got {}: {:?}",
                threshold,
                stable.len(),
                stable.keys_vec()
            );
            return;
        }
        for request in self.unorganized_requests.drain(..) {
            let mut rng = StdRng::from_seed(request.entropy);
            let subset = stable.keys().choose_multiple(&mut rng, threshold);
            let proposer = **subset.choose(&mut rng).unwrap();
            if subset.contains(&&me) {
                tracing::info!(
                    receipt_id = %request.receipt_id,
                    ?me,
                    ?subset,
                    ?proposer,
                    "saving sign request: node is in the signer subset"
                );
                let proposer_requests = self.requests.entry(proposer).or_default();
                proposer_requests.insert(request.receipt_id, request);
                crate::metrics::NUM_SIGN_REQUESTS_MINE
                    .with_label_values(&[my_account_id.as_str()])
                    .inc();
            } else {
                tracing::info!(
                    receipt_id = %request.receipt_id,
                    ?me,
                    ?subset,
                    ?proposer,
                    "skipping sign request: node is NOT in the signer subset"
                );
            }
        }
    }

    pub fn contains(&self, participant: Participant, receipt_id: ReceiptId) -> bool {
        let Some(participant_requests) = self.requests.get(&participant) else {
            return false;
        };
        participant_requests.contains_key(&receipt_id)
    }

    pub fn my_requests(&mut self, me: Participant) -> &mut ParticipantRequests {
        self.requests.entry(me).or_default()
    }
}

/// An ongoing signature generator.
pub struct SignatureGenerator {
    pub protocol: SignatureProtocol,
    pub participants: Vec<Participant>,
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub sign_request_timestamp: Instant,
    pub generator_timestamp: Instant,
    pub timeout: Duration,
    pub timeout_total: Duration,
}

impl SignatureGenerator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: SignatureProtocol,
        participants: Vec<Participant>,
        proposer: Participant,
        presignature_id: PresignatureId,
        request: ContractSignRequest,
        epsilon: Scalar,
        delta: Scalar,
        sign_request_timestamp: Instant,
        cfg: &ProtocolConfig,
    ) -> Self {
        Self {
            protocol,
            participants,
            proposer,
            presignature_id,
            request,
            epsilon,
            delta,
            sign_request_timestamp,
            generator_timestamp: Instant::now(),
            timeout: Duration::from_millis(cfg.signature.generation_timeout),
            timeout_total: Duration::from_millis(cfg.signature.generation_timeout_total),
        }
    }

    pub fn poke(&mut self) -> Result<Action<FullSignature<Secp256k1>>, ProtocolError> {
        if self.sign_request_timestamp.elapsed() > self.timeout_total {
            return Err(ProtocolError::Other(
                anyhow::anyhow!("signature protocol timeout completely").into(),
            ));
        }

        if self.generator_timestamp.elapsed() > self.timeout {
            tracing::warn!(self.presignature_id, "signature protocol timed out");
            return Err(ProtocolError::Other(
                anyhow::anyhow!("signature protocol timeout").into(),
            ));
        }

        self.protocol.poke()
    }
}

/// Generator for signature thas has failed. Only retains essential information
/// for starting up this failed signature once again.
pub struct GenerationRequest {
    pub proposer: Participant,
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub sign_request_timestamp: Instant,
}

pub struct SignatureManager {
    /// Ongoing signature generation protocols.
    generators: HashMap<ReceiptId, SignatureGenerator>,
    /// Failed signatures awaiting to be retried.
    failed: VecDeque<(ReceiptId, GenerationRequest)>,
    /// Set of completed signatures
    completed: HashMap<ReceiptId, Instant>,
    /// Generated signatures assigned to the current node that are yet to be published.
    /// Vec<(receipt_id, msg_hash, timestamp, output)>
    signatures: Vec<ToPublish>,
    me: Participant,
    public_key: PublicKey,
    epoch: u64,
}

pub const MAX_RETRY: u8 = 10;
pub struct ToPublish {
    receipt_id: ReceiptId,
    request: SignatureRequest,
    time_added: Instant,
    signature: FullSignature<Secp256k1>,
    retry_count: u8,
}

impl ToPublish {
    pub fn new(
        receipt_id: ReceiptId,
        request: SignatureRequest,
        time_added: Instant,
        signature: FullSignature<Secp256k1>,
    ) -> ToPublish {
        ToPublish {
            receipt_id,
            request,
            time_added,
            signature,
            retry_count: 0,
        }
    }
}

impl SignatureManager {
    pub fn new(me: Participant, public_key: PublicKey, epoch: u64) -> Self {
        Self {
            generators: HashMap::new(),
            failed: VecDeque::new(),
            completed: HashMap::new(),
            signatures: Vec::new(),
            me,
            public_key,
            epoch,
        }
    }

    pub fn failed_len(&self) -> usize {
        self.failed.len()
    }

    pub fn me(&self) -> Participant {
        self.me
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::result_large_err)]
    fn generate_internal(
        participants: &Participants,
        me: Participant,
        public_key: PublicKey,
        presignature: Presignature,
        req: GenerationRequest,
        cfg: &ProtocolConfig,
    ) -> Result<SignatureGenerator, (Presignature, InitializationError)> {
        let participants = participants.keys_vec();
        let GenerationRequest {
            proposer,
            request,
            epsilon,
            delta,
            sign_request_timestamp,
        } = req;
        let PresignOutput { big_r, k, sigma } = presignature.output;
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (big_r * delta).to_affine(),
            k: k * delta.invert().unwrap(),
            sigma: (sigma + epsilon * k) * delta.invert().unwrap(),
        };
        let presignature_id = presignature.id;
        let protocol = Box::new(
            cait_sith::sign(
                &participants,
                me,
                derive_key(public_key, epsilon),
                output,
                request.payload,
            )
            .map_err(|err| (presignature, err))?,
        );
        Ok(SignatureGenerator::new(
            protocol,
            participants,
            proposer,
            presignature_id,
            request,
            epsilon,
            delta,
            sign_request_timestamp,
            cfg,
        ))
    }

    #[allow(clippy::result_large_err)]
    fn retry_failed_generation(
        &mut self,
        receipt_id: ReceiptId,
        req: GenerationRequest,
        presignature: Presignature,
        participants: &Participants,
        cfg: &ProtocolConfig,
    ) -> Result<(), (Presignature, InitializationError)> {
        tracing::info!(receipt_id = %receipt_id, participants = ?participants.keys_vec(), "restarting failed protocol to generate signature");
        let generator = Self::generate_internal(
            participants,
            self.me,
            self.public_key,
            presignature,
            req,
            cfg,
        )?;
        self.generators.insert(receipt_id, generator);
        Ok(())
    }

    /// Starts a new presignature generation protocol.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::result_large_err)]
    pub fn generate(
        &mut self,
        participants: &Participants,
        receipt_id: ReceiptId,
        presignature: Presignature,
        request: ContractSignRequest,
        epsilon: Scalar,
        delta: Scalar,
        sign_request_timestamp: Instant,
        cfg: &ProtocolConfig,
    ) -> Result<(), (Presignature, InitializationError)> {
        tracing::info!(
            %receipt_id,
            me = ?self.me,
            presignature_id = presignature.id,
            participants = ?participants.keys_vec(),
            "starting protocol to generate a new signature",
        );
        let generator = Self::generate_internal(
            participants,
            self.me,
            self.public_key,
            presignature,
            GenerationRequest {
                proposer: self.me,
                request,
                epsilon,
                delta,
                sign_request_timestamp,
            },
            cfg,
        )?;
        self.generators.insert(receipt_id, generator);
        Ok(())
    }

    /// Ensures that the presignature with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`, or
    /// 4) Depends on triples (`triple0`/`triple1`) that are unknown to the node
    // TODO: What if the presignature completed generation and is already spent?
    #[allow(clippy::too_many_arguments)]
    pub fn get_or_generate(
        &mut self,
        participants: &Participants,
        receipt_id: ReceiptId,
        proposer: Participant,
        presignature_id: PresignatureId,
        request: &ContractSignRequest,
        epsilon: Scalar,
        delta: Scalar,
        presignature_manager: &mut PresignatureManager,
        cfg: &ProtocolConfig,
    ) -> Result<&mut SignatureProtocol, GenerationError> {
        if self.completed.contains_key(&receipt_id) {
            tracing::warn!(%receipt_id, presignature_id, "presignature has already been used to generate a signature");
            return Err(GenerationError::AlreadyGenerated);
        }
        match self.generators.entry(receipt_id) {
            Entry::Vacant(entry) => {
                tracing::info!(%receipt_id, me = ?self.me, presignature_id, "joining protocol to generate a new signature");
                let presignature = match presignature_manager.take(presignature_id) {
                    Ok(presignature) => presignature,
                    Err(err @ GenerationError::PresignatureIsGenerating(_)) => {
                        tracing::warn!(me = ?self.me, presignature_id, "presignature is generating, can't join signature generation protocol");
                        return Err(err);
                    }
                    Err(err @ GenerationError::PresignatureIsMissing(_)) => {
                        tracing::warn!(me = ?self.me, presignature_id, "presignature is missing, can't join signature generation protocol");
                        return Err(err);
                    }
                    Err(err @ GenerationError::PresignatureIsGarbageCollected(_)) => {
                        tracing::warn!(me = ?self.me, presignature_id, "presignature is garbage collected, can't join signature generation protocol");
                        return Err(err);
                    }
                    Err(err) => return Err(err),
                };
                tracing::info!(me = ?self.me, presignature_id, "found presignature: ready to start signature generation");
                let generator = match Self::generate_internal(
                    participants,
                    self.me,
                    self.public_key,
                    presignature,
                    GenerationRequest {
                        proposer,
                        request: request.clone(),
                        epsilon,
                        delta,
                        sign_request_timestamp: Instant::now(),
                    },
                    cfg,
                ) {
                    Ok(generator) => generator,
                    Err((presignature, err @ InitializationError::BadParameters(_))) => {
                        presignature_manager.insert_mine(presignature);
                        tracing::warn!(%receipt_id, presignature_id, ?err, "failed to start signature generation");
                        return Err(GenerationError::CaitSithInitializationError(err));
                    }
                };
                let generator = entry.insert(generator);
                Ok(&mut generator.protocol)
            }
            Entry::Occupied(entry) => Ok(&mut entry.into_mut().protocol),
        }
    }

    /// Pokes all of the ongoing generation protocols and returns a vector of
    /// messages to be sent to the respective participant.
    ///
    /// An empty vector means we cannot progress until we receive a new message.
    pub fn poke(&mut self) -> Vec<(Participant, SignatureMessage)> {
        let mut messages = Vec::new();
        self.generators.retain(|receipt_id, generator| {
            loop {
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(err) => {
                        if generator.proposer == self.me {
                            if generator.sign_request_timestamp.elapsed() < generator.timeout_total {
                                tracing::warn!(?err, "signature failed to be produced; pushing request back into failed queue");
                                // only retry the signature generation if it was initially proposed by us. We do not
                                // want any nodes to be proposing the same signature multiple times.
                                self.failed.push_back((
                                    *receipt_id,
                                    GenerationRequest {
                                        proposer: generator.proposer,
                                        request: generator.request.clone(),
                                        epsilon: generator.epsilon,
                                        delta: generator.delta,
                                        sign_request_timestamp: generator.sign_request_timestamp
                                    },
                                ));
                            } else {
                                self.completed.insert(*receipt_id, Instant::now());
                                tracing::warn!(?err, "signature failed to be produced; trashing request");
                            }
                        }
                        break false;
                    }
                };
                match action {
                    Action::Wait => {
                        tracing::trace!("waiting");
                        // Retain protocol until we are finished
                        return true;
                    }
                    Action::SendMany(data) => {
                        for p in generator.participants.iter() {
                            messages.push((
                                *p,
                                SignatureMessage {
                                    receipt_id: *receipt_id,
                                    proposer: generator.proposer,
                                    presignature_id: generator.presignature_id,
                                    request: generator.request.clone(),
                                    epsilon: generator.epsilon,
                                    delta: generator.delta,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data: data.clone(),
                                    timestamp: Utc::now().timestamp() as u64
                                },
                            ))
                        }
                    }
                    Action::SendPrivate(p, data) => messages.push((
                        p,
                        SignatureMessage {
                            receipt_id: *receipt_id,
                            proposer: generator.proposer,
                            presignature_id: generator.presignature_id,
                            request: generator.request.clone(),
                            epsilon: generator.epsilon,
                            delta: generator.delta,
                            epoch: self.epoch,
                            from: self.me,
                            data,
                            timestamp: Utc::now().timestamp() as u64
                        },
                    )),
                    Action::Return(output) => {
                        tracing::info!(
                            ?receipt_id,
                            me = ?self.me,
                            presignature_id = generator.presignature_id,
                            big_r = ?output.big_r.to_base58(),
                            s = ?output.s,
                            "completed signature generation"
                        );
                        self.completed.insert(*receipt_id, Instant::now());
                        let request = SignatureRequest {
                            epsilon: SerializableScalar {scalar: generator.epsilon},
                            payload_hash: generator.request.payload.into(),
                        };
                        if generator.proposer == self.me {
                            self.signatures
                                .push(ToPublish::new(*receipt_id, request, generator.sign_request_timestamp, output));
                        }
                        // Do not retain the protocol
                        return false;
                    }
                }
            }
        });
        messages
    }

    pub fn handle_requests(
        &mut self,
        threshold: usize,
        stable: &Participants,
        state_views: &HashMap<Participant, StateView>,
        my_requests: &mut ParticipantRequests,
        presignature_manager: &mut PresignatureManager,
        cfg: &ProtocolConfig,
    ) {
        if stable.len() < threshold {
            tracing::info!(
                "Require at least {} stable participants to handle_requests, got {}: {:?}",
                threshold,
                stable.len(),
                stable.keys_vec()
            );
            return;
        }
        let mut failed_presigs = Vec::new();
        let mut alternate = false;
        while let Some(presignature) = {
            if self.failed.is_empty() && my_requests.is_empty() {
                None
            } else {
                presignature_manager.take_mine()
            }
        } {
            let sig_participants = stable.intersection(&[&presignature.participants]);
            if sig_participants.len() < threshold {
                tracing::debug!(
                    participants = ?sig_participants.keys_vec(),
                    "we do not have enough participants to generate a signature"
                );
                failed_presigs.push(presignature);
                continue;
            }
            let state_views = sig_participants
                .iter()
                .filter_map(|(p, _)| Some((*p, state_views.get(p)?)));

            // Filter out the active participants with the state views that have the triples we want to use.
            let stable_filtered = state_views
                .filter(|(_, state_view)| {
                    if let StateView::Running {
                        presignature_postview,
                        ..
                    } = state_view
                    {
                        presignature_postview.contains(&presignature.id)
                    } else {
                        false
                    }
                })
                .map(|(p, _)| p)
                .collect::<Vec<_>>();

            if stable_filtered.len() < threshold {
                failed_presigs.push(presignature);
                continue;
            }

            // NOTE: this prioritizes old requests first then tries to do new ones if there's enough presignatures.
            // TODO: we need to decide how to prioritize certain requests over others such as with gas or time of
            // when the request made it into the NEAR network.
            // issue: https://github.com/near/mpc-recovery/issues/596

            let id = presignature.id;
            alternate = !alternate;
            if alternate && !self.failed.is_empty() {
                let Some((receipt_id, failed_req)) = self.failed.pop_front() else {
                    failed_presigs.push(presignature);
                    continue;
                };

                if let Err((presignature, InitializationError::BadParameters(err))) = self
                    .retry_failed_generation(
                        receipt_id,
                        failed_req,
                        presignature,
                        &sig_participants,
                        cfg,
                    )
                {
                    failed_presigs.push(presignature);
                    tracing::warn!(%receipt_id, id, ?err, "failed to retry signature generation: trashing presignature");
                }
            } else {
                let Some((receipt_id, my_request)) = my_requests.pop_front() else {
                    failed_presigs.push(presignature);
                    continue;
                };
                if let Err((presignature, InitializationError::BadParameters(err))) = self.generate(
                    &sig_participants,
                    receipt_id,
                    presignature,
                    my_request.request,
                    my_request.epsilon,
                    my_request.delta,
                    my_request.time_added,
                    cfg,
                ) {
                    failed_presigs.push(presignature);
                    tracing::warn!(%receipt_id, id, ?err, "failed to start signature generation: trashing presignature");
                }
            }
        }

        // add back the failed presignatures that were incompatible to be made into
        // signatures due to failures or lack of participants.
        for presignature in failed_presigs {
            presignature_manager.insert_mine(presignature);
        }
    }

    pub async fn publish<T: SignerExt>(
        &mut self,
        rpc_client: &near_fetch::Client,
        signer: &T,
        mpc_contract_id: &AccountId,
        my_account_id: &AccountId,
    ) {
        let mut to_retry: Vec<ToPublish> = Vec::new();

        for mut to_publish in self.signatures.drain(..) {
            let ToPublish {
                receipt_id,
                request,
                time_added,
                signature,
                ..
            } = &to_publish;
            let expected_public_key = derive_key(self.public_key, request.epsilon.scalar);
            // We do this here, rather than on the client side, so we can use the ecrecover system function on NEAR to validate our signature
            let Ok(signature) = into_eth_sig(
                &expected_public_key,
                &signature.big_r,
                &signature.s,
                request.payload_hash.scalar,
            ) else {
                tracing::error!(%receipt_id, "Failed to generate a recovery ID");
                continue;
            };
            let response = match rpc_client
                .call(signer, mpc_contract_id, "respond")
                .args_json(serde_json::json!({
                    "request": request,
                    "response": signature,
                }))
                .max_gas()
                .retry_exponential(10, 5)
                .transact()
                .await
            {
                Ok(response) => response,
                Err(err) => {
                    tracing::error!(%receipt_id, error = ?err, "Failed to publish transaction");
                    // Push the response to the back of the queue if it hasn't been retried the max number of times
                    if to_publish.retry_count < MAX_RETRY {
                        to_publish.retry_count += 1;
                        to_retry.push(to_publish);
                    }
                    continue;
                }
            };

            match response.json() {
                Ok(()) => {
                    tracing::info!(%receipt_id, bi_r = signature.big_r.affine_point.to_base58(), s = ?signature.s, "published signature sucessfully")
                }
                Err(err) => {
                    tracing::error!(%receipt_id, bi_r = signature.big_r.affine_point.to_base58(), s = ?signature.s, error = ?err, "smart contract threw error");
                    continue;
                }
            };

            crate::metrics::NUM_SIGN_SUCCESS
                .with_label_values(&[my_account_id.as_str()])
                .inc();
            crate::metrics::SIGN_LATENCY
                .with_label_values(&[my_account_id.as_str()])
                .observe(time_added.elapsed().as_secs_f64());
            if time_added.elapsed().as_secs() <= 30 {
                crate::metrics::NUM_SIGN_SUCCESS_30S
                    .with_label_values(&[my_account_id.as_str()])
                    .inc();
            }
        }
        // Put the failed requests at the back of the queue
        self.signatures.extend(to_retry);
    }

    /// Garbage collect all the completed signatures.
    pub fn garbage_collect(&mut self, cfg: &ProtocolConfig) {
        self.completed.retain(|_, timestamp| {
            timestamp.elapsed() < Duration::from_millis(cfg.signature.garbage_timeout)
        });
    }

    pub fn refresh_gc(&mut self, id: &ReceiptId) -> bool {
        let entry = self
            .completed
            .entry(*id)
            .and_modify(|e| *e = Instant::now());
        matches!(entry, Entry::Occupied(_))
    }
}
