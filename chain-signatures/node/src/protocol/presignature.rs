use super::message::PresignatureMessage;
use super::triple::{Triple, TripleId, TripleManager};
use crate::protocol::contract::primitives::Participants;
use crate::types::{PresignatureProtocol, SecretKeyShare};
use crate::util::AffinePointExt;
use crate::web::StateView;

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::{KeygenOutput, PresignArguments, PresignOutput};
use chrono::Utc;
use crypto_shared::PublicKey;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use sha3::{Digest, Sha3_256};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use near_account_id::AccountId;

/// Unique number used to identify a specific ongoing presignature generation protocol.
/// Without `PresignatureId` it would be unclear where to route incoming cait-sith presignature
/// generation messages.
pub type PresignatureId = u64;

/// A completed presignature.
pub struct Presignature {
    pub id: PresignatureId,
    pub output: PresignOutput<Secp256k1>,
    pub participants: Vec<Participant>,
}

/// An ongoing presignature generator.
pub struct PresignatureGenerator {
    pub participants: Vec<Participant>,
    pub protocol: PresignatureProtocol,
    pub triple0: TripleId,
    pub triple1: TripleId,
    pub mine: bool,
    pub timestamp: Instant,
    pub timeout: Duration,
}

impl PresignatureGenerator {
    pub fn new(
        protocol: PresignatureProtocol,
        participants: Vec<Participant>,
        triple0: TripleId,
        triple1: TripleId,
        mine: bool,
        timeout: u64,
    ) -> Self {
        Self {
            protocol,
            participants,
            triple0,
            triple1,
            mine,
            timestamp: Instant::now(),
            timeout: Duration::from_millis(timeout),
        }
    }

    pub fn poke(&mut self) -> Result<Action<PresignOutput<Secp256k1>>, ProtocolError> {
        if self.timestamp.elapsed() > self.timeout {
            tracing::info!(
                self.triple0,
                self.triple1,
                self.mine,
                "presignature protocol timed out"
            );
            return Err(ProtocolError::Other(
                anyhow::anyhow!("presignature protocol timed out").into(),
            ));
        }

        self.protocol.poke()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("presignature already generated")]
    AlreadyGenerated,
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("triple {0} is missing")]
    TripleIsMissing(TripleId),
    #[error("triple {0} is generating")]
    TripleIsGenerating(TripleId),
    #[error("triple {0} is in garbage collection")]
    TripleIsGarbageCollected(TripleId),
    #[error("presignature {0} is generating")]
    PresignatureIsGenerating(PresignatureId),
    #[error("presignature {0} is missing")]
    PresignatureIsMissing(PresignatureId),
    #[error("presignature {0} is in garbage collection")]
    PresignatureIsGarbageCollected(TripleId),
}

/// Abstracts how triples are generated by providing a way to request a new triple that will be
/// complete some time in the future and a way to take an already generated triple.
pub struct PresignatureManager {
    /// Completed unspent presignatures.
    presignatures: HashMap<PresignatureId, Presignature>,
    /// Ongoing presignature generation protocols.
    generators: HashMap<PresignatureId, PresignatureGenerator>,
    /// List of presignature ids generation of which was initiated by the current node.
    pub mine: VecDeque<PresignatureId>,
    /// The set of presignatures that were introduced to the system by the current node.
    introduced: HashSet<PresignatureId>,
    /// Garbage collection for presignatures that have either been taken or failed. This
    /// will be maintained for at most presignature timeout period just so messages are
    /// cycled through the system.
    gc: HashMap<PresignatureId, Instant>,
    me: Participant,
    threshold: usize,
    epoch: u64,
    my_account_id: AccountId,
}

impl PresignatureManager {
    pub fn new(me: Participant, threshold: usize, epoch: u64, my_account_id: &AccountId) -> Self {
        Self {
            presignatures: HashMap::new(),
            generators: HashMap::new(),
            mine: VecDeque::new(),
            introduced: HashSet::new(),
            gc: HashMap::new(),
            me,
            threshold,
            epoch,
            my_account_id: my_account_id.clone(),
        }
    }

    /// Returns the number of unspent presignatures available in the manager.
    pub fn len(&self) -> usize {
        self.presignatures.len()
    }

    /// Returns the number of unspent presignatures assigned to this node.
    pub fn my_len(&self) -> usize {
        self.mine.len()
    }

    /// Returns the number of unspent presignatures we will have in the manager once
    /// all ongoing generation protocols complete.
    pub fn potential_len(&self) -> usize {
        self.presignatures.len() + self.generators.len()
    }

    /// Returns if there are unspent presignatures available in the manager.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn garbage_collect(&mut self, cfg: &ProtocolConfig) {
        self.gc
            .retain(|_, instant| instant.elapsed() < Duration::from_millis(cfg.garbage_timeout));
    }

    pub fn refresh_gc(&mut self, id: &PresignatureId) -> bool {
        let entry = self.gc.entry(*id).and_modify(|e| *e = Instant::now());
        matches!(entry, Entry::Occupied(_))
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_internal(
        participants: &[Participant],
        me: Participant,
        threshold: usize,
        triple0: Triple,
        triple1: Triple,
        public_key: &PublicKey,
        private_share: &SecretKeyShare,
        mine: bool,
        timeout: u64,
    ) -> Result<PresignatureGenerator, InitializationError> {
        let protocol = Box::new(cait_sith::presign(
            participants,
            me,
            // These paramaters appear to be to make it easier to use different indexing schemes for triples
            // Introduced in this PR https://github.com/LIT-Protocol/cait-sith/pull/7
            participants,
            me,
            PresignArguments {
                triple0: (triple0.share, triple0.public),
                triple1: (triple1.share, triple1.public),
                keygen_out: KeygenOutput {
                    private_share: *private_share,
                    public_key: *public_key,
                },
                threshold,
            },
        )?);
        Ok(PresignatureGenerator::new(
            protocol,
            participants.into(),
            triple0.id,
            triple1.id,
            mine,
            timeout,
        ))
    }

    /// Starts a new presignature generation protocol.
    pub fn generate(
        &mut self,
        participants: &[Participant],
        triple0: Triple,
        triple1: Triple,
        public_key: &PublicKey,
        private_share: &SecretKeyShare,
        timeout: u64,
    ) -> Result<(), InitializationError> {
        let id = hash_as_id(triple0.id, triple1.id);

        // Check if the `id` is already in the system. Error out and have the next cycle try again.
        if self.generators.contains_key(&id)
            || self.presignatures.contains_key(&id)
            || self.gc.contains_key(&id)
        {
            return Err(InitializationError::BadParameters(format!(
                "id collision: presignature_id={id}"
            )));
        }

        tracing::debug!(id, "starting protocol to generate a new presignature");
        let generator = Self::generate_internal(
            participants,
            self.me,
            self.threshold,
            triple0,
            triple1,
            public_key,
            private_share,
            true,
            timeout,
        )?;
        self.generators.insert(id, generator);
        self.introduced.insert(id);
        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE
            .with_label_values(&[self.my_account_id.as_str()])
            .inc();
        Ok(())
    }

    pub async fn stockpile(
        &mut self,
        active: &Participants,
        state_views: &HashMap<Participant, StateView>,
        pk: &PublicKey,
        sk_share: &SecretKeyShare,
        triple_manager: &mut TripleManager,
        cfg: &ProtocolConfig,
    ) -> Result<(), InitializationError> {
        let not_enough_presignatures = {
            // Stopgap to prevent too many presignatures in the system. This should be around min_presig*nodes*2
            // for good measure so that we have enough presignatures to do sig generation while also maintain
            // the minimum number of presignature where a single node can't flood the system.
            if self.potential_len() >= cfg.presignature.max_presignatures as usize {
                false
            } else {
                // We will always try to generate a new triple if we have less than the minimum
                self.my_len() < cfg.presignature.min_presignatures as usize
                    && self.introduced.len() < cfg.max_concurrent_introduction as usize
            }
        };

        if not_enough_presignatures {
            // To ensure there is no contention between different nodes we are only using triples
            // that we proposed. This way in a non-BFT environment we are guaranteed to never try
            // to use the same triple as any other node.
            if let Some((triple0, triple1)) = triple_manager.peek_two_mine() {
                let id0 = triple0.id;
                let id1 = triple1.id;
                let presig_participants = active
                    .intersection(&[&triple0.public.participants, &triple1.public.participants]);
                if presig_participants.len() < self.threshold {
                    tracing::warn!(
                        id0,
                        id1,
                        participants = ?presig_participants.keys_vec(),
                        "running: participants are not above threshold for presignature generation"
                    );
                    return Ok(());
                }

                let state_views = presig_participants
                    .iter()
                    .filter_map(|(p, _)| Some((*p, state_views.get(p)?)));

                // Filter out the active participants with the state views that have the triples we want to use.
                let active_filtered = state_views
                    .filter(|(_, state_view)| {
                        if let StateView::Running {
                            triple_postview, ..
                        } = state_view
                        {
                            triple_postview.contains(&triple0.id)
                                && triple_postview.contains(&triple1.id)
                        } else {
                            false
                        }
                    })
                    .map(|(p, _)| p)
                    .collect::<Vec<_>>();

                if active_filtered.len() < self.threshold {
                    tracing::debug!(
                        id0,
                        id1,
                        participants = ?presig_participants.keys_vec(),
                        "running: we don't have enough participants to generate a presignature"
                    );
                    return Ok(());
                }

                // Actually take the triples now that we have done the necessary checks.
                let Some((triple0, triple1)) = triple_manager.take_two_mine().await else {
                    tracing::warn!("running: popping after peeking should have succeeded");
                    return Ok(());
                };

                if let Err(err @ InitializationError::BadParameters(_)) = self.generate(
                    &active_filtered,
                    triple0,
                    triple1,
                    pk,
                    sk_share,
                    cfg.presignature.generation_timeout,
                ) {
                    tracing::warn!(
                        id0,
                        id1,
                        ?err,
                        "we had to trash two triples due to bad parameters"
                    );
                    return Err(err);
                }
            } else {
                tracing::debug!("running: we don't have enough triples to generate a presignature");
            }
        }

        Ok(())
    }

    /// Ensures that the presignature with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`, or
    /// 4) Depends on triples (`triple0`/`triple1`) that are unknown to the node
    // TODO: What if the presignature completed generation and is already spent?
    #[allow(clippy::too_many_arguments)]
    pub async fn get_or_generate(
        &mut self,
        participants: &Participants,
        id: PresignatureId,
        triple0: TripleId,
        triple1: TripleId,
        triple_manager: &mut TripleManager,
        public_key: &PublicKey,
        private_share: &SecretKeyShare,
        cfg: &ProtocolConfig,
    ) -> Result<&mut PresignatureProtocol, GenerationError> {
        if self.presignatures.contains_key(&id) {
            Err(GenerationError::AlreadyGenerated)
        } else if self.gc.contains_key(&id) {
            Err(GenerationError::PresignatureIsGarbageCollected(id))
        } else {
            match self.generators.entry(id) {
                Entry::Vacant(entry) => {
                    tracing::info!(id, "joining protocol to generate a new presignature");
                    let (triple0, triple1) = match triple_manager.take_two(triple0, triple1).await {
                        Ok(result) => result,
                        Err(error) => match error {
                            GenerationError::TripleIsGenerating(_) => {
                                tracing::warn!(
                                    ?error,
                                    id,
                                    triple0,
                                    triple1,
                                    "could not initiate non-introduced presignature: one triple is generating"
                                );
                                return Err(error);
                            }
                            GenerationError::TripleIsGarbageCollected(_) => {
                                tracing::warn!(
                                    ?error,
                                    id,
                                    triple0,
                                    triple1,
                                    "could not initiate non-introduced presignature: one triple is in garbage collection"
                                );
                                return Err(error);
                            }
                            GenerationError::TripleIsMissing(_) => {
                                tracing::warn!(
                                    ?error,
                                    id,
                                    triple0,
                                    triple1,
                                    "could not initiate non-introduced presignature: one triple is missing"
                                );
                                return Err(error);
                            }
                            _ => {
                                return Err(error);
                            }
                        },
                    };
                    let generator = Self::generate_internal(
                        &participants.keys_vec(),
                        self.me,
                        self.threshold,
                        triple0,
                        triple1,
                        public_key,
                        private_share,
                        false,
                        cfg.presignature.generation_timeout,
                    )?;
                    let generator = entry.insert(generator);
                    crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS
                        .with_label_values(&[self.my_account_id.as_str()])
                        .inc();
                    Ok(&mut generator.protocol)
                }
                Entry::Occupied(entry) => Ok(&mut entry.into_mut().protocol),
            }
        }
    }

    pub fn take_mine(&mut self) -> Option<Presignature> {
        tracing::info!(mine = ?self.mine, "my presignatures");
        let my_presignature_id = self.mine.pop_front()?;
        // SAFETY: This unwrap is safe because taking mine will always succeed since it is only
        // present when generation completes where the determination of ownership is made.
        Some(self.take(my_presignature_id).unwrap())
    }

    pub fn take(&mut self, id: PresignatureId) -> Result<Presignature, GenerationError> {
        if let Some(presignature) = self.presignatures.remove(&id) {
            self.gc.insert(id, Instant::now());
            return Ok(presignature);
        }

        if self.generators.contains_key(&id) {
            return Err(GenerationError::PresignatureIsGenerating(id));
        }
        if self.gc.contains_key(&id) {
            return Err(GenerationError::PresignatureIsGarbageCollected(id));
        }
        Err(GenerationError::PresignatureIsMissing(id))
    }

    pub fn insert_mine(&mut self, presig: Presignature) {
        // Remove from taken list if it was there
        self.gc.remove(&presig.id);
        self.mine.push_back(presig.id);
        self.presignatures.insert(presig.id, presig);
    }

    /// Pokes all of the ongoing generation protocols and returns a vector of
    /// messages to be sent to the respective participant.
    ///
    /// An empty vector means we cannot progress until we receive a new message.
    pub fn poke(&mut self) -> Vec<(Participant, PresignatureMessage)> {
        let mut messages = Vec::new();
        let mut errors = Vec::new();
        self.generators.retain(|id, generator| {
            loop {
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(e) => {
                        self.gc.insert(*id, Instant::now());
                        self.introduced.remove(id);
                        errors.push(e);
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
                                PresignatureMessage {
                                    id: *id,
                                    triple0: generator.triple0,
                                    triple1: generator.triple1,
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
                        PresignatureMessage {
                            id: *id,
                            triple0: generator.triple0,
                            triple1: generator.triple1,
                            epoch: self.epoch,
                            from: self.me,
                            data,
                            timestamp: Utc::now().timestamp() as u64
                        },
                    )),
                    Action::Return(output) => {
                        tracing::info!(
                            id,
                            me = ?self.me,
                            big_r = ?output.big_r.to_base58(),
                            "completed presignature generation"
                        );
                        self.presignatures.insert(
                            *id,
                            Presignature {
                                id: *id,
                                output,
                                participants: generator.participants.clone(),
                            },
                        );
                        if generator.mine {
                            tracing::info!(id, "assigning presignature to myself");
                            self.mine.push_back(*id);
                            crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE_SUCCESS
                                .with_label_values(&[self.my_account_id.as_str()])
                                .inc();
                        }
                        self.introduced.remove(id);

                        crate::metrics::PRESIGNATURE_LATENCY
                            .with_label_values(&[self.my_account_id.as_str()])
                            .observe(generator.timestamp.elapsed().as_secs_f64());
                        crate::metrics::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_SUCCESS
                            .with_label_values(&[self.my_account_id.as_str()])
                            .inc();
                        // Do not retain the protocol
                        return false;
                    }
                }
            }
        });

        if !errors.is_empty() {
            tracing::warn!(?errors, "failed to generate some presignatures");
        }

        messages
    }

    pub fn preview(&self, presignatures: &HashSet<PresignatureId>) -> HashSet<PresignatureId> {
        let presignatures = presignatures
            .into_iter()
            .filter(|id| self.presignatures.contains_key(id))
            .cloned()
            .collect();

        presignatures
    }
}

pub fn hash_as_id(triple0: TripleId, triple1: TripleId) -> PresignatureId {
    let mut hasher = Sha3_256::new();
    hasher.update(triple0.to_le_bytes());
    hasher.update(triple1.to_le_bytes());
    let id: [u8; 32] = hasher.finalize().into();
    let id = u64::from_le_bytes(first_8_bytes(id));

    PresignatureId::from(id)
}

const fn first_8_bytes(input: [u8; 32]) -> [u8; 8] {
    let mut output = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        output[i] = input[i];
        i += 1;
    }
    output
}
