//! On-chain whitelist of RPC providers for foreign-chain transaction validation.
//! Each entry in a vote batch is a per-chain snapshot (provider list + RPC response
//! quorum); the chain's state is replaced once the protocol's signing threshold of
//! participants holds the same proposal.
//!
//! Pending votes are stored hash-only via [`Votes<V>`][crate::primitives::votes::Votes],
//! which is backed by lazy-loaded `IterableMap`s. The applied state lives in
//! `AllowedProviders` (also `IterableMap`-backed) and retains the full `ChainEntry`
//! content. The tipping voter always brings the proposal in as a call argument, so the
//! applied state is reconstructable from the call that crosses threshold — pending
//! state can stay hash-only without losing data on apply.

use std::collections::BTreeMap;

use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    self as dtos, ChainRouting, ForeignChain, ProviderConfig, ProviderId,
};
use near_sdk::near;
use near_sdk::store::IterableMap;

use crate::errors::{ChainEntryValidationError, ConversionError, Error, InvalidParameters};
use crate::primitives::thresholds::ThresholdParameters;
use crate::primitives::votes::{ProposalHash, ProposalHashEncoding, Votes};
use crate::primitives::{key_state::AuthenticatedParticipantId, participants::Participants};
use crate::storage_keys::StorageKey;

impl From<ChainEntryValidationError> for Error {
    fn from(err: ChainEntryValidationError) -> Self {
        InvalidParameters::MalformedPayload {
            reason: err.to_string(),
        }
        .into()
    }
}

/// Contract-side `ChainEntry`. Mirrors [`dtos::ChainEntry`] in layout but enforces
/// validation rules at construction. The DTO type is the wire shape; this type is
/// what the contract stores and reasons about. Conversion is via
/// [`TryFrom<dtos::ChainEntry>`] (validates) and [`From<ChainEntry> for dtos::ChainEntry`]
/// (for view-fn return). Borsh layout matches the DTO so storage bytes are
/// interchangeable and pending-vote hashes agree across voters.
#[near(serializers=[borsh])]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChainEntry {
    providers: NonEmptyBTreeMap<ProviderId, ProviderConfig>,
    quorum: u64,
}

impl TryFrom<dtos::ChainEntry> for ChainEntry {
    type Error = ChainEntryValidationError;

    fn try_from(entry: dtos::ChainEntry) -> Result<Self, Self::Error> {
        let dtos::ChainEntry { providers, quorum } = entry;
        if quorum == 0 {
            return Err(ChainEntryValidationError::ZeroQuorum);
        }
        let providers_len = u64::try_from(providers.len()).map_err(|e| {
            ChainEntryValidationError::ProvidersLenOverflow {
                len: providers.len(),
                reason: e.to_string(),
            }
        })?;
        if quorum > providers_len {
            return Err(ChainEntryValidationError::QuorumExceedsProviders {
                quorum,
                providers_len,
            });
        }
        for (id, config) in providers.iter() {
            if let ChainRouting::PathSegment { segment } = &config.chain_routing {
                if segment.contains('/') {
                    return Err(ChainEntryValidationError::PathSegmentContainsSlash {
                        provider_id: id.0.clone(),
                    });
                }
            }
            if let (
                ChainRouting::QueryParam {
                    name: routing_name, ..
                },
                dtos::AuthScheme::Query { name: auth_name },
            ) = (&config.chain_routing, &config.auth_scheme)
            {
                if routing_name == auth_name {
                    return Err(ChainEntryValidationError::QueryParamCollidesWithAuth {
                        provider_id: id.0.clone(),
                        name: auth_name.clone(),
                    });
                }
            }
        }
        Ok(ChainEntry { providers, quorum })
    }
}

impl From<ChainEntry> for dtos::ChainEntry {
    fn from(entry: ChainEntry) -> Self {
        dtos::ChainEntry {
            providers: entry.providers,
            quorum: entry.quorum,
        }
    }
}

impl ProposalHashEncoding for ChainEntry {
    fn bytes_for_hash(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialization of ChainEntry must succeed")
    }
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub(crate) struct AllowedProviders {
    entries: IterableMap<ForeignChain, ChainEntry>,
}

impl Default for AllowedProviders {
    fn default() -> Self {
        Self {
            entries: IterableMap::new(StorageKey::AllowedForeignChainProvidersV1),
        }
    }
}

impl AllowedProviders {
    fn replace(&mut self, chain: ForeignChain, entry: ChainEntry) {
        self.entries.insert(chain, entry);
    }

    /// Owned clone of the whitelist as DTOs; required by `allowed_foreign_chain_providers`,
    /// which borsh-serializes the result across the contract boundary.
    pub fn snapshot(&self) -> BTreeMap<ForeignChain, dtos::ChainEntry> {
        self.entries
            .iter()
            .map(|(c, e)| (*c, e.clone().into()))
            .collect()
    }
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct ProviderVotes {
    pub pending: Votes<(AuthenticatedParticipantId, ForeignChain)>,
}

impl Default for ProviderVotes {
    fn default() -> Self {
        Self {
            pending: Votes::new(
                StorageKey::ForeignChainProviderVotesByVoterV1,
                StorageKey::ForeignChainProviderVotesByProposalV1,
            ),
        }
    }
}

impl ProviderVotes {
    pub fn retain(&mut self, current: &Participants) {
        self.pending
            .retain_votes(|(p, _)| current.is_participant_given_participant_id(&p.get()));
    }

    /// Records `participant`'s vote for `(chain, hash)`. Returns `true` when `chain`
    /// crosses the signing threshold (stale rows from dropped participants don't count);
    /// on `true`, pending rows for `chain` are cleared and the caller must apply the
    /// new state.
    pub fn vote(
        &mut self,
        chain: ForeignChain,
        hash: ProposalHash,
        participant: AuthenticatedParticipantId,
        threshold_parameters: &ThresholdParameters,
    ) -> Result<bool, Error> {
        let protocol_threshold = threshold_parameters.threshold().value();
        let participants = threshold_parameters.participants();
        // Scope the borrow on `self.pending.vote` so we can mutate `self.pending`
        // after `count_for`.
        let count_usize = {
            let voter_set = self.pending.vote((participant, chain), hash);
            voter_set.count_for(|(p, c)| {
                *c == chain && participants.is_participant_given_participant_id(&p.get())
            })
        };
        let count = u64::try_from(count_usize).map_err(|e| ConversionError::DataConversion {
            reason: format!("vote count {count_usize} does not fit in u64: {e}"),
        })?;
        if count >= protocol_threshold {
            // Drop ALL pending rows for this chain regardless of which proposal
            // they held — matches the previous `clear_chain` semantics.
            self.pending.retain_votes(|(_, c)| *c != chain);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[near(serializers=[borsh])]
#[derive(Debug, Default)]
pub struct ForeignChainRpcWhitelist {
    pub(crate) entries: AllowedProviders,
    pub(crate) votes: ProviderVotes,
}

impl ForeignChainRpcWhitelist {
    /// Record `participant`'s votes; replace each chain's state once
    /// `protocol_threshold` participants hold the same canonical `(providers, quorum)`
    /// pair. `protocol_threshold` is the protocol's signing threshold (the same one
    /// that gates threshold signatures), not to be confused with `ChainEntry.quorum`,
    /// which is the RPC response quorum nodes use when querying the listed providers.
    ///
    /// The input batch is a `NonEmptyBTreeMap<ForeignChain, ChainEntry>`, so two
    /// invariants are enforced at borsh-deserialize time and don't need to be re-checked
    /// here: the batch is non-empty, and each chain appears at most once.
    ///
    /// Returns the chains applied this call.
    pub fn vote(
        &mut self,
        participant: AuthenticatedParticipantId,
        votes: NonEmptyBTreeMap<ForeignChain, dtos::ChainEntry>,
        threshold_parameters: &ThresholdParameters,
    ) -> Result<Vec<ForeignChain>, Error> {
        let mut applied: Vec<ForeignChain> = Vec::new();
        let votes: BTreeMap<ForeignChain, dtos::ChainEntry> = votes.into();
        for (chain, entry) in votes {
            let entry: ChainEntry = entry.try_into()?;
            let hash = ProposalHash::from(entry.clone());
            if self
                .votes
                .vote(chain, hash, participant.clone(), threshold_parameters)?
            {
                self.entries.replace(chain, entry);
                applied.push(chain);
            }
        }
        Ok(applied)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::{key_state::AuthenticatedParticipantId, test_utils::gen_participants};
    use assert_matches::assert_matches;
    use mpc_primitives::Threshold;
    use near_mpc_contract_interface::types::AuthScheme;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    /// Build a `ThresholdParameters` for tests, bypassing the relative-threshold
    /// validation so tests can express edge-case combinations (e.g. the stale-votes
    /// test deliberately uses a threshold > current participant count to assert
    /// the count_for predicate filters out non-participant rows).
    fn tp(participants: &Participants, n: u64) -> ThresholdParameters {
        ThresholdParameters::new_unvalidated(participants.clone(), Threshold::new(n))
    }

    fn provider(id: &str) -> (ProviderId, ProviderConfig) {
        (
            ProviderId(id.to_string()),
            ProviderConfig {
                base_url: format!("https://{id}.example.com"),
                auth_scheme: AuthScheme::None,
                chain_routing: ChainRouting::Embedded,
            },
        )
    }

    /// Build a `dtos::ChainEntry` from a list of provider id stubs and a quorum.
    fn chain_entry(ids: &[&str], quorum: u64) -> dtos::ChainEntry {
        let providers: BTreeMap<ProviderId, ProviderConfig> =
            ids.iter().map(|id| provider(id)).collect();
        dtos::ChainEntry {
            providers: NonEmptyBTreeMap::try_from(providers)
                .expect("test setup: providers must be non-empty"),
            quorum,
        }
    }

    /// Build a single-chain vote batch wrapped in `NonEmptyBTreeMap`.
    fn single_chain_votes(
        chain: ForeignChain,
        ids: &[&str],
        quorum: u64,
    ) -> NonEmptyBTreeMap<ForeignChain, dtos::ChainEntry> {
        NonEmptyBTreeMap::new(chain, chain_entry(ids, quorum))
    }

    /// Build a multi-chain vote batch wrapped in `NonEmptyBTreeMap`.
    fn votes_from(
        entries: impl IntoIterator<Item = (ForeignChain, dtos::ChainEntry)>,
    ) -> NonEmptyBTreeMap<ForeignChain, dtos::ChainEntry> {
        let map: BTreeMap<_, _> = entries.into_iter().collect();
        NonEmptyBTreeMap::try_from(map).expect("test setup: batch must be non-empty")
    }

    /// Build `n` participants and pre-authenticate each one. The pattern intentionally
    /// runs all `testing_env!` resets *before* any storage-backed state is touched —
    /// later vote ops can then write to the mocked storage without an env reset
    /// wiping prior writes.
    fn setup(n: usize) -> (Participants, Vec<AuthenticatedParticipantId>) {
        let participants = gen_participants(n);
        let mut auth_ids = Vec::with_capacity(n);
        for (account_id, _, _) in participants.participants() {
            let mut ctx = VMContextBuilder::new();
            ctx.signer_account_id(account_id.clone());
            testing_env!(ctx.build());
            auth_ids.push(AuthenticatedParticipantId::new(&participants).unwrap());
        }
        (participants, auth_ids)
    }

    fn assert_malformed(err: Error, reason_substring: &str) {
        match err {
            Error::InvalidParameters(InvalidParameters::MalformedPayload { reason }) => {
                assert!(
                    reason.contains(reason_substring),
                    "expected reason to contain {reason_substring:?}, got {reason:?}",
                );
            }
            other => panic!("expected MalformedPayload, got {other:?}"),
        }
    }

    fn stored_entry(
        wl: &ForeignChainRpcWhitelist,
        chain: ForeignChain,
    ) -> Option<dtos::ChainEntry> {
        wl.entries.snapshot().get(&chain).cloned()
    }

    /// Total voters with a pending vote across all chains/proposals.
    fn pending_voter_count(wl: &ForeignChainRpcWhitelist) -> usize {
        wl.votes.pending.all().values().map(|s| s.len()).sum()
    }

    /// Does `voter` currently hold any pending vote at all?
    fn has_pending_vote(
        wl: &ForeignChainRpcWhitelist,
        voter: &(AuthenticatedParticipantId, ForeignChain),
    ) -> bool {
        wl.votes.pending.all().values().any(|s| s.contains(voter))
    }

    /// The `ProposalHash` that `voter` is currently holding (if any).
    fn pending_proposal_hash_for(
        wl: &ForeignChainRpcWhitelist,
        voter: &(AuthenticatedParticipantId, ForeignChain),
    ) -> Option<ProposalHash> {
        wl.votes
            .pending
            .all()
            .into_iter()
            .find_map(|(h, set)| set.contains(voter).then_some(h))
    }

    #[test]
    fn vote__should_apply_chain_when_all_participants_match() {
        // Given
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();

        // When
        let applied_p0 = wl
            .vote(
                auth_ids[0].clone(),
                single_chain_votes(ForeignChain::Ethereum, &["alchemy"], 1),
                &tp(&participants, 2),
            )
            .unwrap();
        assert!(
            applied_p0.is_empty(),
            "first vote can't reach threshold alone"
        );
        assert!(stored_entry(&wl, ForeignChain::Ethereum).is_none());
        assert_eq!(pending_voter_count(&wl), 1);

        let applied_p1 = wl
            .vote(
                auth_ids[1].clone(),
                single_chain_votes(ForeignChain::Ethereum, &["alchemy"], 1),
                &tp(&participants, 2),
            )
            .unwrap();
        assert_eq!(applied_p1, vec![ForeignChain::Ethereum]);

        // Then
        let stored = stored_entry(&wl, ForeignChain::Ethereum).unwrap();
        assert_eq!(stored.providers.len(), 1);
        assert!(stored
            .providers
            .contains_key(&ProviderId("alchemy".to_string())));
        assert_eq!(stored.quorum, 1);
        assert_eq!(pending_voter_count(&wl), 0);
    }

    #[test]
    fn vote__should_canonicalize_provider_order_for_threshold_comparison() {
        // Two participants submit the same logical set in different orders.
        // Given
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();

        // When
        wl.vote(
            auth_ids[0].clone(),
            single_chain_votes(ForeignChain::Ethereum, &["alchemy", "ankr"], 1),
            &tp(&participants, 2),
        )
        .unwrap();
        wl.vote(
            auth_ids[1].clone(),
            single_chain_votes(ForeignChain::Ethereum, &["ankr", "alchemy"], 1),
            &tp(&participants, 2),
        )
        .unwrap();

        // Then
        let stored = stored_entry(&wl, ForeignChain::Ethereum).unwrap();
        assert_eq!(stored.providers.len(), 2);
    }

    #[test]
    fn vote__should_apply_chains_independently() {
        // Given
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();

        // When: both participants agree on Ethereum, disagree on Polygon.
        let applied_p0 = wl
            .vote(
                auth_ids[0].clone(),
                votes_from([
                    (ForeignChain::Ethereum, chain_entry(&["alchemy"], 1)),
                    (ForeignChain::Polygon, chain_entry(&["ankr"], 1)),
                ]),
                &tp(&participants, 2),
            )
            .unwrap();
        assert!(
            applied_p0.is_empty(),
            "first vote can't reach threshold alone"
        );
        let applied_p1 = wl
            .vote(
                auth_ids[1].clone(),
                votes_from([
                    (ForeignChain::Ethereum, chain_entry(&["alchemy"], 1)),
                    (ForeignChain::Polygon, chain_entry(&["infura"], 1)),
                ]),
                &tp(&participants, 2),
            )
            .unwrap();

        // Then: Ethereum applied; Polygon did not (different providers proposed).
        assert_eq!(applied_p1, vec![ForeignChain::Ethereum]);
        assert!(stored_entry(&wl, ForeignChain::Ethereum).is_some());
        assert!(stored_entry(&wl, ForeignChain::Polygon).is_none());
        // Pending should only contain Polygon votes (Ethereum was cleared on apply).
        for voter_set in wl.votes.pending.all().values() {
            for (_, chain) in voter_set {
                assert_eq!(*chain, ForeignChain::Polygon);
            }
        }
    }

    #[test]
    fn vote__should_overwrite_only_mentioned_chain_slots_on_recast() {
        // Given
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_ids[0].clone();
        wl.vote(
            p0.clone(),
            single_chain_votes(ForeignChain::Polygon, &["ankr"], 1),
            &tp(&participants, 2),
        )
        .unwrap();

        // When
        wl.vote(
            p0.clone(),
            single_chain_votes(ForeignChain::Ethereum, &["alchemy"], 1),
            &tp(&participants, 2),
        )
        .unwrap();

        // Then
        assert!(has_pending_vote(&wl, &(p0.clone(), ForeignChain::Polygon)));
        assert!(has_pending_vote(&wl, &(p0, ForeignChain::Ethereum)));
    }

    #[test]
    fn vote__should_overwrite_same_chain_slot_with_latest_proposal() {
        // Given: p0 has voted Polygon with providers=[alchemy], response quorum=1.
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_ids[0].clone();
        wl.vote(
            p0.clone(),
            single_chain_votes(ForeignChain::Polygon, &["alchemy"], 1),
            &tp(&participants, 2),
        )
        .unwrap();

        // When: p0 re-votes Polygon with a different proposal
        // (providers=[ankr, drpc], response quorum=2).
        wl.vote(
            p0.clone(),
            single_chain_votes(ForeignChain::Polygon, &["ankr", "drpc"], 2),
            &tp(&participants, 2),
        )
        .unwrap();

        // Then: exactly one pending row for (p0, Polygon), holding the SECOND proposal.
        // Since pending votes are hash-only, verify by comparing the stored
        // ProposalHash against the hash of the freshly-canonicalized expected entry.
        let voters_for_p0_polygon = wl
            .votes
            .pending
            .all()
            .into_iter()
            .filter(|(_, set)| set.contains(&(p0.clone(), ForeignChain::Polygon)))
            .count();
        assert_eq!(voters_for_p0_polygon, 1);

        let expected_entry: ChainEntry = chain_entry(&["ankr", "drpc"], 2).try_into().unwrap();
        let expected_hash = ProposalHash::from(expected_entry);
        let actual_hash = pending_proposal_hash_for(&wl, &(p0, ForeignChain::Polygon))
            .expect("expected pending row for (p0, Polygon)");
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn vote__should_replace_full_chain_state_on_apply() {
        // Given: chain currently holds [alchemy, ankr].
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        wl.vote(
            auth_ids[0].clone(),
            single_chain_votes(ForeignChain::Ethereum, &["alchemy", "ankr"], 1),
            &tp(&participants, 2),
        )
        .unwrap();
        wl.vote(
            auth_ids[1].clone(),
            single_chain_votes(ForeignChain::Ethereum, &["alchemy", "ankr"], 1),
            &tp(&participants, 2),
        )
        .unwrap();

        // When: both vote a new state [drpc] (alchemy + ankr both removed in one move).
        wl.vote(
            auth_ids[0].clone(),
            single_chain_votes(ForeignChain::Ethereum, &["drpc"], 1),
            &tp(&participants, 2),
        )
        .unwrap();
        wl.vote(
            auth_ids[1].clone(),
            single_chain_votes(ForeignChain::Ethereum, &["drpc"], 1),
            &tp(&participants, 2),
        )
        .unwrap();

        // Then: full snapshot replaced — only drpc remains.
        let stored = stored_entry(&wl, ForeignChain::Ethereum).unwrap();
        assert_eq!(stored.providers.len(), 1);
        assert!(stored
            .providers
            .contains_key(&ProviderId("drpc".to_string())));
    }

    #[test]
    fn vote__should_return_err_on_zero_quorum() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let err = wl
            .vote(
                auth_ids[0].clone(),
                single_chain_votes(ForeignChain::Ethereum, &["alchemy"], 0),
                &tp(&participants, 2),
            )
            .unwrap_err();
        assert_malformed(err, "quorum must be >= 1");
    }

    #[test]
    fn vote__should_return_err_on_quorum_exceeding_providers_len() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let err = wl
            .vote(
                auth_ids[0].clone(),
                single_chain_votes(ForeignChain::Ethereum, &["alchemy", "ankr"], 3),
                &tp(&participants, 2),
            )
            .unwrap_err();
        assert_malformed(err, "exceeds providers.len()");
    }

    #[test]
    fn vote__should_return_err_on_path_segment_with_slash() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let bad = (
            ProviderId("ankr".to_string()),
            ProviderConfig {
                base_url: "https://rpc.ankr.com".to_string(),
                auth_scheme: AuthScheme::None,
                chain_routing: ChainRouting::PathSegment {
                    segment: "eth/sepolia".to_string(),
                },
            },
        );
        let err = wl
            .vote(
                auth_ids[0].clone(),
                NonEmptyBTreeMap::new(
                    ForeignChain::Ethereum,
                    dtos::ChainEntry {
                        providers: NonEmptyBTreeMap::new(bad.0, bad.1),
                        quorum: 1,
                    },
                ),
                &tp(&participants, 2),
            )
            .unwrap_err();
        assert_malformed(err, "PathSegment");
    }

    #[test]
    fn vote__should_return_err_on_query_param_name_colliding_with_auth_query() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let bad = (
            ProviderId("drpc".to_string()),
            ProviderConfig {
                base_url: "https://lb.drpc.org/ogrpc".to_string(),
                auth_scheme: AuthScheme::Query {
                    name: "key".to_string(),
                },
                chain_routing: ChainRouting::QueryParam {
                    name: "key".to_string(),
                    value: "ethereum".to_string(),
                },
            },
        );
        let err = wl
            .vote(
                auth_ids[0].clone(),
                NonEmptyBTreeMap::new(
                    ForeignChain::Ethereum,
                    dtos::ChainEntry {
                        providers: NonEmptyBTreeMap::new(bad.0, bad.1),
                        quorum: 1,
                    },
                ),
                &tp(&participants, 2),
            )
            .unwrap_err();
        assert_malformed(err, "QueryParam.name collides");
    }

    #[test]
    fn vote__should_accept_non_colliding_query_param_and_auth_query() {
        // Given
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let drpc = || {
            (
                ProviderId("drpc".to_string()),
                ProviderConfig {
                    base_url: "https://lb.drpc.org/ogrpc".to_string(),
                    auth_scheme: AuthScheme::Query {
                        name: "dkey".to_string(),
                    },
                    chain_routing: ChainRouting::QueryParam {
                        name: "network".to_string(),
                        value: "ethereum".to_string(),
                    },
                },
            )
        };

        // When: two participants vote the same well-formed entry.
        let drpc_votes = || {
            let (id, config) = drpc();
            NonEmptyBTreeMap::new(
                ForeignChain::Ethereum,
                dtos::ChainEntry {
                    providers: NonEmptyBTreeMap::new(id, config),
                    quorum: 1,
                },
            )
        };
        wl.vote(auth_ids[0].clone(), drpc_votes(), &tp(&participants, 2))
            .unwrap();
        wl.vote(auth_ids[1].clone(), drpc_votes(), &tp(&participants, 2))
            .unwrap();

        // Then: applied, stored entry preserves the routing + auth shapes.
        let stored = stored_entry(&wl, ForeignChain::Ethereum).unwrap();
        assert_eq!(stored.providers.len(), 1);
        let (_, stored_drpc) = stored.providers.iter().next().unwrap();
        assert_matches!(
            stored_drpc.chain_routing,
            ChainRouting::QueryParam { ref name, .. } if name == "network"
        );
        assert_matches!(
            stored_drpc.auth_scheme,
            AuthScheme::Query { ref name } if name == "dkey"
        );
    }

    #[test]
    fn vote__should_not_count_stale_non_participant_votes() {
        // Given: 3 participants; p0 and p1 each vote the same proposal — chain
        // hasn't applied yet (count = 2, threshold = 3).
        let (participants, auth_ids) = setup(3);
        let mut wl = ForeignChainRpcWhitelist::default();
        wl.vote(
            auth_ids[0].clone(),
            single_chain_votes(ForeignChain::Ethereum, &["alchemy"], 1),
            &tp(&participants, 3),
        )
        .unwrap();
        wl.vote(
            auth_ids[1].clone(),
            single_chain_votes(ForeignChain::Ethereum, &["alchemy"], 1),
            &tp(&participants, 3),
        )
        .unwrap();
        assert!(stored_entry(&wl, ForeignChain::Ethereum).is_none());

        // When: the participant set shrinks to drop p0 and p1, but
        // `retain` is NOT called (simulating a missed `clean_tee_status`).
        // p2 (still a participant in the smaller set) casts the same vote.
        let smaller = participants.subset(2..3);
        let applied = wl
            .vote(
                auth_ids[2].clone(),
                single_chain_votes(ForeignChain::Ethereum, &["alchemy"], 1),
                &tp(&smaller, 3),
            )
            .unwrap();

        // Then: chain still does NOT apply because p0/p1's stale rows are
        // filtered out of the count_for predicate — only p2's vote (count = 1)
        // is counted against threshold = 3.
        assert!(applied.is_empty());
        assert!(stored_entry(&wl, ForeignChain::Ethereum).is_none());
    }

    #[test]
    fn clean_non_participant_votes__should_drop_stale_votes() {
        // Given
        let (participants, auth_ids) = setup(3);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_ids[0].clone();
        let p1 = auth_ids[1].clone();
        wl.vote(
            p0.clone(),
            single_chain_votes(ForeignChain::Ethereum, &["alchemy"], 1),
            &tp(&participants, 3),
        )
        .unwrap();
        wl.vote(
            p1.clone(),
            single_chain_votes(ForeignChain::Polygon, &["ankr"], 1),
            &tp(&participants, 3),
        )
        .unwrap();

        // When
        let smaller = participants.subset(1..3);
        wl.votes.retain(&smaller);

        // Then
        assert!(!has_pending_vote(&wl, &(p0, ForeignChain::Ethereum)));
        assert!(has_pending_vote(&wl, &(p1, ForeignChain::Polygon)));
    }

    // Direct tests for `TryFrom<dtos::ChainEntry> for ChainEntry` — the validation
    // step that gates a vote's payload before it ever reaches `Votes<V>::vote`.
    // These complement the `vote__should_return_err_on_*` tests above, which cover
    // the same paths but through the full `ForeignChainRpcWhitelist::vote` entry point.

    #[test]
    fn validate_chain_entry__should_reject_zero_quorum() {
        // Given
        let dto = chain_entry(&["alchemy"], 0);

        // When
        let err = ChainEntry::try_from(dto).unwrap_err();

        // Then
        assert_matches!(err, ChainEntryValidationError::ZeroQuorum);
    }

    #[test]
    fn validate_chain_entry__should_reject_quorum_exceeding_providers_count() {
        // Given
        let dto = chain_entry(&["alchemy"], 2);

        // When
        let err = ChainEntry::try_from(dto).unwrap_err();

        // Then
        assert_matches!(
            err,
            ChainEntryValidationError::QuorumExceedsProviders {
                quorum: 2,
                providers_len: 1,
            }
        );
    }

    #[test]
    fn validate_chain_entry__should_reject_path_segment_containing_slash() {
        // Given
        let dto = dtos::ChainEntry {
            providers: NonEmptyBTreeMap::new(
                ProviderId("ankr".to_string()),
                ProviderConfig {
                    base_url: "https://rpc.ankr.com".to_string(),
                    auth_scheme: AuthScheme::None,
                    chain_routing: ChainRouting::PathSegment {
                        segment: "eth/sepolia".to_string(),
                    },
                },
            ),
            quorum: 1,
        };

        // When
        let err = ChainEntry::try_from(dto).unwrap_err();

        // Then
        assert_matches!(
            err,
            ChainEntryValidationError::PathSegmentContainsSlash { provider_id } if provider_id == "ankr"
        );
    }

    #[test]
    fn validate_chain_entry__should_reject_query_param_colliding_with_auth_query() {
        // Given
        let dto = dtos::ChainEntry {
            providers: NonEmptyBTreeMap::new(
                ProviderId("drpc".to_string()),
                ProviderConfig {
                    base_url: "https://lb.drpc.org/ogrpc".to_string(),
                    auth_scheme: AuthScheme::Query {
                        name: "key".to_string(),
                    },
                    chain_routing: ChainRouting::QueryParam {
                        name: "key".to_string(),
                        value: "ethereum".to_string(),
                    },
                },
            ),
            quorum: 1,
        };

        // When
        let err = ChainEntry::try_from(dto).unwrap_err();

        // Then
        assert_matches!(
            err,
            ChainEntryValidationError::QueryParamCollidesWithAuth { provider_id, name }
                if provider_id == "drpc" && name == "key"
        );
    }

    #[test]
    fn validate_chain_entry__should_accept_well_formed_entry() {
        // Given
        let dto = chain_entry(&["alchemy", "ankr"], 2);

        // When / Then
        ChainEntry::try_from(dto).expect("well-formed entry should validate");
    }
}
