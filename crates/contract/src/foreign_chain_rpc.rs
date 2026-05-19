//! On-chain whitelist of RPC providers for foreign-chain transaction validation.
//! Each `ChainVote` is a per-chain snapshot (provider list + RPC response quorum); the
//! chain's state is replaced once the protocol's signing threshold of participants
//! holds the same proposal.
//!
//! Pending votes are stored hash-only via [`Votes<V>`][crate::primitives::votes::Votes],
//! which is backed by lazy-loaded `IterableMap`s. The applied state lives in
//! [`AllowedProviders`] (also `IterableMap`-backed) and retains the full `ChainEntry`
//! content. The tipping voter always brings the proposal in as a call argument, so the
//! applied state is reconstructable from the call that crosses threshold — pending
//! state can stay hash-only without losing data on apply.

use std::collections::BTreeMap;

use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, ChainVote, ForeignChain, ProviderEntry,
};
use near_sdk::near;
use near_sdk::store::IterableMap;

use crate::errors::{ConversionError, Error, InvalidParameters};
use crate::primitives::votes::{ProposalHash, ProposalHashEncoding, Votes};
use crate::primitives::{key_state::AuthenticatedParticipantId, participants::Participants};
use crate::storage_keys::StorageKey;

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

    /// Snapshot of the whole whitelist. Collected so the caller can ship it across
    /// the contract boundary without holding a borrow on `self`.
    pub fn snapshot(&self) -> BTreeMap<ForeignChain, ChainEntry> {
        self.entries.iter().map(|(c, e)| (*c, e.clone())).collect()
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
    pub fn retain_only(&mut self, current: &Participants) {
        self.pending
            .retain_votes(|(p, _)| current.is_participant_given_participant_id(&p.get()));
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
    /// that gates threshold signatures), not to be confused with `ChainVote.quorum`,
    /// which is the RPC response quorum nodes use when querying the listed providers.
    /// Returns the chains applied this call.
    pub fn vote(
        &mut self,
        participant: AuthenticatedParticipantId,
        votes: Vec<ChainVote>,
        protocol_threshold: u64,
        participants: &Participants,
    ) -> Result<Vec<ForeignChain>, Error> {
        if votes.is_empty() {
            return Err(InvalidParameters::MalformedPayload {
                reason: "vote batch must be non-empty".to_string(),
            }
            .into());
        }
        let mut chains_in_batch: Vec<ForeignChain> = Vec::with_capacity(votes.len());
        let mut applied: Vec<ForeignChain> = Vec::new();
        for ChainVote {
            chain,
            providers,
            quorum,
        } in votes
        {
            if chains_in_batch.contains(&chain) {
                return Err(InvalidParameters::MalformedPayload {
                    reason: format!("duplicate chain {chain:?} in vote batch"),
                }
                .into());
            }
            chains_in_batch.push(chain);
            let entry = canonicalize(providers, quorum)?;
            let hash = ProposalHash::from(entry.clone());
            // Scope the borrow on `self.votes.pending.vote` so we can mutate
            // `self.entries`/`self.votes.pending` after `count`.
            let count_usize = {
                let voter_set = self.votes.pending.vote((participant.clone(), chain), hash);
                voter_set.count_for(|(p, c)| {
                    *c == chain && participants.is_participant_given_participant_id(&p.get())
                })
            };
            let count =
                u64::try_from(count_usize).map_err(|e| ConversionError::DataConversion {
                    reason: format!("vote count {count_usize} does not fit in u64: {e}"),
                })?;
            if count >= protocol_threshold {
                self.entries.replace(chain, entry);
                // Drop ALL pending rows for this chain regardless of which proposal
                // they held — matches the previous `clear_chain` semantics.
                self.votes.pending.retain_votes(|(_, c)| *c != chain);
                applied.push(chain);
            }
        }
        Ok(applied)
    }
}

/// Sort by `provider_id` for order-independent equality at protocol-threshold-check time.
/// `quorum` is the RPC response quorum (`ChainVote.quorum`), not the protocol signing
/// threshold. Errors on: empty `providers`, `quorum == 0` or exceeding `providers.len()`,
/// duplicate `provider_id` within the vote, `PathSegment` containing a literal `/`,
/// or `QueryParam` whose name collides with the entry's `AuthScheme::Query` name.
fn canonicalize(mut providers: Vec<ProviderEntry>, quorum: u64) -> Result<ChainEntry, Error> {
    if providers.is_empty() {
        return Err(InvalidParameters::MalformedPayload {
            reason: "ChainVote.providers must not be empty".to_string(),
        }
        .into());
    }
    if quorum == 0 {
        return Err(InvalidParameters::MalformedPayload {
            reason: "ChainVote.quorum must be >= 1".to_string(),
        }
        .into());
    }
    let providers_len =
        u64::try_from(providers.len()).map_err(|e| ConversionError::DataConversion {
            reason: format!(
                "providers.len() {} does not fit in u64: {e}",
                providers.len()
            ),
        })?;
    if quorum > providers_len {
        return Err(InvalidParameters::MalformedPayload {
            reason: format!(
                "ChainVote.quorum ({quorum}) exceeds providers.len() ({providers_len}) — RPC response quorum is unreachable",
            ),
        }
        .into());
    }
    providers.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));
    if providers
        .windows(2)
        .any(|w| w[0].provider_id == w[1].provider_id)
    {
        return Err(InvalidParameters::MalformedPayload {
            reason:
                "duplicate provider_id within a single ChainVote — each provider may appear at most once per chain"
                    .to_string(),
        }
        .into());
    }
    for p in &providers {
        if let ChainRouting::PathSegment { segment } = &p.chain_routing {
            if segment.contains('/') {
                return Err(InvalidParameters::MalformedPayload {
                    reason: format!(
                        "ChainRouting::PathSegment.segment for provider_id {:?} must not contain '/'",
                        p.provider_id.0
                    ),
                }
                .into());
            }
        }
        if let (
            ChainRouting::QueryParam {
                name: routing_name, ..
            },
            AuthScheme::Query { name: auth_name },
        ) = (&p.chain_routing, &p.auth_scheme)
        {
            if routing_name == auth_name {
                return Err(InvalidParameters::MalformedPayload {
                    reason: format!(
                        "ChainRouting::QueryParam.name collides with AuthScheme::Query.name {:?} for provider_id {:?}",
                        auth_name, p.provider_id.0
                    ),
                }
                .into());
            }
        }
    }
    let providers = NonEmptyVec::try_from(providers).expect("providers non-empty (checked above)");
    Ok(ChainEntry { providers, quorum })
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::{key_state::AuthenticatedParticipantId, test_utils::gen_participants};
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types::{AuthScheme, ChainRouting, ProviderId};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn provider(id: &str) -> ProviderEntry {
        ProviderEntry {
            provider_id: ProviderId(id.to_string()),
            base_url: format!("https://{id}.example.com"),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::Embedded,
        }
    }

    fn chain_vote(chain: ForeignChain, ids: &[&str], quorum: u64) -> ChainVote {
        ChainVote {
            chain,
            providers: ids.iter().map(|id| provider(id)).collect(),
            quorum,
        }
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

    fn stored_entry(wl: &ForeignChainRpcWhitelist, chain: ForeignChain) -> Option<ChainEntry> {
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
                vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
                2,
                &participants,
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
                vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
                2,
                &participants,
            )
            .unwrap();
        assert_eq!(applied_p1, vec![ForeignChain::Ethereum]);

        // Then
        let stored = stored_entry(&wl, ForeignChain::Ethereum).unwrap();
        assert_eq!(stored.providers.len(), 1);
        assert_eq!(
            stored.providers.first().provider_id,
            ProviderId("alchemy".to_string())
        );
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
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy", "ankr"], 1)],
            2,
            &participants,
        )
        .unwrap();
        wl.vote(
            auth_ids[1].clone(),
            vec![chain_vote(ForeignChain::Ethereum, &["ankr", "alchemy"], 1)],
            2,
            &participants,
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
                vec![
                    chain_vote(ForeignChain::Ethereum, &["alchemy"], 1),
                    chain_vote(ForeignChain::Polygon, &["ankr"], 1),
                ],
                2,
                &participants,
            )
            .unwrap();
        assert!(
            applied_p0.is_empty(),
            "first vote can't reach threshold alone"
        );
        let applied_p1 = wl
            .vote(
                auth_ids[1].clone(),
                vec![
                    chain_vote(ForeignChain::Ethereum, &["alchemy"], 1),
                    chain_vote(ForeignChain::Polygon, &["infura"], 1),
                ],
                2,
                &participants,
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
            vec![chain_vote(ForeignChain::Polygon, &["ankr"], 1)],
            2,
            &participants,
        )
        .unwrap();

        // When
        wl.vote(
            p0.clone(),
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
            2,
            &participants,
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
            vec![chain_vote(ForeignChain::Polygon, &["alchemy"], 1)],
            2,
            &participants,
        )
        .unwrap();

        // When: p0 re-votes Polygon with a different proposal
        // (providers=[ankr, drpc], response quorum=2).
        wl.vote(
            p0.clone(),
            vec![chain_vote(ForeignChain::Polygon, &["ankr", "drpc"], 2)],
            2,
            &participants,
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

        let expected_entry = canonicalize(vec![provider("ankr"), provider("drpc")], 2).unwrap();
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
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy", "ankr"], 1)],
            2,
            &participants,
        )
        .unwrap();
        wl.vote(
            auth_ids[1].clone(),
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy", "ankr"], 1)],
            2,
            &participants,
        )
        .unwrap();

        // When: both vote a new state [drpc] (alchemy + ankr both removed in one move).
        wl.vote(
            auth_ids[0].clone(),
            vec![chain_vote(ForeignChain::Ethereum, &["drpc"], 1)],
            2,
            &participants,
        )
        .unwrap();
        wl.vote(
            auth_ids[1].clone(),
            vec![chain_vote(ForeignChain::Ethereum, &["drpc"], 1)],
            2,
            &participants,
        )
        .unwrap();

        // Then: full snapshot replaced — only drpc remains.
        let stored = stored_entry(&wl, ForeignChain::Ethereum).unwrap();
        assert_eq!(stored.providers.len(), 1);
        assert_eq!(
            stored.providers.first().provider_id,
            ProviderId("drpc".to_string())
        );
    }

    #[test]
    fn vote__should_return_err_on_empty_batch() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let err = wl
            .vote(auth_ids[0].clone(), vec![], 2, &participants)
            .unwrap_err();
        assert_malformed(err, "non-empty");
    }

    #[test]
    fn vote__should_return_err_on_duplicate_chain_in_batch() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let err = wl
            .vote(
                auth_ids[0].clone(),
                vec![
                    chain_vote(ForeignChain::Ethereum, &["alchemy"], 1),
                    chain_vote(ForeignChain::Ethereum, &["ankr"], 1),
                ],
                2,
                &participants,
            )
            .unwrap_err();
        assert_malformed(err, "duplicate chain");
    }

    #[test]
    fn vote__should_return_err_on_empty_providers() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let err = wl
            .vote(
                auth_ids[0].clone(),
                vec![ChainVote {
                    chain: ForeignChain::Ethereum,
                    providers: vec![],
                    quorum: 1,
                }],
                2,
                &participants,
            )
            .unwrap_err();
        assert_malformed(err, "providers must not be empty");
    }

    #[test]
    fn vote__should_return_err_on_zero_quorum() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let err = wl
            .vote(
                auth_ids[0].clone(),
                vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 0)],
                2,
                &participants,
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
                vec![chain_vote(ForeignChain::Ethereum, &["alchemy", "ankr"], 3)],
                2,
                &participants,
            )
            .unwrap_err();
        assert_malformed(err, "exceeds providers.len()");
    }

    #[test]
    fn vote__should_return_err_on_duplicate_provider_in_chain_vote() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let err = wl
            .vote(
                auth_ids[0].clone(),
                vec![chain_vote(
                    ForeignChain::Ethereum,
                    &["alchemy", "alchemy"],
                    1,
                )],
                2,
                &participants,
            )
            .unwrap_err();
        assert_malformed(err, "duplicate provider_id");
    }

    #[test]
    fn vote__should_return_err_on_path_segment_with_slash() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let bad = ProviderEntry {
            provider_id: ProviderId("ankr".to_string()),
            base_url: "https://rpc.ankr.com".to_string(),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::PathSegment {
                segment: "eth/sepolia".to_string(),
            },
        };
        let err = wl
            .vote(
                auth_ids[0].clone(),
                vec![ChainVote {
                    chain: ForeignChain::Ethereum,
                    providers: vec![bad],
                    quorum: 1,
                }],
                2,
                &participants,
            )
            .unwrap_err();
        assert_malformed(err, "PathSegment");
    }

    #[test]
    fn vote__should_return_err_on_query_param_name_colliding_with_auth_query() {
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let bad = ProviderEntry {
            provider_id: ProviderId("drpc".to_string()),
            base_url: "https://lb.drpc.org/ogrpc".to_string(),
            auth_scheme: AuthScheme::Query {
                name: "key".to_string(),
            },
            chain_routing: ChainRouting::QueryParam {
                name: "key".to_string(),
                value: "ethereum".to_string(),
            },
        };
        let err = wl
            .vote(
                auth_ids[0].clone(),
                vec![ChainVote {
                    chain: ForeignChain::Ethereum,
                    providers: vec![bad],
                    quorum: 1,
                }],
                2,
                &participants,
            )
            .unwrap_err();
        assert_malformed(err, "QueryParam.name collides");
    }

    #[test]
    fn vote__should_accept_non_colliding_query_param_and_auth_query() {
        // Given
        let (participants, auth_ids) = setup(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let drpc = || ProviderEntry {
            provider_id: ProviderId("drpc".to_string()),
            base_url: "https://lb.drpc.org/ogrpc".to_string(),
            auth_scheme: AuthScheme::Query {
                name: "dkey".to_string(),
            },
            chain_routing: ChainRouting::QueryParam {
                name: "network".to_string(),
                value: "ethereum".to_string(),
            },
        };

        // When: two participants vote the same well-formed entry.
        wl.vote(
            auth_ids[0].clone(),
            vec![ChainVote {
                chain: ForeignChain::Ethereum,
                providers: vec![drpc()],
                quorum: 1,
            }],
            2,
            &participants,
        )
        .unwrap();
        wl.vote(
            auth_ids[1].clone(),
            vec![ChainVote {
                chain: ForeignChain::Ethereum,
                providers: vec![drpc()],
                quorum: 1,
            }],
            2,
            &participants,
        )
        .unwrap();

        // Then: applied, stored entry preserves the routing + auth shapes.
        let stored = stored_entry(&wl, ForeignChain::Ethereum).unwrap();
        assert_eq!(stored.providers.len(), 1);
        assert_matches!(
            stored.providers.first().chain_routing,
            ChainRouting::QueryParam { ref name, .. } if name == "network"
        );
        assert_matches!(
            stored.providers.first().auth_scheme,
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
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
            3,
            &participants,
        )
        .unwrap();
        wl.vote(
            auth_ids[1].clone(),
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
            3,
            &participants,
        )
        .unwrap();
        assert!(stored_entry(&wl, ForeignChain::Ethereum).is_none());

        // When: the participant set shrinks to drop p0 and p1, but
        // `retain_only` is NOT called (simulating a missed `clean_tee_status`).
        // p2 (still a participant in the smaller set) casts the same vote.
        let smaller = participants.subset(2..3);
        let applied = wl
            .vote(
                auth_ids[2].clone(),
                vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
                3,
                &smaller,
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
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
            3,
            &participants,
        )
        .unwrap();
        wl.vote(
            p1.clone(),
            vec![chain_vote(ForeignChain::Polygon, &["ankr"], 1)],
            3,
            &participants,
        )
        .unwrap();

        // When
        let smaller = participants.subset(1..3);
        wl.votes.retain_only(&smaller);

        // Then
        assert!(!has_pending_vote(&wl, &(p0, ForeignChain::Ethereum)));
        assert!(has_pending_vote(&wl, &(p1, ForeignChain::Polygon)));
    }
}
