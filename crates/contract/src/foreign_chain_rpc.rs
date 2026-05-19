//! On-chain whitelist of RPC providers for foreign-chain transaction validation.
//! Each `ChainVote` is a per-chain snapshot (provider list + RPC response quorum); the
//! chain's state is replaced once the protocol's signing threshold of participants
//! holds the same proposal.

use std::collections::BTreeMap;

use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, ChainVote, ForeignChain, ProviderEntry,
};
use near_sdk::near;

use crate::errors::{Error, InvalidParameters};
use crate::primitives::{key_state::AuthenticatedParticipantId, participants::Participants};

#[near(serializers=[borsh])]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct AllowedProviders {
    entries: BTreeMap<ForeignChain, ChainEntry>,
}

impl AllowedProviders {
    fn replace(&mut self, chain: ForeignChain, entry: ChainEntry) {
        self.entries.insert(chain, entry);
    }

    /// Snapshot of the whole whitelist. Cloned so the caller can ship it across the
    /// contract boundary without holding a borrow on `self`.
    pub fn snapshot(&self) -> BTreeMap<ForeignChain, ChainEntry> {
        self.entries.clone()
    }
}

// Flat `(participant, chain)` key (rather than a nested map) halves the BTreeMap
// monomorphizations the contract WASM has to pay for.
#[near(serializers=[borsh])]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProviderVotes {
    pub pending: BTreeMap<(AuthenticatedParticipantId, ForeignChain), ChainEntry>,
}

impl ProviderVotes {
    /// Count pending votes matching `target` for `chain`, filtering out any row whose
    /// participant is no longer in `current`. The filter guards against `clean_tee_status`
    /// not having run after a resharing — stale rows can sit in `pending` until that
    /// sweep, and we don't want them counting toward the gate.
    fn count_for_chain(
        &self,
        chain: ForeignChain,
        target: &ChainEntry,
        current: &Participants,
    ) -> u64 {
        self.pending
            .iter()
            .filter(|((p, c), entry)| {
                *c == chain
                    && *entry == target
                    && current.is_participant_given_participant_id(&p.get())
            })
            .count() as u64
    }

    fn clear_chain(&mut self, chain: ForeignChain) {
        self.pending.retain(|(_, c), _| *c != chain);
    }

    pub fn retain_only(&mut self, current: &Participants) {
        self.pending
            .retain(|(p, _), _| current.is_participant_given_participant_id(&p.get()));
    }
}

#[near(serializers=[borsh])]
#[derive(Debug, Default)]
pub struct ForeignChainRpcWhitelist {
    pub(crate) entries: AllowedProviders,
    pub(crate) votes: ProviderVotes,
}

impl ForeignChainRpcWhitelist {
    /// Record `participant`'s votes; replace each chain's state once `threshold`
    /// participants hold the same canonical `(providers, threshold)` pair. Returns
    /// the chains applied this call.
    pub fn vote(
        &mut self,
        participant: AuthenticatedParticipantId,
        votes: Vec<ChainVote>,
        threshold: u64,
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
            threshold: response_quorum,
        } in votes
        {
            if chains_in_batch.contains(&chain) {
                return Err(InvalidParameters::MalformedPayload {
                    reason: format!("duplicate chain {chain:?} in vote batch"),
                }
                .into());
            }
            chains_in_batch.push(chain);
            let entry = canonicalize(providers, response_quorum)?;
            self.votes
                .pending
                .insert((participant.clone(), chain), entry.clone());
            if self.votes.count_for_chain(chain, &entry, participants) >= threshold {
                self.entries.replace(chain, entry);
                self.votes.clear_chain(chain);
                applied.push(chain);
            }
        }
        Ok(applied)
    }
}

/// Sort by `provider_id` for order-independent equality at threshold-check time.
/// Errors on: empty `providers`, `threshold == 0` or exceeding `providers.len()`,
/// duplicate `provider_id` within the vote, `PathSegment` containing a literal `/`,
/// or `QueryParam` whose name collides with the entry's `AuthScheme::Query` name.
fn canonicalize(mut providers: Vec<ProviderEntry>, threshold: u64) -> Result<ChainEntry, Error> {
    if providers.is_empty() {
        return Err(InvalidParameters::MalformedPayload {
            reason: "ChainVote.providers must not be empty".to_string(),
        }
        .into());
    }
    if threshold == 0 {
        return Err(InvalidParameters::MalformedPayload {
            reason: "ChainVote.threshold must be >= 1".to_string(),
        }
        .into());
    }
    let providers_len = providers.len() as u64;
    if threshold > providers_len {
        return Err(InvalidParameters::MalformedPayload {
            reason: format!(
                "ChainVote.threshold ({threshold}) exceeds providers.len() ({providers_len}) — RPC response quorum is unreachable",
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
    Ok(ChainEntry {
        providers,
        threshold,
    })
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

    fn chain_vote(chain: ForeignChain, ids: &[&str], threshold: u64) -> ChainVote {
        ChainVote {
            chain,
            providers: ids.iter().map(|id| provider(id)).collect(),
            threshold,
        }
    }

    fn auth_as(
        participants: &crate::primitives::participants::Participants,
        participant_index: usize,
    ) -> AuthenticatedParticipantId {
        let (account_id, _, _) = &participants.participants()[participant_index];
        let mut ctx = VMContextBuilder::new();
        ctx.signer_account_id(account_id.clone());
        testing_env!(ctx.build());
        AuthenticatedParticipantId::new(participants).unwrap()
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

    #[test]
    fn vote__should_apply_chain_when_all_participants_match() {
        // Given
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();

        // When
        let p0 = auth_as(&participants, 0);
        let applied_p0 = wl
            .vote(
                p0,
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
        assert_eq!(wl.votes.pending.len(), 1);

        let p1 = auth_as(&participants, 1);
        let applied_p1 = wl
            .vote(
                p1,
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
            stored.providers[0].provider_id,
            ProviderId("alchemy".to_string())
        );
        assert_eq!(stored.threshold, 1);
        assert!(wl.votes.pending.is_empty());
    }

    #[test]
    fn vote__should_canonicalize_provider_order_for_threshold_comparison() {
        // Two participants submit the same logical set in different orders.
        // Given
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();

        // When
        let p0 = auth_as(&participants, 0);
        wl.vote(
            p0,
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy", "ankr"], 1)],
            2,
            &participants,
        )
        .unwrap();
        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
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
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();

        // When: both participants agree on Ethereum, disagree on Polygon.
        let p0 = auth_as(&participants, 0);
        let applied_p0 = wl
            .vote(
                p0,
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
        let p1 = auth_as(&participants, 1);
        let applied_p1 = wl
            .vote(
                p1,
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
        for (_, chain) in wl.votes.pending.keys() {
            assert_eq!(*chain, ForeignChain::Polygon);
        }
    }

    #[test]
    fn vote__should_overwrite_only_mentioned_chain_slots_on_recast() {
        // Given
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
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
        assert!(wl
            .votes
            .pending
            .contains_key(&(p0.clone(), ForeignChain::Polygon)));
        assert!(wl.votes.pending.contains_key(&(p0, ForeignChain::Ethereum)));
    }

    #[test]
    fn vote__should_overwrite_same_chain_slot_with_latest_proposal() {
        // Given: p0 has voted Polygon with providers=[alchemy], response quorum=1.
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
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

        // Then: only one pending row for (p0, Polygon), holding the second proposal.
        assert_eq!(
            wl.votes
                .pending
                .keys()
                .filter(|(p, c)| *p == p0 && *c == ForeignChain::Polygon)
                .count(),
            1,
        );
        let slot = wl.votes.pending.get(&(p0, ForeignChain::Polygon)).unwrap();
        assert_eq!(slot.providers.len(), 2);
        assert_eq!(
            slot.providers[0].provider_id,
            ProviderId("ankr".to_string())
        );
        assert_eq!(
            slot.providers[1].provider_id,
            ProviderId("drpc".to_string())
        );
        assert_eq!(slot.threshold, 2);
    }

    #[test]
    fn vote__should_replace_full_chain_state_on_apply() {
        // Given: chain currently holds [alchemy, ankr].
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        wl.vote(
            p0,
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy", "ankr"], 1)],
            2,
            &participants,
        )
        .unwrap();
        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy", "ankr"], 1)],
            2,
            &participants,
        )
        .unwrap();

        // When: both vote a new state [drpc] (alchemy + ankr both removed in one move).
        let p0 = auth_as(&participants, 0);
        wl.vote(
            p0,
            vec![chain_vote(ForeignChain::Ethereum, &["drpc"], 1)],
            2,
            &participants,
        )
        .unwrap();
        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
            vec![chain_vote(ForeignChain::Ethereum, &["drpc"], 1)],
            2,
            &participants,
        )
        .unwrap();

        // Then: full snapshot replaced — only drpc remains.
        let stored = stored_entry(&wl, ForeignChain::Ethereum).unwrap();
        assert_eq!(stored.providers.len(), 1);
        assert_eq!(
            stored.providers[0].provider_id,
            ProviderId("drpc".to_string())
        );
    }

    #[test]
    fn vote__should_return_err_on_empty_batch() {
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        let err = wl.vote(p0, vec![], 2, &participants).unwrap_err();
        assert_malformed(err, "non-empty");
    }

    #[test]
    fn vote__should_return_err_on_duplicate_chain_in_batch() {
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        let err = wl
            .vote(
                p0,
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
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        let err = wl
            .vote(
                p0,
                vec![ChainVote {
                    chain: ForeignChain::Ethereum,
                    providers: vec![],
                    threshold: 1,
                }],
                2,
                &participants,
            )
            .unwrap_err();
        assert_malformed(err, "providers must not be empty");
    }

    #[test]
    fn vote__should_return_err_on_zero_threshold() {
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        let err = wl
            .vote(
                p0,
                vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 0)],
                2,
                &participants,
            )
            .unwrap_err();
        assert_malformed(err, "threshold must be >= 1");
    }

    #[test]
    fn vote__should_return_err_on_threshold_exceeding_providers_len() {
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        let err = wl
            .vote(
                p0,
                vec![chain_vote(ForeignChain::Ethereum, &["alchemy", "ankr"], 3)],
                2,
                &participants,
            )
            .unwrap_err();
        assert_malformed(err, "exceeds providers.len()");
    }

    #[test]
    fn vote__should_return_err_on_duplicate_provider_in_chain_vote() {
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        let err = wl
            .vote(
                p0,
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
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
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
                p0,
                vec![ChainVote {
                    chain: ForeignChain::Ethereum,
                    providers: vec![bad],
                    threshold: 1,
                }],
                2,
                &participants,
            )
            .unwrap_err();
        assert_malformed(err, "PathSegment");
    }

    #[test]
    fn vote__should_return_err_on_query_param_name_colliding_with_auth_query() {
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
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
                p0,
                vec![ChainVote {
                    chain: ForeignChain::Ethereum,
                    providers: vec![bad],
                    threshold: 1,
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
        let participants = gen_participants(2);
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
        let p0 = auth_as(&participants, 0);
        wl.vote(
            p0,
            vec![ChainVote {
                chain: ForeignChain::Ethereum,
                providers: vec![drpc()],
                threshold: 1,
            }],
            2,
            &participants,
        )
        .unwrap();
        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
            vec![ChainVote {
                chain: ForeignChain::Ethereum,
                providers: vec![drpc()],
                threshold: 1,
            }],
            2,
            &participants,
        )
        .unwrap();

        // Then: applied, stored entry preserves the routing + auth shapes.
        let stored = stored_entry(&wl, ForeignChain::Ethereum).unwrap();
        assert_eq!(stored.providers.len(), 1);
        assert_matches!(
            stored.providers[0].chain_routing,
            ChainRouting::QueryParam { ref name, .. } if name == "network"
        );
        assert_matches!(
            stored.providers[0].auth_scheme,
            AuthScheme::Query { ref name } if name == "dkey"
        );
    }

    #[test]
    fn vote__should_not_count_stale_non_participant_votes() {
        // Given: 3 participants; p0 and p1 each vote the same proposal — chain
        // hasn't applied yet (count = 2, threshold = 3).
        let participants = gen_participants(3);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        wl.vote(
            p0,
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
            3,
            &participants,
        )
        .unwrap();
        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
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
        let p2 = auth_as(&participants, 2);
        let applied = wl
            .vote(
                p2,
                vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
                3,
                &smaller,
            )
            .unwrap();

        // Then: chain still does NOT apply because p0/p1's stale rows are
        // filtered out of count_for_chain — only p2's vote (count = 1) is
        // counted against threshold = 3.
        assert!(applied.is_empty());
        assert!(stored_entry(&wl, ForeignChain::Ethereum).is_none());
    }

    #[test]
    fn clean_non_participant_votes__should_drop_stale_votes() {
        // Given
        let participants = gen_participants(3);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        let p1 = auth_as(&participants, 1);
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
        assert!(!wl.votes.pending.contains_key(&(p0, ForeignChain::Ethereum)));
        assert!(wl.votes.pending.contains_key(&(p1, ForeignChain::Polygon)));
    }
}
