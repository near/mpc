//! On-chain whitelist of RPC providers for foreign-chain transaction validation.
//!
//! Each per-chain `ChainVote` proposes the chain's complete state — its full provider
//! list and the RPC response quorum nodes should use when querying. The chain's stored
//! state is replaced wholesale once the protocol's signing threshold of participants has
//! cast the same `(providers, threshold)` pair. The whitelist is not exposed via a view
//! fn — node-side code reads contract state directly via `view_state` borsh blobs, and a
//! JSON view fn would push WASM past the transaction-size cap.

use std::collections::BTreeMap;

use near_mpc_contract_interface::types::{ChainVote, ForeignChain, ProviderEntry};
use near_sdk::near;

use crate::errors::{Error, InvalidParameters};
use crate::primitives::{key_state::AuthenticatedParticipantId, participants::Participants};

/// Stored state for one chain: the canonical (sorted) provider list and the RPC
/// response quorum to use when querying.
#[near(serializers=[borsh])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainEntry {
    pub providers: Vec<ProviderEntry>,
    pub threshold: u64,
}

#[near(serializers=[borsh])]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct AllowedProviders {
    entries: BTreeMap<ForeignChain, ChainEntry>,
}

impl AllowedProviders {
    fn replace(&mut self, chain: ForeignChain, entry: ChainEntry) {
        self.entries.insert(chain, entry);
    }

    #[cfg(test)]
    pub fn get(&self, chain: ForeignChain) -> Option<&ChainEntry> {
        self.entries.get(&chain)
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
    fn count_for_chain(&self, chain: ForeignChain, target: &ChainEntry) -> u64 {
        self.pending
            .iter()
            .filter(|((_, c), entry)| *c == chain && *entry == target)
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
    /// Record `participant`'s votes and apply any chain whose count of participants
    /// holding the same canonical `(providers, threshold)` pair reaches `threshold`
    /// (the protocol's signing threshold, supplied by the caller — same gate as
    /// `verify_tee` and `vote_add_os_measurement`). Chains the participant didn't touch
    /// in `votes` keep their prior slot. Returns the chains whose threshold was reached
    /// and applied this call; chains still pending are absent from the returned `Vec`.
    /// Returns `InvalidParameters::MalformedPayload` on an empty batch, a duplicate
    /// `chain` within the batch, or a duplicate `provider_id` within any single
    /// `ChainVote.providers`.
    pub fn vote(
        &mut self,
        participant: AuthenticatedParticipantId,
        votes: Vec<ChainVote>,
        threshold: u64,
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
            if self.votes.count_for_chain(chain, &entry) >= threshold {
                self.entries.replace(chain, entry);
                self.votes.clear_chain(chain);
                applied.push(chain);
            }
        }
        Ok(applied)
    }
}

/// Sort providers by `provider_id` so two participants who submitted the same logical
/// set in different orders compare equal at threshold-check time. Returns an error on a
/// duplicate `provider_id` within a single per-chain vote — same provider listed twice
/// for the same chain is unambiguously malformed.
fn canonicalize(mut providers: Vec<ProviderEntry>, threshold: u64) -> Result<ChainEntry, Error> {
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

    #[test]
    fn vote__should_apply_chain_when_all_participants_match() {
        // Given
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();

        // When
        let p0 = auth_as(&participants, 0);
        wl.vote(
            p0,
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
            2,
        )
        .unwrap();
        assert!(wl.entries.get(ForeignChain::Ethereum).is_none());
        assert_eq!(wl.votes.pending.len(), 1);

        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
            2,
        )
        .unwrap();

        // Then
        let stored = wl.entries.get(ForeignChain::Ethereum).unwrap();
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
        )
        .unwrap();
        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
            vec![chain_vote(ForeignChain::Ethereum, &["ankr", "alchemy"], 1)],
            2,
        )
        .unwrap();

        // Then
        let stored = wl.entries.get(ForeignChain::Ethereum).unwrap();
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
            )
            .unwrap();

        // Then: Ethereum applied; Polygon did not (different providers proposed).
        assert_eq!(applied_p1, vec![ForeignChain::Ethereum]);
        assert!(wl.entries.get(ForeignChain::Ethereum).is_some());
        assert!(wl.entries.get(ForeignChain::Polygon).is_none());
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
        )
        .unwrap();

        // When
        wl.vote(
            p0.clone(),
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy"], 1)],
            2,
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
    fn vote__should_replace_full_chain_state_on_apply() {
        // Given: chain currently holds [alchemy, ankr].
        let participants = gen_participants(2);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        wl.vote(
            p0,
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy", "ankr"], 1)],
            2,
        )
        .unwrap();
        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
            vec![chain_vote(ForeignChain::Ethereum, &["alchemy", "ankr"], 1)],
            2,
        )
        .unwrap();

        // When: both vote a new state [drpc] (alchemy + ankr both removed in one move).
        let p0 = auth_as(&participants, 0);
        wl.vote(
            p0,
            vec![chain_vote(ForeignChain::Ethereum, &["drpc"], 1)],
            2,
        )
        .unwrap();
        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
            vec![chain_vote(ForeignChain::Ethereum, &["drpc"], 1)],
            2,
        )
        .unwrap();

        // Then: full snapshot replaced — only drpc remains.
        let stored = wl.entries.get(ForeignChain::Ethereum).unwrap();
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
        let err = wl.vote(p0, vec![], 2).unwrap_err();
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
            )
            .unwrap_err();
        assert_malformed(err, "duplicate chain");
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
            )
            .unwrap_err();
        assert_malformed(err, "duplicate provider_id");
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
        )
        .unwrap();
        wl.vote(
            p1.clone(),
            vec![chain_vote(ForeignChain::Polygon, &["ankr"], 1)],
            3,
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
