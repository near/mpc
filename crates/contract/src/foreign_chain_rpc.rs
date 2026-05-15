//! On-chain whitelist of RPC providers for foreign-chain transaction validation.
//!
//! Mutated via `vote_update_foreign_chain_providers`: the batch is split by chain and each
//! chain applies independently once its per-chain threshold of participants holds the
//! exact same `Vec` for that chain.

use std::collections::{btree_map::Entry, BTreeMap};

use near_mpc_contract_interface::types::{
    ForeignChain, ProviderEntry, ProviderId, ProviderVoteAction,
};
use near_sdk::near;

use crate::primitives::{key_state::AuthenticatedParticipantId, participants::Participants};

pub const DEFAULT_PROVIDER_VOTE_THRESHOLD: u64 = 2;

// Flat `(chain, provider_id)` key (rather than `BTreeMap<chain, BTreeMap<id, _>>`) halves
// the BTreeMap monomorphizations the contract WASM has to pay for.
#[near(serializers=[borsh])]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct AllowedProviders {
    entries: BTreeMap<(ForeignChain, ProviderId), ProviderEntry>,
}

impl AllowedProviders {
    /// Insert a new provider for `chain`. Returns `false` if `provider_id` is already
    /// present (existing entry is left untouched).
    fn add(&mut self, chain: ForeignChain, entry: ProviderEntry) -> bool {
        match self.entries.entry((chain, entry.provider_id.clone())) {
            Entry::Vacant(slot) => {
                slot.insert(entry);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Remove the provider with `provider_id` from `chain`. Returns `true` if an entry
    /// was removed.
    fn remove(&mut self, chain: ForeignChain, provider_id: &ProviderId) -> bool {
        self.entries.remove(&(chain, provider_id.clone())).is_some()
    }

    /// All providers currently whitelisted for `chain`, in `provider_id` order.
    #[cfg(test)]
    pub fn get(&self, chain: ForeignChain) -> impl Iterator<Item = &ProviderEntry> {
        self.entries
            .iter()
            .filter(move |((c, _), _)| *c == chain)
            .map(|(_, entry)| entry)
    }
}

// Flat `(participant, chain)` key — same monomorphization-halving rationale as
// `AllowedProviders`.
#[near(serializers=[borsh])]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProviderVotes {
    pub pending: BTreeMap<(AuthenticatedParticipantId, ForeignChain), Vec<ProviderVoteAction>>,
}

impl ProviderVotes {
    /// Returns the chains whose slot was updated, so the caller can re-check thresholds
    /// for exactly those chains.
    fn upsert(
        &mut self,
        participant: AuthenticatedParticipantId,
        by_chain: BTreeMap<ForeignChain, Vec<ProviderVoteAction>>,
    ) -> Vec<ForeignChain> {
        let touched: Vec<ForeignChain> = by_chain.keys().copied().collect();
        for (chain, actions) in by_chain {
            self.pending.insert((participant.clone(), chain), actions);
        }
        touched
    }

    fn count_for_chain(&self, chain: ForeignChain, target: &[ProviderVoteAction]) -> u64 {
        self.pending
            .iter()
            .filter(|((_, c), actions)| *c == chain && actions.as_slice() == target)
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
    pub(crate) chain_thresholds: BTreeMap<ForeignChain, u64>,
}

impl ForeignChainRpcWhitelist {
    pub fn threshold_for(&self, chain: ForeignChain) -> u64 {
        self.chain_thresholds
            .get(&chain)
            .copied()
            .unwrap_or(DEFAULT_PROVIDER_VOTE_THRESHOLD)
    }

    /// Record `participant`'s vote and apply any chain whose threshold is now reached.
    /// Chains the participant didn't touch in `actions` keep their prior slot. Panics on
    /// an empty batch.
    pub fn vote(
        &mut self,
        participant: AuthenticatedParticipantId,
        actions: Vec<ProviderVoteAction>,
    ) {
        let by_chain = group_by_chain(actions);
        let touched = self.votes.upsert(participant.clone(), by_chain);
        for chain in touched {
            let target = self
                .votes
                .pending
                .get(&(participant.clone(), chain))
                .cloned()
                .unwrap_or_default();
            let count = self.votes.count_for_chain(chain, &target);
            if count >= self.threshold_for(chain) {
                self.apply_chain(chain, &target);
                self.votes.clear_chain(chain);
            }
        }
    }

    fn apply_chain(&mut self, chain: ForeignChain, actions: &[ProviderVoteAction]) {
        for action in actions {
            match action {
                ProviderVoteAction::Add { entry, .. } => {
                    let _ = self.entries.add(chain, entry.clone());
                }
                ProviderVoteAction::Remove { provider_id, .. } => {
                    let _ = self.entries.remove(chain, provider_id);
                }
            }
        }
    }
}

// No structural validation: malformed entries still have to clear per-chain threshold
// consensus, and the node-side chain-identity probe (PR 3) catches the rest at startup.
// In-contract validation would burn WASM bytes the contract doesn't have headroom for.
fn group_by_chain(
    actions: Vec<ProviderVoteAction>,
) -> BTreeMap<ForeignChain, Vec<ProviderVoteAction>> {
    if actions.is_empty() {
        near_sdk::env::panic_str("vote actions batch must be non-empty");
    }
    let mut by_chain: BTreeMap<ForeignChain, Vec<ProviderVoteAction>> = BTreeMap::new();
    for action in actions {
        by_chain.entry(action.chain()).or_default().push(action);
    }
    by_chain
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::{key_state::AuthenticatedParticipantId, test_utils::gen_participants};
    use near_mpc_contract_interface::types::{AuthScheme, ChainRouting};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn entry(provider_id: &str) -> ProviderEntry {
        ProviderEntry {
            provider_id: provider_id.to_string(),
            base_url: format!("https://{provider_id}.example.com"),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::Embedded,
        }
    }

    fn add(chain: ForeignChain, provider_id: &str) -> ProviderVoteAction {
        ProviderVoteAction::Add {
            chain,
            entry: entry(provider_id),
        }
    }

    fn remove(chain: ForeignChain, provider_id: &str) -> ProviderVoteAction {
        ProviderVoteAction::Remove {
            chain,
            provider_id: provider_id.to_string(),
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

    #[test]
    fn vote__should_apply_chain_when_threshold_reached() {
        // Given
        let participants = gen_participants(3);
        let mut wl = ForeignChainRpcWhitelist::default();

        // When
        let p0 = auth_as(&participants, 0);
        wl.vote(p0, vec![add(ForeignChain::Ethereum, "alchemy")]);
        assert_eq!(wl.entries.get(ForeignChain::Ethereum).count(), 0);
        assert_eq!(wl.votes.pending.len(), 1);

        let p1 = auth_as(&participants, 1);
        wl.vote(p1, vec![add(ForeignChain::Ethereum, "alchemy")]);

        // Then
        let entries: Vec<&ProviderEntry> = wl.entries.get(ForeignChain::Ethereum).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].provider_id, "alchemy");
        assert!(wl.votes.pending.is_empty());
    }

    #[test]
    fn vote__should_apply_batch_actions_in_order() {
        // Given
        let participants = gen_participants(3);
        let mut wl = ForeignChainRpcWhitelist::default();

        // When
        let p0 = auth_as(&participants, 0);
        wl.vote(
            p0,
            vec![
                add(ForeignChain::Ethereum, "alchemy"),
                remove(ForeignChain::Ethereum, "alchemy"),
            ],
        );
        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
            vec![
                add(ForeignChain::Ethereum, "alchemy"),
                remove(ForeignChain::Ethereum, "alchemy"),
            ],
        );

        // Then
        assert_eq!(wl.entries.get(ForeignChain::Ethereum).count(), 0);
    }

    #[test]
    fn vote__should_apply_chains_independently() {
        // Given
        let participants = gen_participants(3);
        let mut wl = ForeignChainRpcWhitelist::default();

        // When
        let p0 = auth_as(&participants, 0);
        wl.vote(
            p0,
            vec![
                add(ForeignChain::Ethereum, "alchemy"),
                add(ForeignChain::Polygon, "ankr"),
            ],
        );
        let p1 = auth_as(&participants, 1);
        wl.vote(
            p1,
            vec![
                add(ForeignChain::Ethereum, "alchemy"),
                add(ForeignChain::Polygon, "infura"),
            ],
        );

        // Then
        let eth: Vec<&ProviderEntry> = wl.entries.get(ForeignChain::Ethereum).collect();
        assert_eq!(eth.len(), 1);
        assert_eq!(eth[0].provider_id, "alchemy");
        assert_eq!(wl.entries.get(ForeignChain::Polygon).count(), 0);
        assert!(!wl.votes.pending.is_empty());
        for (_, chain) in wl.votes.pending.keys() {
            assert_ne!(*chain, ForeignChain::Ethereum);
            assert_eq!(*chain, ForeignChain::Polygon);
        }
    }

    #[test]
    fn vote__should_overwrite_only_mentioned_chain_slots_on_recast() {
        // Given
        let participants = gen_participants(3);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        wl.vote(p0.clone(), vec![add(ForeignChain::Polygon, "ankr")]);

        // When
        wl.vote(p0.clone(), vec![add(ForeignChain::Ethereum, "alchemy")]);

        // Then
        assert!(wl
            .votes
            .pending
            .contains_key(&(p0.clone(), ForeignChain::Polygon)));
        assert!(wl.votes.pending.contains_key(&(p0, ForeignChain::Ethereum)));
    }

    #[test]
    #[should_panic(expected = "vote actions batch must be non-empty")]
    fn vote__should_panic_on_empty_batch() {
        let participants = gen_participants(3);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        wl.vote(p0, vec![]);
    }

    #[test]
    fn clean_non_participant_votes__should_drop_stale_votes() {
        // Given
        let participants = gen_participants(3);
        let mut wl = ForeignChainRpcWhitelist::default();
        let p0 = auth_as(&participants, 0);
        let p1 = auth_as(&participants, 1);
        wl.vote(p0.clone(), vec![add(ForeignChain::Ethereum, "alchemy")]);
        wl.vote(p1.clone(), vec![add(ForeignChain::Polygon, "ankr")]);

        // When
        let smaller = participants.subset(1..3);
        wl.votes.retain_only(&smaller);

        // Then
        assert!(!wl.votes.pending.contains_key(&(p0, ForeignChain::Ethereum)));
        assert!(wl.votes.pending.contains_key(&(p1, ForeignChain::Polygon)));
    }

    #[test]
    fn threshold_for__should_fall_back_to_default_when_chain_threshold_not_set() {
        let wl = ForeignChainRpcWhitelist::default();
        assert_eq!(
            wl.threshold_for(ForeignChain::Ethereum),
            DEFAULT_PROVIDER_VOTE_THRESHOLD
        );
    }

    #[test]
    fn threshold_for__should_return_configured_threshold_when_set() {
        let mut wl = ForeignChainRpcWhitelist::default();
        wl.chain_thresholds.insert(ForeignChain::Ethereum, 5);
        assert_eq!(wl.threshold_for(ForeignChain::Ethereum), 5);
        assert_eq!(
            wl.threshold_for(ForeignChain::Polygon),
            DEFAULT_PROVIDER_VOTE_THRESHOLD
        );
    }
}
