//! Per-node foreign-chain support reports and the RPC provider policy that together
//! decide which chains are available for verification.

use crate::errors::{Error, InvalidState};
use crate::primitives::key_state::AuthenticatedParticipantId;
use crate::state::ProtocolContractState;
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{env, log, near};
use std::collections::{BTreeMap, BTreeSet};

#[near]
impl MpcContract {
    /// Registers the set of foreign chains the calling node supports.
    ///
    /// Must be called directly from the participant's own NEAR account
    /// (`voter_or_panic` requires `signer == predecessor`, blocking calls forwarded
    /// through another contract). Callable by a participant in any active protocol phase
    /// (Initializing, Running, or Resharing — authenticated against that phase's participant
    /// set); panics in [`NotInitialized`](ProtocolContractState::NotInitialized) or when the caller is not a participant. Entries for
    /// accounts that are no longer participants are pruned after resharing by
    /// [`Self::clean_foreign_chain_data`].
    #[deprecated(note = "TODO(#3630): drop this. This is superseded by
        register_foreign_chains_config, and feeds only the legacy get_supported_foreign_chains")]
    #[handle_result]
    pub fn register_foreign_chain_support(
        &mut self,
        foreign_chain_support: dtos::SupportedForeignChains,
    ) -> Result<(), Error> {
        let account_id = self.voter_or_panic();

        self.node_foreign_chain_support
            .foreign_chain_support_by_node
            .insert(account_id, foreign_chain_support);

        Ok(())
    }

    /// (Re)registers the foreign chains this node currently covers.
    #[handle_result]
    pub fn register_foreign_chains_config(
        &mut self,
        foreign_chains_config: dtos::ForeignChainsConfig,
    ) -> Result<(), Error> {
        Self::assert_caller_is_signer();
        let signer_account_id = env::signer_account_id();
        let signer_account_pk = env::signer_account_pk();
        let signer_account_ed25519_pk = dtos::Ed25519PublicKey::try_from(&signer_account_pk)
            .unwrap_or_else(|_| env::panic_str("signer account key must be Ed25519"));
        let node_id = self
            .tee_state
            .lookup_node_id_by_signer_pk(&signer_account_ed25519_pk)
            .map_err(|_| InvalidState::NotParticipant {
                account_id: signer_account_id.clone(),
            })?;
        if node_id.account_id != signer_account_id {
            return Err(InvalidState::NotParticipant {
                account_id: signer_account_id,
            }
            .into());
        }
        let is_participant = self
            .protocol_state
            .is_existing_or_prospective_participant(&node_id.account_id)?;
        if !is_participant {
            return Err(InvalidState::NotParticipant {
                account_id: node_id.account_id.clone(),
            }
            .into());
        }
        let tls_key = node_id.tls_public_key.clone();

        self.foreign_chains
            .get_mut()
            .register(tls_key, foreign_chains_config);
        self.recompute_available_foreign_chains();

        Ok(())
    }

    /// No-op when outside [`ProtocolContractState::Running`] and [`ProtocolContractState::Resharing`].
    pub(crate) fn recompute_available_foreign_chains(&mut self) {
        let Ok(params) = self.protocol_state.threshold_parameters() else {
            return;
        };
        // TODO(#3556): replace this with a per-scheme
        // `required_active_signers(protocol, reconstruction_threshold)`.
        let Some(reconstruction_threshold) =
            self.protocol_state.domain_registry().ok().and_then(|r| {
                r.domains()
                    .iter()
                    .filter(|d| d.purpose == dtos::DomainPurpose::ForeignTx)
                    .map(|d| d.reconstruction_threshold.inner())
                    .max()
            })
        else {
            // No op if contract isn't in Running or Resharing state, or
            // there is no foreign tx domain registered.
            // Not panicking is intentional.
            log!("Skipping available foreign chains recomputation");
            return;
        };
        let active_tls_keys: BTreeSet<_> = params
            .participants()
            .participants()
            .iter()
            .map(|(_, _, info)| info.tls_public_key.clone())
            .collect();
        self.foreign_chains
            .get_mut()
            .update_available_chains_config_cache(&active_tls_keys, reconstruction_threshold);
    }

    #[deprecated(
        note = "TODO(#3630): drop this. Nodes register via register_foreign_chains_config instead"
    )]
    #[expect(deprecated)]
    #[handle_result]
    pub fn register_foreign_chain_config(
        &mut self,
        foreign_chain_configuration: dtos::ForeignChainConfiguration,
    ) -> Result<(), Error> {
        let foreign_chain_support: dtos::SupportedForeignChains = foreign_chain_configuration
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            .into();

        self.register_foreign_chain_support(foreign_chain_support)
    }

    /// Vote on per-chain RPC provider whitelist state. The input is keyed by
    /// [`ForeignChain`](dtos::ForeignChain); each [`ChainEntry`](dtos::ChainEntry) value carries the proposed full provider list
    /// and the RPC response quorum for that chain. The chain's stored state is replaced
    /// once the protocol's signing threshold of participants has voted the same
    /// `(providers, quorum)` pair. [`NonEmptyBTreeMap`](near_mpc_bounded_collections::NonEmptyBTreeMap) enforces a non-empty batch and
    /// at-most-one entry per chain at borsh-deserialize time.
    #[handle_result]
    pub fn vote_update_foreign_chain_providers(
        &mut self,
        #[serializer(borsh)] votes: near_mpc_bounded_collections::NonEmptyBTreeMap<
            dtos::ForeignChain,
            dtos::ChainEntry,
        >,
    ) -> Result<Vec<dtos::ForeignChain>, Error> {
        let batch_hash = env::sha256_array(
            borsh::to_vec(&votes).expect("borsh serialization of votes batch must succeed"),
        );
        log!(
            "vote_update_foreign_chain_providers: signer={}, n_votes={}, batch_hash={}",
            env::signer_account_id(),
            votes.len(),
            hex::encode(batch_hash),
        );
        self.voter_or_panic();

        let threshold_parameters = self
            .protocol_state
            .threshold_parameters()
            .expect("voter_or_panic() above already errors on NotInitialized");

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let applied = self.foreign_chains.get_mut().rpc_whitelist.vote(
            participant,
            votes,
            threshold_parameters,
        )?;
        log!(
            "vote_update_foreign_chain_providers: applied chains={:?}",
            applied,
        );
        if !applied.is_empty() {
            self.recompute_available_foreign_chains();
        }
        Ok(applied)
    }

    /// On-chain RPC provider whitelist keyed by [`ForeignChain`](dtos::ForeignChain). Nodes read this at
    /// startup to validate their local `foreign_chains.yaml`. Borsh-encoded result.
    #[result_serializer(borsh)]
    pub fn allowed_foreign_chain_providers(
        &self,
    ) -> std::collections::BTreeMap<dtos::ForeignChain, dtos::ChainEntry> {
        log!("allowed_foreign_chain_providers");
        self.foreign_chains.get().rpc_whitelist.entries.snapshot()
    }

    /// Private endpoint to clean up foreign chain policy votes and node configurations
    /// for non-participants after resharing.
    #[private]
    #[handle_result]
    pub fn clean_foreign_chain_data(&mut self) -> Result<(), Error> {
        log!(
            "clean_foreign_chain_data: signer={}",
            env::signer_account_id()
        );

        let participants = match &self.protocol_state {
            ProtocolContractState::Running(state) => state.parameters.participants(),
            _ => {
                return Err(InvalidState::ProtocolStateNotRunning.into());
            }
        };

        let participant_accounts: std::collections::HashSet<dtos::AccountId> = participants
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();

        let active_tls_keys: std::collections::BTreeSet<dtos::Ed25519PublicKey> = participants
            .participants()
            .iter()
            .map(|(_, _, info)| info.tls_public_key.clone())
            .collect();

        let non_participant_configs: Vec<dtos::AccountId> = self
            .node_foreign_chain_support
            .foreign_chain_support_by_node
            .keys()
            .filter(|account| !participant_accounts.contains(*account))
            .cloned()
            .collect();
        for account in &non_participant_configs {
            self.node_foreign_chain_support
                .foreign_chain_support_by_node
                .remove(account);
        }

        self.foreign_chains
            .get_mut()
            .remove_stale_configs(&active_tls_keys);

        self.foreign_chains
            .get_mut()
            .rpc_whitelist
            .votes
            .retain(participants);

        Ok(())
    }

    #[deprecated(
        note = "TODO(#3630): drop this. It's superseded by get_available_foreign_chains, which gates verify_foreign_transaction"
    )]
    pub fn get_supported_foreign_chains(&self) -> dtos::SupportedForeignChains {
        let active_participant_account_ids = self
            .protocol_state
            .active_participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect::<BTreeSet<_>>();

        let mut foreign_chain_to_node_mapping: BTreeMap<
            &dtos::ForeignChain,
            BTreeSet<dtos::AccountId>,
        > = BTreeMap::new();

        for (account_id, chains) in self
            .node_foreign_chain_support
            .foreign_chain_support_by_node
            .iter()
        {
            for chain in chains.iter() {
                foreign_chain_to_node_mapping
                    .entry(chain)
                    .or_default()
                    .insert(account_id.clone());
            }
        }

        foreign_chain_to_node_mapping
            .into_iter()
            .filter_map(|(foreign_chain, nodes_supporting_chain)| {
                let all_active_nodes_supports_chain =
                    nodes_supporting_chain.is_superset(&active_participant_account_ids);

                if all_active_nodes_supports_chain {
                    Some(foreign_chain)
                } else {
                    None
                }
            })
            .cloned()
            .collect::<BTreeSet<dtos::ForeignChain>>()
            .into()
    }

    #[deprecated(note = "TODO(#3630): drop this, it's deprecated.")]
    pub fn get_foreign_chain_support_by_node(&self) -> dtos::ForeignChainSupportByNode {
        self.node_foreign_chain_support.to_dto()
    }

    /// The **available** foreign chains: whitelisted chains that are supported
    /// by at least the signing threshold of active participants.
    pub fn get_available_foreign_chains(&self) -> dtos::AvailableForeignChains {
        self.foreign_chains.get().available_foreign_chains.clone()
    }

    /// Per-participant view of which foreign chains each node currently covers. Feeds the
    /// available-set computation ([`Self::get_available_foreign_chains`]) and coverage alerting.
    pub fn get_foreign_chains_configs(&self) -> dtos::ForeignChainsConfigs {
        self.foreign_chains.get().snapshot_by_node()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::foreign_chain::test_utils::{
        register_foreign_chains_config_for, whitelist_chain,
    };
    use crate::api::test_utils::{
        basic_setup, basic_setup_with_protocol, forwarded_participant_call_contract,
        make_public_key_for_curve, participant_account_ids,
    };
    use crate::dto_mapping::IntoInterfaceType;
    use crate::primitives::domain::AddDomainsVotes;
    use crate::primitives::key_state::{AttemptId, EpochId, KeyForDomain, Keyset};
    use crate::primitives::participants::ParticipantInfo;
    use crate::primitives::test_utils::{
        bogus_ed25519_public_key, gen_account_id, gen_participant, gen_participants,
    };
    use crate::primitives::thresholds::{
        GovernanceThreshold, GovernanceThresholdParameters, ProposedGovernanceThresholdParameters,
    };
    use crate::state::key_event::tests::Environment;
    use crate::state::running::RunningContractState;
    use crate::state::test_utils::{gen_resharing_state, gen_running_state};
    use crate::tee::tee_state::{NodeAttestation, NodeId, TeeState};
    use dtos::{Curve, DomainConfig, DomainId, Protocol, ReconstructionThreshold};
    use mpc_attestation::attestation::{
        MockAttestation as MpcMockAttestation, VerifiedAttestation,
    };
    use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};
    use near_mpc_contract_interface::types::DestinationNodeInfo;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{AccountId, NearToken, testing_env};
    use rand::rngs::OsRng;
    use std::panic;
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn register_foreign_chain_support__should_panic_when_predecessor_differs_from_signer() {
        let mut contract = forwarded_participant_call_contract();
        contract
            .register_foreign_chain_support(BTreeSet::new().into())
            .expect("expected panic when predecessor != signer");
    }

    #[test]
    fn register_foreign_chain_support__should_store_supported_chains_for_participant() {
        // Given
        let running_state = gen_running_state(1);
        let participants = running_state
            .parameters
            .participants()
            .participants()
            .clone();
        let first_account = participants[0].0.clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        let foreign_chain_support: dtos::SupportedForeignChains =
            BTreeSet::from([dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Ethereum]).into();

        let _env = Environment::new(None, Some(first_account.clone()), None);

        // When
        contract
            .register_foreign_chain_support(foreign_chain_support.clone())
            .expect("register should succeed");

        // Then
        let votes = contract.get_foreign_chain_support_by_node();
        assert_eq!(votes.foreign_chain_support_by_node.len(), 1);
        assert_eq!(
            votes
                .foreign_chain_support_by_node
                .get(&first_account.clone()),
            Some(&foreign_chain_support)
        );
    }

    #[test]
    fn register_foreign_chain_support__should_store_for_previous_participant_during_resharing() {
        // Given: a contract mid-resharing, and a participant from the previous running set.
        let (_env, resharing_state) = gen_resharing_state(1);
        let previous_participant = resharing_state
            .previous_running_state
            .parameters
            .participants()
            .participants()[0]
            .0
            .clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Resharing(resharing_state));
        let foreign_chain_support: dtos::SupportedForeignChains =
            BTreeSet::from([dtos::ForeignChain::Bitcoin]).into();
        let _env = Environment::new(None, Some(previous_participant.clone()), None);

        // When: that participant registers foreign-chain support outside of Running state.
        contract
            .register_foreign_chain_support(foreign_chain_support.clone())
            .expect("a previous participant may register during resharing");

        // Then: the registration is stored against their account.
        let stored = contract.get_foreign_chain_support_by_node();
        assert_eq!(
            stored
                .foreign_chain_support_by_node
                .get(&previous_participant),
            Some(&foreign_chain_support)
        );
    }

    #[test]
    #[should_panic(expected = "not a voter")]
    fn register_foreign_chain_config__should_reject_non_participant() {
        // Given
        let running_state = gen_running_state(1);
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));
        let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([(
            dtos::ForeignChain::Bitcoin,
            NonEmptyBTreeSet::new(dtos::RpcProvider {
                rpc_url: "https://btc.example.com".to_string(),
            }),
        )])
        .into();

        let non_participant = gen_account_id();
        let _env = Environment::new(None, Some(non_participant), None);

        // When / Then: a non-participant is rejected. Registration now authenticates via
        // `voter_or_panic()`, which panics rather than returning an error.
        contract
            .register_foreign_chain_config(foreign_chain_configuration)
            .expect("non-participant should not be able to register");
    }

    #[test]
    fn get_supported_foreign_chains__should_return_chains_supported_by_all_participants() {
        // Given
        let running_state = gen_running_state(1);
        let participants = running_state
            .parameters
            .participants()
            .participants()
            .clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        // Both participants support Bitcoin and Ethereum
        let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([
            (
                dtos::ForeignChain::Bitcoin,
                NonEmptyBTreeSet::new(dtos::RpcProvider {
                    rpc_url: "https://btc.example.com".to_string(),
                }),
            ),
            (
                dtos::ForeignChain::Ethereum,
                NonEmptyBTreeSet::new(dtos::RpcProvider {
                    rpc_url: "https://eth.example.com".to_string(),
                }),
            ),
        ])
        .into();

        for (account_id, _, _) in &participants {
            let _env = Environment::new(None, Some(account_id.clone()), None);
            contract
                .register_foreign_chain_config(foreign_chain_configuration.clone())
                .expect("register should succeed");
        }

        // When
        let result = contract.get_supported_foreign_chains();

        // Then
        assert!(result.contains(&dtos::ForeignChain::Bitcoin));
        assert!(result.contains(&dtos::ForeignChain::Ethereum));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn get_supported_foreign_chains__should_exclude_chains_not_supported_by_all() {
        // Given
        let running_state = gen_running_state(1);
        let participants = running_state
            .parameters
            .participants()
            .participants()
            .clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        // All participants except the last support Bitcoin + Ethereum
        for (account_id, _, _) in &participants[..participants.len() - 1] {
            let _env = Environment::new(None, Some(account_id.clone()), None);
            let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([
                (
                    dtos::ForeignChain::Bitcoin,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "https://btc.example.com".to_string(),
                    }),
                ),
                (
                    dtos::ForeignChain::Ethereum,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "https://eth.example.com".to_string(),
                    }),
                ),
            ])
            .into();
            contract
                .register_foreign_chain_config(foreign_chain_configuration)
                .expect("register should succeed");
        }

        // Last participant supports only Bitcoin
        {
            let last = &participants[participants.len() - 1].0;
            let _env = Environment::new(None, Some(last.clone()), None);
            let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                NonEmptyBTreeSet::new(dtos::RpcProvider {
                    rpc_url: "https://btc.example.com".to_string(),
                }),
            )])
            .into();
            contract
                .register_foreign_chain_config(foreign_chain_configuration)
                .expect("register should succeed");
        }

        // When
        let result = contract.get_supported_foreign_chains();

        // Then - only Bitcoin is unanimous
        assert!(result.contains(&dtos::ForeignChain::Bitcoin));
        assert!(!result.contains(&dtos::ForeignChain::Ethereum));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn get_supported_foreign_chains__different_rpc_urls_per_participant_is_fine() {
        // Given
        let running_state = gen_running_state(1);
        let participants = running_state
            .parameters
            .participants()
            .participants()
            .clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        // Each participant registers the same chains but with different RPC URLs
        for (i, (account_id, _, _)) in participants.iter().enumerate() {
            let _env = Environment::new(None, Some(account_id.clone()), None);
            let foreign_chain_configuration: dtos::ForeignChainConfiguration = BTreeMap::from([
                (
                    dtos::ForeignChain::Bitcoin,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: format!("https://btc-node-{i}.example.com"),
                    }),
                ),
                (
                    dtos::ForeignChain::Ethereum,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: format!("https://eth-node-{i}.example.com"),
                    }),
                ),
            ])
            .into();
            contract
                .register_foreign_chain_config(foreign_chain_configuration)
                .expect("register should succeed");
        }

        // When
        let result = contract.get_supported_foreign_chains();

        // Then — both chains are supported despite different RPC URLs
        assert!(result.contains(&dtos::ForeignChain::Bitcoin));
        assert!(result.contains(&dtos::ForeignChain::Ethereum));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn get_supported_foreign_chains__should_return_empty_when_no_votes() {
        // Given
        let running_state = gen_running_state(1);
        let contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        // When
        let result = contract.get_supported_foreign_chains();

        // Then
        assert!(result.is_empty());
    }

    #[test]
    fn vote_update_foreign_chain_providers__should_apply_chain_and_return_it_when_threshold_reached()
     {
        // Given: a running contract with 4 participants and signing threshold 3.
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let participant_account_ids: Vec<AccountId> = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();
        assert_eq!(participant_account_ids.len(), 4);

        let chain = dtos::ForeignChain::Ethereum;
        let entry = dtos::ChainEntry {
            providers: NonEmptyBTreeMap::new(
                dtos::ProviderId("alchemy".to_string()),
                dtos::ProviderConfig {
                    base_url: "https://alchemy.example.com".to_string(),
                    auth_scheme: dtos::AuthScheme::None,
                    chain_routing: dtos::ChainRouting::Embedded,
                },
            ),
            quorum: 1,
        };
        let batch = NonEmptyBTreeMap::new(chain, entry.clone());

        let vote_as = |contract: &mut MpcContract, account_id: &AccountId| {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_update_foreign_chain_providers(batch.clone())
                .expect("vote should succeed")
        };

        // When: first two participants vote (count = 2, below threshold 3).
        let applied_p0 = vote_as(&mut contract, &participant_account_ids[0]);
        let applied_p1 = vote_as(&mut contract, &participant_account_ids[1]);

        // Then: nothing applied yet.
        assert!(applied_p0.is_empty(), "1st vote should not apply");
        assert!(applied_p1.is_empty(), "2nd vote should not apply");
        assert!(contract.allowed_foreign_chain_providers().is_empty());

        // When: third participant votes (crosses threshold).
        let applied_p2 = vote_as(&mut contract, &participant_account_ids[2]);

        // Then: the chain is reported as applied this call and is now stored.
        assert_eq!(applied_p2, vec![chain]);
        let stored = contract.allowed_foreign_chain_providers();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored.get(&chain), Some(&entry));
    }

    #[test]
    #[should_panic(expected = "not a voter")]
    fn vote_update_foreign_chain_providers__should_panic_when_caller_is_not_a_participant() {
        // Given: a running contract whose participant set does NOT contain `non_participant`.
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let non_participant = gen_account_id();

        let batch = NonEmptyBTreeMap::new(
            dtos::ForeignChain::Ethereum,
            dtos::ChainEntry {
                providers: NonEmptyBTreeMap::new(
                    dtos::ProviderId("alchemy".to_string()),
                    dtos::ProviderConfig {
                        base_url: "https://alchemy.example.com".to_string(),
                        auth_scheme: dtos::AuthScheme::None,
                        chain_routing: dtos::ChainRouting::Embedded,
                    },
                ),
                quorum: 1,
            },
        );

        // When: a non-participant attempts to vote — voter_or_panic should reject.
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(non_participant.clone())
                .predecessor_account_id(non_participant)
                .build()
        );
        let _ = contract.vote_update_foreign_chain_providers(batch);
    }

    #[test]
    // Setup with 4 participants, first 3 supporting 4 chains, 4th one supports only 2.
    // Node operator of 4th node spins up new node, and registers config that supports all 4 chains.
    // Available chains should still be 2.
    // Node operator of 4th node migrates node to new node, and new node becomes participant,
    // then all 4 chains should be supported.
    fn get_available_foreign_chains__should_not_count_non_participant_node_config() {
        // Given: 4 participants, threshold 4 (all must agree); 4 chains whitelisted.
        let (_context, mut contract, _) = basic_setup_with_protocol(
            Protocol::CaitSith,
            dtos::DomainPurpose::ForeignTx,
            &mut OsRng,
        );
        let all_chains = [
            dtos::ForeignChain::Bitcoin,
            dtos::ForeignChain::Ethereum,
            dtos::ForeignChain::Solana,
            dtos::ForeignChain::Bnb,
        ];
        let partial_chains = [dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Ethereum];
        for chain in all_chains {
            whitelist_chain(&mut contract, chain);
        }

        // Raise both the governance threshold and ForeignTx domain threshold to 4 so that all
        // participants must cover a chain for it to be available.
        {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running");
            };
            state.parameters = GovernanceThresholdParameters::new(
                state.parameters.participants().clone(),
                GovernanceThreshold::new(4),
            )
            .unwrap();
            for domain in state.domains.domains_mut() {
                if domain.purpose == dtos::DomainPurpose::ForeignTx {
                    domain.reconstruction_threshold = ReconstructionThreshold::new(4);
                }
            }
        }

        let participants = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .clone();
        let participant_ids = participant_account_ids(&contract);

        // Nodes 1-3 cover all 4 chains.
        for account_id in participant_ids.iter().take(3) {
            register_foreign_chains_config_for(&mut contract, account_id, all_chains);
        }

        // Node 4 (active participant) only covers 2 chains.
        let operator4 = &participant_ids[3];
        register_foreign_chains_config_for(&mut contract, operator4, partial_chains);

        // Operator 4's new migration node (not yet a participant) covers all 4 chains and registers.
        let new_tls_key = dtos::Ed25519PublicKey([99u8; 32]);
        let new_signer_pk = dtos::Ed25519PublicKey([98u8; 32]);
        contract.tee_state.stored_attestations.insert(
            new_tls_key.clone(),
            NodeAttestation {
                node_id: NodeId {
                    account_id: operator4.clone(),
                    tls_public_key: new_tls_key.clone(),
                    account_public_key: new_signer_pk.clone(),
                },
                verified_attestation: VerifiedAttestation::Mock(MpcMockAttestation::Valid),
            },
        );
        let foreign_chains_config: dtos::ForeignChainsConfig =
            all_chains.into_iter().collect::<BTreeSet<_>>().into();
        let mut env = Environment::new(None, Some(operator4.clone()), None);
        env.set_pk(near_sdk::PublicKey::from(new_signer_pk));
        contract
            .register_foreign_chains_config(foreign_chains_config)
            .expect("new node of same operator should be able to register");

        // Then: only 2 chains available — new node's config doesn't count since it's not a participant.
        let available = contract.get_available_foreign_chains();
        assert_eq!(available.len(), 2);
        assert!(available.contains(&dtos::ForeignChain::Bitcoin));
        assert!(available.contains(&dtos::ForeignChain::Ethereum));

        // When: migration completes — participant 4's TLS key is updated to the new node.
        let old_info = participants.info(operator4).unwrap().clone();
        let new_info = ParticipantInfo {
            tls_public_key: new_tls_key,
            ..old_info
        };
        {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running");
            };
            // Reconstruct GovernanceThresholdParameters with the updated participants.
            let mut updated_participants = state.parameters.participants().clone();
            updated_participants
                .update_info(operator4.clone(), new_info)
                .unwrap();
            state.parameters = GovernanceThresholdParameters::new(
                updated_participants,
                GovernanceThreshold::new(4),
            )
            .unwrap();
        }
        contract.recompute_available_foreign_chains();

        // Then: all 4 chains are now available.
        let available = contract.get_available_foreign_chains();
        assert_eq!(available.len(), 4);
    }

    #[test]
    fn conclude_node_migration__should_recompute_available_foreign_chains() {
        // Given: 4 participants, threshold 4; 4 chains whitelisted.
        // Node 4 supports only 2 chains.
        // Node 4's operator migrates to a new node that supports all 4 chains.
        // After conclude_node_migration the cache must reflect 4 chains without a manual recompute.
        let (_context, mut contract, _) = basic_setup_with_protocol(
            Protocol::CaitSith,
            dtos::DomainPurpose::ForeignTx,
            &mut OsRng,
        );
        let all_chains = [
            dtos::ForeignChain::Bitcoin,
            dtos::ForeignChain::Ethereum,
            dtos::ForeignChain::Solana,
            dtos::ForeignChain::Bnb,
        ];
        let partial_chains = [dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Ethereum];
        for chain in all_chains {
            whitelist_chain(&mut contract, chain);
        }
        {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running");
            };
            state.parameters = GovernanceThresholdParameters::new(
                state.parameters.participants().clone(),
                GovernanceThreshold::new(4),
            )
            .unwrap();
            for domain in state.domains.domains_mut() {
                if domain.purpose == dtos::DomainPurpose::ForeignTx {
                    domain.reconstruction_threshold = ReconstructionThreshold::new(4);
                }
            }
        }
        let participant_ids = participant_account_ids(&contract);
        for account_id in participant_ids.iter().take(3) {
            register_foreign_chains_config_for(&mut contract, account_id, all_chains);
        }
        let operator4 = &participant_ids[3];
        register_foreign_chains_config_for(&mut contract, operator4, partial_chains);

        let available = contract.get_available_foreign_chains();
        assert_eq!(
            available.len(),
            2,
            "only partial chains available before migration"
        );

        // When: operator 4 migrates to a new node that supports all 4 chains.
        let (_, new_participant_info) = gen_participant(100);
        let new_tls_key = new_participant_info.tls_public_key.clone();
        let new_signer_pk = bogus_ed25519_public_key();
        let new_signer_near_pk = near_sdk::PublicKey::from(new_signer_pk.clone());
        let destination_node_info = DestinationNodeInfo {
            signer_account_pk: new_signer_pk.clone(),
            destination_node_info: new_participant_info.into(),
        };

        // Add attestation for the new node (mirrors what ConcludeNodeMigrationTestSetup::setup does).
        contract
            .tee_state
            .verify_and_store_mock(
                NodeId {
                    account_id: operator4.clone(),
                    tls_public_key: new_tls_key.clone(),
                    account_public_key: new_signer_pk.clone(),
                },
                MpcMockAttestation::Valid,
                Duration::from_secs(contract.config.tee_upgrade_deadline_duration_seconds),
            )
            .expect("attestation insertion should succeed");

        // New node pre-registers its config.
        let mut env = Environment::new(None, Some(operator4.clone()), None);
        env.set_pk(new_signer_near_pk.clone());
        let full_config: dtos::ForeignChainsConfig =
            all_chains.into_iter().collect::<BTreeSet<_>>().into();
        contract
            .register_foreign_chains_config(full_config)
            .expect("new node should be able to register");

        let keyset = match &contract.protocol_state {
            ProtocolContractState::Running(s) => s.keyset.clone(),
            _ => panic!("expected Running"),
        };
        contract
            .node_migrations
            .set_destination_node_info(operator4.clone(), destination_node_info);
        let mut env = Environment::new(None, Some(operator4.clone()), None);
        env.set_pk(new_signer_near_pk);
        contract
            .conclude_node_migration((&keyset).into_dto_type())
            .expect("migration should succeed");

        // Then: all 4 chains available — no manual recompute needed.
        let available = contract.get_available_foreign_chains();
        assert_eq!(available.len(), 4);
    }

    #[test]
    fn get_available_foreign_chains__should_include_chain_when_at_least_threshold_participants_cover_it()
     {
        // Given: 4 participants, signing threshold 3; Bitcoin whitelisted.
        let (_context, mut contract, _) = basic_setup_with_protocol(
            Protocol::CaitSith,
            dtos::DomainPurpose::ForeignTx,
            &mut OsRng,
        );
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When: exactly the threshold (3) of 4 participants cover Bitcoin — one node does not.
        for account_id in participants.iter().take(3) {
            register_foreign_chains_config_for(
                &mut contract,
                account_id,
                [dtos::ForeignChain::Bitcoin],
            );
        }

        // Then: Bitcoin is available. A single non-covering node cannot take it down — the
        // regression the legacy intersection rule had.
        let available = contract.get_available_foreign_chains();
        assert!(available.contains(&dtos::ForeignChain::Bitcoin));
        assert_eq!(available.len(), 1);
    }

    #[test]
    fn get_available_foreign_chains__should_exclude_chain_when_fewer_than_threshold_cover_it() {
        // Given: 4 participants, threshold 3; Bitcoin whitelisted.
        let (_context, mut contract, _) = basic_setup_with_protocol(
            Protocol::CaitSith,
            dtos::DomainPurpose::ForeignTx,
            &mut OsRng,
        );
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When: only 2 of 4 (< threshold) cover Bitcoin.
        for account_id in participants.iter().take(2) {
            register_foreign_chains_config_for(
                &mut contract,
                account_id,
                [dtos::ForeignChain::Bitcoin],
            );
        }

        // Then: Bitcoin is not available.
        let available = contract.get_available_foreign_chains();
        assert!(!available.contains(&dtos::ForeignChain::Bitcoin));
        assert!(available.is_empty());
    }

    #[test]
    fn get_available_foreign_chains__should_exclude_chain_that_is_covered_but_not_whitelisted() {
        // Given: 4 participants, threshold 3; Bitcoin is NOT whitelisted.
        let (_context, mut contract, _) = basic_setup_with_protocol(
            Protocol::CaitSith,
            dtos::DomainPurpose::ForeignTx,
            &mut OsRng,
        );
        let participants = participant_account_ids(&contract);

        // When: all 4 participants cover Bitcoin.
        for account_id in &participants {
            register_foreign_chains_config_for(
                &mut contract,
                account_id,
                [dtos::ForeignChain::Bitcoin],
            );
        }

        // Then: Bitcoin is still not available — `available` is a subset of `whitelisted`.
        let available = contract.get_available_foreign_chains();
        assert!(available.is_empty());
    }

    #[test]
    fn get_available_foreign_chains__should_only_include_whitelisted_chains_with_threshold_coverage()
     {
        // Given: 4 participants, threshold 3. Bitcoin and Ethereum are whitelisted; Solana is not.
        let (_context, mut contract, _) = basic_setup_with_protocol(
            Protocol::CaitSith,
            dtos::DomainPurpose::ForeignTx,
            &mut OsRng,
        );
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        whitelist_chain(&mut contract, dtos::ForeignChain::Ethereum);

        // When (each participant registers its full covered set in one call, since a
        // registration replaces the participant's previously reported set):
        // - Bitcoin: covered by 3 participants (whitelisted + threshold) -> available.
        // - Ethereum: covered by 1 participant (whitelisted but under threshold) -> not available.
        // - Solana: covered by all 4 (threshold met but not whitelisted) -> not available.
        register_foreign_chains_config_for(
            &mut contract,
            &participants[0],
            [
                dtos::ForeignChain::Bitcoin,
                dtos::ForeignChain::Ethereum,
                dtos::ForeignChain::Solana,
            ],
        );
        register_foreign_chains_config_for(
            &mut contract,
            &participants[1],
            [dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Solana],
        );
        register_foreign_chains_config_for(
            &mut contract,
            &participants[2],
            [dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Solana],
        );
        register_foreign_chains_config_for(
            &mut contract,
            &participants[3],
            [dtos::ForeignChain::Solana],
        );

        // Then: only Bitcoin is available.
        let available = contract.get_available_foreign_chains();
        assert!(available.contains(&dtos::ForeignChain::Bitcoin));
        assert!(!available.contains(&dtos::ForeignChain::Ethereum));
        assert!(!available.contains(&dtos::ForeignChain::Solana));
        assert_eq!(available.len(), 1);
    }

    #[test]
    fn vote_update_foreign_chain_providers__should_populate_available_set_when_whitelisting_covered_chain()
     {
        // Given: 4 participants, threshold 3. Bitcoin is NOT yet whitelisted.
        let (_context, mut contract, _) = basic_setup_with_protocol(
            Protocol::CaitSith,
            dtos::DomainPurpose::ForeignTx,
            &mut OsRng,
        );
        let participants = participant_account_ids(&contract);

        // GovernanceThreshold (3) participants already cover Bitcoin — but the chain is not whitelisted,
        // so the cache must be empty.
        for account_id in participants.iter().take(3) {
            register_foreign_chains_config_for(
                &mut contract,
                account_id,
                [dtos::ForeignChain::Bitcoin],
            );
        }
        assert!(contract.get_available_foreign_chains().is_empty());

        // When: whitelist Bitcoin (vote_update_foreign_chain_providers triggers a recompute).
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // Then: cache flips from empty to populated.
        let available = contract.get_available_foreign_chains();
        assert!(available.contains(&dtos::ForeignChain::Bitcoin));
        assert_eq!(available.len(), 1);
    }

    #[test]
    fn clean_foreign_chain_data__should_drop_departed_participant_contribution_from_cache() {
        // Given: 4 participants, threshold 3, Bitcoin whitelisted.
        // Exactly 3 participants (0, 1, 2) cover Bitcoin → threshold met → available.
        let (_context, mut contract, _) = basic_setup_with_protocol(
            Protocol::CaitSith,
            dtos::DomainPurpose::ForeignTx,
            &mut OsRng,
        );
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        for account_id in participants.iter().take(3) {
            register_foreign_chains_config_for(
                &mut contract,
                account_id,
                [dtos::ForeignChain::Bitcoin],
            );
        }
        assert!(
            contract
                .get_available_foreign_chains()
                .contains(&dtos::ForeignChain::Bitcoin)
        );

        // Simulate resharing completion: the new Running state drops participant[2] and keeps
        // participant[3] (who has not registered any chain).  Participant[2]'s registration
        // entry is still in foreign_chains_configs — this is the stale data that
        // clean_foreign_chain_data must remove.
        let (domains, keyset) = {
            let ProtocolContractState::Running(ref state) = contract.protocol_state else {
                panic!("expected Running state");
            };
            (state.domains.clone(), state.keyset.clone())
        };
        let mut new_participants = {
            let ProtocolContractState::Running(ref state) = contract.protocol_state else {
                panic!("expected Running state");
            };
            state.parameters.participants().clone()
        };
        new_participants.remove(&participants[2]);
        // New Running: participants {0, 1, 3}, threshold 3.  Only 0 and 1 cover Bitcoin → 2 < 3.
        let new_params = GovernanceThresholdParameters::new_unvalidated(
            new_participants,
            GovernanceThreshold::new(3),
        );
        contract.protocol_state = ProtocolContractState::Running(RunningContractState::new(
            domains,
            keyset,
            new_params,
            AddDomainsVotes::default(),
        ));

        // When: vote_reshared recomputes the cache, then clean_foreign_chain_data
        // prunes participant[2]'s stale storage entry.
        contract.recompute_available_foreign_chains();
        contract
            .clean_foreign_chain_data()
            .expect("clean should succeed");

        // Then: 2 participants cover Bitcoin (< threshold 3) → no longer available.
        let available = contract.get_available_foreign_chains();
        assert!(!available.contains(&dtos::ForeignChain::Bitcoin));
        assert!(available.is_empty());
    }

    #[test]
    fn recompute_available_foreign_chains__should_update_cache_during_resharing() {
        // Given: Running contract with Bitcoin whitelisted; threshold 3, only 2 participants
        // registered → Bitcoin not yet available.
        let (_context, mut contract, _) = basic_setup_with_protocol(
            Protocol::CaitSith,
            dtos::DomainPurpose::ForeignTx,
            &mut OsRng,
        );
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        for account_id in participants.iter().take(2) {
            register_foreign_chains_config_for(
                &mut contract,
                account_id,
                [dtos::ForeignChain::Bitcoin],
            );
        }
        assert!(contract.get_available_foreign_chains().is_empty());

        // Transition to Resharing. Use the same participant set so mocked attestations remain valid.
        let resharing = {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running state");
            };
            let proposal = ProposedGovernanceThresholdParameters::new(
                state.parameters.clone(),
                BTreeMap::new(),
            );
            state
                .transition_to_resharing_no_checks(&proposal)
                .expect("contract has at least one domain")
        };
        contract.protocol_state = ProtocolContractState::Resharing(resharing);

        // When: the 3rd participant (from the old running set) registers during Resharing.
        register_foreign_chains_config_for(
            &mut contract,
            &participants[2],
            [dtos::ForeignChain::Bitcoin],
        );

        // Then: cache updated using the embedded previous running-state — Bitcoin now available.
        assert!(
            contract
                .get_available_foreign_chains()
                .contains(&dtos::ForeignChain::Bitcoin)
        );
    }

    #[test]
    fn recompute_available_foreign_chains__should_use_domain_threshold_not_governance_threshold() {
        // Given: 4 participants, governance threshold=3, ForeignTx domain reconstruction_threshold=2.
        // Only 2 supporters will register — below governance threshold but meets domain threshold.
        let contract_account_id = AccountId::from_str("contract_account.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .attached_deposit(NearToken::from_yoctonear(1))
                .predecessor_account_id(contract_account_id.clone())
                .current_account_id(contract_account_id)
                .build()
        );
        let domain_id = DomainId::default();
        let domains = vec![DomainConfig {
            id: domain_id,
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: dtos::DomainPurpose::ForeignTx,
        }];
        let (pk, _sk) = make_public_key_for_curve(Curve::Secp256k1, &mut OsRng);
        let key_for_domain = KeyForDomain {
            domain_id,
            key: pk.try_into().unwrap(),
            attempt: AttemptId::new(),
        };
        let keyset = Keyset::new(EpochId::new(0), vec![key_for_domain]);
        let parameters =
            GovernanceThresholdParameters::new(gen_participants(4), GovernanceThreshold::new(3))
                .unwrap();
        let mut contract = MpcContract::init_running(
            domains,
            1,
            (&keyset).into_dto_type(),
            (&parameters).into_dto_type(),
            None,
        )
        .unwrap();
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When: exactly 2 participants register Bitcoin (meets domain threshold=2, below governance threshold=3).
        register_foreign_chains_config_for(
            &mut contract,
            &participants[0],
            [dtos::ForeignChain::Bitcoin],
        );
        register_foreign_chains_config_for(
            &mut contract,
            &participants[1],
            [dtos::ForeignChain::Bitcoin],
        );

        // Then: Bitcoin is available — the ForeignTx domain threshold (2) is used, not governance (3).
        assert!(
            contract
                .get_available_foreign_chains()
                .contains(&dtos::ForeignChain::Bitcoin),
            "chain should be available at domain threshold=2 even though governance threshold=3"
        );
    }

    #[test]
    fn recompute_available_foreign_chains__should_use_max_threshold_across_foreign_tx_domains() {
        // Given
        // The lower-threshold domain is listed first so a regression to `.find()` would pick
        // threshold=2, whereas `.max()` across both foreign-tx domains picks threshold=3.
        let contract_account_id = AccountId::from_str("contract_account.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .attached_deposit(NearToken::from_yoctonear(1))
                .predecessor_account_id(contract_account_id.clone())
                .current_account_id(contract_account_id)
                .build()
        );
        let foreign_tx_domain = |id: u64, threshold: u64| DomainConfig {
            id: DomainId(id),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(threshold),
            purpose: dtos::DomainPurpose::ForeignTx,
        };
        let domains = vec![foreign_tx_domain(0, 2), foreign_tx_domain(1, 3)];
        let keys_for_domains = domains
            .iter()
            .map(|domain| {
                let (pk, _sk) = make_public_key_for_curve(Curve::Secp256k1, &mut OsRng);
                KeyForDomain {
                    domain_id: domain.id,
                    key: pk.try_into().unwrap(),
                    attempt: AttemptId::new(),
                }
            })
            .collect();
        let keyset = Keyset::new(EpochId::new(0), keys_for_domains);
        let parameters =
            GovernanceThresholdParameters::new(gen_participants(4), GovernanceThreshold::new(3))
                .unwrap();
        let mut contract = MpcContract::init_running(
            domains,
            2,
            (&keyset).into_dto_type(),
            (&parameters).into_dto_type(),
            None,
        )
        .unwrap();
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When
        let bitcoin_available = |contract: &MpcContract| {
            contract
                .get_available_foreign_chains()
                .contains(&dtos::ForeignChain::Bitcoin)
        };
        register_foreign_chains_config_for(
            &mut contract,
            &participants[0],
            [dtos::ForeignChain::Bitcoin],
        );
        register_foreign_chains_config_for(
            &mut contract,
            &participants[1],
            [dtos::ForeignChain::Bitcoin],
        );
        let available_below_threshold = bitcoin_available(&contract);
        register_foreign_chains_config_for(
            &mut contract,
            &participants[2],
            [dtos::ForeignChain::Bitcoin],
        );
        let available_at_threshold = bitcoin_available(&contract);

        // Then
        assert!(
            !available_below_threshold,
            "2 supporters is below the max foreign-tx threshold (3)"
        );
        assert!(
            available_at_threshold,
            "3 supporters meets the max foreign-tx threshold (3)"
        );
    }

    #[test]
    fn register_foreign_chains_config__should_succeed_for_new_participant_during_resharing() {
        // Given: Running contract; transition to Resharing whose proposed set adds a new participant
        // not present in the old running set.
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let (new_account_id, new_info) = gen_participant(100);
        let mut new_participants = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .clone();
        new_participants
            .insert(new_account_id.clone(), new_info)
            .expect("new participant should be inserted");
        let new_params = GovernanceThresholdParameters::new(
            new_participants.clone(),
            GovernanceThreshold::new(3),
        )
        .unwrap();
        let new_proposal = ProposedGovernanceThresholdParameters::new(new_params, BTreeMap::new());

        let resharing = {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running state");
            };
            state
                .transition_to_resharing_no_checks(&new_proposal)
                .expect("contract has at least one domain")
        };
        contract.protocol_state = ProtocolContractState::Resharing(resharing);
        // Provide mocked attestations for every participant in the proposed new set,
        // including the newly added one.
        contract.tee_state = TeeState::with_mocked_participant_attestations(&new_participants);

        // When: the new participant (not in the old running set) registers its foreign chain config.
        let foreign_chains_config: dtos::ForeignChainsConfig =
            BTreeSet::from([dtos::ForeignChain::Bitcoin]).into();
        let new_tls_key = new_participants
            .info(&new_account_id)
            .unwrap()
            .tls_public_key
            .clone();
        let mut env = Environment::new(None, Some(new_account_id.clone()), None);
        // Set the signer pk to the new participant's TLS key, which is also its account_public_key
        // in the mocked attestation, so lookup_node_id_by_signer_pk finds exactly this participant.
        env.set_pk(near_sdk::PublicKey::from(new_tls_key.clone()));

        // Then: the call succeeds — new participant is in the proposed set.
        contract
            .register_foreign_chains_config(foreign_chains_config)
            .expect("new participant should be able to register during Resharing");
        assert!(
            contract
                .foreign_chains
                .get()
                .foreign_chains_configs
                .contains_key(&new_tls_key),
            "config should be stored under the new participant's TLS key"
        );
    }

    #[test]
    fn register_foreign_chains_config__should_allow_two_nodes_from_same_operator_to_register_config()
     {
        // Given: Running contract; pick one operator account.
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let participants = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .clone();
        let (operator_account, _, info) = participants.participants().iter().next().unwrap();
        let tls_key_a = info.tls_public_key.clone();

        // Simulate a second node for the same operator with a distinct TLS key and signer pk.
        let tls_key_b = dtos::Ed25519PublicKey([99u8; 32]);
        let signer_pk_b = dtos::Ed25519PublicKey([98u8; 32]);
        contract.tee_state.stored_attestations.insert(
            tls_key_b.clone(),
            NodeAttestation {
                node_id: NodeId {
                    account_id: operator_account.clone(),
                    tls_public_key: tls_key_b.clone(),
                    account_public_key: signer_pk_b.clone(),
                },
                verified_attestation: VerifiedAttestation::Mock(MpcMockAttestation::Valid),
            },
        );

        // When: node A (the registered participant node) registers its config.
        register_foreign_chains_config_for(
            &mut contract,
            operator_account,
            [dtos::ForeignChain::Bitcoin],
        );

        // When: node B (the migration candidate, same operator) registers its config.
        let foreign_chains_config: dtos::ForeignChainsConfig =
            BTreeSet::from([dtos::ForeignChain::Bitcoin]).into();
        let mut env = Environment::new(None, Some(operator_account.clone()), None);
        env.set_pk(near_sdk::PublicKey::from(signer_pk_b));
        contract
            .register_foreign_chains_config(foreign_chains_config)
            .expect("second node from same operator should be able to register");

        // Then: both nodes' configs exist independently.
        let configs = &contract.foreign_chains.get().foreign_chains_configs;
        assert!(configs.contains_key(&tls_key_a), "node A config must exist");
        assert!(configs.contains_key(&tls_key_b), "node B config must exist");
    }
}
