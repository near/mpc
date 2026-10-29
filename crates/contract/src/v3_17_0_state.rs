//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::VerifiedAttestation;
use near_mpc_contract_interface::types::{
    self as dtos, CKDRequest, ForeignChain, SignatureRequest, VerifyForeignTransactionRequest,
    YieldIndex,
};
use near_sdk::{
    AccountId, log, require,
    store::{IterableMap, Lazy, LookupMap},
};

use crate::{
    config::{
        Config, DEFAULT_CLEAN_FOREIGN_CHAIN_DATA_TERA_GAS,
        DEFAULT_CLEANUP_ORPHANED_NODE_MIGRATIONS_TERA_GAS, DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS,
    },
    foreign_chain_rpc::ChainEntry,
    foreign_chains_metadata::ForeignChainsMetadata,
    node_migrations::NodeMigrations,
    primitives::{
        key_state::{AuthenticatedAccountId, AuthenticatedParticipantId},
        votes::Votes,
    },
    state::ProtocolContractState,
    storage_keys::StorageKey,
    tee::{
        measurements::AllowedMeasurements,
        proposal::{AllowedLauncherImages, StoredDockerImageHashes},
        tee_state::{Node, NodeId, TeeState},
        verifier_votes::TeeVerifierVotes,
    },
    update::ContractUpdateVotes,
};

/// Shadow of the `3.17.0` `LauncherHashVotes` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldLauncherHashVotes {
    vote_by_account: BTreeMap<AuthenticatedParticipantId, dtos::LauncherVoteAction>,
}

/// Shadow of the `3.17.0` `MeasurementVotes` layout.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldMeasurementVotes {
    vote_by_account: BTreeMap<AuthenticatedParticipantId, dtos::MeasurementVoteAction>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldTeeState {
    allowed_docker_image_hashes: StoredDockerImageHashes,
    allowed_launcher_images: AllowedLauncherImages,
    votes: Votes<AuthenticatedAccountId>,
    launcher_votes: OldLauncherHashVotes,
    stored_attestations: IterableMap<dtos::Ed25519PublicKey, OldNodeAttestation>,
    allowed_measurements: AllowedMeasurements,
    measurement_votes: OldMeasurementVotes,
}

impl OldTeeState {
    fn migrate(self) -> TeeState {
        let nodes = migrate_stored_attestations(self.stored_attestations);
        // Pending votes are dropped rather than migrated; participants re-vote after the
        // upgrade.
        TeeState {
            allowed_docker_image_hashes: self.allowed_docker_image_hashes,
            allowed_launcher_images: self.allowed_launcher_images,
            votes: self.votes,
            launcher_votes: Votes::new(
                StorageKey::LauncherHashVotesByVoter,
                StorageKey::LauncherHashVotesByProposal,
            ),
            nodes,
            allowed_measurements: self.allowed_measurements,
            measurement_votes: Votes::new(
                StorageKey::MeasurementVotesByVoter,
                StorageKey::MeasurementVotesByProposal,
            ),
        }
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct OldNodeAttestation {
    node_id: NodeId,
    verified_attestation: VerifiedAttestation,
    accepted_at_seconds: Option<u64>,
}

fn migrate_stored_attestations(
    mut old: IterableMap<dtos::Ed25519PublicKey, OldNodeAttestation>,
) -> IterableMap<dtos::Ed25519PublicKey, Node> {
    let entries: Vec<_> = old.drain().collect();
    // The rebuilt map shares the storage prefix, so its inserts would read the drained entries
    // back from storage until the removals are written
    old.flush();

    let mut migrated = IterableMap::new(StorageKey::Nodes);
    for (tls_public_key, entry) in entries {
        if let Some(accepted_at_seconds) = entry.accepted_at_seconds {
            migrated.insert(
                tls_public_key,
                Node::new(
                    entry.node_id,
                    entry.verified_attestation,
                    accepted_at_seconds,
                ),
            );
        }
    }
    migrated
}

fn relax_rpc_whitelist(foreign_chains: &mut ForeignChainsMetadata) {
    let whitelist = &mut foreign_chains.rpc_whitelist;
    for (chain, entry) in whitelist.entries.snapshot() {
        if chain == ForeignChain::Bitcoin {
            whitelist.entries.remove(&chain);
            continue;
        }
        let relaxed = dtos::ChainEntry {
            quorum: entry.quorum.saturating_sub(1).max(1),
            ..entry
        };
        match ChainEntry::try_from(relaxed) {
            Ok(relaxed) => whitelist.entries.replace(chain, relaxed),
            Err(err) => log!("keeping {chain:?} whitelist entry unchanged: {err}"),
        }
    }
    whitelist
        .votes
        .pending
        .retain_votes(|(_, chain)| *chain != ForeignChain::Bitcoin);
    foreign_chains
        .available_foreign_chains
        .remove(&ForeignChain::Bitcoin);
}

/// Keep this module in sync with [`crate::MpcContract`]: the moment a field's borsh
/// layout diverges, shadow the old type here (see earlier `v*_state.rs` modules in git history
/// for examples) so state written by the `3.17.0` contract still deserializes during migration.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    contract_update_votes: ContractUpdateVotes,
    config: Config,
    tee_state: OldTeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    tee_verifier_account_id: AccountId,
    tee_verifier_votes: TeeVerifierVotes,
    available_attestation_grants: IterableMap<AccountId, u32>,
}

impl From<MpcContract> for crate::MpcContract {
    fn from(old: MpcContract) -> Self {
        require!(
            matches!(old.protocol_state, ProtocolContractState::Running(_)),
            "Contract must be in running state when migrating."
        );

        // Stored budgets were too low for the mainnet state; raise them to at least the new
        // defaults but keep an operator-set higher value.
        let mut config = old.config;
        config.cleanup_orphaned_node_migrations_tera_gas = config
            .cleanup_orphaned_node_migrations_tera_gas
            .max(DEFAULT_CLEANUP_ORPHANED_NODE_MIGRATIONS_TERA_GAS);
        config.clean_foreign_chain_data_tera_gas = config
            .clean_foreign_chain_data_tera_gas
            .max(DEFAULT_CLEAN_FOREIGN_CHAIN_DATA_TERA_GAS);
        config.key_event_timeout_blocks = config
            .key_event_timeout_blocks
            .max(DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS);

        let tee_state = old.tee_state.migrate();
        let mut foreign_chains = old.foreign_chains;
        relax_rpc_whitelist(foreign_chains.get_mut());
        crate::MpcContract {
            protocol_state: old.protocol_state,
            pending_signature_requests: old.pending_signature_requests,
            pending_ckd_requests: old.pending_ckd_requests,
            pending_verify_foreign_tx_requests: old.pending_verify_foreign_tx_requests,
            contract_update_votes: old.contract_update_votes,
            config,
            tee_state,
            accept_requests: old.accept_requests,
            node_migrations: old.node_migrations,
            foreign_chains,
            tee_verifier_account_id: old.tee_verifier_account_id,
            tee_verifier_votes: old.tee_verifier_votes,
            available_attestation_grants: old.available_attestation_grants,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::proposal_hash::ToProposalHash;
    use crate::primitives::test_utils::{gen_authenticated_participants, node_id_for};
    use crate::state::test_utils::gen_running_state;
    use mpc_attestation::attestation::MockAttestation;
    use near_mpc_contract_interface::types::{
        AuthScheme, ChainRouting, ProviderConfig, ProviderId,
    };
    use near_sdk::{test_utils::VMContextBuilder, testing_env};
    use std::collections::BTreeSet;

    fn chain_entry(provider_count: usize, quorum: u64) -> dtos::ChainEntry {
        let providers: BTreeMap<_, _> = (0..provider_count)
            .map(|i| {
                (
                    ProviderId(format!("provider{i}")),
                    ProviderConfig {
                        base_url: format!("https://provider{i}.example.com"),
                        auth_scheme: AuthScheme::None,
                        chain_routing: ChainRouting::Embedded,
                    },
                )
            })
            .collect();
        dtos::ChainEntry {
            providers: providers.try_into().unwrap(),
            quorum,
        }
    }

    fn whitelisted(entries: &[(ForeignChain, dtos::ChainEntry)]) -> ForeignChainsMetadata {
        let mut metadata = ForeignChainsMetadata::default();
        for (chain, entry) in entries {
            metadata
                .rpc_whitelist
                .entries
                .replace(*chain, entry.clone().try_into().unwrap());
        }
        metadata
    }

    fn old_contract(config: Config) -> MpcContract {
        MpcContract {
            protocol_state: ProtocolContractState::Running(gen_running_state(1)),
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV4),
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequestsV3),
            pending_verify_foreign_tx_requests: LookupMap::new(
                StorageKey::PendingVerifyForeignTxRequestsV3,
            ),
            contract_update_votes: ContractUpdateVotes::default(),
            config,
            tee_state: OldTeeState {
                allowed_docker_image_hashes: Default::default(),
                allowed_launcher_images: Default::default(),
                votes: Votes::new(
                    StorageKey::CodeHashVotesByVoter,
                    StorageKey::CodeHashVotesByProposal,
                ),
                launcher_votes: OldLauncherHashVotes {
                    vote_by_account: BTreeMap::new(),
                },
                stored_attestations: IterableMap::new(StorageKey::Nodes),
                allowed_measurements: Default::default(),
                measurement_votes: OldMeasurementVotes {
                    vote_by_account: BTreeMap::new(),
                },
            },
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
            foreign_chains: Lazy::new(
                StorageKey::ForeignChainMetadata,
                ForeignChainsMetadata::default(),
            ),
            tee_verifier_account_id: "verifier.near".parse().unwrap(),
            tee_verifier_votes: TeeVerifierVotes::default(),
            available_attestation_grants: IterableMap::new(StorageKey::AttestationGrants),
        }
    }

    #[test]
    fn from__should_raise_cleanup_gas_budgets_to_the_defaults() {
        // Given a stored config with the pre-3.18 budgets
        testing_env!(VMContextBuilder::new().build());
        let stored = Config {
            cleanup_orphaned_node_migrations_tera_gas: 3,
            clean_foreign_chain_data_tera_gas: 5,
            ..Default::default()
        };

        // When
        let migrated: crate::MpcContract = old_contract(stored.clone()).into();

        // Then only the two budgets change
        let expected = Config {
            cleanup_orphaned_node_migrations_tera_gas:
                DEFAULT_CLEANUP_ORPHANED_NODE_MIGRATIONS_TERA_GAS,
            clean_foreign_chain_data_tera_gas: DEFAULT_CLEAN_FOREIGN_CHAIN_DATA_TERA_GAS,
            ..stored
        };
        assert_eq!(migrated.config, expected);
    }

    #[test]
    fn from__should_keep_cleanup_gas_budgets_above_the_defaults() {
        // Given a stored config an operator already raised
        testing_env!(VMContextBuilder::new().build());
        let stored = Config {
            cleanup_orphaned_node_migrations_tera_gas:
                DEFAULT_CLEANUP_ORPHANED_NODE_MIGRATIONS_TERA_GAS + 1,
            clean_foreign_chain_data_tera_gas: DEFAULT_CLEAN_FOREIGN_CHAIN_DATA_TERA_GAS + 1,
            ..Default::default()
        };

        // When
        let migrated: crate::MpcContract = old_contract(stored.clone()).into();

        // Then
        assert_eq!(migrated.config, stored);
    }

    #[test]
    fn from__should_raise_key_event_timeout_to_the_default() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let stored = Config {
            key_event_timeout_blocks: 30,
            ..Default::default()
        };

        // When
        let migrated: crate::MpcContract = old_contract(stored.clone()).into();

        // Then
        let expected = Config {
            key_event_timeout_blocks: DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS,
            ..stored
        };
        assert_eq!(migrated.config, expected);
    }

    #[test]
    fn from__should_keep_key_event_timeout_above_the_default() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let stored = Config {
            key_event_timeout_blocks: DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS + 1,
            ..Default::default()
        };

        // When
        let migrated: crate::MpcContract = old_contract(stored.clone()).into();

        // Then
        assert_eq!(migrated.config, stored);
    }

    #[test]
    fn from__should_relax_rpc_whitelist() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let mut old = old_contract(Config::default());
        old.foreign_chains = Lazy::new(
            StorageKey::ForeignChainMetadata,
            whitelisted(&[
                (ForeignChain::Bitcoin, chain_entry(1, 1)),
                (ForeignChain::Base, chain_entry(3, 3)),
            ]),
        );

        // When
        let migrated: crate::MpcContract = old.into();

        // Then
        let expected = BTreeMap::from([(ForeignChain::Base, chain_entry(3, 2))]);
        assert_eq!(
            migrated
                .foreign_chains
                .get()
                .rpc_whitelist
                .entries
                .snapshot(),
            expected
        );
    }

    #[test]
    fn relax_rpc_whitelist__should_lower_each_quorum_by_one() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let mut metadata = whitelisted(&[
            (ForeignChain::Solana, chain_entry(4, 3)),
            (ForeignChain::Base, chain_entry(3, 3)),
            (ForeignChain::Fogo, chain_entry(2, 2)),
            (ForeignChain::Ton, chain_entry(1, 1)),
        ]);

        // When
        relax_rpc_whitelist(&mut metadata);

        // Then
        let expected = BTreeMap::from([
            (ForeignChain::Solana, chain_entry(4, 2)),
            (ForeignChain::Base, chain_entry(3, 2)),
            (ForeignChain::Fogo, chain_entry(2, 1)),
            (ForeignChain::Ton, chain_entry(1, 1)),
        ]);
        assert_eq!(metadata.rpc_whitelist.entries.snapshot(), expected);
    }

    #[test]
    fn relax_rpc_whitelist__should_drop_bitcoin() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let mut metadata = whitelisted(&[
            (ForeignChain::Bitcoin, chain_entry(1, 1)),
            (ForeignChain::Base, chain_entry(3, 3)),
        ]);
        let (_, auth_ids) = gen_authenticated_participants(1);
        let proposal = ChainEntry::try_from(chain_entry(2, 2))
            .unwrap()
            .to_proposal_hash();
        for chain in [ForeignChain::Bitcoin, ForeignChain::Base] {
            metadata
                .rpc_whitelist
                .votes
                .pending
                .vote((auth_ids[0].clone(), chain), proposal);
        }
        metadata.available_foreign_chains =
            BTreeSet::from([ForeignChain::Bitcoin, ForeignChain::Base]).into();

        // When
        relax_rpc_whitelist(&mut metadata);

        // Then
        let whitelisted_chains: Vec<_> = metadata
            .rpc_whitelist
            .entries
            .snapshot()
            .into_keys()
            .collect();
        assert_eq!(whitelisted_chains, vec![ForeignChain::Base]);
        let pending_chains: Vec<_> = metadata
            .rpc_whitelist
            .votes
            .pending
            .all()
            .into_values()
            .flatten()
            .map(|(_, chain)| chain)
            .collect();
        assert_eq!(pending_chains, vec![ForeignChain::Base]);
        assert_eq!(
            metadata.available_foreign_chains,
            BTreeSet::from([ForeignChain::Base]).into()
        );
    }

    #[test]
    fn migrate_stored_attestations__should_evict_entries_without_an_acceptance_time() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let accepted_at = 1_800_000_000;
        let stamped = node_id_for(&"alice.near".parse().unwrap());
        let unstamped = node_id_for(&"bob.near".parse().unwrap());
        let mut old = IterableMap::new(StorageKey::Nodes);
        for (node_id, accepted_at_seconds) in [(&stamped, Some(accepted_at)), (&unstamped, None)] {
            old.insert(
                node_id.tls_public_key.clone(),
                OldNodeAttestation {
                    node_id: node_id.clone(),
                    verified_attestation: VerifiedAttestation::Mock(MockAttestation::Valid),
                    accepted_at_seconds,
                },
            );
        }
        old.flush();

        // When
        let migrated = migrate_stored_attestations(old);

        // Then
        let migrated: Vec<_> = migrated
            .values()
            .map(|node| (node.id(), node.attestation_accepted_at_seconds))
            .collect();
        assert_eq!(migrated, vec![(stamped, accepted_at)]);
    }
}
