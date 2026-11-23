//! Backup service registration through a TEE attestation, verified against the backup service's
//! own allowlists, kept apart from the MPC nodes' ones, and the views of registered backup
//! services.

mod allowlists;

use crate::errors::{Error, InvalidState};
use crate::tee::verification_context::VerificationContext;
use crate::{MpcContract, MpcContractExt};
use mpc_attestation::attestation::VerifiedQuote;
use near_mpc_contract_interface::types::{self as dtos, Ed25519PublicKey};
use near_sdk::{AccountId, PromiseError, PromiseOrValue, env, log, near};
use std::time::Duration;
use tee_verifier_interface::VerificationResultWithCollateralDates;

#[near]
impl MpcContract {
    /// Verify-quote callback for a backup service registration: on a verifier verdict it runs
    /// the post-DCAP checks against the backup service allowlists, stores the attestation and
    /// indexes it as the account's backup service. On any failure it fails the submitter's
    /// transaction.
    #[private]
    pub fn resolve_backup_service_verification(
        &mut self,
        #[serializer(borsh)] context: VerificationContext,
        #[serializer(borsh)]
        #[callback_result]
        result: Result<VerificationResultWithCollateralDates, PromiseError>,
    ) -> PromiseOrValue<()> {
        let account_id = context.node.account_id.clone();
        log!("resolve_backup_service_verification: account_id={account_id}");

        let registration_result = Self::quote_verdict(&account_id, result)
            .and_then(|quote| self.verify_post_dcap_and_store_backup_service(context, &quote));
        self.fail_submission_on_err(registration_result)
    }

    /// Returns the account's backup service only while its attestation is valid, so MPC nodes
    /// export keyshares to this key alone. Unlike [`MpcContract::migration_info`], it never
    /// returns an unattested or expired key.
    pub fn attested_backup_service(
        &self,
        account_id: AccountId,
    ) -> Option<dtos::BackupServiceInfo> {
        let node = self.node_migrations.backup_service_of(&account_id)?;
        self.node_migrations
            .backup_service_tee_state
            .has_valid_attestation(
                node,
                Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds),
            )
            .then(|| dtos::BackupServiceInfo {
                public_key: node.tls_public_key.clone(),
            })
    }

    /// Returns the attestation stored for the backup service with the given TLS key, like
    /// [`MpcContract::get_attestation`] does for MPC nodes.
    pub fn get_backup_service_attestation(
        &self,
        tls_public_key: Ed25519PublicKey,
    ) -> Option<dtos::StoredAttestation> {
        self.node_migrations
            .backup_service_tee_state
            .get_attestation(&tls_public_key)
    }

    /// Scans up to the given number of stored backup services and removes those whose attestation
    /// fails re-verification, together with their owners' [`MpcContract::migration_info`] keys.
    /// Gives one attestation-storage grant back to each owner and returns the number of backup
    /// services removed. Callable by anyone in any protocol state.
    pub fn reverify_backup_services(&mut self, max_scan: u32) -> u32 {
        log!(
            "reverify_backup_services: signer={}, max_scan={max_scan}",
            env::signer_account_id()
        );
        let removed_entry_owners = self.node_migrations.remove_invalid_backup_services(
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds),
            max_scan,
        );
        self.return_attestation_storage_grants(&removed_entry_owners)
    }

    /// Re-checks the registration before storing, since this runs a receipt later than the
    /// submission, and a failed callback still commits what it wrote.
    fn verify_post_dcap_and_store_backup_service(
        &mut self,
        VerificationContext { node, tcb_info }: VerificationContext,
        quote: &VerifiedQuote,
    ) -> Result<(), Error> {
        let account_id = node.account_id.clone();
        let tls_public_key = node.tls_public_key.clone();
        let replaced = self.authorize_backup_service_registration(&account_id, &tls_public_key)?;
        self.node_migrations
            .backup_service_tee_state
            .verify_and_store_dstack(
                node,
                &tcb_info,
                &quote.report,
                &quote.collateral_dates,
                Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds),
            )
            .inspect_err(|err| log!("post-DCAP check failed for {account_id}: {err}"))?;
        self.record_backup_service(account_id, tls_public_key, replaced);
        Ok(())
    }

    /// Returns the TLS key of the account's attested backup service, which the registration
    /// replaces. Without one, the registration needs an attestation-storage grant.
    fn authorize_backup_service_registration(
        &self,
        account_id: &AccountId,
        tls_public_key: &Ed25519PublicKey,
    ) -> Result<Option<Ed25519PublicKey>, Error> {
        if !self
            .protocol_state
            .is_existing_or_prospective_participant(account_id)?
        {
            return Err(InvalidState::NotParticipant {
                account_id: account_id.clone(),
            }
            .into());
        }
        self.node_migrations
            .backup_service_tee_state
            .assert_tls_key_claimable(account_id, tls_public_key)?;
        let replaced = self
            .node_migrations
            .backup_service_of(account_id)
            .map(|node| node.tls_public_key.clone());
        if replaced.is_none() {
            self.assert_grant_available(account_id)?;
        }
        Ok(replaced)
    }

    /// Consumes a grant only for an account without an attested backup service, so each account
    /// holds at most one backup service node, paid for by one grant.
    fn record_backup_service(
        &mut self,
        account_id: AccountId,
        tls_public_key: Ed25519PublicKey,
        replaced: Option<Ed25519PublicKey>,
    ) {
        if replaced.is_none() {
            self.consume_attestation_storage_grant(&account_id);
        }
        self.node_migrations
            .set_backup_service(account_id, tls_public_key, replaced.as_ref());
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::{
        freshly_initialized_contract, prepare_dstack_verification, running_state,
        setup_tee_test_contract, verified_verdict, with_dstack_fixture_participant,
    };
    use crate::primitives::test_utils::{
        bogus_ed25519_public_key, create_node, gen_account_id, gen_participants, node_for,
    };
    use crate::tee::attested_service::AttestedService;
    use crate::tee::test_utils::{
        LAUNCHER_TTL, NANOS_PER_SECOND, NEWEST_LAUNCHER_ADDED_AT_SECS, OLD_LAUNCHER_ADDED_AT_SECS,
        after_retention, allow_launcher, dstack_fixture_node, dummy_code_hash, dummy_launcher_hash,
        index_backup_service, launcher_mock, set_block_secs, store_backup_service,
    };
    use mpc_attestation::attestation::{MOCK_EXPIRATION_DURATION_SECONDS, MockAttestation};
    use near_mpc_contract_interface::types::BackupServiceInfo;
    use near_sdk::{test_utils::VMContextBuilder, testing_env};
    use rstest::rstest;
    use std::{assert_matches, collections::BTreeMap};

    #[derive(Debug, PartialEq)]
    struct Registrations {
        migration_info: dtos::MigrationInfo,
        backup_service_nodes: Vec<dtos::NodeInfo>,
        mpc_nodes: Vec<dtos::NodeInfo>,
        fixture_account_grants: u32,
    }

    fn registrations(contract: &MpcContract) -> Registrations {
        Registrations {
            migration_info: contract.migration_info(),
            backup_service_nodes: contract
                .node_migrations
                .backup_service_tee_state
                .get_tee_accounts(),
            mpc_nodes: contract.get_tee_accounts(),
            fixture_account_grants: contract
                .available_attestation_grants(dstack_fixture_node().account_id),
        }
    }

    fn migration_info_of(backup_services: &[dtos::NodeInfo]) -> dtos::MigrationInfo {
        backup_services
            .iter()
            .map(|node| {
                (
                    node.account_id.clone(),
                    (
                        Some(BackupServiceInfo {
                            public_key: node.tls_public_key.clone(),
                        }),
                        None,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>()
            .into()
    }

    /// A contract in which the Dstack fixture's account is a participant with one grant, ready to
    /// run the fixture's verification against the allowlists of `whitelisted`.
    fn backup_service_verification_setup(
        whitelisted: AttestedService,
    ) -> (MpcContract, VerificationContext) {
        let mut contract =
            freshly_initialized_contract(&with_dstack_fixture_participant(&gen_participants(2)), 2);
        let context = prepare_dstack_verification(&mut contract, whitelisted);
        (contract, context)
    }

    fn store_mpc_node(contract: &mut MpcContract, node: dtos::NodeInfo) {
        contract
            .tee_state
            .verify_and_store_mock(node, MockAttestation::Valid, Duration::MAX)
            .unwrap();
    }

    fn fixture_node_under_another_key() -> dtos::NodeInfo {
        dtos::NodeInfo {
            tls_public_key: bogus_ed25519_public_key(),
            ..dstack_fixture_node()
        }
    }

    #[rstest]
    #[case::first_registration(|_: &mut MpcContract| vec![], 1)]
    #[case::reattestation(
        |contract: &mut MpcContract| {
            store_backup_service(contract, dstack_fixture_node());
            vec![]
        },
        0
    )]
    #[case::rotation(
        |contract: &mut MpcContract| {
            store_backup_service(contract, fixture_node_under_another_key());
            vec![]
        },
        0
    )]
    #[case::replacing_a_soft_launch_key(
        |contract: &mut MpcContract| {
            index_backup_service(contract, &fixture_node_under_another_key());
            vec![]
        },
        1
    )]
    #[case::soft_launch_key_now_attested(
        |contract: &mut MpcContract| {
            index_backup_service(contract, &dstack_fixture_node());
            vec![]
        },
        1
    )]
    #[case::soft_launch_key_naming_another_accounts_node(
        |contract: &mut MpcContract| {
            let other_accounts_node = create_node(&gen_account_id(), &bogus_ed25519_public_key());
            store_backup_service(contract, other_accounts_node.clone());
            index_backup_service(
                contract,
                &dtos::NodeInfo {
                    tls_public_key: other_accounts_node.tls_public_key.clone(),
                    ..dstack_fixture_node()
                },
            );
            vec![other_accounts_node]
        },
        1
    )]
    fn resolve_backup_service_verification__should_store_the_backup_service(
        #[case] register_earlier: fn(&mut MpcContract) -> Vec<dtos::NodeInfo>,
        #[case] grants: u32,
    ) {
        // Given
        let (mut contract, context) =
            backup_service_verification_setup(AttestedService::BackupService);
        contract
            .available_attestation_grants
            .insert(context.node.account_id.clone(), grants);
        let backup_service_nodes =
            [register_earlier(&mut contract), vec![context.node.clone()]].concat();

        // When
        let result = contract.resolve_backup_service_verification(context, Ok(verified_verdict()));

        // Then
        assert_eq!(
            (
                matches!(result, PromiseOrValue::Value(())),
                registrations(&contract)
            ),
            (
                true,
                Registrations {
                    migration_info: migration_info_of(&backup_service_nodes),
                    backup_service_nodes,
                    mpc_nodes: vec![],
                    fixture_account_grants: 0,
                }
            )
        );
    }

    #[rstest]
    #[case::grant_spent(
        AttestedService::BackupService,
        |contract: &mut MpcContract| {
            contract
                .available_attestation_grants
                .remove(&dstack_fixture_node().account_id);
        }
    )]
    #[case::not_a_participant(
        AttestedService::BackupService,
        |contract: &mut MpcContract| contract.protocol_state = running_state()
    )]
    #[case::tls_key_of_another_account(
        AttestedService::BackupService,
        |contract: &mut MpcContract| {
            store_backup_service(
                contract,
                create_node(&gen_account_id(), &dstack_fixture_node().tls_public_key),
            )
        }
    )]
    #[case::only_mpc_node_allowlists_match(AttestedService::MpcNode, |_: &mut MpcContract| {})]
    fn resolve_backup_service_verification__should_store_nothing_and_fail_the_submission(
        #[case] whitelisted: AttestedService,
        #[case] intervene: fn(&mut MpcContract),
    ) {
        // Given
        let (mut contract, context) = backup_service_verification_setup(whitelisted);
        intervene(&mut contract);
        let registrations_before = registrations(&contract);

        // When
        let result = contract.resolve_backup_service_verification(context, Ok(verified_verdict()));

        // Then
        assert_eq!(
            (
                matches!(result, PromiseOrValue::Promise(_)),
                registrations(&contract)
            ),
            (true, registrations_before)
        );
    }

    #[rstest]
    #[case::unregistered(|_: &mut MpcContract| {}, false)]
    #[case::soft_launch_key(
        |contract: &mut MpcContract| index_backup_service(contract, &dstack_fixture_node()),
        false
    )]
    #[case::key_owned_by_another_account(
        |contract: &mut MpcContract| {
            store_backup_service(
                contract,
                create_node(&gen_account_id(), &dstack_fixture_node().tls_public_key),
            );
            index_backup_service(contract, &dstack_fixture_node());
        },
        false
    )]
    #[case::key_attested_as_mpc_node(
        |contract: &mut MpcContract| {
            store_mpc_node(contract, dstack_fixture_node());
            index_backup_service(contract, &dstack_fixture_node());
        },
        false
    )]
    #[case::expired(
        |contract: &mut MpcContract| {
            store_backup_service(contract, dstack_fixture_node());
            set_block_secs(MOCK_EXPIRATION_DURATION_SECONDS + 1);
        },
        false
    )]
    #[case::valid(
        |contract: &mut MpcContract| store_backup_service(contract, dstack_fixture_node()),
        true
    )]
    fn attested_backup_service__should_return_only_a_valid_attested_key(
        #[case] register: fn(&mut MpcContract),
        #[case] attested: bool,
    ) {
        // Given
        set_block_secs(0);
        let mut contract = MpcContract::new_from_protocol_state(running_state());
        register(&mut contract);
        let node = dstack_fixture_node();

        // When
        let backup_service = contract.attested_backup_service(node.account_id);

        // Then
        assert_eq!(
            backup_service,
            attested.then_some(BackupServiceInfo {
                public_key: node.tls_public_key,
            })
        );
    }

    #[rstest]
    #[case::valid(0, false)]
    #[case::expired(MOCK_EXPIRATION_DURATION_SECONDS + 1, true)]
    fn reverify_backup_services__should_remove_only_an_invalid_backup_service_and_return_its_grant(
        #[case] reverified_at_secs: u64,
        #[case] expired: bool,
    ) {
        // Given
        set_block_secs(0);
        let mut contract = MpcContract::new_from_protocol_state(running_state());
        let node = dstack_fixture_node();
        store_backup_service(&mut contract, node.clone());
        store_mpc_node(&mut contract, node.clone());
        set_block_secs(reverified_at_secs);
        let other_accounts_node = create_node(&gen_account_id(), &bogus_ed25519_public_key());
        store_backup_service(&mut contract, other_accounts_node.clone());

        // When
        let removed = contract.reverify_backup_services(u32::MAX);

        // Then
        let kept_backup_services: Vec<_> = (!expired)
            .then(|| node.clone())
            .into_iter()
            .chain([other_accounts_node])
            .collect();
        assert_eq!(
            (removed, registrations(&contract)),
            (
                u32::from(expired),
                Registrations {
                    migration_info: migration_info_of(&kept_backup_services),
                    backup_service_nodes: kept_backup_services,
                    mpc_nodes: vec![node],
                    fixture_account_grants: u32::from(expired),
                }
            )
        );
    }

    #[rstest]
    #[case::attested(|contract: &mut MpcContract, _: &dtos::NodeInfo| {
        store_backup_service(contract, dstack_fixture_node());
    }, 1)]
    #[case::soft_launch_key(|contract: &mut MpcContract, _: &dtos::NodeInfo| {
        index_backup_service(contract, &dstack_fixture_node());
    }, 0)]
    #[case::soft_launch_key_naming_a_participants_node(
        |contract: &mut MpcContract, participants_node: &dtos::NodeInfo| {
            index_backup_service(
                contract,
                &dtos::NodeInfo {
                    tls_public_key: participants_node.tls_public_key.clone(),
                    ..dstack_fixture_node()
                },
            );
        },
        0
    )]
    fn cleanup_orphaned_node_migrations__should_remove_a_departed_operators_backup_service_and_return_its_grant(
        #[case] register_departed: fn(&mut MpcContract, &dtos::NodeInfo),
        #[case] returned_grants: u32,
    ) {
        // Given
        let mut contract = MpcContract::new_from_protocol_state(running_state());
        let (participant, _, _) = &contract.protocol_state.active_participants().participants()[0];
        let participants_node = node_for(participant);
        store_backup_service(&mut contract, participants_node.clone());
        register_departed(&mut contract, &participants_node);

        // When
        let result = contract.cleanup_orphaned_node_migrations();

        // Then
        let kept_backup_services = vec![participants_node];
        assert_eq!(
            (result, registrations(&contract)),
            (
                Ok(()),
                Registrations {
                    migration_info: migration_info_of(&kept_backup_services),
                    backup_service_nodes: kept_backup_services,
                    mpc_nodes: vec![],
                    fixture_account_grants: returned_grants,
                }
            )
        );
    }

    #[rstest]
    #[case::indexed(dstack_fixture_node(), true)]
    #[case::not_indexed_key(fixture_node_under_another_key(), false)]
    fn verify_tee__should_keep_the_launcher_a_registered_backup_service_uses(
        #[case] indexed: dtos::NodeInfo,
        #[case] attested_launcher_kept: bool,
    ) {
        // Given
        let code_hash = dummy_code_hash(1);
        let attested = dummy_launcher_hash(1);
        let unused = dummy_launcher_hash(2);
        let (mut contract, _, account_id) = setup_tee_test_contract(3, 2);
        contract.config.launcher_hash_unused_ttl_seconds = LAUNCHER_TTL.as_secs();
        index_backup_service(&mut contract, &indexed);
        let tee_state = &mut contract.node_migrations.backup_service_tee_state;
        set_block_secs(OLD_LAUNCHER_ADDED_AT_SECS);
        allow_launcher(tee_state, attested, code_hash, LAUNCHER_TTL);
        tee_state
            .verify_and_store_mock(
                dstack_fixture_node(),
                launcher_mock(&attested, &code_hash),
                Duration::MAX,
            )
            .unwrap();
        set_block_secs(NEWEST_LAUNCHER_ADDED_AT_SECS);
        allow_launcher(tee_state, unused, code_hash, LAUNCHER_TTL);
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id)
                .block_timestamp(after_retention(NEWEST_LAUNCHER_ADDED_AT_SECS) * NANOS_PER_SECOND)
                .build()
        );

        // When
        let result = contract.verify_tee();

        // Then
        assert_matches!(result, Ok(true));
        assert_eq!(
            contract.allowed_backup_service_launcher_image_hashes(),
            vec![if attested_launcher_kept {
                attested
            } else {
                unused
            }]
        );
    }

    #[test]
    fn backup_service_views__should_keep_their_json_format() {
        // Given
        let (mut contract, context) =
            backup_service_verification_setup(AttestedService::BackupService);
        let node = context.node.clone();
        let _ = contract.resolve_backup_service_verification(context, Ok(verified_verdict()));

        // When
        let views = serde_json::json!({
            "attested_backup_service": contract.attested_backup_service(node.account_id),
            "get_backup_service_attestation":
                contract.get_backup_service_attestation(node.tls_public_key),
        });

        // Then
        insta::assert_json_snapshot!(views);
    }
}
