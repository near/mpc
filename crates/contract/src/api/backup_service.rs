//! Backup service registration through a TEE attestation, verified against the backup service's
//! own allowlists, kept apart from the MPC nodes' ones.

mod allowlists;

use crate::errors::{Error, InvalidState};
use crate::tee::verification_context::VerificationContext;
use crate::{MpcContract, MpcContractExt};
use mpc_attestation::attestation::VerifiedQuote;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_sdk::{AccountId, PromiseError, PromiseOrValue, log, near};
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
        freshly_initialized_contract, prepare_dstack_verification, running_state, verified_verdict,
        with_dstack_fixture_participant,
    };
    use crate::primitives::test_utils::{
        bogus_ed25519_public_key, create_node, gen_account_id, gen_participants,
    };
    use crate::tee::attested_service::AttestedService;
    use crate::tee::test_utils::dstack_fixture_node;
    use mpc_attestation::attestation::MockAttestation;
    use near_mpc_contract_interface::types::{self as dtos, BackupServiceInfo};
    use rstest::rstest;
    use std::collections::BTreeMap;

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

    fn index_backup_service(contract: &mut MpcContract, node: &dtos::NodeInfo) {
        contract.node_migrations.set_backup_service(
            node.account_id.clone(),
            node.tls_public_key.clone(),
            None,
        );
    }

    fn store_backup_service(contract: &mut MpcContract, node: dtos::NodeInfo) {
        index_backup_service(contract, &node);
        contract
            .node_migrations
            .backup_service_tee_state
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
}
