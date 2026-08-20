// applied on module since near proc macro is unable to apply the expect lint
#![expect(deprecated, reason = "ForeignChainConfiguration is being deprecated")]
#![doc = include_str!("../README.md")]

pub mod api;
pub mod config;
pub mod crypto_shared;
pub mod errors;
pub mod foreign_chain_rpc;
pub mod foreign_chains_metadata;
pub mod node_migrations;
pub mod primitives;
pub mod state;
pub mod storage_keys;
pub mod tee;
pub mod update;
#[cfg(feature = "dev-utils")]
pub mod utils;

pub mod v3_14_0_state;

#[cfg(feature = "bench-contract-methods")]
mod bench;
mod dto_mapping;
mod pending_requests;
#[cfg(feature = "sandbox-test-methods")]
mod sandbox_test_methods;

/// Re-export of the fan-out cap so sandbox tests can lock against the same source of
/// truth as the contract rather than duplicating the literal.
#[cfg(feature = "sandbox-test-methods")]
pub use crate::pending_requests::MAX_PENDING_REQUEST_FAN_OUT;

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use crate::{
    dto_mapping::{IntoInterfaceType, TryIntoContractType, args_into_verify_foreign_tx_request},
    errors::Error,
    foreign_chains_metadata::ForeignChainsMetadata,
    primitives::ckd::CKDRequest,
    storage_keys::StorageKey,
    tee::tee_state::{AttestationSubmissionError, ParticipantInsertion, TeeState},
    tee::verification_context::VerificationContext,
    tee::verifier_votes::TeeVerifierVotes,
    update::ProposedUpdates,
};
use config::Config;
use crypto_shared::types::PublicKeyExtended;
use errors::{InvalidParameters, InvalidState, RespondError, TeeError};
use near_mpc_contract_interface::deposits::SIGN_DEPOSIT_YOCTONEAR;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_mpc_contract_interface::types::{
    self as dtos, VerifyForeignTransactionRequest, VerifyForeignTransactionRequestArgs,
    VerifyForeignTransactionResponse,
};

use dtos::DomainPurpose;
use mpc_attestation::attestation::{Attestation, DstackAttestation};
use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash};
use near_sdk::{
    AccountId, CryptoHash, Gas, NearToken, Promise, PromiseError, PromiseOrValue, env, log, near,
    store::{IterableMap, Lazy, LookupMap},
};
use node_migrations::NodeMigrations;
use primitives::{
    domain::max_reconstruction_threshold,
    key_state::AuthenticatedParticipantId,
    signature::{SignatureRequest, YieldIndex},
    thresholds::{
        GovernanceThreshold, GovernanceThresholdParameters, ProposedGovernanceThresholdParameters,
    },
};
use tee::measurements::{ContractExpectedMeasurements, MeasurementVoteAction, MeasurementVotes};
use tee::proposal::{CodeHashesVotes, LauncherHashVotes};
use tee_verifier_interface::{VerificationResult, VerifiedReport};

use state::ProtocolContractState;
use tee::{
    proposal::{LauncherVoteAction, NodeImageHash},
    tee_state::{NodeId, TeeValidationResult},
};

impl Default for MpcContract {
    fn default() -> Self {
        env::panic_str("Calling default not allowed.");
    }
}

#[near(contract_state)]
#[derive(Debug)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, Vec<YieldIndex>>,
    pending_ckd_requests: LookupMap<CKDRequest, Vec<YieldIndex>>,
    pending_verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, Vec<YieldIndex>>,
    proposed_updates: ProposedUpdates,
    // TODO(#3475): drop this once we upgrade the contract and nodes start using
    // the new API.
    node_foreign_chain_support: SupportedForeignChainsByNode,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
    foreign_chains: Lazy<ForeignChainsMetadata>,
    /// The verifier contract account trusted for DCAP verification, or [`None`]
    /// until participants vote one in. An [`Attestation::Dstack`] submission
    /// offloads quote verification to this account; while it is [`None`], such
    /// submissions are rejected with [`TeeError::VerifierNotConfigured`].
    // TODO(#3639): once participants have voted a verifier in, make this
    // non-optional via a migration that requires it be set.
    tee_verifier_account_id: Option<AccountId>,
    tee_verifier_votes: TeeVerifierVotes,
    /// A row is removed at zero, so the map holds no entry for an account with none.
    available_attestation_grants: IterableMap<AccountId, u32>,
}

#[near(serializers=[borsh])]
#[derive(Debug)]
struct SupportedForeignChainsByNode {
    foreign_chain_support_by_node: IterableMap<dtos::AccountId, dtos::SupportedForeignChains>,
}

impl Default for SupportedForeignChainsByNode {
    fn default() -> Self {
        Self {
            foreign_chain_support_by_node: IterableMap::new(
                StorageKey::SupportedForeignChainsByNode,
            ),
        }
    }
}

impl SupportedForeignChainsByNode {
    fn to_dto(&self) -> dtos::ForeignChainSupportByNode {
        let foreign_chain_configuration_by_node = self
            .foreign_chain_support_by_node
            .iter()
            .map(|(account_id, foreign_chains)| (account_id.clone(), foreign_chains.clone()))
            .collect();

        dtos::ForeignChainSupportByNode {
            foreign_chain_support_by_node: foreign_chain_configuration_by_node,
        }
    }
}

impl MpcContract {
    fn add_verify_foreign_tx_request(
        &mut self,
        request: VerifyForeignTransactionRequest,
        data_id: CryptoHash,
    ) {
        pending_requests::push_pending_yield(
            &mut self.pending_verify_foreign_tx_requests,
            request,
            data_id,
        );
    }
}

// User contract API
#[near]
impl MpcContract {
    /// Submit a verification + signing request for a foreign chain transaction.
    /// MPC nodes will verify the transaction on the foreign chain before signing.
    /// The signed payload is derived from the transaction ID (hash of tx_id).
    #[handle_result]
    #[payable]
    pub fn verify_foreign_transaction(&mut self, request: VerifyForeignTransactionRequestArgs) {
        log!(
            "verify_foreign_transaction: predecessor={:?}, request={:?}",
            env::predecessor_account_id(),
            request
        );

        self.check_request_preconditions(
            request.domain_id,
            DomainPurpose::ForeignTx,
            Gas::from_tgas(self.config.sign_call_gas_attachment_requirement_tera_gas),
            NearToken::from_yoctonear(SIGN_DEPOSIT_YOCTONEAR),
        );

        let requested_chain = request.request.chain();
        let supported_chains = self.get_supported_foreign_chains();
        if !supported_chains.contains(&requested_chain) {
            env::panic_str(
                &InvalidParameters::ForeignChainNotSupported {
                    requested: requested_chain,
                }
                .to_string(),
            );
        }

        let callback_gas = Gas::from_tgas(
            self.config
                .return_signature_and_clean_state_on_success_call_tera_gas,
        );

        let request = args_into_verify_foreign_tx_request(request);
        let callback_args = serde_json::to_vec(&(&request,)).unwrap();
        self.enqueue_yield_request(
            method_names::RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS,
            callback_args,
            callback_gas,
            move |this, id| this.add_verify_foreign_tx_request(request, id),
        );
    }
}

// Node API
#[near]
impl MpcContract {
    #[handle_result]
    pub fn respond_verify_foreign_tx(
        &mut self,
        request: VerifyForeignTransactionRequest,
        response: VerifyForeignTransactionResponse,
    ) -> Result<(), Error> {
        let signer = Self::assert_caller_is_signer();

        log!(
            "respond_verify_foreign_tx: signer={}, request={:?}",
            &signer,
            &request
        );

        self.assert_caller_is_attested_participant_and_protocol_active();

        if !self.protocol_state.is_running_or_resharing() {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }

        if !self.accept_requests {
            return Err(TeeError::TeeValidationFailed.into());
        }

        if let Some(expected_payload_hash) = &request.expected_payload_hash
            && &response.payload_hash != expected_payload_hash
        {
            return Err(RespondError::UnexpectedPayloadHash.into());
        }

        let domain = request.domain_id;
        let public_key = self.public_key_extended(domain.0.into())?;

        let signature_is_valid = match (&response.signature, public_key) {
            (
                dtos::SignatureResponse::Secp256k1(signature_response),
                PublicKeyExtended::Secp256k1 { near_public_key },
            ) => {
                let secp_pk = dtos::Secp256k1PublicKey::try_from(&near_public_key)
                    .expect("Secp256k1 variant always has a secp256k1 key");

                let payload_hash: [u8; 32] = response.payload_hash.0;

                // Check the signature is correct against the root public key
                near_mpc_signature_verifier::verify_ecdsa_signature(
                    signature_response,
                    &payload_hash,
                    &secp_pk,
                )
                .is_ok()
            }
            (signature_response, public_key_requested) => {
                return Err(RespondError::SignatureSchemeMismatch {
                    mpc_scheme: Box::new(signature_response.clone()),
                    user_scheme: Box::new(public_key_requested),
                }
                .into());
            }
        };

        if !signature_is_valid {
            return Err(RespondError::InvalidSignature.into());
        }

        pending_requests::resolve_yields_for(
            &mut self.pending_verify_foreign_tx_requests,
            &request,
            serde_json::to_vec(&response).unwrap(),
        )
    }

    pub fn available_attestation_grants(&self, account_id: AccountId) -> u32 {
        self.grants_for(&account_id)
    }

    fn grants_for(&self, account_id: &AccountId) -> u32 {
        self.available_attestation_grants
            .get(account_id)
            .copied()
            .unwrap_or(0)
    }

    /// Buys `grants` attestation-storage grants for `account_id`.
    ///
    /// Permissionless, which is what lets an operator fund a node whose function-call key
    /// cannot attach a deposit. Requires exactly the fee times `grants`; no refunds, no
    /// withdrawal.
    #[payable]
    #[handle_result]
    pub fn prepay_attestation_storage(
        &mut self,
        account_id: AccountId,
        grants: u32,
    ) -> Result<(), Error> {
        if grants == 0 {
            return Err(InvalidParameters::MalformedPayload {
                reason: "grants must be greater than zero".to_string(),
            }
            .into());
        }

        let required = self
            .attestation_storage_fee()
            .as_yoctonear()
            .checked_mul(u128::from(grants))
            .ok_or(InvalidParameters::MalformedPayload {
                reason: "requested grants overflow the fee calculation".to_string(),
            })?;
        let attached = env::attached_deposit().as_yoctonear();
        if attached != required {
            return Err(InvalidParameters::UnexpectedDeposit { attached, required }.into());
        }

        let available = self.grants_for(&account_id);
        let credited =
            available
                .checked_add(grants)
                .ok_or(InvalidParameters::MalformedPayload {
                    reason: "grant counter would overflow".to_string(),
                })?;
        self.available_attestation_grants
            .insert(account_id.clone(), credited);

        Ok(())
    }

    /// Submit a TEE attestation for a current or prospective participant.
    ///
    /// - [`Attestation::Mock`] is verified synchronously.
    /// - [`Attestation::Dstack`] is verified asynchronously via a cross-contract
    ///   `verify_quote` call, with [`Self::resolve_verification`] chained as its
    ///   callback to run the post-DCAP checks and store the attestation.
    ///
    /// A node submits with no deposit via its function-call access key. Storing a *new* entry
    /// consumes one attestation-storage grant, prepaid for the node's account by whoever
    /// onboards it; a re-attestation under a key the account already owns consumes none.
    #[handle_result]
    pub fn submit_participant_info(
        &mut self,
        proposed_participant_attestation: dtos::Attestation,
        tls_public_key: dtos::Ed25519PublicKey,
    ) -> Result<PromiseOrValue<()>, Error> {
        let proposed_participant_attestation =
            proposed_participant_attestation.try_into_contract_type()?;

        let account_key = env::signer_account_pk();
        let account_id = Self::assert_caller_is_signer();

        log!(
            "submit_participant_info: signer={}, proposed_participant_attestation={:?}, account_key={:?}",
            account_id,
            proposed_participant_attestation,
            account_key
        );

        // The node always signs submissions with an Ed25519 key
        // (`near_signer_key`), so the signer key here is Ed25519 in practice.
        // Reject non-Ed25519 signer keys rather than silently storing a value
        // we could never match against in `is_caller_an_attested_participant`.
        let account_public_key = dtos::Ed25519PublicKey::try_from(&account_key).map_err(|_| {
            InvalidParameters::InvalidTeeRemoteAttestation {
                reason: "signer account key must be Ed25519".to_string(),
            }
        })?;

        let node_id = NodeId {
            account_id: account_id.clone(),
            tls_public_key,
            account_public_key,
        };

        // Before any verification: an ungranted or unauthorised submission stops here.
        self.assert_attestation_storage_grant_available(
            &node_id.account_id,
            &node_id.tls_public_key,
        )?;

        match proposed_participant_attestation {
            Attestation::Mock(mock) => {
                let tee_upgrade_deadline_duration =
                    Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);
                let insertion = self.tee_state.verify_and_store_mock(
                    node_id.clone(),
                    mock,
                    tee_upgrade_deadline_duration,
                )?;
                if matches!(insertion, ParticipantInsertion::NewlyInsertedParticipant) {
                    self.consume_attestation_storage_grant(&node_id.account_id);
                }

                // A `WithConstraints` mock may reference a launcher hash; refresh-on-use keeps
                // it alive, matching the dstack path. No-op for mocks without a launcher.
                // Capability token: only a current participant may keep its launcher hash alive.
                let authenticated_participant = self
                    .protocol_state
                    .threshold_parameters()
                    .ok()
                    .and_then(|params| AuthenticatedParticipantId::new(params.participants()).ok());
                if let Some(authenticated_participant) = &authenticated_participant {
                    let launcher_unused_ttl =
                        Duration::from_secs(self.config.launcher_hash_unused_ttl_seconds);
                    self.tee_state.refresh_launcher_usage(
                        &node_id.tls_public_key,
                        authenticated_participant,
                        launcher_unused_ttl,
                    );
                }

                Ok(PromiseOrValue::Value(()))
            }
            Attestation::Dstack(attestation) => Ok(PromiseOrValue::Promise(
                self.submit_dstack_attestation(node_id, attestation)?,
            )),
        }
    }

    /// Read from `config()` by operators; deliberately not its own view.
    fn attestation_storage_fee(&self) -> NearToken {
        NearToken::from_millinear(u128::from(self.config.attestation_storage_fee_millinear))
    }

    fn attestation_submission_needs_grant(
        &self,
        account_id: &AccountId,
        tls_public_key: &dtos::Ed25519PublicKey,
    ) -> Result<bool, Error> {
        match self.tee_state.attestation_owner(tls_public_key) {
            Some(owner) if &owner == account_id => Ok(false),
            Some(_) => Err(AttestationSubmissionError::TlsKeyOwnedByOtherAccount.into()),
            None => Ok(true),
        }
    }

    fn assert_attestation_storage_grant_available(
        &self,
        account_id: &AccountId,
        tls_public_key: &dtos::Ed25519PublicKey,
    ) -> Result<(), Error> {
        if self.attestation_submission_needs_grant(account_id, tls_public_key)?
            && self.grants_for(account_id) == 0
        {
            return Err(InvalidParameters::NoAttestationStorageGrant {
                account_id: account_id.to_string(),
            }
            .into());
        }
        Ok(())
    }

    /// Consumes one grant for `account_id`.
    fn consume_attestation_storage_grant(&mut self, account_id: &AccountId) {
        let remaining = self
            .grants_for(account_id)
            .checked_sub(1)
            .expect("caller must establish an available grant before consuming one");
        if remaining == 0 {
            self.available_attestation_grants.remove(account_id);
        } else {
            self.available_attestation_grants
                .insert(account_id.clone(), remaining);
        }
    }

    fn return_attestation_storage_grant(&mut self, account_id: &AccountId) {
        let available = self.grants_for(account_id);
        // Checked, not saturating: at `u32::MAX` a returned grant would be dropped silently.
        let Some(returned) = available.checked_add(1) else {
            log!("grant counter for {account_id} is saturated; not returning a grant");
            return;
        };
        self.available_attestation_grants
            .insert(account_id.clone(), returned);
    }

    /// Async [`Attestation::Dstack`] submission: spawns a promise calling
    /// `verify_quote` on the trusted verifier contract, with
    /// [`Self::resolve_verification`] chained as its callback.
    fn submit_dstack_attestation(
        &mut self,
        node_id: NodeId,
        attestation: DstackAttestation,
    ) -> Result<Promise, Error> {
        let Some(verifier_account_id) = self.tee_verifier_account_id.clone() else {
            return Err(TeeError::VerifierNotConfigured.into());
        };

        Ok(Promise::new(verifier_account_id)
            .function_call(
                method_names::VERIFY_QUOTE.to_string(),
                borsh::to_vec(&(&attestation.quote, &attestation.collateral))
                    .expect("borsh serialization of verify_quote args must succeed"),
                NearToken::from_near(0),
                Gas::from_tgas(self.config.verifier_tera_gas),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(self.config.resolve_verification_tera_gas))
                    .resolve_verification(VerificationContext {
                        node_id,
                        attestation,
                    }),
            ))
    }

    #[handle_result]
    pub fn get_attestation(
        &self,
        tls_public_key: dtos::Ed25519PublicKey,
    ) -> Result<Option<dtos::VerifiedAttestation>, Error> {
        Ok(self
            .tee_state
            .stored_attestations
            .get(&tls_public_key)
            .map(|node_attestation| {
                node_attestation
                    .verified_attestation
                    .clone()
                    .into_dto_type()
            }))
    }

    /// Registers the set of foreign chains the calling node supports.
    ///
    /// Must be called directly from the participant's own NEAR account
    /// (`voter_or_panic` requires `signer == predecessor`, blocking calls forwarded
    /// through another contract). Callable by a participant in any active protocol phase
    /// (Initializing, Running, or Resharing — authenticated against that phase's participant
    /// set); panics in [`NotInitialized`](ProtocolContractState::NotInitialized) or when the caller is not a participant. Entries for
    /// accounts that are no longer participants are pruned after resharing by
    /// [`Self::clean_foreign_chain_data`].
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
        let signer_account_ed25519_pk = Ed25519PublicKey::try_from(&signer_account_pk)
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
    fn recompute_available_foreign_chains(&mut self) {
        let Ok(params) = self.protocol_state.threshold_parameters() else {
            return;
        };
        // TODO(#3556): replace this with a per-scheme
        // `required_active_signers(protocol, reconstruction_threshold)`.
        let Some(reconstruction_threshold) =
            self.protocol_state.domain_registry().ok().and_then(|r| {
                r.domains()
                    .iter()
                    .filter(|d| d.purpose == DomainPurpose::ForeignTx)
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
        note = "https://github.com/near/mpc/issues/3079. Node will be upgraded to use register_foreign_chain_support instead"
    )]
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

    #[handle_result]
    pub fn vote_code_hash(&mut self, code_hash: NodeImageHash) -> Result<(), Error> {
        log!(
            "vote_code_hash: signer={}, code_hash={:?}",
            env::signer_account_id(),
            code_hash,
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let votes = self.tee_state.vote(code_hash, &participant);

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        // If the vote threshold is met and the new Docker hash is allowed by the TEE's RTMR3,
        // update the state
        if votes >= self.threshold()?.value() {
            self.tee_state
                .whitelist_tee_proposal(code_hash, tee_upgrade_deadline_duration);
        }

        Ok(())
    }

    /// Vote to add a new launcher image hash to the allowed set. Requires threshold votes.
    /// When the threshold is reached, compose hashes are automatically derived for all
    /// currently allowed MPC image hashes.
    #[handle_result]
    pub fn vote_add_launcher_hash(
        &mut self,
        launcher_hash: LauncherImageHash,
    ) -> Result<(), Error> {
        log!(
            "vote_add_launcher_hash: signer={}, launcher_hash={:?}",
            env::signer_account_id(),
            launcher_hash,
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let action = LauncherVoteAction::Add(launcher_hash);
        let votes = self.tee_state.vote_launcher(action, &participant);

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);
        let launcher_unused_ttl = Duration::from_secs(self.config.launcher_hash_unused_ttl_seconds);

        if votes >= self.threshold()?.value() {
            let outcome = self.tee_state.add_launcher_image(
                launcher_hash,
                tee_upgrade_deadline_duration,
                launcher_unused_ttl,
            );
            log!("launcher hash {:?}: {:?}", outcome, launcher_hash);
        }

        Ok(())
    }

    /// Vote to remove a launcher image hash from the allowed set. Requires ALL participants
    /// to vote for removal, since this invalidates attestations of nodes running that launcher.
    #[handle_result]
    pub fn vote_remove_launcher_hash(
        &mut self,
        launcher_hash: LauncherImageHash,
    ) -> Result<(), Error> {
        log!(
            "vote_remove_launcher_hash: signer={}, launcher_hash={:?}",
            env::signer_account_id(),
            launcher_hash,
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let action = LauncherVoteAction::Remove(launcher_hash);
        let votes = self.tee_state.vote_launcher(action, &participant);

        // Removal requires ALL participants to vote
        let total_participants = threshold_parameters.participants().len() as u64;
        if votes >= total_participants {
            let removed = self.tee_state.remove_launcher_image(&launcher_hash);
            log!("launcher hash remove result: {}", removed);
        }

        Ok(())
    }

    /// Vote to add a new OS measurement set to the allowed list. Requires threshold votes.
    #[handle_result]
    pub fn vote_add_os_measurement(
        &mut self,
        measurement: ContractExpectedMeasurements,
    ) -> Result<(), Error> {
        log!(
            "vote_add_os_measurement: signer={}, measurement={:?}",
            env::signer_account_id(),
            measurement,
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let action = MeasurementVoteAction::Add(measurement.clone());
        let votes = self.tee_state.vote_measurement(action, &participant);

        if votes >= self.threshold()?.value() {
            let added = self.tee_state.add_measurement(measurement);
            log!("OS measurement add result: {}", added);
        }

        Ok(())
    }

    /// Vote to remove an OS measurement set from the allowed list. Requires ALL participants
    /// to vote for removal.
    #[handle_result]
    pub fn vote_remove_os_measurement(
        &mut self,
        measurement: ContractExpectedMeasurements,
    ) -> Result<(), Error> {
        log!(
            "vote_remove_os_measurement: signer={}, measurement={:?}",
            env::signer_account_id(),
            measurement,
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let action = MeasurementVoteAction::Remove(measurement.clone());
        let votes = self.tee_state.vote_measurement(action, &participant);

        // Removal requires ALL participants to vote
        let total_participants = threshold_parameters.participants().len() as u64;
        if votes >= total_participants {
            let removed = self.tee_state.remove_measurement(&measurement);
            log!("OS measurement remove result: {}", removed);
        }

        Ok(())
    }

    /// Returns the current OS measurement votes, showing each participant's vote.
    pub fn os_measurement_votes(&self) -> MeasurementVotes {
        log!("os_measurement_votes");
        self.tee_state.measurement_votes.clone()
    }

    /// Returns all currently allowed OS measurements.
    pub fn allowed_os_measurements(&self) -> Vec<ContractExpectedMeasurements> {
        log!("allowed_os_measurements");
        self.tee_state.get_allowed_measurements()
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

    /// Returns all accounts that have TEE attestations stored in the contract.
    /// Note: This includes both current protocol participants and accounts that may have
    /// submitted TEE information but are not currently part of the active participant set.
    pub fn get_tee_accounts(&self) -> Vec<dtos::NodeId> {
        log!("get_tee_accounts");
        self.tee_state.get_tee_accounts()
    }

    /// Verifies if all current participants have an accepted TEE state.
    /// Automatically enters a resharing, in case one or more participants do not have an accepted
    /// TEE state.
    /// Returns `false` and stops the contract from accepting new signature requests or responses,
    /// in case less than `threshold` participants run in an accepted TEE State.
    #[handle_result]
    pub fn verify_tee(&mut self) -> Result<bool, Error> {
        log!("verify_tee: signer={}", env::signer_account_id());
        // Caller must be a participant (node or operator).
        self.voter_or_panic();
        let ProtocolContractState::Running(running_state) = &mut self.protocol_state else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };
        let current_params = running_state.parameters.clone();

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        match self.tee_state.reverify_and_cleanup_participants(
            current_params.participants(),
            tee_upgrade_deadline_duration,
        ) {
            TeeValidationResult::Full => {
                self.accept_requests = true;
                log!("All participants have an accepted Tee status");
                Ok(true)
            }
            TeeValidationResult::Partial {
                participants_with_valid_attestation,
            } => {
                let remaining = participants_with_valid_attestation.len();
                // Defense in depth: the surviving participant set must keep the full
                // threshold relation intact — the GovernanceThreshold must still sit
                // within its bounds for the smaller set (in particular it must not
                // exceed the remaining participant count or the upper cap) and must
                // remain at least every domain's ReconstructionThreshold (the kickout
                // keeps the existing per-domain thresholds). Otherwise we refuse and
                // wait for manual intervention.
                let max_reconstruction_threshold =
                    max_reconstruction_threshold(running_state.domains.domains());
                if let Err(err) =
                    GovernanceThresholdParameters::validate_governance_against_reconstruction(
                        u64::try_from(remaining).expect("participant count fits in u64"),
                        current_params.threshold(),
                        max_reconstruction_threshold,
                    )
                {
                    log!(
                        "Kicking out participants with an invalid TEE status would break the threshold relation ({:?}); {} participants remain with a valid TEE status. This requires manual intervention. We will not accept new signature requests as a safety precaution.",
                        err,
                        remaining,
                    );
                    self.accept_requests = false;
                    return Ok(false);
                }

                // here, we set it to true, because at this point, we have at least `threshold`
                // number of participants with an accepted Tee status.
                self.accept_requests = true;

                // do we want to adjust the threshold?
                //let n_participants_new = new_participants.len();
                //let new_threshold = (3 * n_participants_new + 4) / 5; // minimum 60%
                //let new_threshold = new_threshold.max(2); // but also minimum 2
                let new_threshold = usize::try_from(current_params.threshold().value())
                    .expect("threshold value fits in usize");

                let threshold_parameters = GovernanceThresholdParameters::new(
                    participants_with_valid_attestation,
                    GovernanceThreshold::new(new_threshold as u64),
                )
                .expect("Require valid threshold parameters"); // this should never happen.
                current_params.validate_incoming_proposal(&threshold_parameters)?;
                // This resharing only changes the participant set, so the
                // per-domain reconstruction-threshold updates map is empty.
                let proposed_parameters = ProposedGovernanceThresholdParameters::new(
                    threshold_parameters,
                    BTreeMap::new(),
                );
                let res = running_state.transition_to_resharing_no_checks(&proposed_parameters);
                if let Some(resharing) = res {
                    self.protocol_state = ProtocolContractState::Resharing(resharing);
                }

                Ok(true)
            }
        }
    }

    /// Private endpoint to drop votes cast by non-participants after resharing.
    /// Attestation cleanup is handled separately by [`MpcContract::clean_invalid_attestations`].
    #[private]
    #[handle_result]
    pub fn clean_tee_status(&mut self) -> Result<(), Error> {
        log!("clean_tee_status: signer={}", env::signer_account_id());

        let participants = match &self.protocol_state {
            ProtocolContractState::Running(state) => state.parameters.participants(),
            _ => {
                return Err(InvalidState::ProtocolStateNotRunning.into());
            }
        };

        self.tee_state.clean_non_participant_votes(participants);
        Ok(())
    }

    /// Prunes up to `max_scan` stored attestations that fail re-verification (expired or
    /// referencing stale whitelists), returning one attestation-storage grant to the owner of
    /// each entry removed. Returns the number of entries removed. Callable by anyone while the
    /// protocol is in [`Running`](ProtocolContractState::Running).
    #[handle_result]
    pub fn clean_invalid_attestations(&mut self, max_scan: u32) -> Result<u32, Error> {
        log!(
            "clean_invalid_attestations: signer={}, max_scan={}",
            env::signer_account_id(),
            max_scan
        );
        // Running-only: keygen / resharing may reference attestations that have not yet
        // been activated, so cleanup is off-limits during those phases.
        if !matches!(self.protocol_state, ProtocolContractState::Running(_)) {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }
        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);
        let removed_entry_owners = self
            .tee_state
            .clean_invalid_attestations(tee_upgrade_deadline_duration, max_scan as usize);
        for account_id in &removed_entry_owners {
            self.return_attestation_storage_grant(account_id);
        }
        Ok(u32::try_from(removed_entry_owners.len())
            .expect("u32 should always be convertible from usize on wasm32"))
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
}

// Contract developer helper API
#[near]
impl MpcContract {
    /// Returns all allowed code hashes in descending order of their expiry
    /// date. Note that the expiration depends on the contract configuration
    /// (c.f. [`dtos::Config::tee_upgrade_deadline_duration_seconds`]).
    pub fn allowed_docker_image_hashes(&self) -> Vec<dtos::AllowedMpcDockerImageHash> {
        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        let mut entries = self
            .tee_state
            .get_allowed_mpc_docker_images(tee_upgrade_deadline_duration);
        entries.reverse();
        entries
    }

    pub fn allowed_launcher_compose_hashes(&self) -> Vec<LauncherDockerComposeHash> {
        self.tee_state.get_allowed_launcher_compose_hashes()
    }

    pub fn allowed_launcher_image_hashes(&self) -> Vec<LauncherImageHash> {
        self.tee_state.get_allowed_launcher_hashes()
    }

    /// Returns the current launcher hash votes, showing each participant's vote.
    pub fn launcher_hash_votes(&self) -> LauncherHashVotes {
        self.tee_state.launcher_votes.clone()
    }

    /// Returns the current code hash votes, showing each participant's vote.
    pub fn code_hash_votes(&self) -> CodeHashesVotes {
        self.tee_state.votes.clone()
    }

    /// Presence check for a pending foreign-tx verification request, exposed as a
    /// view call.
    ///
    /// See [`Self::get_pending_request`] for the contract: the returned [`YieldIndex`]
    /// is an arbitrary representative of a fan-out queue, not "the" yield. Only the
    /// `Some`/`None` distinction is meaningful.
    pub fn get_pending_verify_foreign_tx_request(
        &self,
        request: &VerifyForeignTransactionRequest,
    ) -> Option<YieldIndex> {
        self.pending_verify_foreign_tx_requests
            .get(request)
            .and_then(|q| q.first().cloned())
    }

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

    /// Verify-quote callback: on a verifier verdict it runs the post-DCAP checks and stores the
    /// attestation, consuming one attestation-storage grant if the entry is new. On any failure
    /// it fails the submitter's transaction.
    #[private]
    pub fn resolve_verification(
        &mut self,
        #[serializer(borsh)] context: VerificationContext,
        #[serializer(borsh)]
        #[callback_result]
        result: Result<VerificationResult, PromiseError>,
    ) -> PromiseOrValue<()> {
        let account_id = context.node_id.account_id.clone();
        log!("resolve_verification: account_id={account_id}");

        let attestation_result = match result {
            Ok(VerificationResult::Verified(report)) => {
                self.verify_post_dcap_and_store(&context, &report)
            }
            Ok(VerificationResult::Rejected(reason)) => {
                log!("verifier rejected quote for {account_id}: {reason}");
                Err(TeeError::QuoteRejected {
                    reason: reason.to_string(),
                }
                .into())
            }
            // No verdict (verifier unreachable, panicked, or out of gas)
            Err(promise_err) => {
                log!("verifier did not answer for {account_id}: {promise_err:?}");
                Err(TeeError::VerifierUnavailable.into())
            }
        };

        match attestation_result {
            Ok(()) => PromiseOrValue::Value(()),
            Err(err) => {
                // Fail the submitter's transaction from a separate receipt so any prior state
                // commits (a panic here would roll it back)
                let promise = Promise::new(env::current_account_id()).function_call(
                    method_names::FAIL_ATTESTATION_SUBMISSION.to_string(),
                    borsh::to_vec(&err.to_string())
                        .expect("borsh serialization of reason must succeed"),
                    NearToken::from_near(0),
                    Gas::from_tgas(self.config.fail_attestation_submission_tera_gas),
                );
                PromiseOrValue::Promise(promise.as_return())
            }
        }
    }

    /// Runs the post-DCAP checks and stores the attestation for a
    /// [`VerificationResult::Verified`] response. Re-checks that a grant is available before
    /// storing, since this runs a receipt later than the submission that reserved it.
    fn verify_post_dcap_and_store(
        &mut self,
        context: &VerificationContext,
        report: &VerifiedReport,
    ) -> Result<(), Error> {
        let account_id = context.node_id.account_id.clone();
        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);
        let launcher_unused_ttl = Duration::from_secs(self.config.launcher_hash_unused_ttl_seconds);

        // Capability token: only a current participant may keep its launcher hash alive.
        // The signer is preserved across the verifier promise, so this reflects the
        // original submitter.
        let authenticated_participant = self
            .protocol_state
            .threshold_parameters()
            .ok()
            .and_then(|params| AuthenticatedParticipantId::new(params.participants()).ok());
        let tls_public_key_for_refresh = context.node_id.tls_public_key.clone();

        self.assert_attestation_storage_grant_available(
            &account_id,
            &context.node_id.tls_public_key,
        )?;

        let insertion = match self.tee_state.verify_and_store_dstack(
            context.node_id.clone(),
            &context.attestation,
            report,
            tee_upgrade_deadline_duration,
        ) {
            Ok(insertion) => insertion,
            Err(err) => {
                log!("post-DCAP check failed for {account_id}: {err}");
                return Err(err.into());
            }
        };
        if matches!(insertion, ParticipantInsertion::NewlyInsertedParticipant) {
            self.consume_attestation_storage_grant(&account_id);
        }

        // Refresh-on-use: a current participant's successful submission keeps the launcher
        // hash its attestation references from expiring.
        if let Some(participant) = &authenticated_participant {
            self.tee_state.refresh_launcher_usage(
                &tls_public_key_for_refresh,
                participant,
                launcher_unused_ttl,
            );
        }

        Ok(())
    }

    /// Yield-resume callback for a single queued foreign-tx verification request.
    ///
    /// On success, returns the verification response to the original caller. On
    /// timeout, pops this yield's slot (the head of the FIFO fan-out queue) from the
    /// pending-request map and fires `fail_on_timeout` to fail the original
    /// transaction. Sibling yields queued under the same request key remain pending
    /// and are cleaned up by their own timeouts (or drained together by a subsequent
    /// `respond_verify_foreign_tx`).
    #[private]
    pub fn return_verify_foreign_tx_and_clean_state_on_success(
        &mut self,
        request: VerifyForeignTransactionRequest,
        #[callback_result] response: Result<VerifyForeignTransactionResponse, PromiseError>,
    ) -> PromiseOrValue<VerifyForeignTransactionResponse> {
        match response {
            Ok(response) => PromiseOrValue::Value(response),
            Err(_) => {
                pending_requests::pop_oldest_pending_yield(
                    &mut self.pending_verify_foreign_tx_requests,
                    &request,
                );
                let fail_on_timeout_gas = Gas::from_tgas(self.config.fail_on_timeout_tera_gas);
                let promise = Promise::new(env::current_account_id()).function_call(
                    method_names::FAIL_ON_TIMEOUT.to_string(),
                    vec![],
                    NearToken::from_near(0),
                    fail_on_timeout_gas,
                );
                near_sdk::PromiseOrValue::Promise(promise.as_return())
            }
        }
    }

    #[private]
    pub fn fail_attestation_submission(#[serializer(borsh)] reason: String) {
        log!("fail_attestation_submission: {reason}");
        env::panic_str(&reason);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::{
        collections::{BTreeMap, HashSet},
        panic,
        str::FromStr,
    };

    use super::*;
    use crate::api::test_utils::*;

    use crate::primitives::domain::AddDomainsVotes;
    use crate::primitives::key_state::EpochId;
    use crate::state::running::RunningContractState;

    use crate::primitives::participants::{ParticipantId, ParticipantInfo, Participants};
    use crate::primitives::test_utils::{
        bogus_ed25519_near_public_key, bogus_ed25519_public_key, create_node_id, gen_account_id,
        gen_participant, gen_participants,
    };
    use crate::state::key_event::KeyEvent;
    use crate::state::key_event::tests::Environment;
    use crate::state::resharing::ResharingContractState;
    use crate::state::test_utils::{
        gen_initializing_state, gen_resharing_state, gen_running_state,
    };
    use crate::tee::measurements::{
        KeyProviderEventDigest, MrtdHash, Rtmr0Hash, Rtmr1Hash, Rtmr2Hash,
    };
    use crate::tee::proposal::{LauncherVoteAction, get_docker_compose_hash};
    use crate::tee::tee_state::{NodeAttestation, NodeId};
    use assert_matches::assert_matches;
    use dtos::{Attestation, Ed25519PublicKey, ForeignTxSignPayload, MockAttestation};
    use dtos::{Curve, DomainConfig, DomainId, Protocol, ReconstructionThreshold};

    use k256::{self, Secp256k1, ecdsa::SigningKey, elliptic_curve};
    use mpc_attestation::attestation::{
        MockAttestation as MpcMockAttestation, ValidatedDstackAttestation, VerifiedAttestation,
        default_measurements,
    };
    use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};

    use near_mpc_contract_interface::types::DestinationNodeInfo;
    use near_mpc_contract_interface::types::{
        BitcoinExtractedValue, BitcoinExtractor, BitcoinRpcRequest, ExtractedValue,
        ForeignTxPayloadVersion, ForeignTxSignPayloadV1,
    };
    use near_sdk::{NearToken, test_utils::VMContextBuilder, testing_env};
    use primitives::key_state::{AttemptId, KeyForDomain, Keyset};
    use rand::SeedableRng;
    use rand::rngs::OsRng;

    use rstest::rstest;

    use crate::tee::{
        test_utils::whitelist_dstack_measurements, verification_context::VerificationContext,
    };
    use test_utils::attestation::{
        VALID_ATTESTATION_TIMESTAMP, account_key, image_digest, launcher_compose_digest,
        launcher_image_hash, mock_dstack_attestation_inner, p2p_tls_key, verified_report,
    };

    /// Register the given foreign chains as supported by all active participants.
    fn register_supported_chains(
        contract: &mut MpcContract,
        chains: impl IntoIterator<Item = dtos::ForeignChain>,
    ) {
        let foreign_chain_configuration: dtos::ForeignChainConfiguration = chains
            .into_iter()
            .map(|foreign_chain| {
                (
                    foreign_chain,
                    NonEmptyBTreeSet::new(dtos::RpcProvider {
                        rpc_url: "dummy_url.com".to_string(),
                    }),
                )
            })
            .collect::<BTreeMap<dtos::ForeignChain, NonEmptyBTreeSet<dtos::RpcProvider>>>()
            .into();

        // pub struct ForeignChainConfiguration(BTreeMap<ForeignChain, NonEmptyBTreeSet<RpcProvider>>);

        let participants: Vec<_> = contract
            .protocol_state
            .active_participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();
        for account_id in participants {
            let _env = Environment::new(None, Some(account_id), None);
            contract
                .register_foreign_chain_config(foreign_chain_configuration.clone())
                .expect("register should succeed");
        }
    }

    #[test]
    fn verify_foreign_transaction__should_queue_duplicates_from_different_callers() {
        // Given: two different callers will submit the same foreign-tx verification request.
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };

        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());

        // When: caller alice submits the request.
        let alice = AccountId::from_str("alice.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(alice.clone())
                .predecessor_account_id(alice)
                .current_account_id(context.current_account_id.clone())
                .attached_deposit(NearToken::from_yoctonear(1))
                .build()
        );
        contract.verify_foreign_transaction(request_args.clone());

        // And: caller bob submits the identical request — a different account would today
        // be blocked from receiving a response by alice's submission.
        let bob = AccountId::from_str("bob.near").unwrap();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(bob.clone())
                .predecessor_account_id(bob)
                .current_account_id(context.current_account_id.clone())
                .attached_deposit(NearToken::from_yoctonear(1))
                .build()
        );
        contract.verify_foreign_transaction(request_args);

        // Then: both yields are queued under the single (caller-agnostic) request key.
        assert_eq!(
            contract
                .pending_verify_foreign_tx_requests
                .get(&request)
                .map(|q| q.len()),
            Some(2),
            "duplicate foreign-tx requests from different callers should fan out",
        );

        // When: a single valid response is delivered.
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let payload_hash_arr = payload.compute_msg_hash().unwrap().0;
        let secret_key_ec: elliptic_curve::SecretKey<Secp256k1> =
            elliptic_curve::SecretKey::from_bytes(&secret_key.to_bytes()).unwrap();
        let signing_key = SigningKey::from_bytes(&secret_key_ec.to_bytes()).unwrap();
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&payload_hash_arr)
            .unwrap();
        let response = VerifyForeignTransactionResponse {
            payload_hash: payload.compute_msg_hash().unwrap(),
            signature: dtos::SignatureResponse::Secp256k1(
                dtos::K256Signature::from_ecdsa_recoverable(&signature, recovery_id),
            ),
        };

        with_active_participant_and_attested_context(&contract);
        contract
            .respond_verify_foreign_tx(request.clone(), response)
            .expect("respond_verify_foreign_tx should succeed");

        // Then: both queued yields are drained from the single map entry.
        assert!(
            contract
                .pending_verify_foreign_tx_requests
                .get(&request)
                .is_none()
        );
    }

    #[test]
    fn respond_verify_foreign_tx__should_succeed_when_response_is_valid_and_request_exists() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };

        // When
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        contract
            .get_pending_verify_foreign_tx_request(&request)
            .unwrap();
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let response = sign_foreign_tx_payload(&secret_key, &payload);

        with_active_participant_and_attested_context(&contract);

        // Then
        match contract.respond_verify_foreign_tx(request.clone(), response.clone()) {
            Ok(_) => {
                contract
                    .return_verify_foreign_tx_and_clean_state_on_success(
                        request.clone(),
                        Ok(response),
                    )
                    .detach();

                assert!(
                    contract
                        .get_pending_verify_foreign_tx_request(&request)
                        .is_none(),
                );
            }
            Err(_) => panic!("respond_verify_foreign_tx should not fail"),
        }
    }

    #[test]
    fn respond_verify_foreign_tx__should_reject_response_with_unexpected_payload_hash() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: Some(dtos::Hash256([1u8; 32])),
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let response = sign_foreign_tx_payload(&secret_key, &payload);
        with_active_participant_and_attested_context(&contract);

        // When
        let result = contract.respond_verify_foreign_tx(request.clone(), response);

        // Then
        assert_matches!(
            result.unwrap_err(),
            Error::Respond(RespondError::UnexpectedPayloadHash)
        );
        assert!(
            contract
                .get_pending_verify_foreign_tx_request(&request)
                .is_some(),
            "the pending request must remain unresolved",
        );
    }

    #[test]
    fn respond_verify_foreign_tx__should_succeed_when_response_matches_expected_payload_hash() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let rpc_request = dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: [7u8; 32].into(),
            confirmations: 2.into(),
            extractors: vec![BitcoinExtractor::BlockHash],
        });
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: rpc_request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: Some(payload.compute_msg_hash().unwrap()),
            request: rpc_request,
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        let response = sign_foreign_tx_payload(&secret_key, &payload);
        with_active_participant_and_attested_context(&contract);

        // When
        let result = contract.respond_verify_foreign_tx(request.clone(), response);

        // Then
        assert!(
            result.is_ok(),
            "response matching the expected payload hash must be accepted: {result:?}",
        );
    }

    #[test]
    fn respond_verify_foreign_tx__should_reject_request_with_erased_expected_payload_hash() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let SharedSecretKey::Secp256k1(secret_key) = secret_key else {
            unreachable!();
        };
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: Some(dtos::Hash256([1u8; 32])),
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());
        contract.verify_foreign_transaction(request_args);
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: request.request.clone(),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });
        let response = sign_foreign_tx_payload(&secret_key, &payload);
        with_active_participant_and_attested_context(&contract);

        // When
        let tampered_request = VerifyForeignTransactionRequest {
            expected_payload_hash: None,
            ..request.clone()
        };
        let result = contract.respond_verify_foreign_tx(tampered_request, response);

        // Then
        assert_matches!(
            result.unwrap_err(),
            Error::InvalidParameters(InvalidParameters::RequestNotFound)
        );
        assert!(
            contract
                .get_pending_verify_foreign_tx_request(&request)
                .is_some(),
            "the pending request must remain unresolved",
        );
    }

    fn sign_foreign_tx_payload(
        secret_key: &k256::Scalar,
        payload: &ForeignTxSignPayload,
    ) -> VerifyForeignTransactionResponse {
        let payload_hash = payload.compute_msg_hash().unwrap();
        let secret_key_ec: elliptic_curve::SecretKey<Secp256k1> =
            elliptic_curve::SecretKey::from_bytes(&secret_key.to_bytes()).unwrap();
        let secret_key = SigningKey::from_bytes(&secret_key_ec.to_bytes()).unwrap();
        let (signature, recovery_id) = secret_key
            .sign_prehash_recoverable(&payload_hash.0)
            .unwrap();
        let signature = dtos::SignatureResponse::Secp256k1(
            dtos::K256Signature::from_ecdsa_recoverable(&signature, recovery_id),
        );
        VerifyForeignTransactionResponse {
            payload_hash,
            signature,
        }
    }

    #[test]
    fn test_verify_foreign_tx_timeout() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        register_supported_chains(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context.clone());
        let request_args = VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };
        let request = args_into_verify_foreign_tx_request(request_args.clone());

        // When
        contract.verify_foreign_transaction(request_args);

        // Then
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(
            contract.return_verify_foreign_tx_and_clean_state_on_success(
                request.clone(),
                Err(PromiseError::Failed)
            ),
            PromiseOrValue::Promise(_)
        ));
        assert!(
            contract
                .get_pending_verify_foreign_tx_request(&request)
                .is_none()
        );
    }

    #[rstest]
    #[case(Protocol::CaitSith, DomainPurpose::Sign)]
    #[case(Protocol::ConfidentialKeyDerivation, DomainPurpose::CKD)]
    #[should_panic(expected = "this method requires ForeignTx")]
    fn verify_foreign_tx__should_reject_non_foreign_tx_domain(
        #[case] protocol: Protocol,
        #[case] purpose: DomainPurpose,
    ) {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_context, mut contract, _sk) = basic_setup_with_protocol(protocol, purpose, &mut rng);

        // When
        contract.verify_foreign_transaction(VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        });
    }

    #[test]
    #[should_panic(expected = "Requested foreign chain, Bitcoin, is not supported.")]
    fn verify_foreign_tx__should_reject_chain_not_in_policy() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _sk) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut rng);
        // Supported chains has Solana but not Bitcoin
        register_supported_chains(&mut contract, [dtos::ForeignChain::Solana]);
        testing_env!(context.clone());

        // When - requesting Bitcoin which is not in the policy
        contract.verify_foreign_transaction(VerifyForeignTransactionRequestArgs {
            domain_id: DomainId::default().0.into(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            request: dtos::ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: [7u8; 32].into(),
                confirmations: 2.into(),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        });
    }

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn register_foreign_chain_support__should_panic_when_predecessor_differs_from_signer() {
        let mut contract = forwarded_participant_call_contract();
        contract
            .register_foreign_chain_support(BTreeSet::new().into())
            .expect("expected panic when predecessor != signer");
    }

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn test_submit_participant_info_panics_if_predecessor_differs() {
        let (mut contract, participants, _first_participant_id) = setup_tee_test_contract(3, 2);

        submit_valid_attestations(&mut contract, &participants, &[0, 1, 2]);

        let (participant_id, _, participant_info) = participants
            .participants()
            .first()
            .expect("at least one participant")
            .clone();

        let valid_attestation = Attestation::Mock(MockAttestation::Valid);

        // ❌ Case: signer != predecessor — should panic
        let ctx = VMContextBuilder::new()
            .signer_account_id(participant_id.clone())
            .predecessor_account_id("outsider.near".parse().unwrap())
            .build();
        testing_env!(ctx);

        let _ = contract
            .submit_participant_info(valid_attestation, participant_info.tls_public_key.clone())
            .expect("Expected panic if predecessor != signer");
    }

    fn dstack_verification_setup() -> (MpcContract, VerificationContext) {
        let (_, mut contract, _) = basic_setup(Curve::Edwards25519, &mut OsRng);
        let contract_account_id = env::current_account_id();
        let context = VMContextBuilder::new()
            .current_account_id(contract_account_id.clone())
            .predecessor_account_id(contract_account_id)
            .block_timestamp(VALID_ATTESTATION_TIMESTAMP * 1_000_000_000)
            .build();
        testing_env!(context);

        contract.tee_state = TeeState::default();
        whitelist_dstack_measurements(
            &mut contract.tee_state,
            image_digest(),
            launcher_image_hash(),
            Some(launcher_compose_digest()),
        );

        // Storing a new entry consumes a grant, so stand in for the operator's prepayment.
        contract
            .available_attestation_grants
            .insert("alice.near".parse().unwrap(), 1);

        let node_id = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: Ed25519PublicKey(p2p_tls_key()),
            account_public_key: Ed25519PublicKey(account_key()),
        };
        let attestation = mock_dstack_attestation_inner();
        (
            contract,
            VerificationContext {
                node_id,
                attestation,
            },
        )
    }

    /// The deposit must be exactly `fee × grants`, which is what makes a remainder — and so a
    /// refund path — impossible.
    #[rstest]
    #[case::one_yocto_short(-1)]
    #[case::one_yocto_over(1)]
    fn prepay_attestation_storage__should_reject_a_deposit_that_is_not_an_exact_multiple(
        #[case] offset: i128,
    ) {
        // Given
        let (_, mut contract, _) = basic_setup(Curve::Edwards25519, &mut OsRng);
        let node: AccountId = "newcomer.near".parse().unwrap();
        let fee = u128::from(contract.config().attestation_storage_fee_millinear);
        let exact = NearToken::from_millinear(fee * 2).as_yoctonear();
        let attached = NearToken::from_yoctonear((exact as i128 + offset) as u128);
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id("operator.near".parse().unwrap())
                .attached_deposit(attached)
                .build()
        );

        // When
        let result = contract.prepay_attestation_storage(node.clone(), 2);

        // Then
        assert_matches!(
            &result,
            Err(Error::InvalidParameters(InvalidParameters::UnexpectedDeposit {
                attached: a,
                required
            })) if *a == attached.as_yoctonear() && *required == exact
        );
        assert_eq!(contract.available_attestation_grants(node), 0);
    }

    #[test]
    fn prepay_attestation_storage__should_reject_zero_grants() {
        // Given
        let (_, mut contract, _) = basic_setup(Curve::Edwards25519, &mut OsRng);
        let node: AccountId = "newcomer.near".parse().unwrap();
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id("operator.near".parse().unwrap())
                .attached_deposit(NearToken::from_yoctonear(0))
                .build()
        );

        // When
        let result = contract.prepay_attestation_storage(node.clone(), 0);

        // Then
        assert_matches!(
            &result,
            Err(Error::InvalidParameters(
                InvalidParameters::MalformedPayload { .. }
            ))
        );
        assert_eq!(contract.available_attestation_grants(node), 0);
    }

    /// Without this the async path would store for free while the synchronous one charged.
    #[test]
    fn resolve_verification__should_consume_one_grant_when_the_entry_is_new() {
        // Given: the setup prepays one grant for alice.near.
        let (mut contract, context) = dstack_verification_setup();
        let account_id = context.node_id.account_id.clone();
        assert_eq!(contract.available_attestation_grants(account_id.clone()), 1);

        // When
        let result = contract
            .resolve_verification(context, Ok(VerificationResult::Verified(verified_report())));

        // Then
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Value(())));
        assert_eq!(
            contract.available_attestation_grants(account_id),
            0,
            "storing a new entry should consume the grant"
        );
    }

    /// The callback runs a receipt later than the submission that reserved the grant, so it
    /// re-checks availability: another submission from the same account may have spent it in
    /// between. Without the re-check this would store an entry no grant paid for.
    #[test]
    fn resolve_verification__should_store_nothing_when_the_grant_was_spent_before_the_callback() {
        // Given: the grant reserved at submit time is gone by the time the callback runs.
        let (mut contract, context) = dstack_verification_setup();
        let account_id = context.node_id.account_id.clone();
        contract.available_attestation_grants.remove(&account_id);

        // When
        let result = contract
            .resolve_verification(context, Ok(VerificationResult::Verified(verified_report())));

        // Then: the submitter's transaction is failed from its own receipt, and nothing is stored.
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Promise(_)));
        assert!(contract.tee_state.stored_attestations.is_empty());
    }

    #[test]
    fn resolve_verification__should_store_on_verified_verdict() {
        // Given
        let (mut contract, context) = dstack_verification_setup();
        let node_id = context.node_id.clone();

        // When
        let result = contract
            .resolve_verification(context, Ok(VerificationResult::Verified(verified_report())));

        // Then
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Value(())));
        assert_eq!(contract.tee_state.stored_attestations.len(), 1);
        let stored = contract
            .tee_state
            .stored_attestations
            .get(&node_id.tls_public_key)
            .expect("attestation must be stored");
        assert_eq!(stored.node_id, node_id);
    }

    #[test]
    fn resolve_verification__should_refresh_launcher_for_participant() {
        // Given a launcher whose expiry was stamped earlier (STAMPED_AT_SECONDS), to be
        // resolved later (RESOLVE_AT_SECONDS) by a current participant.
        const STAMPED_AT_SECONDS: u64 = VALID_ATTESTATION_TIMESTAMP - 1_000;
        let resolve_at_seconds = VALID_ATTESTATION_TIMESTAMP;

        let (mut contract, context) = dstack_verification_setup();
        let ttl_secs = contract.config.launcher_hash_unused_ttl_seconds;
        let ttl = Duration::from_secs(ttl_secs);

        let participant: AccountId = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .participants()[0]
            .0
            .clone();

        // Stamp the launcher earlier with the config TTL so its expiry is
        // STAMPED_AT_SECONDS + ttl; a refresh on resolve (restamps to
        // RESOLVE_AT_SECONDS + ttl) is then observable.
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(STAMPED_AT_SECONDS * 1_000_000_000)
                .build()
        );
        contract.tee_state.allowed_launcher_images.add_or_refresh(
            launcher_image_hash(),
            &[image_digest()],
            ttl,
        );
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher_image_hash()),
            Some(STAMPED_AT_SECONDS + ttl_secs)
        );

        // When resolve runs later with the signer set to a current participant. Predecessor
        // stays the contract account for the `#[private]` callback.
        let contract_account_id = env::current_account_id();
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(contract_account_id.clone())
                .predecessor_account_id(contract_account_id)
                .signer_account_id(participant)
                .block_timestamp(resolve_at_seconds * 1_000_000_000)
                .build()
        );
        let result = contract
            .resolve_verification(context, Ok(VerificationResult::Verified(verified_report())));

        // Then the launcher is refreshed by the participant: expiry restamped to
        // RESOLVE_AT_SECONDS + ttl.
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Value(())));
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher_image_hash()),
            Some(resolve_at_seconds + ttl_secs)
        );
    }

    #[test]
    fn resolve_verification__should_not_refresh_for_non_participant() {
        // Given a launcher whose expiry was stamped earlier (STAMPED_AT_SECONDS), to be
        // resolved later (RESOLVE_AT_SECONDS) by a non-participant.
        const STAMPED_AT_SECONDS: u64 = VALID_ATTESTATION_TIMESTAMP - 1_000;
        let resolve_at_seconds = VALID_ATTESTATION_TIMESTAMP;

        let (mut contract, context) = dstack_verification_setup();
        let ttl_secs = contract.config.launcher_hash_unused_ttl_seconds;
        let ttl = Duration::from_secs(ttl_secs);

        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(STAMPED_AT_SECONDS * 1_000_000_000)
                .build()
        );
        contract.tee_state.allowed_launcher_images.add_or_refresh(
            launcher_image_hash(),
            &[image_digest()],
            ttl,
        );
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher_image_hash()),
            Some(STAMPED_AT_SECONDS + ttl_secs)
        );

        // When resolve runs later with a non-participant signer: the submission still stores,
        // but the launcher's expiry must not be extended.
        let non_participant: AccountId = "non-participant.near".parse().unwrap();
        let contract_account_id = env::current_account_id();
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(contract_account_id.clone())
                .predecessor_account_id(contract_account_id)
                .signer_account_id(non_participant)
                .block_timestamp(resolve_at_seconds * 1_000_000_000)
                .build()
        );
        let result = contract
            .resolve_verification(context, Ok(VerificationResult::Verified(verified_report())));

        // Then the launcher is not refreshed: expiry unchanged from the setup stamp.
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Value(())));
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher_image_hash()),
            Some(STAMPED_AT_SECONDS + ttl_secs)
        );
    }

    #[test]
    fn submit_participant_info__should_not_refresh_launcher_for_non_participant() {
        // Given a launcher stamped earlier (STAMPED_AT_SECONDS) with the config TTL, so its
        // expiry is STAMPED_AT_SECONDS + ttl.
        let (_, mut contract, _) = basic_setup(Curve::Edwards25519, &mut OsRng);
        let ttl_secs = contract.config.launcher_hash_unused_ttl_seconds;
        let ttl = Duration::from_secs(ttl_secs);

        let launcher = LauncherImageHash::from([7u8; 32]);
        let mpc_hash = crate::tee::proposal::NodeImageHash::from([8u8; 32]);
        let compose = crate::tee::proposal::get_docker_compose_hash(&launcher, &mpc_hash);

        const STAMPED_AT_SECONDS: u64 = 1_000_000;
        let submit_at_seconds = STAMPED_AT_SECONDS + 1_000;

        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(STAMPED_AT_SECONDS * 1_000_000_000)
                .build()
        );
        contract
            .tee_state
            .allowed_launcher_images
            .add_or_refresh(launcher, &[mpc_hash], ttl);
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher),
            Some(STAMPED_AT_SECONDS + ttl_secs)
        );

        // When a non-participant submits a `WithConstraints` mock referencing the live
        // launcher later (submit_at_seconds > STAMPED_AT_SECONDS). The submission stores, but
        // the participant-gated refresh must not run.
        let non_participant: AccountId = "non-participant.near".parse().unwrap();
        // Storing a new entry consumes an attestation-storage grant; this test is about the
        // launcher refresh gate, so fund the submission rather than have it rejected earlier.
        contract
            .available_attestation_grants
            .insert(non_participant.clone(), 1);
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(non_participant.clone())
                .predecessor_account_id(non_participant)
                .block_timestamp(submit_at_seconds * 1_000_000_000)
                .build()
        );
        let tls_key = Ed25519PublicKey([9u8; 32]);
        let mock = MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: Some(compose),
            expiry_timestamp_seconds: Some(submit_at_seconds + 1_000_000),
            expected_measurements: None,
        };
        let _ = contract
            .submit_participant_info(Attestation::Mock(mock), tls_key.clone())
            .unwrap();

        // Then the attestation is stored (so it reached the gate)...
        assert!(
            contract
                .tee_state
                .stored_attestations
                .get(&tls_key)
                .is_some()
        );
        // ...but the launcher's expiry was not extended.
        assert_eq!(
            contract
                .tee_state
                .allowed_launcher_images
                .expires_at_secs(&launcher),
            Some(STAMPED_AT_SECONDS + ttl_secs)
        );
    }

    #[test]
    fn resolve_verification__should_return_fail_promise_and_store_nothing_on_verifier_unavailable()
    {
        // Given
        let (mut contract, context) = dstack_verification_setup();

        // When
        let result = contract.resolve_verification(context, Err(PromiseError::Failed));

        // Then
        // assert_matches! requires Debug, which PromiseOrValue doesn't implement
        assert!(matches!(result, PromiseOrValue::Promise(_)));
        assert!(contract.tee_state.stored_attestations.is_empty());
    }

    #[test]
    #[should_panic(expected = "Caller must be an attested participant")]
    fn test_attested_but_not_participant_panics() {
        let (mut contract, participants, _first_participant_id) = setup_tee_test_contract(3, 2);

        submit_valid_attestations(&mut contract, &participants, &[0, 1, 2]);

        let outsider_id: AccountId = "outsider.near".parse().unwrap();

        let fake_tls_pk = bogus_ed25519_near_public_key(); // unique TLS key for outsider
        let dto_public_key = dtos::Ed25519PublicKey::try_from(&fake_tls_pk).unwrap();

        let valid_attestation = Attestation::Mock(MockAttestation::Valid);

        // A new entry consumes a grant; stand in for the operator's prepayment.
        contract
            .available_attestation_grants
            .insert(outsider_id.clone(), 1);

        // use outsider account to call submit_participant_info
        let ctx = VMContextBuilder::new()
            .signer_account_id(outsider_id.clone())
            .predecessor_account_id(outsider_id.clone())
            .build();
        testing_env!(ctx);

        let _ = contract
            .submit_participant_info(valid_attestation, dto_public_key)
            .expect("Outsider attestation submission should succeed");

        contract.assert_caller_is_attested_participant_and_protocol_active();
    }

    #[rstest]
    #[case(ProtocolContractState::Running(gen_running_state(NUM_DOMAINS)))]
    #[case(ProtocolContractState::Resharing(gen_resharing_state(NUM_DOMAINS).1))]
    #[case(ProtocolContractState::Initializing(gen_initializing_state(NUM_DOMAINS, NUM_GENERATED_DOMAINS).1))]
    fn test_contract_stores_allowed_hashes(#[case] protocol_state: ProtocolContractState) {
        const CURRENT_BLOCK_TIME_STAMP: u64 = 10;
        let mut contract = MpcContract::new_from_protocol_state(protocol_state);
        let code_hash = [9; 32];

        let participant_account_ids: Vec<_> = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();

        for participant_account_id in participant_account_ids {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(participant_account_id.clone())
                    .predecessor_account_id(participant_account_id.clone())
                    .block_timestamp(CURRENT_BLOCK_TIME_STAMP)
                    .build()
            );

            contract
                .vote_code_hash(code_hash.into())
                .expect("vote succeeds");
        }

        let allowed_docker_image_hashes: Vec<NodeImageHash> = contract
            .tee_state
            .get_allowed_mpc_docker_images(Duration::from_secs(10))
            .into_iter()
            .map(|allowed_image_hash| allowed_image_hash.image_hash)
            .collect();

        assert_eq!(
            allowed_docker_image_hashes,
            vec![NodeImageHash::from(code_hash)]
        )
    }

    /// Tests that [`MpcContract::verify_tee`] triggers resharing and kicks out a participant
    /// when their attestation is expired.
    ///
    /// Verifies the behavior when:
    /// 1. [`MpcContract::verify_tee`] returns [`TeeValidationResult::Partial`] (some attestations
    ///    expired/invalid)
    /// 2. The remaining participants meet threshold requirements
    /// 3. The contract transitions to [`ProtocolContractState::Resharing`] state
    /// 4. The participant with expired attestation is excluded from the new parameters
    #[test]
    fn test_verify_tee_triggers_resharing_and_kickout_on_expired_attestation() {
        const PARTICIPANT_COUNT: usize = 3;
        const ATTESTATION_EXPIRY_SECONDS: u64 = 5;
        const TEE_UPGRADE_DURATION: Duration = Duration::MAX;

        let participants = gen_participants(PARTICIPANT_COUNT);
        let parameters =
            GovernanceThresholdParameters::new(participants.clone(), GovernanceThreshold::new(2))
                .unwrap();

        // Set up contract in Running state
        let domain_id = DomainId::default();
        let domains = vec![DomainConfig {
            id: domain_id,
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(2),
            purpose: DomainPurpose::Sign,
        }];
        let (pk, _) = make_public_key_for_curve(Curve::Secp256k1, &mut OsRng);
        let key_for_domain = KeyForDomain {
            domain_id,
            key: pk.try_into().unwrap(),
            attempt: AttemptId::new(),
        };
        let keyset = Keyset::new(EpochId::new(0), vec![key_for_domain.clone()]);

        let mut contract = MpcContract::init_running(
            domains.clone(),
            1,
            keyset.clone(),
            (&parameters).into_dto_type(),
            None,
        )
        .unwrap();

        assert_matches!(contract.protocol_state, ProtocolContractState::Running(_));

        // Get participant info for the target (last participant)
        let participant_list: Vec<_> = participants.participants().to_vec();
        let (target_account_id, _, target_participant_info) = &participant_list[2];

        // Replace the target's attestation with an expired one
        let node_id = create_node_id(target_account_id, &target_participant_info.tls_public_key);
        let expiring_attestation = MpcMockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(ATTESTATION_EXPIRY_SECONDS),
            expected_measurements: None,
        };
        contract
            .tee_state
            .verify_and_store_mock(node_id, expiring_attestation, TEE_UPGRADE_DURATION)
            .expect("mock attestation is not yet expired and valid");

        // Capture the running state before verify_tee for comparison
        let ProtocolContractState::Running(running_state_before) = &contract.protocol_state else {
            panic!("expected Running state");
        };
        let running_state_before = running_state_before.clone();

        // Set time to exact expiry boundary
        let (first_account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(first_account_id.clone())
                .predecessor_account_id(first_account_id.clone())
                .block_timestamp(ATTESTATION_EXPIRY_SECONDS * 1_000_000_000) // nanoseconds
                .build()
        );

        // Call verify_tee - should trigger resharing
        let result = contract.verify_tee();
        assert_matches!(
            result,
            Ok(true),
            "verify_tee should return Ok(true) when threshold is met"
        );

        // Verify contract transitioned to Resharing state
        let ProtocolContractState::Resharing(resharing_state) = &contract.protocol_state else {
            panic!(
                "expected Resharing state, got {:?}",
                contract.protocol_state
            );
        };

        // Build expected participants: exclude the target (participant 2) who has expired attestation
        let expected_participants = Participants::init(
            ParticipantId(PARTICIPANT_COUNT as u32),
            participant_list[0..2]
                .iter()
                .map(|(acc, id, info)| (acc.clone(), *id, info.clone()))
                .collect(),
        );
        let expected_params =
            GovernanceThresholdParameters::new(expected_participants, parameters.threshold())
                .unwrap();

        let expected_resharing_state = ResharingContractState {
            previous_running_state: running_state_before,
            reshared_keys: Vec::new(),
            resharing_key: KeyEvent::new(
                keyset.epoch_id.next(),
                domains[0].clone(),
                expected_params,
            ),
            cancellation_requests: HashSet::new(),
            per_domain_thresholds: BTreeMap::new(),
        };

        assert_eq!(*resharing_state, expected_resharing_state);
    }

    /// Tests that [`MpcContract::verify_tee`] refuses to reshare when a TEE
    /// kickout would leave fewer participants than the threshold relation requires.
    /// The contract stays Running and stops accepting requests.
    #[test]
    fn verify_tee__should_refuse_kickout_when_remaining_breaks_threshold_relation() {
        const PARTICIPANT_COUNT: usize = 5;
        const ATTESTATION_EXPIRY_SECONDS: u64 = 5;
        const TEE_UPGRADE_DURATION: Duration = Duration::MAX;

        // Given: 5 participants, GovernanceThreshold 5, and one domain whose
        // reconstruction threshold is 5 (every participant is needed to sign). Dropping
        // to 4 participants would leave the GovernanceThreshold above the participant
        // count, breaking the threshold relation.
        let participants = gen_participants(PARTICIPANT_COUNT);
        let parameters = GovernanceThresholdParameters::new(
            participants.clone(),
            GovernanceThreshold::new(
                u64::try_from(PARTICIPANT_COUNT).expect("participant count fits in u64"),
            ),
        )
        .unwrap();
        let domain_id = DomainId::default();
        let domains = vec![DomainConfig {
            id: domain_id,
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(5),
            purpose: DomainPurpose::Sign,
        }];
        let (pk, _) = make_public_key_for_curve(Curve::Secp256k1, &mut OsRng);
        let keyset = Keyset::new(
            EpochId::new(0),
            vec![KeyForDomain {
                domain_id,
                key: pk.try_into().unwrap(),
                attempt: AttemptId::new(),
            }],
        );
        let mut contract =
            MpcContract::init_running(domains, 1, keyset, (&parameters).into_dto_type(), None)
                .unwrap();

        // Expire the last participant's attestation so a kickout drops the set to 4.
        let participant_list: Vec<_> = participants.participants().to_vec();
        let (target_account_id, _, target_participant_info) =
            &participant_list[PARTICIPANT_COUNT - 1];
        let node_id = create_node_id(target_account_id, &target_participant_info.tls_public_key);
        let expiring_attestation = MpcMockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(ATTESTATION_EXPIRY_SECONDS),
            expected_measurements: None,
        };
        contract
            .tee_state
            .verify_and_store_mock(node_id, expiring_attestation, TEE_UPGRADE_DURATION)
            .expect("mock attestation is not yet expired and valid");

        let (first_account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(first_account_id.clone())
                .predecessor_account_id(first_account_id.clone())
                .block_timestamp(ATTESTATION_EXPIRY_SECONDS * 1_000_000_000) // nanoseconds
                .build()
        );

        // When
        let result = contract.verify_tee();

        // Then: with only 4 surviving participants the GovernanceThreshold of 5 would
        // exceed the participant count, breaking the threshold relation, so verify_tee
        // refuses to reshare, stays Running, and stops accepting requests.
        assert_matches!(result, Ok(false));
        assert_matches!(contract.protocol_state, ProtocolContractState::Running(_));
        assert!(!contract.accept_requests);
    }

    fn make_launcher_hash(byte: u8) -> LauncherImageHash {
        LauncherImageHash::from([byte; 32])
    }

    #[test]
    fn test_vote_add_launcher_hash_reaches_threshold() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xAA);

        // First 2 votes (below threshold of 3) — launcher should NOT be added yet
        for (account_id, _, _) in &participant_list[0..2] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_launcher_hash(launcher_hash)
                .expect("vote should succeed");
        }
        assert!(
            contract.allowed_launcher_image_hashes().is_empty(),
            "launcher hash should not be added before threshold"
        );

        // 3rd vote reaches threshold — launcher should be added
        let (account_id, _, _) = &participant_list[2];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("vote should succeed");

        let allowed = contract.allowed_launcher_image_hashes();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0], launcher_hash);
    }

    #[test]
    fn test_vote_add_launcher_hash_duplicate_vote_is_idempotent() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xBB);

        let (account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );

        // Same participant votes twice — should count as 1 vote
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("vote should succeed");
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("duplicate vote should succeed");

        assert!(
            contract.allowed_launcher_image_hashes().is_empty(),
            "duplicate vote should not double-count"
        );
    }

    #[test]
    fn test_vote_remove_launcher_hash_requires_unanimity() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xCC);
        let launcher_hash_2 = make_launcher_hash(0xDD);

        // Add two launcher hashes so removal of one doesn't hit the "last entry" guard
        for hash in [launcher_hash, launcher_hash_2] {
            for (account_id, _, _) in participant_list {
                testing_env!(
                    VMContextBuilder::new()
                        .signer_account_id(account_id.clone())
                        .predecessor_account_id(account_id.clone())
                        .build()
                );
                contract
                    .vote_add_launcher_hash(hash)
                    .expect("add vote should succeed");
            }
        }
        assert_eq!(contract.allowed_launcher_image_hashes().len(), 2);

        // Now vote to remove — first 3 votes (not all 4) should NOT remove
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_remove_launcher_hash(launcher_hash)
                .expect("remove vote should succeed");
        }
        assert_eq!(
            contract.allowed_launcher_image_hashes().len(),
            2,
            "launcher hash should not be removed before unanimity"
        );

        // 4th vote — unanimous, should remove
        let (account_id, _, _) = &participant_list[3];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_remove_launcher_hash(launcher_hash)
            .expect("remove vote should succeed");

        assert_eq!(
            contract.allowed_launcher_image_hashes().len(),
            1,
            "launcher hash should be removed after unanimity"
        );
    }

    #[test]
    fn test_cannot_remove_last_launcher_hash() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xCC);

        // Add a single launcher hash
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_launcher_hash(launcher_hash)
                .expect("add vote should succeed");
        }
        assert_eq!(contract.allowed_launcher_image_hashes().len(), 1);

        // All 4 vote to remove — should still not remove because it's the last one
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_remove_launcher_hash(launcher_hash)
                .expect("remove vote should succeed");
        }
        assert_eq!(
            contract.allowed_launcher_image_hashes().len(),
            1,
            "last launcher hash should not be removable"
        );
    }

    #[test]
    fn test_vote_add_launcher_hash_derives_compose_hashes() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xDD);

        // First approve an MPC image hash so compose hashes can be derived
        let mpc_hash_bytes: [u8; 32] = [0x11; 32];
        let mpc_hash = mpc_primitives::hash::NodeImageHash::from(mpc_hash_bytes);
        let block_ts = 1_000_000_000u64;

        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .block_timestamp(block_ts)
                    .build()
            );
            contract
                .vote_code_hash(mpc_hash)
                .expect("mpc vote should succeed");
        }

        // Now add a launcher hash — should auto-derive compose hashes
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .block_timestamp(block_ts)
                    .build()
            );
            contract
                .vote_add_launcher_hash(launcher_hash)
                .expect("launcher vote should succeed");
        }

        let compose_hashes = contract.allowed_launcher_compose_hashes();
        assert_eq!(
            compose_hashes.len(),
            1,
            "should have 1 compose hash (1 launcher x 1 mpc)"
        );
    }

    #[test]
    fn test_allowed_launcher_image_hashes_view_returns_empty_initially() {
        let (contract, _participants, _first) = setup_tee_test_contract(3, 2);
        assert!(contract.allowed_launcher_image_hashes().is_empty());
    }

    #[test]
    fn test_vote_add_launcher_hash_clears_votes_on_success() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xEE);

        // Vote with 3 participants to reach threshold
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_launcher_hash(launcher_hash)
                .expect("vote should succeed");
        }
        assert_eq!(contract.allowed_launcher_image_hashes().len(), 1);

        // Votes should be cleared — voting for a second hash should start from 0
        let launcher_hash_2 = make_launcher_hash(0xFF);
        let (account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_add_launcher_hash(launcher_hash_2)
            .expect("vote should succeed");

        // Only 1 vote for hash_2, should not be added yet
        assert_eq!(
            contract.allowed_launcher_image_hashes().len(),
            1,
            "second hash should not be added with only 1 vote"
        );
    }

    /// Tests the [`launcher_hash_votes()`] view method:
    /// 1. Starts empty
    /// 2. After each vote, reflects the correct count and action (Add)
    /// 3. After threshold is reached, votes are cleared
    #[test]
    fn test_launcher_hash_votes_view() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xCC);

        assert!(contract.launcher_hash_votes().vote_by_account.is_empty());

        // First vote
        let (account_0, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_0.clone())
                .predecessor_account_id(account_0.clone())
                .build()
        );
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("vote should succeed");

        let votes = &contract.launcher_hash_votes().vote_by_account;
        assert_eq!(votes.len(), 1);
        let expected_action = LauncherVoteAction::Add(launcher_hash);
        assert!(votes.values().all(|v| *v == expected_action));

        // Second vote
        let (account_1, _, _) = &participant_list[1];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_1.clone())
                .predecessor_account_id(account_1.clone())
                .build()
        );
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("vote should succeed");

        let votes = &contract.launcher_hash_votes().vote_by_account;
        assert_eq!(votes.len(), 2);
        assert!(votes.values().all(|v| *v == expected_action));

        // Third vote reaches threshold — votes should be cleared
        let (account_2, _, _) = &participant_list[2];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_2.clone())
                .predecessor_account_id(account_2.clone())
                .build()
        );
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("vote should succeed");

        assert!(
            contract.launcher_hash_votes().vote_by_account.is_empty(),
            "votes should be cleared after threshold reached"
        );
    }

    /// Tests the [`code_hash_votes()`] view method:
    /// 1. Starts empty
    /// 2. After each vote, reflects the correct participant and hash
    /// 3. After threshold is reached, votes are cleared
    #[test]
    fn test_code_hash_votes_view() {
        let num_participants = 4;
        let threshold = 3;
        let (mut contract, participants, _) = setup_tee_test_contract(num_participants, threshold);
        let participant_list = participants.participants();
        let code_hash = NodeImageHash::from([0xAB; 32]);

        assert!(contract.code_hash_votes().proposal_by_account.is_empty());

        for (i, (account, _, _)) in participant_list[..threshold as usize].iter().enumerate() {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account.clone())
                    .predecessor_account_id(account.clone())
                    .build()
            );
            contract
                .vote_code_hash(code_hash)
                .expect("vote should succeed");

            let votes = &contract.code_hash_votes().proposal_by_account;
            if i < (threshold - 1) as usize {
                assert_eq!(votes.len(), i + 1);
                assert!(votes.values().all(|v| *v == code_hash));
            } else {
                assert!(
                    votes.is_empty(),
                    "votes should be cleared after threshold reached"
                );
            }
        }
    }

    #[test]
    fn test_new_mpc_image_derives_compose_for_existing_launchers() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xAA);
        let block_ts = 1_000_000_000u64;

        // First approve an MPC image
        let mpc_hash_1 = mpc_primitives::hash::NodeImageHash::from([0x11; 32]);
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .block_timestamp(block_ts)
                    .build()
            );
            contract
                .vote_code_hash(mpc_hash_1)
                .expect("mpc vote should succeed");
        }

        // Add a launcher hash
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .block_timestamp(block_ts)
                    .build()
            );
            contract
                .vote_add_launcher_hash(launcher_hash)
                .expect("launcher vote should succeed");
        }
        assert_eq!(contract.allowed_launcher_compose_hashes().len(), 1);

        // Now vote in a second MPC image — should auto-derive a new compose hash
        let mpc_hash_2 = mpc_primitives::hash::NodeImageHash::from([0x22; 32]);
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .block_timestamp(block_ts)
                    .build()
            );
            contract
                .vote_code_hash(mpc_hash_2)
                .expect("mpc vote 2 should succeed");
        }

        assert_eq!(
            contract.allowed_launcher_compose_hashes().len(),
            2,
            "should have 2 compose hashes (1 launcher x 2 mpc images)"
        );
    }

    /// Tests the full launcher compose hash lifecycle with MPC hash expiry:
    /// 1. Add M1, add L1 → compose: {L1,M1}
    /// 2. Add M2 → compose: {L1,M1}, {L1,M2}
    /// 3. Advance time past M2's deadline so M1 is fully expired
    ///    (allowed_images keeps the last expired entry as cutoff, so M1 only
    ///    drops when M2's grace period also passes)
    /// 4. Stored compose hashes persist — still {L1,M1}, {L1,M2}
    /// 5. Add L2 → paired only with valid M2, not expired M1
    /// 6. Add M3 → paired with both L1 and L2
    /// 7. Final: {L1,M1}, {L1,M2}, {L1,M3}, {L2,M2}, {L2,M3}
    ///    Note: {L2,M1} is NOT present since M1 was expired when L2 was added
    #[test]
    fn test_launcher_compose_lifecycle_with_mpc_expiry() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let sec = 1_000_000_000u64;
        let day = 24 * 60 * 60 * sec;
        let upgrade_deadline = 7 * day;
        let t0 = sec;

        let vote_mpc = |contract: &mut MpcContract, hash: NodeImageHash, ts: u64| {
            for (account_id, _, _) in participant_list {
                testing_env!(
                    VMContextBuilder::new()
                        .signer_account_id(account_id.clone())
                        .predecessor_account_id(account_id.clone())
                        .block_timestamp(ts)
                        .build()
                );
                contract
                    .vote_code_hash(hash)
                    .expect("mpc vote should succeed");
            }
        };

        let vote_launcher = |contract: &mut MpcContract, hash: LauncherImageHash, ts: u64| {
            for (account_id, _, _) in &participant_list[0..3] {
                testing_env!(
                    VMContextBuilder::new()
                        .signer_account_id(account_id.clone())
                        .predecessor_account_id(account_id.clone())
                        .block_timestamp(ts)
                        .build()
                );
                contract
                    .vote_add_launcher_hash(hash)
                    .expect("launcher vote should succeed");
            }
        };

        let l1 = make_launcher_hash(0xA1);
        let l2 = make_launcher_hash(0xA2);
        let m1 = NodeImageHash::from([0x11; 32]);
        let m2 = NodeImageHash::from([0x22; 32]);
        let m3 = NodeImageHash::from([0x33; 32]);

        vote_mpc(&mut contract, m1, t0);
        vote_launcher(&mut contract, l1, t0);
        assert_eq!(contract.allowed_launcher_compose_hashes().len(), 1);

        let t1 = t0 + day;
        vote_mpc(&mut contract, m2, t1);
        assert_eq!(contract.allowed_launcher_compose_hashes().len(), 2);

        let t2 = t1 + upgrade_deadline + sec;
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(participant_list[0].0.clone())
                .predecessor_account_id(participant_list[0].0.clone())
                .block_timestamp(t2)
                .build()
        );
        assert_eq!(
            contract.allowed_launcher_compose_hashes().len(),
            2,
            "stored compose hashes persist even after MPC hash expires"
        );

        vote_launcher(&mut contract, l2, t2);
        assert_eq!(
            contract.allowed_launcher_compose_hashes().len(),
            3,
            "L2 paired only with valid M2, not expired M1"
        );

        vote_mpc(&mut contract, m3, t2);
        assert_eq!(
            contract.allowed_launcher_compose_hashes().len(),
            5,
            "M3 paired with both L1 and L2"
        );

        let compose_hashes = contract.allowed_launcher_compose_hashes();
        assert!(compose_hashes.contains(&get_docker_compose_hash(&l1, &m1)));
        assert!(compose_hashes.contains(&get_docker_compose_hash(&l1, &m2)));
        assert!(compose_hashes.contains(&get_docker_compose_hash(&l1, &m3)));
        assert!(compose_hashes.contains(&get_docker_compose_hash(&l2, &m2)));
        assert!(compose_hashes.contains(&get_docker_compose_hash(&l2, &m3)));
        assert!(!compose_hashes.contains(&get_docker_compose_hash(&l2, &m1)));
    }

    fn make_measurement(byte: u8) -> ContractExpectedMeasurements {
        ContractExpectedMeasurements {
            mrtd: MrtdHash::from([byte; 48]),
            rtmr0: Rtmr0Hash::from([byte.wrapping_add(1); 48]),
            rtmr1: Rtmr1Hash::from([byte.wrapping_add(2); 48]),
            rtmr2: Rtmr2Hash::from([byte.wrapping_add(3); 48]),
            key_provider_event_digest: KeyProviderEventDigest::from([byte.wrapping_add(4); 48]),
        }
    }

    /// Tests that adding an OS measurement requires threshold votes and that
    /// duplicate measurements are rejected.
    #[test]
    fn test_vote_add_os_measurement_threshold() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement = make_measurement(0xAA);

        // First 2 votes — below threshold (3)
        for (account_id, _, _) in &participant_list[0..2] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement.clone())
                .expect("add vote should succeed");
        }
        assert!(
            contract.allowed_os_measurements().is_empty(),
            "measurement should not be added before threshold"
        );

        // 3rd vote — threshold reached
        let (account_id, _, _) = &participant_list[2];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_add_os_measurement(measurement.clone())
            .expect("add vote should succeed");
        assert_eq!(contract.allowed_os_measurements().len(), 1);
        assert_eq!(contract.allowed_os_measurements()[0], measurement);

        // Voting for the same measurement again should not duplicate
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement.clone())
                .expect("add vote should succeed");
        }
        assert_eq!(
            contract.allowed_os_measurements().len(),
            1,
            "duplicate measurement should not be added"
        );
    }

    /// Tests that removing an OS measurement requires unanimity and that
    /// the last measurement cannot be removed.
    #[test]
    fn test_vote_remove_os_measurement_unanimity() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement_1 = make_measurement(0xAA);
        let measurement_2 = make_measurement(0xBB);

        // Add two measurements
        for m in [&measurement_1, &measurement_2] {
            for (account_id, _, _) in participant_list {
                testing_env!(
                    VMContextBuilder::new()
                        .signer_account_id(account_id.clone())
                        .predecessor_account_id(account_id.clone())
                        .build()
                );
                contract
                    .vote_add_os_measurement(m.clone())
                    .expect("add vote should succeed");
            }
        }
        assert_eq!(contract.allowed_os_measurements().len(), 2);

        // 3 votes to remove — not enough (need all 4)
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_remove_os_measurement(measurement_1.clone())
                .expect("remove vote should succeed");
        }
        assert_eq!(
            contract.allowed_os_measurements().len(),
            2,
            "measurement should not be removed before unanimity"
        );

        // 4th vote — unanimous, should remove
        let (account_id, _, _) = &participant_list[3];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_remove_os_measurement(measurement_1.clone())
            .expect("remove vote should succeed");
        assert_eq!(contract.allowed_os_measurements().len(), 1);
        assert_eq!(contract.allowed_os_measurements()[0], measurement_2);
    }

    /// Tests that the last OS measurement cannot be removed.
    #[test]
    fn test_cannot_remove_last_os_measurement() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement = make_measurement(0xAA);

        // Add a single measurement
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement.clone())
                .expect("add vote should succeed");
        }
        assert_eq!(contract.allowed_os_measurements().len(), 1);

        // All 4 vote to remove — should not remove because it's the last one
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_remove_os_measurement(measurement.clone())
                .expect("remove vote should succeed");
        }
        assert_eq!(
            contract.allowed_os_measurements().len(),
            1,
            "last OS measurement should not be removable"
        );
    }

    /// Tests the os_measurement_votes view method returns correct vote data.
    #[test]
    fn test_os_measurement_votes_view() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement = make_measurement(0xCC);

        // Initially empty
        assert!(contract.os_measurement_votes().vote_by_account.is_empty());

        // Cast one vote
        let (account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_add_os_measurement(measurement.clone())
            .expect("add vote should succeed");

        let votes = contract.os_measurement_votes();
        assert_eq!(votes.vote_by_account.len(), 1);
        let (_, action) = votes.vote_by_account.iter().next().unwrap();
        assert_eq!(*action, MeasurementVoteAction::Add(measurement));
    }

    /// Tests the allowed_os_measurements view method returns the full structs
    /// with correct field values after adding measurements.
    #[test]
    fn test_allowed_os_measurements_view() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement_1 = make_measurement(0xAA);
        let measurement_2 = make_measurement(0xBB);

        // Initially empty
        assert!(contract.allowed_os_measurements().is_empty());

        // Add first measurement (3 votes = threshold)
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement_1.clone())
                .expect("add vote should succeed");
        }

        let allowed = contract.allowed_os_measurements();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0], measurement_1);

        // Add second measurement
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement_2.clone())
                .expect("add vote should succeed");
        }

        let allowed = contract.allowed_os_measurements();
        assert_eq!(allowed.len(), 2);
        assert_eq!(allowed[0], measurement_1);
        assert_eq!(allowed[1], measurement_2);
    }

    /// Tests that votes are cleared after a successful measurement add,
    /// so a subsequent vote starts from scratch.
    #[test]
    fn test_vote_add_os_measurement_clears_votes_on_success() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement = make_measurement(0xAA);

        // Vote with 3 participants to reach threshold
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement.clone())
                .expect("vote should succeed");
        }
        assert_eq!(contract.allowed_os_measurements().len(), 1);

        // Votes should be cleared — voting for a second measurement should start from 0
        let measurement_2 = make_measurement(0xBB);
        let (account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_add_os_measurement(measurement_2.clone())
            .expect("vote should succeed");

        // Only 1 vote for measurement_2, should not be added yet
        assert_eq!(
            contract.allowed_os_measurements().len(),
            1,
            "second measurement should not be added with only 1 vote"
        );
    }

    /// Tests JSON serialization roundtrip for [`ContractExpectedMeasurements`].
    /// Verifies hex encoding/decoding of 48-byte fields works correctly.
    #[test]
    fn test_contract_expected_measurements_json_roundtrip() {
        let measurement = make_measurement(0xAA);
        let json = serde_json::to_string(&measurement).expect("serialize to JSON");
        let deserialized: ContractExpectedMeasurements =
            serde_json::from_str(&json).expect("deserialize from JSON");
        assert_eq!(measurement, deserialized);

        // Verify the JSON contains hex strings, not raw byte arrays
        assert!(json.contains("aa"), "JSON should contain hex-encoded bytes");
        assert!(
            !json.contains('['),
            "JSON should not contain array brackets"
        );
    }

    #[cfg(all(feature = "__abi-generate", not(target_arch = "wasm32")))]
    #[test]
    fn mpc_contract_borsh_schema_has_not_changed() {
        let schema = borsh::schema::BorshSchemaContainer::for_type::<MpcContract>();
        insta::assert_debug_snapshot!(schema);
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

    /// Votes `chain` into the on-chain RPC whitelist using the signing threshold of
    /// participants (so the chain becomes whitelisted).
    fn whitelist_chain(contract: &mut MpcContract, chain: dtos::ForeignChain) {
        let entry = dtos::ChainEntry {
            providers: NonEmptyBTreeMap::new(
                dtos::ProviderId("alchemy".to_string()),
                dtos::ProviderConfig {
                    base_url: "https://provider.example.com".to_string(),
                    auth_scheme: dtos::AuthScheme::None,
                    chain_routing: dtos::ChainRouting::Embedded,
                },
            ),
            quorum: 1,
        };
        let batch = NonEmptyBTreeMap::new(chain, entry);
        let threshold = contract.threshold().unwrap().value() as usize;
        for account_id in participant_account_ids(contract).iter().take(threshold) {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_update_foreign_chain_providers(batch.clone())
                .expect("vote should succeed");
        }
    }

    fn register_foreign_chain_config(
        contract: &mut MpcContract,
        account_id: &AccountId,
        chains: impl IntoIterator<Item = dtos::ForeignChain>,
    ) {
        let foreign_chains_config: dtos::ForeignChainsConfig =
            chains.into_iter().collect::<BTreeSet<_>>().into();
        // In mock setup, account_public_key == tls_public_key.
        let tls_key = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .info(account_id)
            .expect("account must be a participant")
            .tls_public_key
            .clone();
        let mut env = Environment::new(None, Some(account_id.clone()), None);
        env.set_pk(near_sdk::PublicKey::from(tls_key));
        contract
            .register_foreign_chains_config(foreign_chains_config)
            .expect("register should succeed");
    }

    #[test]
    // Setup with 4 participants, first 3 supporting 4 chains, 4th one supports only 2.
    // Node operator of 4th node spins up new node, and registers config that supports all 4 chains.
    // Available chains should still be 2.
    // Node operator of 4th node migrates node to new node, and new node becomes participant,
    // then all 4 chains should be supported.
    fn get_available_foreign_chains__should_not_count_non_participant_node_config() {
        // Given: 4 participants, threshold 4 (all must agree); 4 chains whitelisted.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
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
                if domain.purpose == DomainPurpose::ForeignTx {
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
            register_foreign_chain_config(&mut contract, account_id, all_chains);
        }

        // Node 4 (active participant) only covers 2 chains.
        let operator4 = &participant_ids[3];
        register_foreign_chain_config(&mut contract, operator4, partial_chains);

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
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
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
                if domain.purpose == DomainPurpose::ForeignTx {
                    domain.reconstruction_threshold = ReconstructionThreshold::new(4);
                }
            }
        }
        let participant_ids = participant_account_ids(&contract);
        for account_id in participant_ids.iter().take(3) {
            register_foreign_chain_config(&mut contract, account_id, all_chains);
        }
        let operator4 = &participant_ids[3];
        register_foreign_chain_config(&mut contract, operator4, partial_chains);

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
            .conclude_node_migration(&keyset)
            .expect("migration should succeed");

        // Then: all 4 chains available — no manual recompute needed.
        let available = contract.get_available_foreign_chains();
        assert_eq!(available.len(), 4);
    }

    #[test]
    fn get_available_foreign_chains__should_include_chain_when_at_least_threshold_participants_cover_it()
     {
        // Given: 4 participants, signing threshold 3; Bitcoin whitelisted.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When: exactly the threshold (3) of 4 participants cover Bitcoin — one node does not.
        for account_id in participants.iter().take(3) {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
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
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When: only 2 of 4 (< threshold) cover Bitcoin.
        for account_id in participants.iter().take(2) {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
        }

        // Then: Bitcoin is not available.
        let available = contract.get_available_foreign_chains();
        assert!(!available.contains(&dtos::ForeignChain::Bitcoin));
        assert!(available.is_empty());
    }

    #[test]
    fn get_available_foreign_chains__should_exclude_chain_that_is_covered_but_not_whitelisted() {
        // Given: 4 participants, threshold 3; Bitcoin is NOT whitelisted.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);

        // When: all 4 participants cover Bitcoin.
        for account_id in &participants {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
        }

        // Then: Bitcoin is still not available — `available` is a subset of `whitelisted`.
        let available = contract.get_available_foreign_chains();
        assert!(available.is_empty());
    }

    #[test]
    fn get_available_foreign_chains__should_only_include_whitelisted_chains_with_threshold_coverage()
     {
        // Given: 4 participants, threshold 3. Bitcoin and Ethereum are whitelisted; Solana is not.
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        whitelist_chain(&mut contract, dtos::ForeignChain::Ethereum);

        // When (each participant registers its full covered set in one call, since a
        // registration replaces the participant's previously reported set):
        // - Bitcoin: covered by 3 participants (whitelisted + threshold) -> available.
        // - Ethereum: covered by 1 participant (whitelisted but under threshold) -> not available.
        // - Solana: covered by all 4 (threshold met but not whitelisted) -> not available.
        register_foreign_chain_config(
            &mut contract,
            &participants[0],
            [
                dtos::ForeignChain::Bitcoin,
                dtos::ForeignChain::Ethereum,
                dtos::ForeignChain::Solana,
            ],
        );
        register_foreign_chain_config(
            &mut contract,
            &participants[1],
            [dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Solana],
        );
        register_foreign_chain_config(
            &mut contract,
            &participants[2],
            [dtos::ForeignChain::Bitcoin, dtos::ForeignChain::Solana],
        );
        register_foreign_chain_config(
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
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);

        // GovernanceThreshold (3) participants already cover Bitcoin — but the chain is not whitelisted,
        // so the cache must be empty.
        for account_id in participants.iter().take(3) {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
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
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        for account_id in participants.iter().take(3) {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
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
        let (_context, mut contract, _) =
            basic_setup_with_protocol(Protocol::CaitSith, DomainPurpose::ForeignTx, &mut OsRng);
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);
        for account_id in participants.iter().take(2) {
            register_foreign_chain_config(&mut contract, account_id, [dtos::ForeignChain::Bitcoin]);
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
        register_foreign_chain_config(
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
            purpose: DomainPurpose::ForeignTx,
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
        let mut contract =
            MpcContract::init_running(domains, 1, keyset, (&parameters).into_dto_type(), None)
                .unwrap();
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When: exactly 2 participants register Bitcoin (meets domain threshold=2, below governance threshold=3).
        register_foreign_chain_config(
            &mut contract,
            &participants[0],
            [dtos::ForeignChain::Bitcoin],
        );
        register_foreign_chain_config(
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
            purpose: DomainPurpose::ForeignTx,
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
        let mut contract =
            MpcContract::init_running(domains, 2, keyset, (&parameters).into_dto_type(), None)
                .unwrap();
        let participants = participant_account_ids(&contract);
        whitelist_chain(&mut contract, dtos::ForeignChain::Bitcoin);

        // When
        let bitcoin_available = |contract: &MpcContract| {
            contract
                .get_available_foreign_chains()
                .contains(&dtos::ForeignChain::Bitcoin)
        };
        register_foreign_chain_config(
            &mut contract,
            &participants[0],
            [dtos::ForeignChain::Bitcoin],
        );
        register_foreign_chain_config(
            &mut contract,
            &participants[1],
            [dtos::ForeignChain::Bitcoin],
        );
        let available_below_threshold = bitcoin_available(&contract);
        register_foreign_chain_config(
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
        register_foreign_chain_config(
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

    const MAX_HASH: [u8; 32] = [0xff; 32];

    /// Charged storage of the largest attestation entry the contract can store, in bytes:
    /// a 64-byte account id (NEAR's cap) plus fixed-width keys and the largest
    /// [`VerifiedAttestation`] variant, including the [`IterableMap`] record overhead.
    const WORST_CASE_ENTRY_BYTES: u64 = 604;

    /// Ceiling on one entry's storage cost at today's price, with headroom over
    /// [`WORST_CASE_ENTRY_BYTES`] for storage-price changes.
    const WORST_CASE_ENTRY_COST_CEILING: NearToken = NearToken::from_millinear(10);

    fn worst_case_dstack_attestation() -> VerifiedAttestation {
        VerifiedAttestation::Dstack(ValidatedDstackAttestation {
            mpc_image_hash: MAX_HASH.into(),
            launcher_compose_hash: MAX_HASH.into(),
            expiry_timestamp_seconds: u64::MAX,
            measurements: default_measurements()[0],
        })
    }

    fn worst_case_mock_attestation() -> VerifiedAttestation {
        VerifiedAttestation::Mock(MpcMockAttestation::WithConstraints {
            mpc_docker_image_hash: Some(MAX_HASH.into()),
            launcher_docker_compose_hash: Some(MAX_HASH.into()),
            expiry_timestamp_seconds: Some(u64::MAX),
            expected_measurements: Some(default_measurements()[0]),
        })
    }

    /// Storage the contract pays for one stored attestation entry, measured the way the runtime
    /// charges it. NEAR caps an account id at 64 bytes; every other [`NodeId`] field is fixed-size,
    /// so this is the worst case for the given attestation variant.
    fn measure_stored_entry_bytes(verified_attestation: VerifiedAttestation) -> u64 {
        testing_env!(VMContextBuilder::new().build());
        let node_id = create_node_id(
            &"a".repeat(64).parse().unwrap(),
            &bogus_ed25519_public_key(),
        );

        let mut tee_state = TeeState::default();
        let before = env::storage_usage();
        tee_state.stored_attestations.insert(
            node_id.tls_public_key.clone(),
            NodeAttestation {
                node_id,
                verified_attestation,
            },
        );
        tee_state.stored_attestations.flush();

        env::storage_usage() - before
    }

    fn measure_grant_row_bytes() -> u64 {
        let (_, mut contract, _) = basic_setup(Curve::Edwards25519, &mut OsRng);
        testing_env!(VMContextBuilder::new().build());
        let account: AccountId = "a".repeat(64).parse().unwrap();

        let before = env::storage_usage();
        contract.available_attestation_grants.insert(account, 1);
        contract.available_attestation_grants.flush();

        env::storage_usage() - before
    }

    /// Pins the exact stored size of the largest variant of each attestation kind.
    ///
    /// Do not update these numbers just to make a failing case pass. The contract funds every
    /// entry from its own balance, so a size change alters what the contract pays per node, and
    /// everything derived from it must be revisited in the same change — today
    /// [`WORST_CASE_ENTRY_BYTES`] and [`WORST_CASE_ENTRY_COST_CEILING`].
    ///
    /// The prepaid-storage fee is sized from these numbers.
    #[rstest]
    #[case::dstack(599, worst_case_dstack_attestation())]
    #[case::mock(604, worst_case_mock_attestation())]
    fn stored_attestation_entry__should_have_the_pinned_size(
        #[case] expected_bytes: u64,
        #[case] verified_attestation: VerifiedAttestation,
    ) {
        // Given / When
        let bytes_stored = measure_stored_entry_bytes(verified_attestation);

        // Then
        assert_eq!(
            bytes_stored, expected_bytes,
            "stored entry size changed; see this test's doc comment before updating the number"
        );
        assert!(
            bytes_stored <= WORST_CASE_ENTRY_BYTES,
            "entry ({bytes_stored} bytes) exceeds the pinned worst case \
             ({WORST_CASE_ENTRY_BYTES} bytes)"
        );
    }

    /// The fee covers the worst-case entry plus the grants row, and is held to twice that, so
    /// growth is caught while there is still room rather than once the fee is already breached.
    /// A failure here is a prompt to re-price, not a broken test.
    ///
    /// Does not guard a real storage re-pricing: [`env::storage_byte_cost`] is a near-sdk
    /// constant, not a protocol read.
    ///
    /// TODO(#4123): a fee voted below the floor is not caught here either.
    #[test]
    fn attestation_storage_fee__should_keep_double_the_floor() {
        // Given
        const BUFFER: u128 = 2;
        let worst_case_entry_bytes = measure_stored_entry_bytes(worst_case_mock_attestation())
            .max(measure_stored_entry_bytes(worst_case_dstack_attestation()));
        let floor_bytes = worst_case_entry_bytes + measure_grant_row_bytes();

        // When
        let floor = env::storage_byte_cost().saturating_mul(u128::from(floor_bytes));
        let fee = NearToken::from_millinear(u128::from(
            Config::default().attestation_storage_fee_millinear,
        ));

        // Then
        assert!(
            floor.saturating_mul(BUFFER) <= fee,
            "attestation storage fee ({fee}) must be at least {BUFFER}x the floor \
             ({floor_bytes} bytes, {floor}) at today's storage price"
        );
    }

    #[rstest]
    #[case::dstack(worst_case_dstack_attestation())]
    #[case::mock(worst_case_mock_attestation())]
    fn stored_attestation_entry__should_stay_under_the_cost_ceiling(
        #[case] verified_attestation: VerifiedAttestation,
    ) {
        // Given / When
        let bytes_grown = measure_stored_entry_bytes(verified_attestation);
        let cost = env::storage_byte_cost().saturating_mul(u128::from(bytes_grown));

        // Then
        assert!(
            cost <= WORST_CASE_ENTRY_COST_CEILING,
            "worst-case entry cost ({bytes_grown} bytes, {cost}) must stay under \
             {WORST_CASE_ENTRY_COST_CEILING} at today's storage price"
        );
    }
}
