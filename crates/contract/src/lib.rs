#![deny(clippy::mod_module_files)]
pub mod config;
pub mod crypto_shared;
pub mod errors;
pub mod legacy_contract_state;
pub mod node_migrations;
pub mod primitives;
pub mod state;
pub mod storage_keys;
pub mod tee;
pub mod update;
#[cfg(feature = "dev-utils")]
pub mod utils;
pub mod v0_state;

mod dto_mapping;

use std::{collections::BTreeMap, time::Duration};

use crate::{
    crypto_shared::{near_public_key_to_affine_point, types::CKDResponse},
    dto_mapping::{IntoContractType, IntoDtoType, TryIntoDtoType},
    errors::{Error, RequestError},
    primitives::ckd::{CKDRequest, CKDRequestArgs},
    storage_keys::StorageKey,
    tee::tee_state::{TeeQuoteStatus, TeeState},
    update::{ProposeUpdateArgs, ProposedUpdates, Update, UpdateId},
};
use borsh::{BorshDeserialize, BorshSerialize};
use config::{Config, InitConfig};
use crypto_shared::{
    derive_key_secp256k1, derive_tweak,
    kdf::{check_ec_signature, derive_public_key_edwards_point_ed25519},
    types::{PublicKeyExtended, PublicKeyExtendedConversionError, SignatureResponse},
};
use dtos_contract::PublicKey;
use errors::{
    DomainError, InvalidParameters, InvalidState, PublicKeyError, RespondError, TeeError,
};
use k256::elliptic_curve::PrimeField;
use near_sdk::{
    env::{self, ed25519_verify},
    log, near_bindgen,
    store::LookupMap,
    AccountId, CryptoHash, Gas, GasWeight, NearToken, Promise, PromiseError, PromiseOrValue,
};
use node_migrations::{BackupServiceInfo, DestinationNodeInfo, NodeMigrations};
use primitives::{
    domain::{DomainConfig, DomainId, DomainRegistry, SignatureScheme},
    key_state::{AuthenticatedParticipantId, EpochId, KeyEventId, Keyset},
    signature::{SignRequest, SignRequestArgs, SignatureRequest, YieldIndex},
    thresholds::{Threshold, ThresholdParameters},
};
use state::{running::RunningContractState, ProtocolContractState};
use tee::{
    proposal::MpcDockerImageHash,
    tee_state::{NodeId, TeeValidationResult},
};

/// Gas required for a sign request
const GAS_FOR_SIGN_CALL: Gas = Gas::from_tgas(15);

/// Gas required for a CKD request
const GAS_FOR_CKD_CALL: Gas = Gas::from_tgas(15);

/// Register used to receive data id from `promise_await_data`
const DATA_ID_REGISTER: u64 = 0;

/// Prepaid gas for a `return_signature_and_clean_state_on_success` call
const RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_CALL_GAS: Gas = Gas::from_tgas(7);

/// Prepaid gas for a `return_ck_and_clean_state_on_success` call
const RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS_CALL_GAS: Gas = Gas::from_tgas(7);

/// Prepaid gas for a `update_config` call
const UPDATE_CONFIG_GAS: Gas = Gas::from_tgas(5);

/// Prepaid gas for a `fail_on_timeout` call
const FAIL_ON_TIMEOUT_GAS: Gas = Gas::from_tgas(2);

/// Prepaid gas for a `clean_tee_status` call
const CLEAN_TEE_STATUS_GAS: Gas = Gas::from_tgas(3);

/// Minimum deposit required for sign requests
const MINIMUM_SIGN_REQUEST_DEPOSIT: NearToken = NearToken::from_yoctonear(1);

/// Minimum deposit required for CKD requests
const MINIMUM_CKD_REQUEST_DEPOSIT: NearToken = NearToken::from_yoctonear(1);

/// Prepaid gas for a `cleanup_orphaned_node_migrations` call
/// todo: benchmark [#1164](https://github.com/near/mpc/issues/1164)
const CLEAN_NODE_MIGRATIONS: Gas = Gas::from_tgas(3);

impl Default for MpcContract {
    fn default() -> Self {
        env::panic_str("Calling default not allowed.");
    }
}

#[near_bindgen]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pending_ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    proposed_updates: ProposedUpdates,
    config: Config,
    tee_state: TeeState,
    accept_requests: bool,
    node_migrations: NodeMigrations,
}

impl MpcContract {
    pub(crate) fn public_key_extended(
        &self,
        domain_id: DomainId,
    ) -> Result<PublicKeyExtended, Error> {
        self.protocol_state.public_key(domain_id)
    }

    fn threshold(&self) -> Result<Threshold, Error> {
        self.protocol_state.threshold()
    }

    /// Returns true if the request was already pending
    fn add_signature_request(&mut self, request: &SignatureRequest, data_id: CryptoHash) -> bool {
        self.pending_signature_requests
            .insert(request.clone(), YieldIndex { data_id })
            .is_some()
    }

    /// Returns true if the request was already pending
    fn add_ckd_request(&mut self, request: &CKDRequest, data_id: CryptoHash) -> bool {
        self.pending_ckd_requests
            .insert(request.clone(), YieldIndex { data_id })
            .is_some()
    }
}

// User contract API
#[near_bindgen]
impl MpcContract {
    /// `key_version` must be less than or equal to the value at `latest_key_version`
    /// To avoid overloading the network with too many requests,
    /// we ask for a small deposit for each signature request.
    #[handle_result]
    #[payable]
    pub fn sign(&mut self, request: SignRequestArgs) {
        log!(
            "sign: predecessor={:?}, request={:?}",
            env::predecessor_account_id(),
            request
        );
        let initial_storage = env::storage_usage();

        let request: SignRequest = request.try_into().unwrap();
        let Ok(public_key) = self.public_key(Some(request.domain_id)) else {
            env::panic_str(
                &InvalidParameters::DomainNotFound {
                    provided: request.domain_id,
                }
                .to_string(),
            );
        };

        // ensure the signer sent a valid signature request
        // It's important we fail here because the MPC nodes will fail in an identical way.
        // This allows users to get the error message
        match &public_key {
            PublicKey::Secp256k1(_) => {
                let hash = *request.payload.as_ecdsa().expect("Payload is not Ecdsa");
                k256::Scalar::from_repr(hash.into())
                    .into_option()
                    .expect("Ecdsa payload cannot be converted to Scalar");
            }
            PublicKey::Ed25519(_) => {
                request.payload.as_eddsa().expect("Payload is not EdDSA");
            }
            PublicKey::Bls12381(_) => {
                env::panic_str(
                    &InvalidParameters::InvalidDomainId.message("Selected domain is used for Bls12381, which is not compatible with this function")
                    .to_string(),
                );
            }
        }

        // Make sure sign call will not run out of gas doing yield/resume logic
        if env::prepaid_gas() < GAS_FOR_SIGN_CALL {
            env::panic_str(
                &InvalidParameters::InsufficientGas
                    .message(format!(
                        "Provided: {}, required: {}",
                        env::prepaid_gas(),
                        GAS_FOR_SIGN_CALL
                    ))
                    .to_string(),
            );
        }

        // Check deposit and refund if required
        let predecessor = env::predecessor_account_id();
        let deposit = env::attached_deposit();
        let storage_used = env::storage_usage() - initial_storage;
        let storage_cost = env::storage_byte_cost().saturating_mul(u128::from(storage_used));
        let storage_cost = std::cmp::max(storage_cost, MINIMUM_SIGN_REQUEST_DEPOSIT);

        match deposit.checked_sub(storage_cost) {
            None => {
                env::panic_str(
                    &InvalidParameters::InsufficientDeposit
                        .message(format!(
                            "Require a deposit of {} yoctonear, found: {}",
                            storage_cost.as_yoctonear(),
                            deposit.as_yoctonear(),
                        ))
                        .to_string(),
                );
            }
            Some(diff) => {
                if diff > NearToken::from_yoctonear(0) {
                    log!("refund excess deposit {diff} to {predecessor}");
                    Promise::new(predecessor.clone()).transfer(diff);
                }
            }
        }

        let request = SignatureRequest::new(
            request.domain_id,
            request.payload,
            &predecessor,
            &request.path,
        );

        if !self.accept_requests {
            env::panic_str(&TeeError::TeeValidationFailed.to_string())
        }

        let promise_index = env::promise_yield_create(
            "return_signature_and_clean_state_on_success",
            &serde_json::to_vec(&(&request,)).unwrap(),
            RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_CALL_GAS,
            GasWeight(0),
            DATA_ID_REGISTER,
        );

        // Store the request in the contract's local state
        let return_sig_id: CryptoHash = env::read_register(DATA_ID_REGISTER)
            .expect("read_register failed")
            .try_into()
            .expect("conversion to CryptoHash failed");
        if self.add_signature_request(&request, return_sig_id) {
            log!("signature request already present, overriding callback.")
        }

        env::promise_return(promise_index);
    }

    /// This is the root public key combined from all the public keys of the participants.
    /// The domain parameter specifies which domain we're querying the public key for;
    /// the default is the first domain.
    #[handle_result]
    pub fn public_key(
        &self,
        domain_id: Option<DomainId>,
    ) -> Result<dtos_contract::PublicKey, Error> {
        let domain_id = domain_id.unwrap_or_else(DomainId::legacy_ecdsa_id);
        self.public_key_extended(domain_id).map(Into::into)
    }

    /// This is the derived public key of the caller given path and predecessor
    /// if predecessor is not provided, it will be the caller of the contract.
    ///
    /// The domain parameter specifies which domain we're deriving the public key for;
    /// the default is the first domain.
    #[handle_result]
    pub fn derived_public_key(
        &self,
        path: String,
        predecessor: Option<AccountId>,
        domain_id: Option<DomainId>,
    ) -> Result<dtos_contract::PublicKey, Error> {
        let predecessor: AccountId = predecessor.unwrap_or_else(env::predecessor_account_id);
        let tweak = derive_tweak(&predecessor, &path);

        let domain = domain_id.unwrap_or_else(DomainId::legacy_ecdsa_id);
        let public_key = self.public_key_extended(domain)?;

        let derived_public_key: dtos_contract::PublicKey = match public_key {
            PublicKeyExtended::Secp256k1 { near_public_key } => {
                let derived_public_key =
                    derive_key_secp256k1(&near_public_key_to_affine_point(near_public_key), &tweak)
                        .map_err(PublicKeyError::from)?;
                derived_public_key.into_dto_type().into()
            }
            PublicKeyExtended::Ed25519 { edwards_point, .. } => {
                let derived_public_key_edwards_point =
                    derive_public_key_edwards_point_ed25519(&edwards_point, &tweak);
                derived_public_key_edwards_point
                    .compress()
                    .into_dto_type()
                    .into()
            }
            PublicKeyExtended::Bls12381 { public_key } => public_key,
        };

        Ok(derived_public_key)
    }

    /// Key versions refer new versions of the root key that we may choose to generate on cohort
    /// changes. Older key versions will always work but newer key versions were never held by
    /// older signers. Newer key versions may also add new security features, like only existing
    /// within a secure enclave. The signature_scheme parameter specifies which protocol
    /// we're querying the latest version for. The default is Secp256k1. The default is **NOT**
    /// to query across all protocols.
    pub fn latest_key_version(&self, signature_scheme: Option<SignatureScheme>) -> u32 {
        self.state()
            .most_recent_domain_for_protocol(signature_scheme.unwrap_or_default())
            .unwrap()
            .0 as u32
    }

    /// To avoid overloading the network with too many requests,
    /// we ask for a small deposit for each ckd request.
    #[handle_result]
    #[payable]
    pub fn request_app_private_key(&mut self, request: CKDRequestArgs) {
        log!(
            "request_app_private_key: predecessor={:?}, request={:?}",
            env::predecessor_account_id(),
            request
        );
        let initial_storage = env::storage_usage();

        let Ok(public_key) = self.public_key(Some(request.domain_id)) else {
            env::panic_str(
                &InvalidParameters::DomainNotFound {
                    provided: request.domain_id,
                }
                .to_string(),
            );
        };

        match public_key {
            dtos_contract::PublicKey::Secp256k1(_) | dtos_contract::PublicKey::Ed25519(_) => {
                env::panic_str(
                    &InvalidParameters::InvalidDomainId
                        .message("Provided domain ID key type is not Bls12381")
                        .to_string(),
                )
            }
            dtos_contract::PublicKey::Bls12381(_) => {}
        }

        // Make sure CKD call will not run out of gas doing yield/resume logic
        if env::prepaid_gas() < GAS_FOR_CKD_CALL {
            env::panic_str(
                &InvalidParameters::InsufficientGas
                    .message(format!(
                        "Provided: {}, required: {}",
                        env::prepaid_gas(),
                        GAS_FOR_CKD_CALL
                    ))
                    .to_string(),
            );
        }

        let predecessor = env::predecessor_account_id();
        // Check deposit and refund if required
        let deposit = env::attached_deposit();
        let storage_used = env::storage_usage() - initial_storage;
        let cost = env::storage_byte_cost().saturating_mul(u128::from(storage_used));
        let cost = std::cmp::max(cost, MINIMUM_CKD_REQUEST_DEPOSIT);

        match deposit.checked_sub(cost) {
            None => {
                env::panic_str(
                    &InvalidParameters::InsufficientDeposit
                        .message(format!(
                            "Require a deposit of {} yoctonear, found: {}",
                            cost.as_yoctonear(),
                            deposit.as_yoctonear(),
                        ))
                        .to_string(),
                );
            }
            Some(diff) => {
                if diff > NearToken::from_yoctonear(0) {
                    log!("refund excess deposit {diff} to {predecessor}");
                    Promise::new(predecessor.clone()).transfer(diff);
                }
            }
        }

        let mpc_contract = self;

        if !mpc_contract.accept_requests {
            env::panic_str(&TeeError::TeeValidationFailed.to_string())
        }

        let app_id = env::predecessor_account_id();
        let request = CKDRequest::new(request.app_public_key, app_id, request.domain_id);

        let promise_index = env::promise_yield_create(
            "return_ck_and_clean_state_on_success",
            &serde_json::to_vec(&(&request,)).unwrap(),
            RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS_CALL_GAS,
            GasWeight(0),
            DATA_ID_REGISTER,
        );

        // Store the request in the contract's local state
        let return_ck_id: CryptoHash = env::read_register(DATA_ID_REGISTER)
            .expect("read_register failed")
            .try_into()
            .expect("conversion to CryptoHash failed");
        if mpc_contract.add_ckd_request(&request, return_ck_id) {
            log!("request already present, overriding callback.")
        }

        env::promise_return(promise_index);
    }
}

// Node API
#[near_bindgen]
impl MpcContract {
    #[handle_result]
    pub fn respond(
        &mut self,
        request: SignatureRequest,
        response: SignatureResponse,
    ) -> Result<(), Error> {
        let signer = env::signer_account_id();
        log!("respond: signer={}, request={:?}", &signer, &request);

        if !self.protocol_state.is_running_or_resharing() {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }

        if !self.accept_requests {
            return Err(TeeError::TeeValidationFailed.into());
        }

        let domain = request.domain_id;
        let public_key = self.public_key_extended(domain)?;

        let signature_is_valid = match (&response, public_key) {
            (
                SignatureResponse::Secp256k1(signature_response),
                PublicKeyExtended::Secp256k1 { near_public_key },
            ) => {
                // generate the expected public key
                let expected_public_key = derive_key_secp256k1(
                    &near_public_key_to_affine_point(near_public_key),
                    &request.tweak,
                )
                .map_err(RespondError::from)?;

                let payload_hash = request.payload.as_ecdsa().expect("Payload is not ECDSA");

                // Check the signature is correct
                check_ec_signature(
                    &expected_public_key,
                    &signature_response.big_r.affine_point,
                    &signature_response.s.scalar,
                    payload_hash,
                    signature_response.recovery_id,
                )
                .is_ok()
            }
            (
                SignatureResponse::Ed25519 { signature },
                PublicKeyExtended::Ed25519 {
                    edwards_point: public_key_edwards_point,
                    ..
                },
            ) => {
                let derived_public_key_edwards_point = derive_public_key_edwards_point_ed25519(
                    &public_key_edwards_point,
                    &request.tweak,
                );
                let derived_public_key_32_bytes =
                    *derived_public_key_edwards_point.compress().as_bytes();

                let message = request.payload.as_eddsa().expect("Payload is not EdDSA");

                ed25519_verify(signature.as_bytes(), message, &derived_public_key_32_bytes)
            }
            (signature_response, public_key_requested) => {
                return Err(RespondError::SignatureSchemeMismatch.message(format!(
                    "Signature response from MPC: {:?}. Key requested by user {:?}",
                    signature_response, public_key_requested
                )));
            }
        };

        if !signature_is_valid {
            return Err(RespondError::InvalidSignature.into());
        }

        // First get the yield promise of the (potentially timed out) request.
        if let Some(YieldIndex { data_id }) = self.pending_signature_requests.remove(&request) {
            // Finally, resolve the promise. This will have no effect if the request already timed.
            env::promise_yield_resume(&data_id, &serde_json::to_vec(&response).unwrap());
            Ok(())
        } else {
            Err(InvalidParameters::RequestNotFound.into())
        }
    }

    #[handle_result]
    pub fn respond_ckd(&mut self, request: CKDRequest, response: CKDResponse) -> Result<(), Error> {
        let signer = env::signer_account_id();
        log!("respond_ckd: signer={}, request={:?}", &signer, &request);

        if !self.protocol_state.is_running_or_resharing() {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }

        if !self.accept_requests {
            return Err(TeeError::TeeValidationFailed.into());
        }

        // First get the yield promise of the (potentially timed out) request.
        if let Some(YieldIndex { data_id }) = self.pending_ckd_requests.remove(&request) {
            // Finally, resolve the promise. This will have no effect if the request already timed.
            env::promise_yield_resume(&data_id, &serde_json::to_vec(&response).unwrap());
            Ok(())
        } else {
            Err(InvalidParameters::RequestNotFound.into())
        }
    }

    /// (Prospective) Participants can submit their tee participant information through this
    /// endpoint.
    #[payable]
    #[handle_result]
    pub fn submit_participant_info(
        &mut self,
        proposed_participant_attestation: dtos_contract::Attestation,
        tls_public_key: dtos_contract::Ed25519PublicKey,
    ) -> Result<(), Error> {
        let proposed_participant_attestation =
            proposed_participant_attestation.into_contract_type();

        let account_id = env::signer_account_id();
        let account_key = env::signer_account_pk();

        log!(
            "submit_participant_info: signer={}, proposed_participant_attestation={:?}, account_key={:?}",
            account_id,
            proposed_participant_attestation,
            account_key
        );

        // Save the initial storage usage to know how much to charge the proposer for the storage
        // used
        let initial_storage = env::storage_usage();

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        // Verify the TEE quote and Docker image for the proposed participant
        let status = self.tee_state.verify_proposed_participant_attestation(
            &proposed_participant_attestation,
            tls_public_key.clone(),
            tee_upgrade_deadline_duration,
        );

        if status == TeeQuoteStatus::Invalid {
            return Err(InvalidParameters::InvalidTeeRemoteAttestation
                .message("TeeQuoteStatus is invalid".to_string()));
        }

        // Add the participant information to the contract state
        let is_new_attestation = self.tee_state.add_participant(
            NodeId {
                account_id: account_id.clone(),
                tls_public_key: tls_public_key.into_contract_type(),
            },
            proposed_participant_attestation,
        );

        // Both participants and non-participants can propose. Non-participants must pay for the
        // storage they use; participants do not.
        if self.voter_account().is_err() || is_new_attestation {
            let storage_used = env::storage_usage() - initial_storage;
            let cost = env::storage_byte_cost().saturating_mul(storage_used as u128);
            let attached = env::attached_deposit();

            if attached < cost {
                return Err(InvalidParameters::InsufficientDeposit.message(format!(
                    "Attached {}, Required {}",
                    attached.as_yoctonear(),
                    cost.as_yoctonear(),
                )));
            }

            // Refund the difference if the proposer attached more than required
            if let Some(diff) = attached.checked_sub(cost) {
                if diff > NearToken::from_yoctonear(0) {
                    Promise::new(account_id).transfer(diff);
                }
            }
        }

        Ok(())
    }

    #[handle_result]
    pub fn get_attestation(
        &self,
        tls_public_key: dtos_contract::Ed25519PublicKey,
    ) -> Result<Option<dtos_contract::Attestation>, Error> {
        Ok(self
            .tee_state
            .participants_attestations
            .iter()
            .find(|(node_id, _)| node_id.tls_public_key == tls_public_key.into_contract_type())
            .map(|(_, attestation)| attestation.clone().into_dto_type()))
    }

    /// Propose a new set of parameters (participants and threshold) for the MPC network.
    /// If a threshold number of votes are reached on the exact same proposal, this will transition
    /// the contract into the Resharing state.
    ///
    /// The epoch_id must be equal to 1 plus the current epoch ID (if Running) or prospective epoch
    /// ID (if Resharing). Otherwise the vote is ignored. This is to prevent late transactions from
    /// accidentally voting on outdated proposals.
    #[handle_result]
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposal: ThresholdParameters,
    ) -> Result<(), Error> {
        log!(
            "vote_new_parameters: signer={}, proposal={:?}",
            env::signer_account_id(),
            proposal,
        );

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        let validation_result = self
            .tee_state
            .validate_tee(proposal.participants(), tee_upgrade_deadline_duration);

        let proposed_participants = proposal.participants();

        match validation_result {
            TeeValidationResult::Full => {
                if let Some(new_state) = self
                    .protocol_state
                    .vote_new_parameters(prospective_epoch_id, &proposal)?
                {
                    self.protocol_state = new_state;
                }
                Ok(())
            }
            TeeValidationResult::Partial {
                participants_with_valid_attestation,
            } => {
                let invalid_participants: Vec<_> = proposed_participants
                    .participants()
                    .iter()
                    .filter(|(account_id, _, _)| {
                        participants_with_valid_attestation.is_participant(account_id)
                    })
                    .collect();

                Err(
                    InvalidParameters::InvalidTeeRemoteAttestation.message(format!(
                        "The following participants have invalid TEE status: {:?}",
                        invalid_participants
                    )),
                )
            }
        }
    }

    /// Propose adding a new set of domains for the MPC network.
    /// If a threshold number of votes are reached on the exact same proposal, this will transition
    /// the contract into the Initializing state to generate keys for the new domains.
    ///
    /// The specified list of domains must have increasing and contiguous IDs, and the first ID
    /// must be the same as the `next_domain_id` returned by state().
    #[handle_result]
    pub fn vote_add_domains(&mut self, domains: Vec<DomainConfig>) -> Result<(), Error> {
        log!(
            "vote_add_domains: signer={}, domains={:?}",
            env::signer_account_id(),
            domains,
        );

        if let Some(new_state) = self.protocol_state.vote_add_domains(domains)? {
            self.protocol_state = new_state;
        }
        Ok(())
    }

    /// Starts a new attempt to generate a key for the current domain.
    /// This only succeeds if the signer is the leader (the participant with the lowest ID).
    #[handle_result]
    pub fn start_keygen_instance(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        log!("start_keygen_instance: signer={}", env::signer_account_id(),);
        self.protocol_state
            .start_keygen_instance(key_event_id, self.config.key_event_timeout_blocks)
    }

    /// Casts a vote for `public_key` for the attempt identified by `key_event_id`.
    ///
    /// The effect of this method is either:
    ///  - Returns error (which aborts with no changes), if there is no active key generation
    ///    attempt (including if the attempt timed out), if the signer is not a participant, or if
    ///    the key_event_id corresponds to a different domain, different epoch, or different attempt
    ///    from the current key generation attempt.
    ///  - Returns Ok(()), with one of the following changes:
    ///    - A vote has been collected but we don't have enough votes yet.
    ///    - This vote is for a public key that disagrees from an earlier voted public key, causing
    ///      the attempt to abort; another call to `start` is then necessary.
    ///    - Everyone has now voted for the same public key; the state transitions into generating a
    ///      key for the next domain.
    ///    - Same as the last case, except that all domains have a generated key now, and the state
    ///      transitions into Running with the newly generated keys.
    #[handle_result]
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: dtos_contract::PublicKey,
    ) -> Result<(), Error> {
        log!(
            "vote_pk: signer={}, key_event_id={:?}, public_key={:?}",
            env::signer_account_id(),
            key_event_id,
            public_key,
        );

        let extended_key =
            public_key
                .try_into()
                .map_err(|err: PublicKeyExtendedConversionError| {
                    InvalidParameters::MalformedPayload.message(err.to_string())
                })?;

        if let Some(new_state) = self.protocol_state.vote_pk(key_event_id, extended_key)? {
            self.protocol_state = new_state;
        }

        Ok(())
    }

    /// Starts a new attempt to reshare the key for the current domain.
    /// This only succeeds if the signer is the leader (the participant with the lowest ID).
    #[handle_result]
    pub fn start_reshare_instance(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        log!(
            "start_reshare_instance: signer={}",
            env::signer_account_id()
        );
        self.protocol_state
            .start_reshare_instance(key_event_id, self.config.key_event_timeout_blocks)
    }

    /// Casts a vote for the successful resharing of the attempt identified by `key_event_id`.
    ///
    /// The effect of this method is either:
    ///  - Returns error (which aborts with no changes), if there is no active key resharing attempt
    ///    (including if the attempt timed out), if the signer is not a participant, or if the
    ///    key_event_id corresponds to a different domain, different epoch, or different attempt
    ///    from the current key resharing attempt.
    ///  - Returns Ok(()), with one of the following changes:
    ///    - A vote has been collected but we don't have enough votes yet.
    ///    - Everyone has now voted; the state transitions into resharing the key for the next
    ///      domain.
    ///    - Same as the last case, except that all domains' keys have been reshared now, and the
    ///      state transitions into Running with the newly reshared keys.
    #[handle_result]
    pub fn vote_reshared(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        log!(
            "vote_reshared: signer={}, resharing_id={:?}",
            env::signer_account_id(),
            key_event_id,
        );

        let resharing_concluded =
            if let Some(new_state) = self.protocol_state.vote_reshared(key_event_id)? {
                // Resharing has concluded, transition to running state
                self.protocol_state = new_state;
                true
            } else {
                false
            };

        if resharing_concluded {
            // Spawn a promise to clean up TEE information for non-participants
            Promise::new(env::current_account_id()).function_call(
                "clean_tee_status".to_string(),
                vec![],
                NearToken::from_yoctonear(0),
                CLEAN_TEE_STATUS_GAS,
            );
            // Spawn a promise to clean up orphaned node migrations for non-participants
            Promise::new(env::current_account_id()).function_call(
                "cleanup_orphaned_node_migrations".to_string(),
                vec![],
                NearToken::from_yoctonear(0),
                CLEAN_NODE_MIGRATIONS,
            );
        }

        Ok(())
    }

    /// Casts a vote to cancel the current key resharing. If a threshold number of unique
    /// votes are collected to cancel the resharing, the contract state will revert back to the
    /// previous running state.
    ///
    /// - This method is idempotent, meaning a single account can not make more than one vote.
    /// - Only nodes from the previous running state are allowed to vote.
    ///
    /// Return value:
    /// - [Ok] if the vote was successfully collected.
    /// - [Err] if:
    ///     - The signer is not a participant in the previous running state.
    ///     - The contract is not in a resharing state.
    #[handle_result]
    pub fn vote_cancel_resharing(&mut self) -> Result<(), Error> {
        log!("vote_cancel_resharing: signer={}", env::signer_account_id());

        if let Some(new_state) = self.protocol_state.vote_cancel_resharing()? {
            self.protocol_state = new_state;
        }

        Ok(())
    }

    /// Casts a vote to cancel key generation. Any keys that have already been generated
    /// are kept and we transition into Running state; remaining domains are permanently deleted.
    /// Deleted domain IDs cannot be reused again in future calls to vote_add_domains.
    ///
    /// A next_domain_id that matches that in the state's domains struct must be passed in. This is
    /// to prevent stale requests from accidentally cancelling a future key generation state.
    #[handle_result]
    pub fn vote_cancel_keygen(&mut self, next_domain_id: u64) -> Result<(), Error> {
        log!("vote_cancel_keygen: signer={}", env::signer_account_id());

        if let Some(new_state) = self.protocol_state.vote_cancel_keygen(next_domain_id)? {
            self.protocol_state = new_state;
        }
        Ok(())
    }

    /// Casts a vote to abort the current key event instance. If succesful, the contract aborts the
    /// instance and a new instance with the next attempt_id can be started.
    #[handle_result]
    pub fn vote_abort_key_event_instance(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        log!(
            "vote_abort_key_event_instance: signer={}",
            env::signer_account_id()
        );

        self.protocol_state
            .vote_abort_key_event_instance(key_event_id)
    }

    /// Propose update to either code or config, but not both of them at the same time.
    #[payable]
    #[handle_result]
    pub fn propose_update(
        &mut self,
        #[serializer(borsh)] args: ProposeUpdateArgs,
    ) -> Result<UpdateId, Error> {
        // Only voters can propose updates:
        let proposer = self.voter_or_panic();
        let update: Update = args.try_into()?;

        let attached = env::attached_deposit();
        let required = ProposedUpdates::required_deposit(&update);
        if attached < required {
            return Err(InvalidParameters::InsufficientDeposit.message(format!(
                "Attached {}, Required {}",
                attached.as_yoctonear(),
                required.as_yoctonear(),
            )));
        }

        let id = self.proposed_updates.propose(update);

        log!(
            "propose_update: signer={}, id={:?}",
            env::signer_account_id(),
            id,
        );

        // Refund the difference if the proposer attached more than required.
        if let Some(diff) = attached.checked_sub(required) {
            if diff > NearToken::from_yoctonear(0) {
                Promise::new(proposer).transfer(diff);
            }
        }

        Ok(id)
    }

    /// Vote for a proposed update given the [`UpdateId`] of the update.
    ///
    /// Returns Ok(true) if the amount of voters surpassed the threshold and the update was
    /// executed. Returns Ok(false) if the amount of voters did not surpass the threshold.
    /// Returns Err if the update was not found or if the voter is not a participant in the
    /// protocol.
    #[handle_result]
    pub fn vote_update(&mut self, id: UpdateId) -> Result<bool, Error> {
        log!(
            "vote_update: signer={}, id={:?}",
            env::signer_account_id(),
            id,
        );
        let ProtocolContractState::Running(_running_state) = &self.protocol_state else {
            env::panic_str("protocol must be in running state");
        };

        let threshold = self.threshold()?;

        let voter = self.voter_or_panic();
        let Some(votes) = self.proposed_updates.vote(&id, voter) else {
            return Err(InvalidParameters::UpdateNotFound.into());
        };

        // Not enough votes, wait for more.
        if (votes.len() as u64) < threshold.value() {
            return Ok(false);
        }

        let Some(_promise) = self.proposed_updates.do_update(&id, UPDATE_CONFIG_GAS) else {
            return Err(InvalidParameters::UpdateNotFound.into());
        };

        Ok(true)
    }

    #[handle_result]
    pub fn vote_code_hash(&mut self, code_hash: MpcDockerImageHash) -> Result<(), Error> {
        log!(
            "vote_code_hash: signer={}, code_hash={:?}",
            env::signer_account_id(),
            code_hash,
        );
        self.voter_or_panic();

        let ProtocolContractState::Running(state) = &self.protocol_state else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };

        let participant = AuthenticatedParticipantId::new(state.parameters.participants())?;
        let votes = self.tee_state.vote(code_hash.clone(), &participant);

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

    pub fn allowed_code_hashes(&self) -> Vec<MpcDockerImageHash> {
        log!("allowed_code_hashes: signer={}", env::signer_account_id());

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        self.tee_state
            .get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration)
    }

    pub fn latest_code_hash(&mut self) -> MpcDockerImageHash {
        log!("latest_code_hash: signer={}", env::signer_account_id());

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        self.tee_state
            .get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration)
            .last()
            .expect("there must be at least one allowed code hash")
            .clone()
    }

    /// Returns all accounts that have TEE attestations stored in the contract.
    /// Note: This includes both current protocol participants and accounts that may have
    /// submitted TEE information but are not currently part of the active participant set.
    pub fn get_tee_accounts(&self) -> Vec<NodeId> {
        log!("get_tee_accounts: signer={}", env::signer_account_id());
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
        let ProtocolContractState::Running(running_state) = &mut self.protocol_state else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };
        let current_params = running_state.parameters.clone();

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        match self
            .tee_state
            .validate_tee(current_params.participants(), tee_upgrade_deadline_duration)
        {
            TeeValidationResult::Full => {
                self.accept_requests = true;
                log!("All participants have an accepted Tee status");
                Ok(true)
            }
            TeeValidationResult::Partial {
                participants_with_valid_attestation,
            } => {
                let threshold = current_params.threshold().value() as usize;
                let remaining = participants_with_valid_attestation.len();
                if threshold > remaining {
                    log!(
                        "Less than `threshold` participants are left with a valid TEE status. This requires manual intervention. We will not accept new signature requests as a safety precaution."
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
                let new_threshold = threshold;

                let threshold_parameters = ThresholdParameters::new(
                    participants_with_valid_attestation,
                    Threshold::new(new_threshold as u64),
                )
                .expect("Require valid threshold parameters"); // this should never happen.
                current_params.validate_incoming_proposal(&threshold_parameters)?;
                let res = running_state.transition_to_resharing_no_checks(&threshold_parameters);
                if let Some(resharing) = res {
                    self.protocol_state = ProtocolContractState::Resharing(resharing);
                }

                Ok(true)
            }
        }
    }

    /// Private endpoint to clean up TEE information for non-participants after resharing.
    /// This can only be called by the contract itself via a promise.
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

        self.tee_state.clean_non_participants(participants);
        Ok(())
    }
}

// Contract developer helper API
#[near_bindgen]
impl MpcContract {
    #[handle_result]
    #[init]
    pub fn init(
        parameters: ThresholdParameters,
        init_config: Option<InitConfig>,
    ) -> Result<Self, Error> {
        log!(
            "init: signer={}, parameters={:?}, init_config={:?}",
            env::signer_account_id(),
            parameters,
            init_config,
        );
        parameters.validate()?;

        parameters.validate().unwrap();

        // TODO: https://github.com/near/mpc/issues/1087
        // Every participant must have a valid attestation, otherwise we risk
        // participants being immediately kicked out once contract transitions into running.
        let initial_participants = parameters.participants();
        let tee_state = TeeState::with_mocked_participant_attestations(initial_participants);

        Ok(Self {
            protocol_state: ProtocolContractState::Running(RunningContractState::new(
                DomainRegistry::default(),
                Keyset::new(EpochId::new(0), Vec::new()),
                parameters,
            )),
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV2),
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequests),
            proposed_updates: ProposedUpdates::default(),
            config: Config::from(init_config),
            tee_state,
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
        })
    }

    // This function can be used to transfer the MPC network to a new contract.
    #[private]
    #[init]
    #[handle_result]
    pub fn init_running(
        domains: Vec<DomainConfig>,
        next_domain_id: u64,
        keyset: Keyset,
        parameters: ThresholdParameters,
        init_config: Option<InitConfig>,
    ) -> Result<Self, Error> {
        log!(
            "init_running: signer={}, domains={:?}, keyset={:?}, parameters={:?}, init_config={:?}",
            env::signer_account_id(),
            domains,
            keyset,
            parameters,
            init_config,
        );
        parameters.validate()?;
        let domains = DomainRegistry::from_raw_validated(domains, next_domain_id)?;

        // Check that the domains match exactly those in the keyset.
        let domain_ids_from_domains = domains.domains().iter().map(|d| d.id).collect::<Vec<_>>();
        let domain_ids_from_keyset = keyset
            .domains
            .iter()
            .map(|k| k.domain_id)
            .collect::<Vec<_>>();
        if domain_ids_from_domains != domain_ids_from_keyset {
            return Err(DomainError::DomainsMismatch.into());
        }

        Ok(MpcContract {
            config: Config::from(init_config),
            protocol_state: ProtocolContractState::Running(RunningContractState::new(
                domains, keyset, parameters,
            )),
            pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV2),
            pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequests),
            proposed_updates: Default::default(),
            tee_state: Default::default(),
            accept_requests: true,
            node_migrations: NodeMigrations::default(),
        })
    }

    /// This will be called internally by the contract to migrate the state when a new contract
    /// is deployed. This function should be changed every time state is changed to do the proper
    /// migrate flow.
    ///
    /// If nothing is changed, then this function will just return the current state. If it fails
    /// to read the state, then it will return an error.
    #[private]
    #[init(ignore_state)]
    #[handle_result]
    pub fn migrate() -> Result<Self, Error> {
        log!("migrating contract");
        if let Some(contract) = env::state_read::<v0_state::VersionedMpcContract>() {
            return match contract {
                v0_state::VersionedMpcContract::V1(x) => Ok(x.into()),
                _ => env::panic_str("expected V1"),
            };
        }
        Err(InvalidState::ContractStateIsMissing.into())
    }

    pub fn state(&self) -> &ProtocolContractState {
        &self.protocol_state
    }

    pub fn allowed_docker_image_hashes(&self) -> Vec<MpcDockerImageHash> {
        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        self.tee_state
            .get_allowed_mpc_docker_images(tee_upgrade_deadline_duration)
            .into_iter()
            .map(|allowed_image_hash| allowed_image_hash.image_hash)
            .collect()
    }

    pub fn get_pending_request(&self, request: &SignatureRequest) -> Option<YieldIndex> {
        self.pending_signature_requests.get(request).cloned()
    }

    pub fn get_pending_ckd_request(&self, request: &CKDRequest) -> Option<YieldIndex> {
        self.pending_ckd_requests.get(request).cloned()
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    // contract version
    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Upon success, removes the signature from state and returns it.
    /// If the signature request times out, removes the signature request from state and panics to
    /// fail the original transaction
    #[private]
    pub fn return_signature_and_clean_state_on_success(
        &mut self,
        request: SignatureRequest, // this change here should actually be ok.
        #[callback_result] signature: Result<SignatureResponse, PromiseError>,
    ) -> PromiseOrValue<SignatureResponse> {
        match signature {
            Ok(signature) => PromiseOrValue::Value(signature),
            Err(_) => {
                self.pending_signature_requests.remove(&request);
                let promise = Promise::new(env::current_account_id()).function_call(
                    "fail_on_timeout".to_string(),
                    vec![],
                    NearToken::from_near(0),
                    FAIL_ON_TIMEOUT_GAS,
                );
                near_sdk::PromiseOrValue::Promise(promise.as_return())
            }
        }
    }

    /// Upon success, removes the confidential key from state and returns it.
    /// If the ckd request times out, removes the ckd request from state and panics to fail the
    /// original transaction
    #[private]
    pub fn return_ck_and_clean_state_on_success(
        &mut self,
        request: CKDRequest,
        #[callback_result] ck: Result<CKDResponse, PromiseError>,
    ) -> PromiseOrValue<CKDResponse> {
        match ck {
            Ok(ck) => PromiseOrValue::Value(ck),
            Err(_) => {
                self.pending_ckd_requests.remove(&request);
                let promise = Promise::new(env::current_account_id()).function_call(
                    "fail_on_timeout".to_string(),
                    vec![],
                    NearToken::from_near(0),
                    FAIL_ON_TIMEOUT_GAS,
                );
                near_sdk::PromiseOrValue::Promise(promise.as_return())
            }
        }
    }

    #[private]
    pub fn fail_on_timeout(&self) {
        // To stay consistent with the old version of the timeout error
        env::panic_str(&RequestError::Timeout.to_string());
    }

    #[private]
    pub fn update_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Get our own account id as a voter. Returns an error if we are not a participant.
    fn voter_account(&self) -> Result<AccountId, Error> {
        let voter = env::signer_account_id();
        self.protocol_state.authenticate_update_vote()?;
        Ok(voter)
    }

    /// Get our own account id as a voter. If we are not a participant, panic.
    fn voter_or_panic(&self) -> AccountId {
        match self.voter_account() {
            Ok(voter) => voter,
            Err(err) => env::panic_str(&format!("not a voter, {:?}", err)),
        }
    }
}

/// Methods for Migration service
#[near_bindgen]
impl MpcContract {
    // todo: [#1248](https://github.com/near/mpc/issues/1248), we might want to delete this one
    pub fn my_migration_info(
        &self,
    ) -> (
        AccountId,
        Option<BackupServiceInfo>,
        Option<DestinationNodeInfo>,
    ) {
        let account_id = env::signer_account_id();
        log!("my_migration_info: signer={:?}", account_id,);
        self.node_migrations.get_for_account(&account_id)
    }

    pub fn migration_info(
        &self,
    ) -> BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)> {
        log!("migration_info");
        self.node_migrations.get_all()
    }

    /// Registers or updates the backup service information for the caller account.  
    ///
    /// The caller (`signer_account_id`) must be an existing or prospective participant.  
    /// Otherwise, the transaction will fail.  
    /// # Notes
    /// - A deposit requirement may be added in the future.  
    #[handle_result]
    pub fn register_backup_service(
        &mut self,
        backup_service_info: BackupServiceInfo,
    ) -> Result<(), Error> {
        let account_id = env::signer_account_id();
        log!(
            "register_backup_service: signer={:?}, backup_service_info={:?}",
            account_id,
            backup_service_info
        );
        if !self
            .protocol_state
            .is_existing_or_prospective_participant(&account_id)?
        {
            return Err(errors::InvalidState::NotParticipant.message(format!("account:  {} is not in the set of curent or prospective participants and not eligible to store backup service information", account_id)));
        }
        self.node_migrations
            .set_backup_service_info(account_id, backup_service_info);
        Ok(())
    }

    /// Sets the destination node for the calling account.
    ///
    /// This function can only be called while the protocol is in a `Running` state.
    /// The signer must be a current participant of the current epoch, otherwise an error is returned.
    /// On success, the provided [`DestinationNodeInfo`] is stored in the contract state
    /// under the signer’s account ID.
    ///
    /// # Errors
    /// - [`InvalidState::ProtocolStateNotRunning`] if the protocol is not in the `Running` state.  
    /// - [`InvalidState::NotParticipant`] if the signer is not a current participant.
    /// # Note:
    /// - might require a deposit
    #[handle_result]
    pub fn start_node_migration(
        &mut self,
        destination_node_info: DestinationNodeInfo,
    ) -> Result<(), Error> {
        // todo: require a deposit [#1163](https://github.com/near/mpc/issues/1163)
        let account_id = env::signer_account_id();
        log!(
            "start_node_migration: signer={:?}, destination_node_info={:?}",
            account_id,
            destination_node_info
        );
        let ProtocolContractState::Running(running_state) = &self.protocol_state else {
            return Err(errors::InvalidState::ProtocolStateNotRunning.message(
                "migration of nodes is only possible while the protocol is in `Running` state."
                    .to_string(),
            ));
        };

        if !running_state.is_participant(&account_id) {
            return Err(errors::InvalidState::NotParticipant.message(format!("account:  {} is not in the set of curent participants and thus not eligible to initiate a node migration.", account_id)));
        }
        self.node_migrations
            .set_destination_node_info(account_id, destination_node_info);
        Ok(())
    }

    /// Finalizes a node migration for the calling account.
    ///
    /// This method can only be called while the protocol is in a `Running` state
    /// and by an existing participant. On success, the participant’s information is
    /// updated to the new destination node.
    ///
    /// # Errors
    /// Returns the following errors:
    /// - `InvalidState::ProtocolStateNotRunning`: if protocol is not in `Running` state
    /// - `InvalidState::NotParticipant`: if caller is not a current participant
    /// - `NodeMigrationError::KeysetMismatch`: if provided keyset does not match the expected keyset
    /// - `NodeMigrationError::MigrationNotFound`: if no migration record exists for the caller
    /// - `NodeMigrationError::AccountPublicKeyMismatch`: if caller’s public key does not match the expected destination node
    /// - `InvalidParameters::InvalidTeeRemoteAttestation`: if destination node’s TEE quote is invalid
    #[handle_result]
    pub fn conclude_node_migration(&mut self, keyset: &Keyset) -> Result<(), Error> {
        let account_id = env::signer_account_id();
        let signer_pk = env::signer_account_pk();
        log!(
            "conclude_node_migration: signer={:?}, signer_pk={:?} keyset={:?}",
            account_id,
            signer_pk,
            keyset
        );
        let ProtocolContractState::Running(running_state) = &mut self.protocol_state else {
            return Err(errors::InvalidState::ProtocolStateNotRunning.message(
                "migration of nodes is only possible while the protocol is in `Running` state."
                    .to_string(),
            ));
        };

        if !running_state.is_participant(&account_id) {
            return Err(errors::InvalidState::NotParticipant.message(format!("account:  {} is not in the set of curent participants and thus eligible to initiate a node migration.", account_id)));
        }

        let expected_keyset = &running_state.keyset;
        if expected_keyset != keyset {
            return Err(errors::NodeMigrationError::KeysetMismatch.message(format!(
                "keyset={:?}, expected_keyset={:?}",
                keyset, expected_keyset
            )));
        }

        let Some(expected_destination_node) = self.node_migrations.remove_migration(&account_id)
        else {
            return Err(errors::NodeMigrationError::MigrationNotFound.into());
        };
        if expected_destination_node.signer_account_pk != signer_pk {
            return Err(
                errors::NodeMigrationError::AccountPublicKeyMismatch.message(format!(
                    "found  {:?}, expected {:?}",
                    signer_pk, expected_destination_node.signer_account_pk
                )),
            );
        }
        // ensure that this node has a valid TEE quote
        let node_id = NodeId {
            account_id: account_id.clone(),
            tls_public_key: expected_destination_node
                .destination_node_info
                .sign_pk
                .clone(),
        };

        if !(matches!(
            self.tee_state.verify_tee_participant(
                &node_id,
                Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds)
            ),
            TeeQuoteStatus::Valid
        )) {
            return Err(errors::InvalidParameters::InvalidTeeRemoteAttestation.into());
        };

        log!(
            "Moving Account {:?} to {:?}",
            account_id,
            expected_destination_node.destination_node_info
        );

        running_state
            .parameters
            .update_info(account_id, expected_destination_node.destination_node_info)?;
        Ok(())
    }

    #[private]
    #[handle_result]
    pub fn cleanup_orphaned_node_migrations(&mut self) -> Result<(), Error> {
        log!(
            "cleanup_orphaned_node_migrations signer={:?}",
            env::signer_account_id(),
        );
        let backup_services: Vec<AccountId> = self
            .node_migrations
            .backup_services_info()
            .keys()
            .cloned()
            .collect();

        for account_id in &backup_services {
            if !self
                .protocol_state
                .is_existing_or_prospective_participant(account_id)?
            {
                self.node_migrations.remove_account_data(account_id);
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_shared::k256_types;
    use crate::errors::{ErrorKind, NodeMigrationError};
    use crate::primitives::participants::{ParticipantId, ParticipantInfo};
    use crate::primitives::test_utils::{
        bogus_ed25519_near_public_key, bogus_ed25519_public_key, gen_account_id, gen_participant,
    };
    use crate::primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        participants::Participants,
        signature::{Payload, Tweak},
        test_utils::gen_participants,
    };
    use crate::state::initializing::tests::gen_initializing_state;
    use crate::state::key_event::tests::Environment;
    use crate::state::resharing::tests::gen_resharing_state;
    use crate::state::running::running_tests::gen_running_state;
    use dtos_contract::{Attestation, Ed25519PublicKey, MockAttestation};
    use k256::{
        self,
        ecdsa::SigningKey,
        elliptic_curve::point::DecompactPoint,
        {elliptic_curve, AffinePoint, Secp256k1},
    };
    use near_sdk::{test_utils::VMContextBuilder, testing_env, NearToken, VMContext};
    use primitives::key_state::{AttemptId, KeyForDomain};
    use rand::{rngs::OsRng, RngCore};

    pub fn derive_secret_key(secret_key: &k256::SecretKey, tweak: &Tweak) -> k256::SecretKey {
        let tweak = k256::Scalar::from_repr(tweak.as_bytes().into()).unwrap();
        k256::SecretKey::new((tweak + secret_key.to_nonzero_scalar().as_ref()).into())
    }

    fn basic_setup() -> (VMContext, MpcContract, SigningKey) {
        let context = VMContextBuilder::new()
            .attached_deposit(NearToken::from_yoctonear(1))
            .build();
        testing_env!(context.clone());
        let secret_key = SigningKey::random(&mut OsRng);
        let encoded_point = secret_key.verifying_key().to_encoded_point(false);
        // The first byte of the binary representation of `EncodedPoint` is the tag, so we take the
        // rest 64 bytes
        let public_key_data = encoded_point.as_bytes()[1..].to_vec();
        let domain_id = DomainId::legacy_ecdsa_id();
        let domains = vec![DomainConfig {
            id: domain_id,
            scheme: SignatureScheme::Secp256k1,
        }];
        let epoch_id = EpochId::new(0);
        let near_public_key =
            near_sdk::PublicKey::from_parts(near_sdk::CurveType::SECP256K1, public_key_data)
                .unwrap();

        let key_for_domain = KeyForDomain {
            domain_id,
            key: PublicKeyExtended::Secp256k1 { near_public_key },
            attempt: AttemptId::new(),
        };
        let keyset = Keyset::new(epoch_id, vec![key_for_domain]);
        let parameters = ThresholdParameters::new(gen_participants(4), Threshold::new(3)).unwrap();
        let contract = MpcContract::init_running(domains, 1, keyset, parameters, None).unwrap();
        (context, contract, secret_key)
    }

    fn test_signature_common(success: bool, legacy_v1_api: bool) {
        let (context, mut contract, secret_key) = basic_setup();
        let mut payload_hash = [0u8; 32];
        OsRng.fill_bytes(&mut payload_hash);
        let payload = Payload::from_legacy_ecdsa(payload_hash);
        let key_path = "m/44'\''/60'\''/0'\''/0/0".to_string();

        let request = if legacy_v1_api {
            SignRequestArgs {
                deprecated_payload: Some(payload_hash),
                deprecated_key_version: Some(0),
                path: key_path.clone(),
                ..Default::default()
            }
        } else {
            SignRequestArgs {
                payload_v2: Some(payload.clone()),
                path: key_path.clone(),
                domain_id: Some(DomainId::legacy_ecdsa_id()),
                ..Default::default()
            }
        };
        let signature_request = SignatureRequest::new(
            DomainId::default(),
            payload.clone(),
            &context.predecessor_account_id,
            &request.path,
        );
        contract.sign(request);
        contract.get_pending_request(&signature_request).unwrap();

        // simulate signature and response to the signing request
        let derivation_path = derive_tweak(&context.predecessor_account_id, &key_path);
        let secret_key_ec: elliptic_curve::SecretKey<Secp256k1> =
            elliptic_curve::SecretKey::from_bytes(&secret_key.to_bytes()).unwrap();
        let derived_secret_key = derive_secret_key(&secret_key_ec, &derivation_path);
        let secret_key = SigningKey::from_bytes(&derived_secret_key.to_bytes()).unwrap();
        let (signature, recovery_id) = secret_key
            .sign_prehash_recoverable(payload.as_ecdsa().unwrap())
            .unwrap();
        let (r, s) = signature.split_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(s.as_slice());
        let signature_response = if success {
            SignatureResponse::Secp256k1(k256_types::Signature::new(
                AffinePoint::decompact(&r).unwrap(),
                k256::Scalar::from_repr(bytes.into()).unwrap(),
                recovery_id.to_byte(),
            ))
        } else {
            // submit an incorrect signature to make the respond call fail
            SignatureResponse::Secp256k1(k256_types::Signature::new(
                AffinePoint::decompact(&r).unwrap(),
                k256::Scalar::from_repr([0u8; 32].into()).unwrap(),
                recovery_id.to_byte(),
            ))
        };

        match contract.respond(signature_request.clone(), signature_response.clone()) {
            Ok(_) => {
                assert!(success);
                contract.return_signature_and_clean_state_on_success(
                    signature_request.clone(),
                    Ok(signature_response),
                );

                assert!(contract.get_pending_request(&signature_request).is_none(),);
            }
            Err(_) => assert!(!success),
        }
    }

    #[test]
    fn test_signature_simple() {
        test_signature_common(true, false);
        test_signature_common(false, false);
    }

    #[test]
    fn test_signature_simple_legacy() {
        test_signature_common(true, true);
        test_signature_common(false, true);
    }

    #[test]
    fn test_signature_timeout() {
        let (context, mut contract, _) = basic_setup();
        let payload = Payload::from_legacy_ecdsa([0u8; 32]);
        let key_path = "m/44'\''/60'\''/0'\''/0/0".to_string();

        let request = SignRequestArgs {
            payload_v2: Some(payload.clone()),
            path: key_path.clone(),
            domain_id: Some(DomainId::legacy_ecdsa_id()),
            ..Default::default()
        };
        let signature_request = SignatureRequest::new(
            DomainId::default(),
            payload,
            &context.predecessor_account_id,
            &request.path,
        );
        contract.sign(request);
        assert!(matches!(
            contract.return_signature_and_clean_state_on_success(
                signature_request.clone(),
                Err(PromiseError::Failed)
            ),
            PromiseOrValue::Promise(_)
        ));
        assert!(contract.get_pending_request(&signature_request).is_none());
    }

    #[test]
    #[ignore] // TODO(#1242): This test cannot work anymore, as `basic_setup` only works for Secp256k1
    fn test_ckd_simple() {
        let (context, mut contract, _secret_key) = basic_setup();
        let app_public_key: dtos_contract::Bls12381G1PublicKey =
            "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                .parse()
                .unwrap();
        let request = CKDRequestArgs {
            app_public_key: app_public_key.clone(),
            domain_id: DomainId::default(),
        };
        let ckd_request = CKDRequest::new(
            app_public_key,
            context.predecessor_account_id,
            request.domain_id,
        );
        contract.request_app_private_key(request);
        contract.get_pending_ckd_request(&ckd_request).unwrap();

        let response = CKDResponse {
            big_y: dtos_contract::Bls12381G1PublicKey([1u8; 48]),
            big_c: dtos_contract::Bls12381G1PublicKey([2u8; 48]),
        };

        match contract.respond_ckd(ckd_request.clone(), response.clone()) {
            Ok(_) => {
                contract.return_ck_and_clean_state_on_success(ckd_request.clone(), Ok(response));

                assert!(contract.get_pending_ckd_request(&ckd_request).is_none(),);
            }
            Err(_) => panic!("respond_ckd should not fail"),
        }
    }

    #[test]
    #[ignore] // TODO(#1242): This test cannot work anymore, as `basic_setup` only works for Secp256k1
    fn test_ckd_timeout() {
        let (context, mut contract, _secret_key) = basic_setup();
        let app_public_key: dtos_contract::Bls12381G1PublicKey =
            "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                .parse()
                .unwrap();
        let request = CKDRequestArgs {
            app_public_key: app_public_key.clone(),
            domain_id: DomainId::default(),
        };
        let ckd_request = CKDRequest::new(
            app_public_key,
            context.predecessor_account_id,
            request.domain_id,
        );
        contract.request_app_private_key(request);
        assert!(matches!(
            contract.return_ck_and_clean_state_on_success(
                ckd_request.clone(),
                Err(PromiseError::Failed)
            ),
            PromiseOrValue::Promise(_)
        ));
        assert!(contract.get_pending_ckd_request(&ckd_request).is_none());
    }

    fn setup_tee_test_contract(
        num_participants: usize,
        threshold_value: u64,
    ) -> (MpcContract, Participants, AccountId) {
        let participants = primitives::test_utils::gen_participants(num_participants);
        let first_participant_id = participants.participants()[0].0.clone();

        let context = VMContextBuilder::new()
            .signer_account_id(first_participant_id.clone())
            .attached_deposit(NearToken::from_near(1))
            .build();
        testing_env!(context);

        let threshold = Threshold::new(threshold_value);
        let parameters = ThresholdParameters::new(participants.clone(), threshold).unwrap();
        let contract = MpcContract::init(parameters, None).unwrap();

        (contract, participants, first_participant_id)
    }

    fn submit_attestation(
        contract: &mut MpcContract,
        participants: &Participants,
        participant_index: usize,
        is_valid: bool,
    ) -> Result<(), crate::errors::Error> {
        let participants_list = participants.participants();
        let (account_id, _, participant_info) = &participants_list[participant_index];
        let attestation = if is_valid {
            MockAttestation::Valid
        } else {
            MockAttestation::Invalid
        };

        let dto_public_key = participant_info
            .sign_pk
            .clone()
            .try_into_dto_type()
            .unwrap();

        let participant_context = VMContextBuilder::new()
            .signer_account_id(account_id.clone())
            .attached_deposit(NearToken::from_near(1))
            .build();
        testing_env!(participant_context);

        contract.submit_participant_info(Attestation::Mock(attestation), dto_public_key)
    }

    fn submit_valid_attestations(
        contract: &mut MpcContract,
        participants: &Participants,
        participant_indices: &[usize],
    ) {
        for &participant_index in participant_indices {
            let result = submit_attestation(contract, participants, participant_index, true);
            assert!(
                result.is_ok(),
                "submit_participant_info should succeed with valid attestation for participant {}",
                participant_index
            );
        }
    }

    /// Sets up the voting context and calls [`VersionedMpcContract::vote_new_parameters`] with the
    /// given parameters.
    fn setup_voting_context_and_vote(
        contract: &mut MpcContract,
        first_participant_id: &AccountId,
        participants: Participants,
        threshold: Threshold,
    ) -> Result<(), crate::errors::Error> {
        let voting_context = VMContextBuilder::new()
            .signer_account_id(first_participant_id.clone())
            .attached_deposit(NearToken::from_yoctonear(0))
            .build();
        testing_env!(voting_context);

        let proposal = ThresholdParameters::new(participants, threshold).unwrap();
        contract.vote_new_parameters(EpochId::new(1), proposal)
    }

    /// Test that [`VersionedMpcContract::vote_new_parameters`] succeeds when all participants have
    /// default TEE status ([`TeeQuoteStatus::None`]). This tests the basic scenario where no
    /// participants have submitted attestation information, and all have the default TEE status
    /// of [`TeeQuoteStatus::None`], which is considered acceptable.
    #[test]
    fn test_vote_new_parameters_succeeds_with_default_tee_status() {
        let (mut contract, participants, first_participant_id) = setup_tee_test_contract(3, 2);
        let threshold = Threshold::new(2);

        // No attestations submitted - all participants have default TEE status None
        let result = setup_voting_context_and_vote(
            &mut contract,
            &first_participant_id,
            participants,
            threshold,
        );
        assert!(
            result.is_ok(),
            "Should succeed when all participants have default TEE status None"
        );
    }

    /// Test that [`MpcContract::vote_new_parameters`] succeeds when all participants
    /// submit valid TEE attestations. This tests the scenario where all participants successfully
    /// submit valid attestations through [`MpcContract::submit_participant_info`],
    /// resulting in [`TeeQuoteStatus::Valid`] TEE status for all participants.
    #[test]
    fn test_vote_new_parameters_succeeds_when_all_participants_have_valid_tee() {
        let (mut contract, participants, first_participant_id) = setup_tee_test_contract(3, 2);
        let threshold = Threshold::new(2);

        // Submit valid attestations for all participants
        submit_valid_attestations(&mut contract, &participants, &[0, 1, 2]);

        // This should succeed because all participants now have valid TEE status
        let result = setup_voting_context_and_vote(
            &mut contract,
            &first_participant_id,
            participants,
            threshold,
        );
        assert!(
            result.is_ok(),
            "Should succeed when all participants have valid TEE status"
        );
    }

    /// Test that attempts to submit invalid attestations are rejected by
    /// [`MpcContract::submit_participant_info`]. This test demonstrates that
    /// participants cannot have Invalid TEE status because the contract proactively rejects
    /// invalid attestations at submission time. The 4th participant tries to submit an invalid
    /// attestation but is rejected, leaving them with [`TeeQuoteStatus::Invalid`] status, which
    /// combined with valid participants still allows successful voting.
    #[test]
    fn test_vote_new_parameters_succeeds_after_invalid_attestation_rejected() {
        let (mut contract, participants, first_participant_id) = setup_tee_test_contract(4, 3);
        let threshold = Threshold::new(3);

        // Submit valid attestations for first 3 participants
        submit_valid_attestations(&mut contract, &participants, &[0, 1, 2]);

        // Try to submit invalid attestation for the 4th participant
        let participant_index = 3;
        let result = submit_attestation(&mut contract, &participants, participant_index, false);
        assert!(
            result.is_err(),
            "Invalid attestation should be rejected by submit_participant_info"
        );

        if let Err(error) = result {
            let error_string = error.to_string();
            assert!(
                error_string.contains("TeeQuoteStatus is invalid"),
                "Error should mention invalid TEE status, got: {}",
                error_string
            );
        }

        // This should succeed because:
        // - 3 participants have Valid TEE status (from successful attestations)
        // - 1 participant has None TEE status (invalid attestation was rejected)
        // - Both Valid and None are allowed by the TEE validation
        let result = setup_voting_context_and_vote(
            &mut contract,
            &first_participant_id,
            participants,
            threshold,
        );
        assert!(
            result.is_ok(),
            "Should succeed when participants have Valid or None TEE status (invalid attestations rejected)"
        );
    }

    impl MpcContract {
        pub fn new_from_protocol_sate(protocol_state: ProtocolContractState) -> Self {
            MpcContract {
                protocol_state,
                pending_signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV2),
                pending_ckd_requests: LookupMap::new(StorageKey::PendingCKDRequests),
                proposed_updates: ProposedUpdates::default(),
                config: Config::default(),
                tee_state: TeeState::default(),
                accept_requests: true,
                node_migrations: NodeMigrations::default(),
            }
        }
    }

    #[test]
    fn test_start_node_migration_failure_not_participant() {
        let running_state = ProtocolContractState::Running(gen_running_state(2));
        let mut contract = MpcContract::new_from_protocol_sate(running_state);

        // sanity check
        assert!(contract.migration_info().is_empty());
        let destination_node_info = gen_random_destination_info();

        let non_participant = gen_account_id();
        Environment::new(None, Some(non_participant), None);

        let res = contract.start_node_migration(destination_node_info);
        assert!(res.is_err());
        assert!(contract.migration_info().is_empty());
    }

    #[test]
    fn test_start_node_migration_success() {
        let running_state = ProtocolContractState::Running(gen_running_state(2));
        let mut contract = MpcContract::new_from_protocol_sate(running_state);

        // sanity check
        assert!(contract.migration_info().is_empty());

        let participants = {
            let ProtocolContractState::Running(running) = &contract.protocol_state else {
                panic!("expected running state");
            };
            running.parameters.participants().clone()
        };
        let mut expected_migration_state = BTreeMap::new();
        let mut test_env = Environment::new(None, None, None);
        for (account_id, _, _) in participants.participants() {
            test_env.set_signer(account_id);
            // sanity check
            assert_eq!(
                contract.my_migration_info(),
                (account_id.clone(), None, None)
            );
            let destination_node_info = gen_random_destination_info();
            let res = contract.start_node_migration(destination_node_info.clone());
            assert!(res.is_ok(), "res: {:?}", res);
            let expected_res = (account_id.clone(), None, Some(destination_node_info));
            assert_eq!(contract.my_migration_info(), expected_res);
            expected_migration_state.insert(expected_res.0, (expected_res.1, expected_res.2));
        }
        let expected_migration_state = expected_migration_state.into_iter().collect();
        let result = contract.migration_info();

        assert_eq!(result, expected_migration_state);
    }

    fn gen_random_destination_info() -> DestinationNodeInfo {
        let node_signer_pk = bogus_ed25519_near_public_key();
        let url_id: usize = rand::random();
        let (_, participant_info) = gen_participant(url_id);
        DestinationNodeInfo {
            signer_account_pk: node_signer_pk,
            destination_node_info: participant_info,
        }
    }

    fn test_start_migration_node_failure_not_running(mut contract: MpcContract) {
        assert!(contract.migration_info().is_empty());
        let destination_node_info = gen_random_destination_info();
        let res = contract.start_node_migration(destination_node_info);
        let expected_error_kind = &ErrorKind::InvalidState(InvalidState::ProtocolStateNotRunning);
        assert_eq!(res.unwrap_err().kind(), expected_error_kind);
        assert!(contract.migration_info().is_empty());
    }

    #[test]
    fn test_start_node_migration_failure_initializing() {
        let initializing_state =
            ProtocolContractState::Initializing(gen_initializing_state(2, 0).1);
        let contract = MpcContract::new_from_protocol_sate(initializing_state);
        test_start_migration_node_failure_not_running(contract);
    }

    #[test]
    fn test_start_node_migration_failure_resharing() {
        let resharing_state = ProtocolContractState::Resharing(gen_resharing_state(2).1);
        let contract = MpcContract::new_from_protocol_sate(resharing_state);
        test_start_migration_node_failure_not_running(contract);
    }

    fn test_register_backup_service_fail_non_participant(mut contract: MpcContract) {
        // sanity check
        assert!(contract.migration_info().is_empty());
        let backup_service_info = BackupServiceInfo {
            public_key: bogus_ed25519_public_key(),
        };

        let non_participant = gen_account_id();
        Environment::new(None, Some(non_participant), None);
        let res = contract.register_backup_service(backup_service_info);
        let expected_error_kind = &ErrorKind::InvalidState(InvalidState::NotParticipant);
        assert_eq!(res.unwrap_err().kind(), expected_error_kind);
        assert!(contract.migration_info().is_empty());
    }

    #[test]
    fn test_register_backup_service_fail_non_participant_running() {
        let running_state = ProtocolContractState::Running(gen_running_state(2));
        let contract = MpcContract::new_from_protocol_sate(running_state);
        test_register_backup_service_fail_non_participant(contract);
    }

    #[test]
    fn test_register_backup_service_fail_non_participant_initializing() {
        let initializing_state =
            ProtocolContractState::Initializing(gen_initializing_state(2, 0).1);
        let contract = MpcContract::new_from_protocol_sate(initializing_state);
        test_register_backup_service_fail_non_participant(contract);
    }

    #[test]
    fn test_register_backup_service_fail_non_participant_resharnig() {
        let resharing_state = ProtocolContractState::Resharing(gen_resharing_state(2).1);
        let contract = MpcContract::new_from_protocol_sate(resharing_state);
        test_register_backup_service_fail_non_participant(contract);
    }

    fn test_register_backup_service_success(
        participants: &Participants,
        mut contract: MpcContract,
    ) {
        // sanity check
        assert!(contract.migration_info().is_empty());
        let mut expected_migration_state = BTreeMap::new();
        let mut test_env = Environment::new(None, None, None);
        for (account_id, _, _) in participants.participants() {
            test_env.set_signer(account_id);
            // sanity check
            assert_eq!(
                contract.my_migration_info(),
                (account_id.clone(), None, None)
            );
            let backup_service_info = BackupServiceInfo {
                public_key: bogus_ed25519_public_key(),
            };
            let res = contract.register_backup_service(backup_service_info.clone());
            assert!(res.is_ok(), "res: {:?}", res);
            let expected_res = (account_id.clone(), Some(backup_service_info), None);
            assert_eq!(contract.my_migration_info(), expected_res);
            expected_migration_state.insert(expected_res.0, (expected_res.1, expected_res.2));
        }
        let result = contract.migration_info();

        assert_eq!(result, expected_migration_state);
    }

    #[test]
    fn test_register_backup_service_success_running() {
        let running_state = gen_running_state(2);
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let contract = MpcContract::new_from_protocol_sate(running_state);
        test_register_backup_service_success(&participants, contract);
    }

    #[test]
    fn test_register_backup_service_success_resharing() {
        let resharing_state = gen_resharing_state(2).1;
        let participants = resharing_state
            .resharing_key
            .proposed_parameters()
            .participants()
            .clone();
        let resharing_state = ProtocolContractState::Resharing(resharing_state);
        let contract = MpcContract::new_from_protocol_sate(resharing_state);
        test_register_backup_service_success(&participants, contract);
    }

    #[test]
    fn test_register_backup_service_success_initializing() {
        let initializing_state = gen_initializing_state(2, 0).1;
        let participants = initializing_state
            .generating_key
            .proposed_parameters()
            .participants()
            .clone();
        let initializing_state = ProtocolContractState::Initializing(initializing_state);
        let contract = MpcContract::new_from_protocol_sate(initializing_state);
        test_register_backup_service_success(&participants, contract);
    }

    #[test]
    fn test_conclude_node_migration_success() {
        let running_state = gen_running_state(2);
        let keyset = running_state.keyset.clone();
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_sate(running_state);
        for (account_id, expected_participant_id, _) in participants.participants() {
            let destination_node_info = gen_random_destination_info();
            let setup = ConcludeNodeMigrationTestSetup {
                destination_node_info: Some(destination_node_info.clone()),
                attestation_tls_key: destination_node_info
                    .destination_node_info
                    .sign_pk
                    .clone()
                    .try_into_dto_type()
                    .unwrap(),
                signer_account_id: account_id.clone(),
                signer_account_pk: destination_node_info.signer_account_pk,
                expected_error_kind: None,
                expected_post_call_info: Some((
                    expected_participant_id.clone(),
                    destination_node_info.destination_node_info.clone(),
                )),
            };
            setup.run(&mut contract, &keyset);
        }
        assert!(contract.node_migrations.get_all().is_empty());
    }

    #[test]
    fn test_conclude_node_migration_invalid_tee() {
        let running_state = gen_running_state(2);
        let keyset = running_state.keyset.clone();
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_sate(running_state);
        for (account_id, expected_participant_id, expected_participant_info) in
            participants.participants()
        {
            let destination_node_info = gen_random_destination_info();
            let setup = ConcludeNodeMigrationTestSetup {
                destination_node_info: Some(destination_node_info.clone()),
                attestation_tls_key: bogus_ed25519_public_key(),
                signer_account_id: account_id.clone(),
                signer_account_pk: destination_node_info.signer_account_pk,
                expected_error_kind: Some(ErrorKind::InvalidParameters(
                    InvalidParameters::InvalidTeeRemoteAttestation,
                )),
                expected_post_call_info: Some((
                    expected_participant_id.clone(),
                    expected_participant_info.clone(),
                )),
            };
            setup.run(&mut contract, &keyset);
        }
    }

    #[test]
    fn test_conclude_node_migration_migration_not_found() {
        let running_state = gen_running_state(2);
        let keyset = running_state.keyset.clone();
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_sate(running_state);
        for (account_id, expected_participant_id, expected_participant_info) in
            participants.participants()
        {
            let destination_node_info = gen_random_destination_info();
            let setup = ConcludeNodeMigrationTestSetup {
                destination_node_info: None,
                attestation_tls_key: destination_node_info
                    .destination_node_info
                    .sign_pk
                    .clone()
                    .try_into_dto_type()
                    .unwrap(),
                signer_account_id: account_id.clone(),
                signer_account_pk: destination_node_info.signer_account_pk.clone(),
                expected_error_kind: Some(ErrorKind::NodeMigrationError(
                    NodeMigrationError::MigrationNotFound,
                )),
                expected_post_call_info: Some((
                    expected_participant_id.clone(),
                    expected_participant_info.clone(),
                )),
            };
            setup.run(&mut contract, &keyset);
        }
    }

    #[test]
    fn test_conclude_node_migration_keyset_mismatch() {
        let running_state = gen_running_state(2);
        let mut keyset = running_state.keyset.clone();
        keyset.epoch_id = keyset.epoch_id.next();
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_sate(running_state);
        for (account_id, expected_participant_id, expected_participant_info) in
            participants.participants()
        {
            let destination_node_info = gen_random_destination_info();
            let setup = ConcludeNodeMigrationTestSetup {
                destination_node_info: Some(destination_node_info.clone()),
                attestation_tls_key: destination_node_info
                    .destination_node_info
                    .sign_pk
                    .clone()
                    .try_into_dto_type()
                    .unwrap(),
                signer_account_id: account_id.clone(),
                signer_account_pk: destination_node_info.signer_account_pk,
                expected_error_kind: Some(ErrorKind::NodeMigrationError(
                    NodeMigrationError::KeysetMismatch,
                )),
                expected_post_call_info: Some((
                    expected_participant_id.clone(),
                    expected_participant_info.clone(),
                )),
            };
            setup.run(&mut contract, &keyset);
        }
    }

    #[test]
    fn test_conclude_node_migration_not_participant() {
        let running_state = gen_running_state(2);
        let keyset = running_state.keyset.clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_sate(running_state);
        let non_participant_account_id = gen_account_id();
        let destination_node_info = gen_random_destination_info();
        let setup = ConcludeNodeMigrationTestSetup {
            destination_node_info: Some(destination_node_info.clone()),
            attestation_tls_key: destination_node_info
                .destination_node_info
                .sign_pk
                .clone()
                .try_into_dto_type()
                .unwrap(),
            signer_account_id: non_participant_account_id.clone(),
            signer_account_pk: destination_node_info.signer_account_pk,
            expected_error_kind: Some(ErrorKind::InvalidState(InvalidState::NotParticipant)),
            expected_post_call_info: None,
        };
        setup.run(&mut contract, &keyset);
    }

    fn test_conclude_node_migration_failure_not_running(
        participants: &Participants,
        contract: &mut MpcContract,
        keyset: &Keyset,
    ) {
        for (account_id, expected_participant_id, expected_participant_info) in
            participants.participants()
        {
            let destination_node_info = gen_random_destination_info();
            let setup = ConcludeNodeMigrationTestSetup {
                destination_node_info: Some(destination_node_info.clone()),
                attestation_tls_key: destination_node_info
                    .destination_node_info
                    .sign_pk
                    .clone()
                    .try_into_dto_type()
                    .unwrap(),
                signer_account_id: account_id.clone(),
                signer_account_pk: destination_node_info.signer_account_pk,
                expected_error_kind: Some(ErrorKind::InvalidState(
                    InvalidState::ProtocolStateNotRunning,
                )),
                expected_post_call_info: Some((
                    expected_participant_id.clone(),
                    expected_participant_info.clone(),
                )),
            };
            setup.run(contract, keyset);
        }
    }

    #[test]
    fn test_conclude_node_migration_failure_resharing() {
        let (_, resharing_state) = gen_resharing_state(2);

        let keyset = resharing_state.previous_running_state.keyset.clone();
        let participants = resharing_state
            .previous_running_state
            .parameters
            .participants()
            .clone();
        let resharing_state = ProtocolContractState::Resharing(resharing_state);
        let mut contract = MpcContract::new_from_protocol_sate(resharing_state);
        test_conclude_node_migration_failure_not_running(&participants, &mut contract, &keyset);
    }

    #[test]
    fn test_conclude_node_migration_failure_initializing() {
        let (_, initializing) = gen_initializing_state(2, 0);

        let keyset = Keyset::new(
            initializing.generating_key.epoch_id(),
            initializing.generated_keys.clone(),
        );
        let participants = initializing
            .generating_key
            .proposed_parameters()
            .participants()
            .clone();
        let initializing_state = ProtocolContractState::Initializing(initializing);
        let mut contract = MpcContract::new_from_protocol_sate(initializing_state);
        test_conclude_node_migration_failure_not_running(&participants, &mut contract, &keyset);
    }

    struct ConcludeNodeMigrationTestSetup {
        // a destination node info to store in the migration state
        destination_node_info: Option<DestinationNodeInfo>,
        // the tls key to store for the attestation
        attestation_tls_key: Ed25519PublicKey,
        signer_account_id: AccountId,
        signer_account_pk: near_sdk::PublicKey,
        expected_error_kind: Option<ErrorKind>,
        expected_post_call_info: Option<(ParticipantId, ParticipantInfo)>,
    }

    impl ConcludeNodeMigrationTestSetup {
        fn setup(&self, contract: &mut MpcContract) {
            if let Some(destination_node_info) = self.destination_node_info.clone() {
                contract.node_migrations.set_destination_node_info(
                    self.signer_account_id.clone(),
                    destination_node_info,
                );
            }
            let valid_participant_attestation = attestation::attestation::Attestation::Mock(
                attestation::attestation::MockAttestation::Valid,
            );
            contract.tee_state.add_participant(
                NodeId {
                    account_id: self.signer_account_id.clone(),
                    tls_public_key: self.attestation_tls_key.clone().into_contract_type(),
                },
                valid_participant_attestation,
            );
        }

        pub fn run(&self, contract: &mut MpcContract, keyset: &Keyset) {
            self.setup(contract);
            let mut test_env = Environment::new(None, None, None);
            test_env.set_signer(&self.signer_account_id);
            test_env.set_pk(self.signer_account_pk.clone());

            let res = contract.conclude_node_migration(keyset);

            if let Some(expected_error_kind) = &self.expected_error_kind {
                assert_eq!(res.unwrap_err().kind(), expected_error_kind);
            } else {
                assert!(res.is_ok());
            }
            if let Some((expected_participant_id, expected_participant_info)) =
                &self.expected_post_call_info
            {
                let res_participants = {
                    match &contract.protocol_state {
                        ProtocolContractState::Running(running) => {
                            running.parameters.participants()
                        }
                        ProtocolContractState::Resharing(resharing) => {
                            resharing.previous_running_state.parameters.participants()
                        }
                        ProtocolContractState::Initializing(initializing) => initializing
                            .generating_key
                            .proposed_parameters()
                            .participants(),
                        _ => panic!("expected different state"),
                    }
                };
                let found_info = res_participants.info(&self.signer_account_id).unwrap();
                assert_eq!(found_info, expected_participant_info);
                let found_id = res_participants.id(&self.signer_account_id).unwrap();
                assert_eq!(&found_id, expected_participant_id);
            }
        }
    }

    #[test]
    pub fn test_cleanup_orphaned_node_migrations() {
        let running_state = gen_running_state(2);
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_sate(running_state);
        let mut expected_vals = BTreeMap::new();
        for (account_id, _, _) in participants.participants() {
            let destination_node_info = gen_random_destination_info();

            contract
                .node_migrations
                .set_destination_node_info(account_id.clone(), destination_node_info.clone());
            let backup_service_info = BackupServiceInfo {
                public_key: bogus_ed25519_public_key(),
            };
            contract
                .node_migrations
                .set_backup_service_info(account_id.clone(), backup_service_info.clone());
            expected_vals.insert(
                account_id.clone(),
                (Some(backup_service_info), Some(destination_node_info)),
            );
        }
        let destination_node_info = gen_random_destination_info();

        let non_participant_account_id = gen_account_id();
        contract.node_migrations.set_destination_node_info(
            non_participant_account_id.clone(),
            destination_node_info.clone(),
        );
        let backup_service_info = BackupServiceInfo {
            public_key: bogus_ed25519_public_key(),
        };
        contract
            .node_migrations
            .set_backup_service_info(non_participant_account_id.clone(), backup_service_info);

        assert!(contract.cleanup_orphaned_node_migrations().is_ok());
        let result = contract.migration_info();
        assert_eq!(result, expected_vals);
    }
}
