//! Plumbing shared by more than one feature

use crate::errors::{Error, InvalidParameters, RequestError, TeeError};
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types as dtos;
use near_sdk::{AccountId, CryptoHash, Gas, GasWeight, NearToken, Promise, env, log, near};

use dtos::{DomainConfig, DomainId, DomainPurpose};

impl MpcContract {
    /// Common preconditions enforced on every user-facing request method (`sign`,
    /// `request_app_private_key`, `verify_foreign_transaction`):
    ///
    /// 1. The target domain exists and its purpose matches `expected_purpose`.
    /// 2. The caller attached enough prepaid gas to perform the yield/resume flow.
    /// 3. The caller attached at least `minimum_deposit` (excess is refunded).
    /// 4. The contract is currently accepting user requests.
    ///
    /// Returns the validated domain config and the caller's account id.
    pub(crate) fn check_request_preconditions(
        &self,
        domain_id: DomainId,
        expected_purpose: DomainPurpose,
        minimum_gas: Gas,
        minimum_deposit: NearToken,
    ) -> (DomainConfig, AccountId) {
        // 1. Look up the domain and check its purpose.
        let domains = match self.protocol_state.domain_registry() {
            Ok(domains) => domains,
            Err(err) => env::panic_str(&err.to_string()),
        };
        let Some(domain_config) = domains.get_domain_by_domain_id(domain_id) else {
            env::panic_str(
                &InvalidParameters::DomainNotFound {
                    provided: domain_id,
                }
                .to_string(),
            );
        };
        if domain_config.purpose != expected_purpose {
            env::panic_str(
                &InvalidParameters::WrongDomainPurpose {
                    domain_id: domain_config.id,
                    expected: expected_purpose,
                    actual: domain_config.purpose,
                }
                .to_string(),
            );
        }
        let domain_config = domain_config.clone();

        // 2. Make sure the call will not run out of gas doing yield/resume logic.
        let prepaid_gas = env::prepaid_gas();
        if prepaid_gas < minimum_gas {
            env::panic_str(
                &InvalidParameters::InsufficientGas {
                    provided: prepaid_gas.as_gas(),
                    required: minimum_gas.as_gas(),
                }
                .to_string(),
            );
        }

        // 3. Require the minimum deposit and refund any excess.
        let predecessor = env::predecessor_account_id();
        require_deposit(minimum_deposit, &predecessor);

        // 4. Refuse the request if the contract is not currently accepting requests
        //    (e.g. because TEE validation has failed).
        if !self.accept_requests {
            env::panic_str(&TeeError::TeeValidationFailed.to_string())
        }

        (domain_config, predecessor)
    }

    /// Creates a yield-resume promise that calls back into `callback_method` with the
    /// pre-serialized `callback_args`, and stores the resulting yield id via `insert`.
    ///
    /// This function calls [`env::promise_return`] and so must be the last operation performed
    /// in the enclosing contract method.
    pub(crate) fn enqueue_yield_request(
        &mut self,
        callback_method: &str,
        callback_args: Vec<u8>,
        callback_gas: Gas,
        insert: impl FnOnce(&mut Self, CryptoHash),
    ) {
        let promise_index = env::promise_yield_create(
            callback_method,
            callback_args,
            callback_gas,
            GasWeight(0),
            DATA_ID_REGISTER,
        );

        let return_id: CryptoHash = env::read_register(DATA_ID_REGISTER)
            .expect("read_register failed")
            .try_into()
            .expect("conversion to CryptoHash failed");
        insert(self, return_id);

        env::promise_return(promise_index);
    }

    /// Get our own account id as a voter. Returns an error if we are not a participant.
    pub(crate) fn voter_account(&self) -> Result<AccountId, Error> {
        if !Self::caller_is_signer() {
            return Err(InvalidParameters::CallerNotSigner.into());
        }
        let voter = env::signer_account_id();
        self.protocol_state.authenticate_update_vote()?;
        Ok(voter)
    }

    /// Returns true if the caller is the signer account.
    pub(crate) fn caller_is_signer() -> bool {
        let signer = env::signer_account_id();
        let predecessor = env::predecessor_account_id();
        signer == predecessor
    }

    /// Get our own account id as a voter. If we are not a participant, panic.
    /// also ensures that the caller is the signer account.
    pub(crate) fn voter_or_panic(&self) -> AccountId {
        Self::assert_caller_is_signer();
        match self.voter_account() {
            Ok(voter) => voter,
            Err(err) => env::panic_str(&format!("not a voter, {:?}", err)),
        }
    }

    /// Ensures that the caller is an attested participant
    /// in the currently active protocol phase.
    ///
    /// Active phases:
    /// - [`Initializing`](crate::state::ProtocolContractState::Initializing) → uses proposed participants from generating_key
    /// - [`Running`](crate::state::ProtocolContractState::Running) → uses current active participants
    /// - [`Resharing`](crate::state::ProtocolContractState::Resharing) → uses new participants from resharing proposal
    ///
    /// Panics if:
    /// - The protocol is not active (e.g., NotInitialized)
    /// - The caller is not attested or not in the relevant participants set
    /// - The caller is not the signer account
    pub(crate) fn assert_caller_is_attested_participant_and_protocol_active(&self) {
        let participants = self.protocol_state.active_participants();

        Self::assert_caller_is_signer();

        let attestation_check = self
            .tee_state
            .is_caller_an_attested_participant(participants);

        assert_matches::assert_matches!(
            attestation_check,
            Ok(()),
            "Caller must be an attested participant"
        );
    }

    /// Ensures the current call originates from the signer account itself.
    /// Panics if `signer_account_id` and `predecessor_account_id` differ.
    ///
    /// This enforces the network-wide policy that **all governance methods must be called
    /// directly from the participant's own NEAR account**, never forwarded through another
    /// contract such as a multisig.
    ///
    /// This check reaches every signer-authenticated mutating method through one of three
    /// paths (the list below is illustrative, not exhaustive):
    /// - Called directly: `vote_new_parameters`, `vote_add_domains`, `vote_cancel_resharing`,
    ///   `vote_cancel_keygen`, `register_foreign_chain_support`, `submit_participant_info`,
    ///   and the node-migration methods.
    /// - Via [`Self::voter_or_panic`]: `propose_update`, `vote_update`, `remove_update_vote`,
    ///   `vote_code_hash`, the launcher/OS-measurement votes,
    ///   `vote_update_foreign_chain_providers`, and `verify_tee`.
    /// - Via [`Self::assert_caller_is_attested_participant_and_protocol_active`]: the key-event
    ///   votes `vote_pk`, `vote_reshared`, `vote_abort_key_event_instance`, and the leader-only
    ///   `start_keygen_instance` / `start_reshare_instance`, plus the `respond*` callbacks.
    pub(crate) fn assert_caller_is_signer() -> AccountId {
        let signer_id = env::signer_account_id();
        let predecessor_id = env::predecessor_account_id();

        assert_eq!(
            signer_id, predecessor_id,
            "Caller must be the signer account (signer: {}, predecessor: {})",
            signer_id, predecessor_id
        );

        signer_id
    }
}

#[near]
impl MpcContract {
    #[private]
    pub fn fail_on_timeout() {
        // To stay consistent with the old version of the timeout error
        env::panic_str(&RequestError::Timeout.to_string());
    }
}

/// Register used to receive data id from `promise_await_data`.
/// Note: This is an implementation constant, not a configurable policy value.
const DATA_ID_REGISTER: u64 = 0;

/// Minimum deposit required for sign requests, also charged for foreign-transaction verification
pub(crate) const MINIMUM_SIGN_REQUEST_DEPOSIT: NearToken = NearToken::from_yoctonear(1);

/// Checks that the caller attached at least `minimum_deposit` and refunds any excess.
///
/// A non-zero deposit is required so that the transaction must be signed by a
/// full-access key: function-call access keys cannot attach a deposit (their
/// allowance covers gas only). This prevents a **malicious frontend** from silently
/// submitting signature requests on behalf of a user via a restricted
/// function-call access key. In other words, requiring a deposit ensures the user
/// (or their full-access key) explicitly authorised the call.
///
/// See the "Deposit requirement" section in the contract README for more
/// details.
pub(crate) fn require_deposit(minimum_deposit: NearToken, predecessor: &AccountId) {
    let deposit = env::attached_deposit();
    match deposit.checked_sub(minimum_deposit) {
        None => {
            env::panic_str(
                &InvalidParameters::InsufficientDeposit {
                    attached: deposit.as_yoctonear(),
                    required: minimum_deposit.as_yoctonear(),
                }
                .to_string(),
            );
        }
        Some(diff) => refund_to(predecessor, diff),
    }
}

/// Transfers `amount` to `account_id` via a detached promise; no-op when zero.
pub(crate) fn refund_to(account_id: &AccountId, amount: NearToken) {
    if amount > NearToken::from_near(0) {
        log!("refund {amount} to {account_id}");
        Promise::new(account_id.clone()).transfer(amount).detach();
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::*;
    use dtos::Curve;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use rand::{SeedableRng, rngs::OsRng};

    fn override_context_for_preconditions(deposit: NearToken, prepaid_gas: Gas) {
        let predecessor: AccountId = "contract_account.near".parse().unwrap();
        let context = VMContextBuilder::new()
            .predecessor_account_id(predecessor.clone())
            .current_account_id(predecessor)
            .attached_deposit(deposit)
            .prepaid_gas(prepaid_gas)
            .build();
        testing_env!(context);
    }

    #[test]
    fn check_request_preconditions__returns_domain_config_and_predecessor_on_valid_call() {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_, contract, _) = basic_setup(Curve::Secp256k1, &mut rng);
        let (config, predecessor) = contract.check_request_preconditions(
            DomainId::default(),
            DomainPurpose::Sign,
            Gas::from_tgas(1),
            NearToken::from_yoctonear(1),
        );
        assert_eq!(config.id, DomainId::default());
        assert_eq!(Curve::from(config.protocol), Curve::Secp256k1);
        assert_eq!(config.purpose, DomainPurpose::Sign);
        assert_eq!(predecessor.as_str(), "contract_account.near");
    }

    #[test]
    #[should_panic(expected = "was not found")]
    fn check_request_preconditions__panics_when_domain_does_not_exist() {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_, contract, _) = basic_setup(Curve::Secp256k1, &mut rng);
        contract.check_request_preconditions(
            DomainId(999),
            DomainPurpose::Sign,
            Gas::from_tgas(1),
            NearToken::from_yoctonear(1),
        );
    }

    #[test]
    #[should_panic(expected = "purpose")]
    fn check_request_preconditions__panics_when_domain_purpose_does_not_match() {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_, contract, _) = basic_setup(Curve::Secp256k1, &mut rng);
        contract.check_request_preconditions(
            DomainId::default(),
            DomainPurpose::CKD,
            Gas::from_tgas(1),
            NearToken::from_yoctonear(1),
        );
    }

    #[test]
    #[should_panic(expected = "Provided gas is lower than required")]
    fn check_request_preconditions__panics_when_prepaid_gas_is_insufficient() {
        let (_, contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        override_context_for_preconditions(NearToken::from_yoctonear(1), Gas::from_tgas(1));
        contract.check_request_preconditions(
            DomainId::default(),
            DomainPurpose::Sign,
            Gas::from_tgas(100),
            NearToken::from_yoctonear(1),
        );
    }

    #[test]
    #[should_panic(expected = "Attached deposit is lower than required")]
    fn check_request_preconditions__panics_when_attached_deposit_is_insufficient() {
        let (_, contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        override_context_for_preconditions(NearToken::from_near(0), Gas::from_tgas(300));
        contract.check_request_preconditions(
            DomainId::default(),
            DomainPurpose::Sign,
            Gas::from_tgas(1),
            NearToken::from_yoctonear(1),
        );
    }

    #[test]
    #[should_panic(expected = "TEE validation")]
    fn check_request_preconditions__panics_when_contract_is_not_accepting_requests() {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_, mut contract, _) = basic_setup(Curve::Secp256k1, &mut rng);
        contract.accept_requests = false;
        contract.check_request_preconditions(
            DomainId::default(),
            DomainPurpose::Sign,
            Gas::from_tgas(1),
            NearToken::from_yoctonear(1),
        );
    }
}
