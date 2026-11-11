//! V2 foreign transaction requests. Callers make them under the external name
//! Read RPC. Each request waits on its own yield, under an id the contract picks.

use crate::errors::RequestError;
use crate::events::MpcContractEvent;
use crate::pending_verify_foreign_tx_v2::PendingVerifyForeignTxRequestV2;
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::deposits::SIGN_DEPOSIT_YOCTONEAR;
use near_mpc_contract_interface::events::VerifyForeignTxV2YieldCreated;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types as dtos;
use near_sdk::{Gas, GasWeight, NearToken, PromiseError, PromiseOrValue, env, log, near};

#[near]
impl MpcContract {
    /// Submits a V2 foreign transaction verification request. The MPC nodes
    /// answer it with a signed
    /// [`ForeignTxVerificationOutcome`](dtos::ForeignTxVerificationOutcome).
    ///
    /// The contract announces the [`dtos::YieldId`] of the request in a
    /// [`VerifyForeignTxV2YieldCreated`] event. Without an answer, the request
    /// times out like a V1 request.
    #[payable]
    pub fn read_rpc(&mut self, request: dtos::VerifyForeignTransactionRequestV2) {
        // The expected values have no size cap, and NEAR caps the log bytes of a call.
        log!(
            "read_rpc: predecessor={:?}, request={:?}, domain_id={:?}",
            env::predecessor_account_id(),
            request.request,
            request.domain_id
        );

        self.check_request_preconditions(
            request.domain_id,
            dtos::DomainPurpose::ForeignTx,
            Gas::from_tgas(self.config.sign_call_gas_attachment_requirement_tera_gas),
            NearToken::from_yoctonear(SIGN_DEPOSIT_YOCTONEAR),
        );
        self.require_foreign_chain_available(request.request.chain());

        let expected_values_hash = request
            .expected_values_hash()
            .unwrap_or_else(|err| env::panic_str(&format!("hashing expected values: {err}")));
        let yield_id = self
            .pending_verify_foreign_tx_v2_requests
            .take_next_yield_id();
        let callback_args = serde_json::to_vec(&(yield_id,))
            .unwrap_or_else(|err| env::panic_str(&format!("encoding callback args: {err}")));
        let callback_gas = Gas::from_tgas(
            self.config
                .return_signature_and_clean_state_on_success_call_tera_gas,
        );
        let Some(promise_index) = env::promise_yield_create_with_id(
            method_names::RETURN_VERIFY_FOREIGN_TX_V2_AND_CLEAN_STATE_ON_TIMEOUT,
            callback_args,
            NearToken::ZERO,
            callback_gas,
            GasWeight(0),
            &yield_id.0,
        ) else {
            env::panic_str(&RequestError::YieldIdCollision { yield_id }.to_string());
        };

        self.pending_verify_foreign_tx_v2_requests.insert(
            yield_id,
            PendingVerifyForeignTxRequestV2 {
                request: request.request,
                domain_id: request.domain_id,
                expected_values_hash,
                request_block_height: dtos::BlockHeight::new(env::block_height()),
            },
        );
        MpcContractEvent::VerifyForeignTxV2YieldCreated(VerifyForeignTxV2YieldCreated { yield_id })
            .emit();

        env::promise_return(promise_index);
    }

    /// Yield callback of a V2 request. Returns the response to the caller. On
    /// timeout, removes the request stored under `yield_id` and fails the
    /// caller's transaction.
    #[private]
    pub fn return_verify_foreign_tx_v2_and_clean_state_on_timeout(
        &mut self,
        yield_id: dtos::YieldId,
        #[callback_result] response: Result<dtos::VerifyForeignTransactionResponseV2, PromiseError>,
    ) -> PromiseOrValue<dtos::VerifyForeignTransactionResponseV2> {
        match response {
            // `respond_verify_foreign_tx_v2` removed the request when it resumed the yield.
            Ok(response) => PromiseOrValue::Value(response),
            Err(_) => {
                self.pending_verify_foreign_tx_v2_requests.remove(&yield_id);
                let promise = Self::ext_self()
                    .with_static_gas(Gas::from_tgas(self.config.fail_on_timeout_tera_gas))
                    .with_unused_gas_weight(0)
                    .fail_on_timeout();
                PromiseOrValue::Promise(promise.as_return())
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::foreign_chain::test_utils::{
        announced_yield_ids, bitcoin_request_v2, make_chains_available,
    };
    use crate::api::test_utils::basic_setup_with_protocol;
    use dtos::Protocol;
    use near_sdk::testing_env;
    use rand::SeedableRng;

    /// NEAR's `max_total_log_length` for one function call.
    const MAX_TOTAL_LOG_BYTES: usize = 16 * 1024;

    fn setup_with_bitcoin_available() -> MpcContract {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, dtos::DomainPurpose::ForeignTx, &mut rng);
        make_chains_available(&mut contract, [dtos::ForeignChain::Bitcoin]);
        testing_env!(context);
        contract
    }

    #[test]
    fn read_rpc__should_store_the_request_under_the_announced_yield_id() {
        // Given
        let mut contract = setup_with_bitcoin_available();
        let request = bitcoin_request_v2();
        let block_height = env::block_height();

        // When
        contract.read_rpc(request.clone());

        // Then
        let [yield_id] = announced_yield_ids()[..] else {
            panic!("expected exactly one yield created event");
        };
        assert_eq!(
            contract
                .pending_verify_foreign_tx_v2_requests
                .get(&yield_id),
            Some(&PendingVerifyForeignTxRequestV2 {
                request: request.request.clone(),
                domain_id: request.domain_id,
                expected_values_hash: request.expected_values_hash().unwrap(),
                request_block_height: dtos::BlockHeight::new(block_height),
            })
        );
    }

    #[test]
    fn read_rpc__should_accept_expected_values_larger_than_the_log_limit() {
        // Given
        let mut contract = setup_with_bitcoin_available();
        let mut request = bitcoin_request_v2();
        request.expected_values = vec![request.expected_values[0].clone(); 1_000];
        assert!(serde_json::to_vec(&request.expected_values).unwrap().len() > MAX_TOTAL_LOG_BYTES);

        // When
        contract.read_rpc(request.clone());

        // Then
        let [yield_id] = announced_yield_ids()[..] else {
            panic!("expected exactly one yield created event");
        };
        assert_eq!(
            contract
                .pending_verify_foreign_tx_v2_requests
                .get(&yield_id)
                .map(|stored| stored.expected_values_hash.clone()),
            Some(request.expected_values_hash().unwrap())
        );
    }

    #[test]
    fn read_rpc__should_give_identical_requests_different_yield_ids() {
        // Given
        let mut contract = setup_with_bitcoin_available();

        // When
        contract.read_rpc(bitcoin_request_v2());
        contract.read_rpc(bitcoin_request_v2());

        // Then
        let [first, second] = announced_yield_ids()[..] else {
            panic!("expected one yield created event per request");
        };
        assert_ne!(first, second);
        assert!(
            contract
                .pending_verify_foreign_tx_v2_requests
                .get(&first)
                .is_some()
        );
        assert!(
            contract
                .pending_verify_foreign_tx_v2_requests
                .get(&second)
                .is_some()
        );
    }

    #[test]
    fn return_verify_foreign_tx_v2_and_clean_state_on_timeout__should_remove_only_the_timed_out_request()
     {
        // Given
        let mut contract = setup_with_bitcoin_available();
        contract.read_rpc(bitcoin_request_v2());
        contract.read_rpc(bitcoin_request_v2());
        let [timed_out, still_pending] = announced_yield_ids()[..] else {
            panic!("expected one yield created event per request");
        };

        // When
        let result = contract.return_verify_foreign_tx_v2_and_clean_state_on_timeout(
            timed_out,
            Err(PromiseError::Failed),
        );

        // Then
        // assert_matches! requires Debug, and PromiseOrValue does not implement it
        assert!(matches!(result, PromiseOrValue::Promise(_)));
        assert!(
            contract
                .pending_verify_foreign_tx_v2_requests
                .get(&timed_out)
                .is_none()
        );
        assert!(
            contract
                .pending_verify_foreign_tx_v2_requests
                .get(&still_pending)
                .is_some()
        );
    }

    #[test]
    #[should_panic(expected = "Requested foreign chain, Bitcoin, is not available.")]
    fn read_rpc__should_reject_a_chain_that_is_not_available() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (context, mut contract, _secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, dtos::DomainPurpose::ForeignTx, &mut rng);
        make_chains_available(&mut contract, [dtos::ForeignChain::Solana]);
        testing_env!(context);

        // When
        contract.read_rpc(bitcoin_request_v2());
    }

    #[test]
    #[should_panic(expected = "this method requires ForeignTx")]
    fn read_rpc__should_reject_a_domain_that_is_not_for_foreign_tx() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_context, mut contract, _secret_key) =
            basic_setup_with_protocol(Protocol::CaitSith, dtos::DomainPurpose::Sign, &mut rng);

        // When
        contract.read_rpc(bitcoin_request_v2());
    }
}
