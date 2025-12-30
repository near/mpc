#![allow(clippy::disallowed_types)]

mod consts;
mod dto_mapping;
mod types;

use attestation::{attestation::DstackAttestation, report_data::ReportData};
use near_sdk::{AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseError, env, log, near};

use contract_interface::types as dtos;
use serde_json::json;

use crate::{dto_mapping::IntoContractType, types::DomainId};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    mpc_account: AccountId,
    domain_id: DomainId,
}

#[near]
impl Contract {
    #[init]
    #[private]
    pub fn init(mpc_account: AccountId, domain_id: DomainId) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        Self {
            mpc_account,
            domain_id,
        }
    }

    fn assert_caller_is_signer() -> near_sdk::AccountId {
        let signer_id = env::signer_account_id();
        let predecessor_id = env::predecessor_account_id();

        assert_eq!(
            signer_id, predecessor_id,
            "Caller must be the signer account (signer: {}, predecessor: {})",
            signer_id, predecessor_id
        );

        signer_id
    }

    fn current_time_seconds() -> u64 {
        let current_time_milliseconds = env::block_timestamp_ms();
        current_time_milliseconds / 1_000
    }

    fn assert_valid_attestation(attestation: dtos::DstackAttestation) {
        let attestation: DstackAttestation = attestation.into_contract_type();
        let timestamp_seconds = Self::current_time_seconds();
        let expected_report_data: ReportData = consts::EXPECTED_REPORT_DATA.into();
        let accepted_measurements = [consts::ACCEPTED_MEASUREMENT];
        attestation
            .verify(
                expected_report_data,
                timestamp_seconds,
                &accepted_measurements,
            )
            .expect("Attestation did not succeed");
    }

    // ->
    pub fn request_confidential_key(
        &self,
        attestation: dtos::DstackAttestation,
        app_public_key: dtos::Bls12381G1PublicKey,
    ) -> Promise {
        let signer = Self::assert_caller_is_signer();
        log!(
            "request_confidential_key: signer={}, app_public_key={:?}",
            &signer,
            &app_public_key
        );

        Self::assert_valid_attestation(attestation);

        let derivation_path = signer.into();

        let ckd_request = types::CKDArgs {
            derivation_path,
            app_public_key,
            domain_id: self.domain_id.clone(),
        };

        let arguments = json!({ "request": ckd_request }).to_string().into_bytes();

        let promise = Promise::new(self.mpc_account.clone()).function_call(
            "request_app_private_key".to_owned(),
            arguments,
            NearToken::ZERO,
            Gas::from_tgas(10),
        );

        promise.then(
            Self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(2))
                .request_confidential_key_callback(),
        )
    }

    #[private]
    pub fn request_confidential_key_callback(
        &self,
        #[callback_result] call_result: Result<types::CKDResponse, PromiseError>,
    ) -> types::CKDResponse {
        match call_result {
            Ok(response) => response,
            Err(err) => {
                env::panic_str(&format!(
                    "There was an error contacting {}: {:?}",
                    self.mpc_account, err
                ));
            }
        }
    }
}
