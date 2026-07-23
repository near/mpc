//! Typed client for the NEAR MPC signer contract.
//!
//! [`MpcContractHandle`] is the single source of each method's wire format
//! (method name, argument struct, gas, deposit), generic over a transport
//! backend implementing [`CallContract`].

use near_contract_transport::{CallContract, FunctionCallArgs, NearGas, NearToken};

use crate::call_args::{
    RequestAppPrivateKeyArgs, SignArgs, SubmitParticipantInfoArgs, VerifyForeignTransactionArgs,
};
use crate::deposits::{SIGN_DEPOSIT_YOCTONEAR, SUBMIT_PARTICIPANT_INFO_DEPOSIT_MILLINEAR};
use crate::method_names::{
    REQUEST_APP_PRIVATE_KEY, SIGN, SUBMIT_PARTICIPANT_INFO, VERIFY_FOREIGN_TRANSACTION, VERIFY_TEE,
};
use crate::types::{
    AccountId, Attestation, CKDAppPublicKey, CKDRequestArgs, Ed25519PublicKey, SignRequestArgs,
    VerifyForeignTransactionRequestArgs,
};

/// Default gas for handle-issued calls without a method-specific amount.
// TODO(#166): 300 Tgas used to be the protocol maximum and higher than most methods
// need; benchmark per method and reduce.
pub const MAX_GAS: NearGas = NearGas::from_gas(300_000_000_000_000);

pub const SIGN_GAS: NearGas = NearGas::from_tgas(15);
// AppPublicKeyPV does an on-chain bls12381_pairing_check (2 pairs) before yielding,
// which costs significantly more than a plain CKD or sign request.
pub const CKD_PV_GAS: NearGas = NearGas::from_tgas(100);

/// Typed interface to the MPC signer contract at a fixed account, generic over
/// the transport backend `C`.
#[derive(Clone)]
pub struct MpcContractHandle<C> {
    caller: C,
    contract_id: AccountId,
}

impl<C> MpcContractHandle<C> {
    pub fn new(caller: C, contract_id: AccountId) -> Self {
        Self {
            caller,
            contract_id,
        }
    }
}

impl<C: CallContract> MpcContractHandle<C> {
    pub async fn sign(
        &self,
        request: SignRequestArgs,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&SignArgs::new(request))?;
        self.caller
            .call_contract(
                &self.contract_id,
                FunctionCallArgs {
                    method_name: SIGN.to_string(),
                    args,
                    gas: SIGN_GAS,
                    deposit: NearToken::from_yoctonear(SIGN_DEPOSIT_YOCTONEAR),
                },
            )
            .await
            .map_err(MpcContractHandleError::Call)
    }

    pub async fn request_app_private_key(
        &self,
        request: CKDRequestArgs,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let gas = match request.app_public_key {
            CKDAppPublicKey::AppPublicKey(_) => SIGN_GAS,
            CKDAppPublicKey::AppPublicKeyPV(_) => CKD_PV_GAS,
        };
        let args = serde_json::to_vec(&RequestAppPrivateKeyArgs::new(request))?;
        self.caller
            .call_contract(
                &self.contract_id,
                FunctionCallArgs {
                    method_name: REQUEST_APP_PRIVATE_KEY.to_string(),
                    args,
                    gas,
                    deposit: NearToken::from_yoctonear(SIGN_DEPOSIT_YOCTONEAR),
                },
            )
            .await
            .map_err(MpcContractHandleError::Call)
    }

    pub async fn verify_foreign_transaction(
        &self,
        request: VerifyForeignTransactionRequestArgs,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&VerifyForeignTransactionArgs::new(request))?;
        self.caller
            .call_contract(
                &self.contract_id,
                FunctionCallArgs {
                    method_name: VERIFY_FOREIGN_TRANSACTION.to_string(),
                    args,
                    gas: SIGN_GAS,
                    deposit: NearToken::from_yoctonear(SIGN_DEPOSIT_YOCTONEAR),
                },
            )
            .await
            .map_err(MpcContractHandleError::Call)
    }

    pub async fn submit_participant_info(
        &self,
        proposed_participant_attestation: Attestation,
        tls_public_key: Ed25519PublicKey,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&SubmitParticipantInfoArgs::new(
            proposed_participant_attestation,
            tls_public_key,
        ))?;
        self.caller
            .call_contract(
                &self.contract_id,
                FunctionCallArgs {
                    method_name: SUBMIT_PARTICIPANT_INFO.to_string(),
                    args,
                    gas: MAX_GAS,
                    deposit: NearToken::from_millinear(SUBMIT_PARTICIPANT_INFO_DEPOSIT_MILLINEAR),
                },
            )
            .await
            .map_err(MpcContractHandleError::Call)
    }

    pub async fn verify_tee(&self) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        self.caller
            .call_contract(
                &self.contract_id,
                FunctionCallArgs {
                    method_name: VERIFY_TEE.to_string(),
                    args: b"{}".to_vec(),
                    gas: MAX_GAS,
                    deposit: NearToken::from_yoctonear(0),
                },
            )
            .await
            .map_err(MpcContractHandleError::Call)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MpcContractHandleError<E> {
    #[error("failed to serialize call arguments: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("contract call failed: {0}")]
    Call(E),
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::MpcContractHandle;
    use crate::types::{
        AccountId, Attestation, BitcoinExtractor, BitcoinRpcRequest, BitcoinTxId,
        BlockConfirmations, CKDAppPublicKey, CKDAppPublicKeyPV, CKDRequestArgs, DomainId,
        Ed25519PublicKey, ForeignChainRpcRequest, ForeignTxPayloadVersion, MockAttestation,
        Payload, SignRequestArgs, VerifyForeignTransactionRequestArgs,
    };
    use near_contract_transport::{CallContract, FunctionCallArgs};
    use near_mpc_crypto_types::{Bls12381G1PublicKey, Bls12381G2PublicKey};
    use std::sync::Mutex;

    /// A [`CallContract`] that records the calls it is handed, so a test can
    /// assert the exact wire encoding a handle method produced.
    #[derive(Default)]
    struct RecordingCaller {
        calls: Mutex<Vec<(AccountId, FunctionCallArgs)>>,
    }

    impl CallContract for RecordingCaller {
        type Output = ();
        type Error = ();

        async fn call_contract(
            &self,
            contract_id: &AccountId,
            call_args: FunctionCallArgs,
        ) -> Result<(), Self::Error> {
            self.calls
                .lock()
                .unwrap()
                .push((contract_id.clone(), call_args));
            Ok(())
        }
    }

    /// Renders a recorded call as its reviewable wire format
    /// (method, gas, deposit, args).
    fn render(contract_id: &AccountId, call: &FunctionCallArgs) -> String {
        format!(
            "contract: {contract_id}\nmethod:   {}\ngas:      {}\ndeposit:  {}\nargs:     {}",
            call.method_name,
            call.gas,
            call.deposit.exact_amount_display(),
            String::from_utf8_lossy(&call.args),
        )
    }

    /// One catalog snapshot for the whole handle: every method is called once
    /// and its wire format becomes a section of the snapshot. New handle
    /// methods add a call here.
    #[tokio::test]
    async fn mpc_contract_handle__should_match_the_wire_format_catalog() {
        // Given
        let caller = RecordingCaller::default();
        let handle = MpcContractHandle::new(&caller, "mpc.near".parse().unwrap());

        // When: every handle method, once, in declaration order
        handle
            .sign(SignRequestArgs {
                path: "test".to_string(),
                payload: Payload::Ecdsa([7u8; 32].into()),
                domain_id: DomainId(0),
            })
            .await
            .unwrap();
        handle
            .request_app_private_key(CKDRequestArgs {
                derivation_path: "test".to_string(),
                app_public_key: CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey([7u8; 48])),
                domain_id: DomainId(0),
            })
            .await
            .unwrap();
        handle
            .request_app_private_key(CKDRequestArgs {
                derivation_path: "test".to_string(),
                app_public_key: CKDAppPublicKey::AppPublicKeyPV(CKDAppPublicKeyPV {
                    pk1: Bls12381G1PublicKey([7u8; 48]),
                    pk2: Bls12381G2PublicKey([7u8; 96]),
                }),
                domain_id: DomainId(0),
            })
            .await
            .unwrap();
        handle
            .verify_foreign_transaction(VerifyForeignTransactionRequestArgs {
                request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                    tx_id: BitcoinTxId([7u8; 32]),
                    confirmations: BlockConfirmations(1),
                    extractors: vec![BitcoinExtractor::BlockHash],
                }),
                domain_id: DomainId(0),
                payload_version: ForeignTxPayloadVersion::V1,
            })
            .await
            .unwrap();
        handle
            .submit_participant_info(
                Attestation::Mock(MockAttestation::Valid),
                Ed25519PublicKey::from([7u8; 32]),
            )
            .await
            .unwrap();
        handle.verify_tee().await.unwrap();

        // Then
        let calls = caller.calls.lock().unwrap();
        assert_eq!(calls.len(), 6);
        let catalog = calls
            .iter()
            .map(|(contract_id, call)| render(contract_id, call))
            .collect::<Vec<_>>()
            .join("\n\n");
        insta::assert_snapshot!(catalog);
    }
}
