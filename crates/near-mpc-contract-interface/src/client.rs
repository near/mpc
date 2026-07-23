//! Typed client for the NEAR MPC signer contract.
//!
//! [`MpcContractHandle`] is the single source of each method's wire format
//! (method name, argument struct, gas, deposit), generic over a transport
//! backend implementing [`CallContract`].

use near_contract_transport::{CallContract, FunctionCallArgs, NearGas, NearToken};

use crate::call_args::{
    RegisterBackupServiceArgs, RegisterForeignChainSupportArgs, RequestAppPrivateKeyArgs, SignArgs,
    StartNodeMigrationArgs, SubmitParticipantInfoArgs, UpdateParticipantUrlArgs,
    VerifyForeignTransactionArgs, VoteAddDomainsArgs, VoteCancelKeygenArgs, VoteNewParametersArgs,
    VoteUpdateArgs,
};
use crate::deposits::{
    PROPOSE_UPDATE_DEPOSIT_MILLINEAR, SIGN_DEPOSIT_YOCTONEAR,
    SUBMIT_PARTICIPANT_INFO_DEPOSIT_MILLINEAR,
};
use crate::method_names::{
    PROPOSE_UPDATE, REGISTER_BACKUP_SERVICE, REGISTER_FOREIGN_CHAIN_SUPPORT,
    REQUEST_APP_PRIVATE_KEY, SIGN, START_NODE_MIGRATION, SUBMIT_PARTICIPANT_INFO,
    UPDATE_PARTICIPANT_URL, VERIFY_FOREIGN_TRANSACTION, VERIFY_TEE, VOTE_ADD_DOMAINS,
    VOTE_CANCEL_KEYGEN, VOTE_CANCEL_RESHARING, VOTE_NEW_PARAMETERS, VOTE_UPDATE,
    VOTE_UPDATE_FOREIGN_CHAIN_PROVIDERS,
};
use crate::types::{
    AccountId, Attestation, BackupServiceInfo, CKDAppPublicKey, CKDRequestArgs, ChainEntry,
    DestinationNodeInfo, DomainConfig, Ed25519PublicKey, EpochId, ForeignChain, ProposeUpdateArgs,
    ProposedThresholdParameters, SignRequestArgs, SupportedForeignChains,
    VerifyForeignTransactionRequestArgs,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;

/// Default gas for handle-issued calls without a method-specific amount.
// TODO(#166): 300 Tgas is the protocol maximum and higher than most methods
// need; benchmark per method and reduce.
pub const MAX_GAS: NearGas = NearGas::from_gas(300_000_000_000_000);

pub const SIGN_GAS: NearGas = NearGas::from_tgas(15);

pub const CKD_PV_GAS: NearGas = NearGas::from_tgas(100);

pub const VOTE_FOREIGN_CHAIN_GAS: NearGas = NearGas::from_tgas(30);

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

    pub async fn propose_update(
        &self,
        args: ProposeUpdateArgs,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = borsh::to_vec(&args)?;
        self.caller
            .call_contract(
                &self.contract_id,
                FunctionCallArgs {
                    method_name: PROPOSE_UPDATE.to_string(),
                    args,
                    gas: MAX_GAS,
                    deposit: NearToken::from_millinear(PROPOSE_UPDATE_DEPOSIT_MILLINEAR),
                },
            )
            .await
            .map_err(MpcContractHandleError::Call)
    }

    pub async fn vote_update(
        &self,
        id: u64,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&VoteUpdateArgs::new(id))?;
        self.caller
            .call_contract(
                &self.contract_id,
                FunctionCallArgs {
                    method_name: VOTE_UPDATE.to_string(),
                    args,
                    gas: MAX_GAS,
                    deposit: NearToken::from_yoctonear(0),
                },
            )
            .await
            .map_err(MpcContractHandleError::Call)
    }

    pub async fn vote_add_domains(
        &self,
        domains: Vec<DomainConfig>,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&VoteAddDomainsArgs::new(domains))?;
        self.call_without_deposit(VOTE_ADD_DOMAINS, args, MAX_GAS)
            .await
    }

    pub async fn vote_new_parameters(
        &self,
        prospective_epoch_id: EpochId,
        proposal: ProposedThresholdParameters,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&VoteNewParametersArgs::new(prospective_epoch_id, proposal))?;
        self.call_without_deposit(VOTE_NEW_PARAMETERS, args, MAX_GAS)
            .await
    }

    pub async fn vote_cancel_keygen(
        &self,
        next_domain_id: u64,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&VoteCancelKeygenArgs::new(next_domain_id))?;
        self.call_without_deposit(VOTE_CANCEL_KEYGEN, args, MAX_GAS)
            .await
    }

    pub async fn vote_cancel_resharing(
        &self,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        self.call_without_deposit(VOTE_CANCEL_RESHARING, b"{}".to_vec(), MAX_GAS)
            .await
    }

    pub async fn update_participant_url(
        &self,
        url: String,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&UpdateParticipantUrlArgs::new(url))?;
        self.call_without_deposit(UPDATE_PARTICIPANT_URL, args, MAX_GAS)
            .await
    }

    pub async fn register_backup_service(
        &self,
        backup_service_info: BackupServiceInfo,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&RegisterBackupServiceArgs::new(backup_service_info))?;
        self.call_without_deposit(REGISTER_BACKUP_SERVICE, args, MAX_GAS)
            .await
    }

    pub async fn start_node_migration(
        &self,
        destination_node_info: DestinationNodeInfo,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = serde_json::to_vec(&StartNodeMigrationArgs::new(destination_node_info))?;
        self.call_without_deposit(START_NODE_MIGRATION, args, MAX_GAS)
            .await
    }

    pub async fn register_foreign_chain_support(
        &self,
        foreign_chain_support: SupportedForeignChains,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args =
            serde_json::to_vec(&RegisterForeignChainSupportArgs::new(foreign_chain_support))?;
        self.call_without_deposit(REGISTER_FOREIGN_CHAIN_SUPPORT, args, MAX_GAS)
            .await
    }

    pub async fn vote_update_foreign_chain_providers(
        &self,
        batch: NonEmptyBTreeMap<ForeignChain, ChainEntry>,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        let args = borsh::to_vec(&batch)?;
        self.call_without_deposit(
            VOTE_UPDATE_FOREIGN_CHAIN_PROVIDERS,
            args,
            VOTE_FOREIGN_CHAIN_GAS,
        )
        .await
    }

    /// Zero-deposit call with pre-encoded args.
    async fn call_without_deposit(
        &self,
        method_name: &str,
        args: Vec<u8>,
        gas: NearGas,
    ) -> Result<C::Output, MpcContractHandleError<C::Error>> {
        self.caller
            .call_contract(
                &self.contract_id,
                FunctionCallArgs {
                    method_name: method_name.to_string(),
                    args,
                    gas,
                    deposit: NearToken::from_yoctonear(0),
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
    #[error("failed to borsh-encode call arguments: {0}")]
    Encode(#[from] std::io::Error),
    #[error("contract call failed: {0}")]
    Call(E),
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::MpcContractHandle;
    use crate::types::{
        AccountId, Attestation, AuthScheme, BackupServiceInfo, BitcoinExtractor, BitcoinRpcRequest,
        BitcoinTxId, BlockConfirmations, CKDAppPublicKey, CKDAppPublicKeyPV, CKDRequestArgs,
        ChainEntry, ChainRouting, DestinationNodeInfo, DomainConfig, DomainId, DomainPurpose,
        Ed25519PublicKey, EpochId, ForeignChain, ForeignChainRpcRequest, ForeignTxPayloadVersion,
        MockAttestation, ParticipantId, ParticipantInfo, Participants, Payload, ProposeUpdateArgs,
        ProposedThresholdParameters, Protocol, ProviderConfig, ProviderId, ReconstructionThreshold,
        SignRequestArgs, Threshold, ThresholdParameters, VerifyForeignTransactionRequestArgs,
    };
    use near_contract_transport::{CallContract, FunctionCallArgs};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use near_mpc_crypto_types::{Bls12381G1PublicKey, Bls12381G2PublicKey};
    use std::collections::{BTreeMap, BTreeSet};
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
        let args = if call.args.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            String::from_utf8_lossy(&call.args).into_owned()
        } else {
            format!("0x{}", hex::encode(&call.args))
        };
        format!(
            "contract: {contract_id}\nmethod:   {}\ngas:      {}\ndeposit:  {}\nargs:     {args}",
            call.method_name,
            call.gas,
            call.deposit.exact_amount_display(),
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
            .propose_update(ProposeUpdateArgs {
                code: Some(vec![7u8; 4]),
                config: None,
            })
            .await
            .unwrap();
        handle.vote_update(7).await.unwrap();
        handle
            .vote_add_domains(vec![DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::Sign,
            }])
            .await
            .unwrap();
        handle
            .vote_new_parameters(
                EpochId::new(7),
                ProposedThresholdParameters {
                    parameters: ThresholdParameters {
                        threshold: Threshold(1),
                        participants: Participants {
                            next_id: ParticipantId(1),
                            participants: vec![(
                                "alice.near".parse().unwrap(),
                                ParticipantId(0),
                                ParticipantInfo {
                                    url: "http://localhost:7".to_string(),
                                    tls_public_key: Ed25519PublicKey::from([7u8; 32]),
                                },
                            )],
                        },
                    },
                    per_domain_thresholds: BTreeMap::new(),
                },
            )
            .await
            .unwrap();
        handle.vote_cancel_keygen(7).await.unwrap();
        handle.vote_cancel_resharing().await.unwrap();
        handle
            .update_participant_url("http://localhost:7".to_string())
            .await
            .unwrap();
        handle
            .register_backup_service(BackupServiceInfo {
                public_key: Ed25519PublicKey::from([7u8; 32]),
            })
            .await
            .unwrap();
        handle
            .start_node_migration(DestinationNodeInfo {
                signer_account_pk: Ed25519PublicKey::from([7u8; 32]),
                destination_node_info: ParticipantInfo {
                    url: "http://localhost:7".to_string(),
                    tls_public_key: Ed25519PublicKey::from([7u8; 32]),
                },
            })
            .await
            .unwrap();
        handle
            .register_foreign_chain_support(BTreeSet::from([ForeignChain::Bitcoin]).into())
            .await
            .unwrap();
        handle
            .vote_update_foreign_chain_providers(NonEmptyBTreeMap::new(
                ForeignChain::Bitcoin,
                ChainEntry {
                    providers: NonEmptyBTreeMap::new(
                        ProviderId("alchemy".to_string()),
                        ProviderConfig {
                            base_url: "http://localhost:7".to_string(),
                            auth_scheme: AuthScheme::None,
                            chain_routing: ChainRouting::Embedded,
                        },
                    ),
                    quorum: 1,
                },
            ))
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
        assert_eq!(calls.len(), 17);
        let catalog = calls
            .iter()
            .map(|(contract_id, call)| render(contract_id, call))
            .collect::<Vec<_>>()
            .join("\n\n");
        insta::assert_snapshot!(catalog);
    }
}
