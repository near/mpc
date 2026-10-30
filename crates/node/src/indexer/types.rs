use crate::trait_extensions::convert_to_contract_dto::IntoContractInterfaceType;
use crate::types::{SignatureRequest, VerifyForeignTxRequest};
use anyhow::Context;
use k256::{AffinePoint, Scalar, ecdsa::RecoveryId};
use near_kit_primitives::transaction::FunctionCall;
use near_mpc_contract_interface::call_args as contract_args;
use near_mpc_contract_interface::contract::MpcContract;
use near_mpc_contract_interface::method_names::{
    CONCLUDE_NODE_MIGRATION, REGISTER_FOREIGN_CHAINS_CONFIG, RESPOND, RESPOND_CKD,
    RESPOND_VERIFY_FOREIGN_TX, START_KEYGEN_INSTANCE, START_RESHARE_INSTANCE,
    SUBMIT_PARTICIPANT_INFO, VERIFY_TEE, VOTE_ABORT_KEY_EVENT_INSTANCE, VOTE_PK, VOTE_RESHARED,
};
use near_mpc_contract_interface::types::{self as dtos};
use serde::Serialize;
use threshold_signatures::ecdsa::Signature;
use threshold_signatures::frost_ed25519;
use threshold_signatures::frost_secp256k1::VerifyingKey;

const RECOVERY_ID_FAILED: &str = "failed to compute the recovery id of the ECDSA signature";

fn k256_signature_response(
    big_r: AffinePoint,
    s: Scalar,
    recovery_id: RecoveryId,
) -> dtos::SignatureResponse {
    dtos::SignatureResponse::Secp256k1(dtos::K256Signature {
        big_r: dtos::K256AffinePoint::from(big_r),
        s: dtos::K256Scalar::from(s),
        recovery_id: recovery_id.to_byte(),
    })
}
pub trait ChainRespondArgs {}

impl ChainRespondArgs for contract_args::SignatureRespondArgs {}
impl ChainRespondArgs for contract_args::CKDRespondArgs {}
impl ChainRespondArgs for contract_args::VerifyForeignTransactionRespondArgs {}

/// Request to send a transaction to the contract on chain.
#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum ChainSendTransactionRequest {
    Respond(contract_args::SignatureRespondArgs),
    CKDRespond(contract_args::CKDRespondArgs),
    VotePk(contract_args::VotePkArgs),
    StartKeygen(contract_args::StartKeygenArgs),
    VoteReshared(contract_args::VoteResharedArgs),
    RegisterForeignChainsConfig(contract_args::RegisterForeignChainsConfigArgs),
    StartReshare(contract_args::StartReshareArgs),
    VoteAbortKeyEventInstance(contract_args::VoteAbortKeyEventInstanceArgs),
    VerifyTee(),
    // Boxed as this variant is big, 2168 bytes.
    // Big discrepancies in variant sizes will lead to memory fragmentation
    // due to rust's memory layout for enums.
    //
    // For more info see clippy lint:
    // https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant
    SubmitParticipantInfo(Box<contract_args::SubmitParticipantInfoArgs>),

    ConcludeNodeMigration(contract_args::ConcludeNodeMigrationArgs),
    VerifyForeignTransactionRespond(contract_args::VerifyForeignTransactionRespondArgs),
}

impl ChainSendTransactionRequest {
    pub fn method(&self) -> &'static str {
        match self {
            ChainSendTransactionRequest::Respond(_) => RESPOND,
            ChainSendTransactionRequest::CKDRespond(_) => RESPOND_CKD,
            ChainSendTransactionRequest::VotePk(_) => VOTE_PK,
            ChainSendTransactionRequest::VoteReshared(_) => VOTE_RESHARED,
            ChainSendTransactionRequest::RegisterForeignChainsConfig(_) => {
                REGISTER_FOREIGN_CHAINS_CONFIG
            }
            ChainSendTransactionRequest::StartReshare(_) => START_RESHARE_INSTANCE,
            ChainSendTransactionRequest::StartKeygen(_) => START_KEYGEN_INSTANCE,
            ChainSendTransactionRequest::VoteAbortKeyEventInstance(_) => {
                VOTE_ABORT_KEY_EVENT_INSTANCE
            }
            ChainSendTransactionRequest::VerifyTee() => VERIFY_TEE,
            ChainSendTransactionRequest::SubmitParticipantInfo(_) => SUBMIT_PARTICIPANT_INFO,
            ChainSendTransactionRequest::ConcludeNodeMigration(_) => CONCLUDE_NODE_MIGRATION,
            ChainSendTransactionRequest::VerifyForeignTransactionRespond(_) => {
                RESPOND_VERIFY_FOREIGN_TX
            }
        }
    }

    /// The contract call, with the gas `MpcContract` declares for it.
    pub fn function_call(&self) -> FunctionCall {
        match self {
            Self::Respond(args) => {
                MpcContract::respond(args.request.clone(), args.response.clone())
            }
            Self::CKDRespond(args) => {
                MpcContract::respond_ckd(args.request.clone(), args.response.clone())
            }
            Self::VotePk(args) => MpcContract::vote_pk(args.key_event_id, args.public_key.clone()),
            Self::VoteReshared(args) => MpcContract::vote_reshared(args.key_event_id),
            Self::RegisterForeignChainsConfig(args) => {
                MpcContract::register_foreign_chains_config(args.foreign_chains_config.clone())
            }
            Self::StartReshare(args) => MpcContract::start_reshare_instance(args.key_event_id),
            Self::StartKeygen(args) => MpcContract::start_keygen_instance(args.key_event_id),
            Self::VoteAbortKeyEventInstance(args) => {
                MpcContract::vote_abort_key_event_instance(args.key_event_id)
            }
            Self::VerifyTee() => MpcContract::verify_tee(),
            Self::SubmitParticipantInfo(args) => MpcContract::submit_participant_info(
                args.proposed_participant_attestation.clone(),
                args.tls_public_key.clone(),
            ),
            Self::ConcludeNodeMigration(args) => {
                MpcContract::conclude_node_migration(args.keyset.clone())
            }
            Self::VerifyForeignTransactionRespond(args) => {
                MpcContract::respond_verify_foreign_tx(args.request.clone(), args.response.clone())
            }
        }
    }
}

/// Extension trait for constructing SignatureRespond arguments from node-internal types.
pub trait SignatureRespondArgsExt {
    fn from_ecdsa(
        request: &SignatureRequest,
        response: &Signature,
        public_key: &VerifyingKey,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn from_eddsa(
        request: &SignatureRequest,
        response: &frost_ed25519::Signature,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl SignatureRespondArgsExt for contract_args::SignatureRespondArgs {
    fn from_ecdsa(
        request: &SignatureRequest,
        response: &Signature,
        public_key: &VerifyingKey,
    ) -> anyhow::Result<Self> {
        let recovery_id = response
            .recovery_id(
                &public_key.to_element().to_affine(),
                request
                    .payload
                    .as_ecdsa()
                    .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?,
            )
            .context(RECOVERY_ID_FAILED)?;
        Ok(contract_args::SignatureRespondArgs::new(
            request.into_contract_interface_type(),
            k256_signature_response(response.big_r, response.s, recovery_id),
        ))
    }

    fn from_eddsa(
        request: &SignatureRequest,
        response: &frost_ed25519::Signature,
    ) -> anyhow::Result<Self> {
        let response: [u8; 64] = response
            .serialize()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Response is not 64 bytes"))?;

        Ok(contract_args::SignatureRespondArgs::new(
            request.into_contract_interface_type(),
            dtos::SignatureResponse::Ed25519 {
                signature: dtos::Ed25519Signature::from(response),
            },
        ))
    }
}

pub trait VerifyForeignTransactionRespondArgsExt {
    fn from_signature(
        request: VerifyForeignTxRequest,
        payload_hash: dtos::Hash256,
        signature: Signature,
        public_key: VerifyingKey,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl VerifyForeignTransactionRespondArgsExt for contract_args::VerifyForeignTransactionRespondArgs {
    fn from_signature(
        request: VerifyForeignTxRequest,
        payload_hash: dtos::Hash256,
        signature: Signature,
        public_key: VerifyingKey,
    ) -> anyhow::Result<Self> {
        let recovery_id = signature
            .recovery_id(&public_key.to_element().to_affine(), payload_hash.as_ref())
            .context(RECOVERY_ID_FAILED)?;

        let dto_signature = dtos::K256Signature {
            big_r: dtos::K256AffinePoint::from(signature.big_r),
            s: dtos::K256Scalar::from(signature.s),
            recovery_id: recovery_id.to_byte(),
        };
        Ok(contract_args::VerifyForeignTransactionRespondArgs::new(
            dtos::VerifyForeignTransactionRequest {
                request: request.request,
                domain_id: request.domain_id,
                payload_version: request.payload_version,
                expected_payload_hash: request.expected_payload_hash,
            },
            dtos::VerifyForeignTransactionResponse {
                payload_hash,
                signature: dtos::SignatureResponse::Secp256k1(dto_signature),
            },
        ))
    }
}
