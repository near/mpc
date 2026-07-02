//! Argument types for the NEAR MPC signer contract function calls.

use crate::types::{
    Attestation, CKDRequest, CKDResponse, Ed25519PublicKey, KeyEventId, Keyset, PublicKey,
    SignatureRequest, SignatureResponse, VerifyForeignTransactionRequest,
    VerifyForeignTransactionResponse,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Deserialize, Clone, derive_more::Constructor)]
pub struct SignatureRespondArgs {
    pub request: SignatureRequest,
    pub response: SignatureResponse,
}

#[derive(Serialize, Debug, Deserialize, Clone, derive_more::Constructor)]
pub struct CKDRespondArgs {
    pub request: CKDRequest,
    pub response: CKDResponse,
}

#[derive(Serialize, Debug, Deserialize, Clone, derive_more::Constructor)]
pub struct VerifyForeignTransactionRespondArgs {
    pub request: VerifyForeignTransactionRequest,
    pub response: VerifyForeignTransactionResponse,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct GetPendingSignatureRequestArgs {
    pub request: SignatureRequest,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct GetPendingCKDRequestArgs {
    pub request: CKDRequest,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct GetPendingVerifyForeignTxRequestArgs {
    pub request: VerifyForeignTransactionRequest,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct GetAttestationArgs<'a> {
    pub tls_public_key: &'a Ed25519PublicKey,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct VotePkArgs {
    pub key_event_id: KeyEventId,
    pub public_key: PublicKey,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct VoteResharedArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Serialize, Debug)]
pub struct RegisterForeignChainConfigArgs {
    #[expect(deprecated)]
    pub foreign_chain_configuration: crate::types::ForeignChainConfiguration,
}

impl RegisterForeignChainConfigArgs {
    #[expect(deprecated)]
    pub fn new(foreign_chain_configuration: crate::types::ForeignChainConfiguration) -> Self {
        Self {
            foreign_chain_configuration,
        }
    }
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct StartReshareArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct StartKeygenArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, derive_more::Constructor)]
pub struct SubmitParticipantInfoArgs {
    pub proposed_participant_attestation: Attestation,
    pub tls_public_key: Ed25519PublicKey,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct VoteAbortKeyEventInstanceArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct ConcludeNodeMigrationArgs {
    pub keyset: Keyset,
}
