//! Argument types for the NEAR MPC signer contract function calls.

use crate::types::{
    Attestation, CKDRequest, CKDResponse, ChainEntry, Ed25519PublicKey, ForeignChain, KeyEventId,
    Keyset, PublicKey, SignatureRequest, SignatureResponse, VerifyForeignTransactionRequest,
    VerifyForeignTransactionResponse,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
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

#[derive(Serialize, Debug, Clone, derive_more::Constructor)]
pub struct VotePkArgs {
    pub key_event_id: KeyEventId,
    pub public_key: PublicKey,
}

#[derive(Serialize, Debug, Clone, derive_more::Constructor)]
pub struct VoteResharedArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Serialize, Debug, Clone, derive_more::Constructor)]
pub struct RegisterForeignChainsConfigArgs {
    pub foreign_chains_config: crate::types::ForeignChainsConfig,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct VoteUpdateForeignChainProvidersArgs {
    pub votes: NonEmptyBTreeMap<ForeignChain, ChainEntry>,
}

#[derive(Serialize, Debug, Clone, derive_more::Constructor)]
pub struct StartReshareArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Serialize, Debug, Clone, derive_more::Constructor)]
pub struct StartKeygenArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, derive_more::Constructor)]
pub struct SubmitParticipantInfoArgs {
    pub proposed_participant_attestation: Attestation,
    pub tls_public_key: Ed25519PublicKey,
}

#[derive(Serialize, Debug, Clone, derive_more::Constructor)]
pub struct VoteAbortKeyEventInstanceArgs {
    pub key_event_id: KeyEventId,
}

#[derive(Serialize, Debug, Clone, derive_more::Constructor)]
pub struct ConcludeNodeMigrationArgs {
    pub keyset: Keyset,
}
