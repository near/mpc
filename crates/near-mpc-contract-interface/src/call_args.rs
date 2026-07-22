//! Argument types for the NEAR MPC signer contract function calls.

use crate::types::{
    Attestation, BackupServiceInfo, CKDRequest, CKDRequestArgs, CKDResponse, DestinationNodeInfo,
    DomainConfig, Ed25519PublicKey, EpochId, KeyEventId, Keyset, ProposedThresholdParameters,
    PublicKey, SignRequestArgs, SignatureRequest, SignatureResponse, SupportedForeignChains,
    VerifyForeignTransactionRequest, VerifyForeignTransactionRequestArgs,
    VerifyForeignTransactionResponse,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct SignArgs {
    pub request: SignRequestArgs,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct RequestAppPrivateKeyArgs {
    pub request: CKDRequestArgs,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct VerifyForeignTransactionArgs {
    pub request: VerifyForeignTransactionRequestArgs,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct VoteAddDomainsArgs {
    pub domains: Vec<DomainConfig>,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct VoteNewParametersArgs {
    pub prospective_epoch_id: EpochId,
    pub proposal: ProposedThresholdParameters,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct VoteCancelKeygenArgs {
    pub next_domain_id: u64,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct UpdateParticipantUrlArgs {
    pub url: String,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct RegisterBackupServiceArgs {
    pub backup_service_info: BackupServiceInfo,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct StartNodeMigrationArgs {
    pub destination_node_info: DestinationNodeInfo,
}

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct RegisterForeignChainSupportArgs {
    pub foreign_chain_support: SupportedForeignChains,
}

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

#[derive(Serialize, Debug, derive_more::Constructor)]
pub struct VoteUpdateArgs {
    pub id: u64,
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
pub struct RegisterForeignChainsConfigArgs {
    pub foreign_chains_config: crate::types::ForeignChainsConfig,
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
