use near_sdk::{BorshStorageKey, near};

// !!! IMPORTANT !!!
// for backwards compatibility, ensure the order is preserved and only append to this list
// Renaming is OK.
#[near(serializers=[borsh] )]
#[derive(Hash, Clone, Debug, PartialEq, Eq, BorshStorageKey)]
pub enum StorageKey {
    _DeprecatedPendingRequests,
    /// Proposed updates to the contract code and config.
    _DeprecatedProposedUpdatesEntries,
    _DeprecatedRequestsByTimestamp,
    PendingSignatureRequestsV2,
    ProposedUpdatesEntriesV2,
    ProposedUpdatesVotesV2,
    _DeprecatedTeeParticipantAttestation,
    _DeprecatedPendingCKDRequests,
    BackupServicesInfo,
    NodeMigrations,
    _ForeignChainPolicyVotes,
    _DeprecatedPendingVerifyForeignTxRequests,
    _DeprecatedPendingCKDRequestsV2,
    _SupportedForeignChainsVotes,
    _DeprecatedPendingSignatureRequestsV3,
    StoredAttestations,
    SupportedForeignChainsByNode,
    PendingSignatureRequestsV4,
    PendingCKDRequestsV3,
    PendingVerifyForeignTxRequestsV2,
    AllowedForeignChainProvidersV1,
    ForeignChainProviderVotesByVoterV1,
    ForeignChainProviderVotesByProposalV1,
    ForeignChainsConfigs,
    ForeignChainAvailability,
}
