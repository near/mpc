use near_sdk::{near, BorshStorageKey};

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
    PendingCKDRequests,
    BackupServicesInfo,
    NodeMigrations,
    ForeignChainPolicyVotes,
    PendingVerifyForeignTxRequests,
    PendingSignatureRequestsV3,
}
