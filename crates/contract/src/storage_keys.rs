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
    _DeprecatedPendingCKDRequests,
    BackupServicesInfo,
    NodeMigrations,
    _ForeignChainPolicyVotes,
    PendingVerifyForeignTxRequests,
    PendingCKDRequestsV2,
    _SupportedForeignChainsVotes,
    PendingSignatureRequestsV3,
    StoredAttestations,
    SupportedForeignChainsByNode,
    /// Pending signature yields keyed by a contract-minted `request_id`
    /// (#3184). The id is allocated from a monotonic counter *before* the
    /// `promise_yield_create` call, baked into the yield's `callback_args`,
    /// and emitted via the `MPC_REQUEST_ID:` log so the node can route
    /// `respond` to the specific yield. Value type is
    /// `(SignatureRequest, YieldIndex)` because the runtime-allocated
    /// `data_id` is only known after `promise_yield_create` and we need to
    /// keep it around for `promise_yield_resume`. Replaces
    /// [`PendingSignatureRequestsV3`] as the source of truth for
    /// post-upgrade requests; the V3 map is kept read-only as the legacy
    /// fallback until pre-upgrade yields drain.
    PendingSignatureRequestsByIdV4,
    PendingCKDRequestsByIdV3,
    PendingVerifyForeignTxRequestsByIdV2,
}
