/// A service whose TEE attestations the contract verifies. Each has its own
/// [`TeeState`](crate::tee::tee_state::TeeState), so an attestation accepted for one never
/// counts for the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestedService {
    MpcNode,
    BackupService,
}
