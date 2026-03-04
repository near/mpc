pub const MPC_IMAGE_HASH_EVENT: &str = "mpc-image-digest";

pub mod types {
    use mpc_primitives::hash::MpcDockerImageHash;
    use serde::{Deserialize, Serialize};

    /// JSON structure for the approved hashes file written by the MPC node.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ApprovedHashesFile {
        pub approved_hashes: bounded_collections::NonEmptyVec<MpcDockerImageHash>,
    }

    impl ApprovedHashesFile {
        pub fn newest_approved_hash(&self) -> &MpcDockerImageHash {
            self.approved_hashes.first()
        }
    }
}

// TODO: add insta snapshot test for this type

mod paths {}
