pub mod types {
    use mpc_primitives::hash::MpcDockerImageHash;
    use serde::{Deserialize, Serialize};

    /// JSON structure for the approved hashes file written by the MPC node.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ApprovedHashesFile {
        pub approved_hashes: Vec<MpcDockerImageHash>,
    }
}

mod paths {}
