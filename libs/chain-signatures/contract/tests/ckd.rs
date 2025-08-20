pub mod common;
use common::{
    candidates, create_response_ckd, init, init_env_ed25519, derive_confidential_key,
};
use mpc_contract::{
    config::InitConfig,
    crypto_shared::CKDResponse,
    errors,
    primitives::{
        participants::Participants,
        ckd::CKDRequestArgs,
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_workspaces::types::NearToken;