use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::providers::{PublicKeyConversion};
use crate::ckd_request::{CKDRequestStorage, CKDId};
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::primitives::domain::DomainId;
use std::collections::HashMap;
use std::sync::Arc;
use threshold_signatures::eddsa::KeygenOutput;

#[derive(Clone)]
pub struct CKDProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    ckd_request_store: Arc<CKDRequestStorage>,
    keyshares: HashMap<DomainId, KeygenOutput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum CKDTaskId {
    CKD { id: CKDId },
}

impl From<CKDTaskId> for MpcTaskId {
    fn from(value: CKDTaskId) -> Self {
        MpcTaskId::CKDTaskId(value)
    }
}

impl CKDProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        ckd_request_store: Arc<CKDRequestStorage>,
        keyshares: HashMap<DomainId, KeygenOutput>,
    ) -> Self {
        Self {
            config,
            mpc_config,
            client,
            ckd_request_store,
            keyshares,
        }
    }
}