use std::{collections::HashMap, sync::Arc};

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::primitives::domain::DomainId;
use threshold_signatures::ecdsa::KeygenOutput;

use crate::{ckd_request::{CKDId, CKDRequestStorage}, config::{ConfigFile, MpcConfig}, network::MeshNetworkClient, primitives::MpcTaskId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum CKDTaskId {
    Ckd { id: CKDId },
}

impl From<CKDTaskId> for MpcTaskId {
    fn from(value: CKDTaskId) -> Self {
        MpcTaskId::CKDTaskId(value)
    }
}


#[derive(Clone)]
pub struct CKDProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    sign_request_store: Arc<CKDRequestStorage>,
    keyshares: HashMap<DomainId, KeygenOutput>,
}


impl CKDProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        sign_request_store: Arc<CKDRequestStorage>,
        keyshares: HashMap<DomainId, KeygenOutput>,
    ) -> Self {
        Self {
            config,
            mpc_config,
            client,
            sign_request_store,
            keyshares,
        }
    }
}