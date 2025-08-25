use std::{collections::HashMap, sync::Arc};

use borsh::{BorshDeserialize, BorshSerialize};
use k256::AffinePoint;
use mpc_contract::{
    crypto_shared::{k256_types, CKDResponse},
    primitives::domain::DomainId,
};
use threshold_signatures::ecdsa::KeygenOutput;

use crate::{
    config::{ConfigFile, MpcConfig},
    network::{MeshNetworkClient, NetworkTaskChannel},
    primitives::MpcTaskId,
    storage::CKDRequestStorage,
    types::CKDId,
};

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
#[allow(dead_code)]
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

    pub async fn make_ckd(self: Arc<Self>, _id: CKDId) -> anyhow::Result<CKDResponse> {
        Ok(CKDResponse {
            big_c: k256_types::SerializableAffinePoint {
                affine_point: AffinePoint::GENERATOR,
            },
            big_y: k256_types::SerializableAffinePoint {
                affine_point: AffinePoint::GENERATOR,
            },
        })
    }

    pub async fn process_channel(
        self: Arc<Self>,
        _channel: NetworkTaskChannel,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
