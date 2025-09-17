mod provider;

use std::{collections::HashMap, sync::Arc};

use borsh::{BorshDeserialize, BorshSerialize};
use k256::AffinePoint;
use mpc_contract::primitives::domain::DomainId;
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
pub struct CKDProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    ckd_request_store: Arc<CKDRequestStorage>,
    keyshares: HashMap<DomainId, KeygenOutput>,
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

    pub async fn make_ckd(
        self: Arc<Self>,
        id: CKDId,
    ) -> anyhow::Result<(AffinePoint, AffinePoint)> {
        self.make_ckd_leader(id).await
    }

    pub async fn process_channel(
        self: Arc<Self>,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::CKDTaskId(task) => match task {
                CKDTaskId::Ckd { id } => {
                    self.make_ckd_follower(channel, id).await?;
                }
            },
            _ => anyhow::bail!(
                "ckd task handler: received unexpected task id: {:?}",
                channel.task_id()
            ),
        }

        Ok(())
    }

    pub async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()> {
        Ok(())
    }
}
