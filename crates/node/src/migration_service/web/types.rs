use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use tokio::sync::{RwLock, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    config::AesKey256,
    keyshare::{Keyshare, KeyshareStorage},
    migration_service::types::MigrationInfo,
};

pub(crate) struct WebServerState {
    pub import_keyshares_sender: watch::Sender<Vec<Keyshare>>,
    pub keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    pub backup_encryption_key: AesKey256,
    /// `true` once the contract has confirmed this node as the configured account's node. Until
    /// then no keyshares are exported, so an account id changed in the host-supplied config cannot
    /// redirect them to another participant's backup service.
    pub onboarded: watch::Receiver<bool>,
}

#[derive(Clone)]
pub(crate) struct ExpectedPeerInfo {
    pub expected_pk: Option<VerifyingKey>,
    pub cancelled: CancellationToken,
}

impl ExpectedPeerInfo {
    pub fn from_migration(migration_info: MigrationInfo, cancelled: CancellationToken) -> Self {
        let expected_pk = migration_info.get_pk_backup_service();
        Self {
            expected_pk,
            cancelled,
        }
    }
}
