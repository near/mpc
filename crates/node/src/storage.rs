use crate::db::{DBCol, SecretDB};
use crate::metrics;
use crate::types::{CKDId, CKDRequest};
use crate::types::{SignatureId, SignatureRequest};
use std::sync::Arc;
use tokio::sync::broadcast;

pub struct SignRequestStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<SignatureId>,
}

impl SignRequestStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(500);
        Ok(Self { db, add_sender: tx })
    }

    /// If given request is already in the database, returns false.
    /// Otherwise, inserts the request and returns true.
    pub fn add(&self, request: &SignatureRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        if self
            .db
            .get(DBCol::SignRequest, &key)
            .expect("Unrecoverable error reading from database")
            .is_some()
        {
            return false;
        }
        let value_ser = serde_json::to_vec(&request).unwrap();
        let mut update = self.db.update();
        update.put(DBCol::SignRequest, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        let _ = self.add_sender.send(request.id);
        true
    }

    /// Blocks until a signature request with given id is present, then returns it.
    /// This behavior is necessary because a peer might initiate computation for a signature
    /// request before our indexer has caught up to the request. We need proof of the request
    /// from on-chain in order to participate in the computation.
    pub async fn get(&self, id: SignatureId) -> Result<SignatureRequest, anyhow::Error> {
        let key = borsh::to_vec(&id)?;
        let mut rx = self.add_sender.subscribe();
        if let Some(request_ser) = self.db.get(DBCol::SignRequest, &key)? {
            return Ok(serde_json::from_slice(&request_ser)?);
        }
        loop {
            let added_id = match rx.recv().await {
                Ok(added_id) => added_id,
                Err(e) => match e {
                    broadcast::error::RecvError::Closed => {
                        metrics::SIGN_REQUEST_CHANNEL_FAILED.inc();
                        return Err(anyhow::anyhow!("Error in sign_request channel recv, {e}"));
                    }
                    broadcast::error::RecvError::Lagged(msg_n) => {
                        tracing::info!("{msg_n} messages lagged during sign_request channel recv");
                        continue;
                    }
                },
            };
            if added_id == id {
                break;
            }
        }
        let request_ser = self.db.get(DBCol::SignRequest, &key)?.unwrap();
        Ok(serde_json::from_slice(&request_ser)?)
    }
}

pub struct CKDRequestStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<CKDId>,
}

impl CKDRequestStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(500);
        Ok(Self { db, add_sender: tx })
    }

    /// If given request is already in the database, returns false.
    /// Otherwise, inserts the request and returns true.
    pub fn add(&self, request: &CKDRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        if self
            .db
            .get(DBCol::CKDRequest, &key)
            .expect("Unrecoverable error reading from database")
            .is_some()
        {
            return false;
        }
        let value_ser = serde_json::to_vec(&request).unwrap();
        let mut update = self.db.update();
        update.put(DBCol::CKDRequest, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        let _ = self.add_sender.send(request.id);
        true
    }

    /// Blocks until a ckd request with given id is present, then returns it.
    /// This behavior is necessary because a peer might initiate computation for a ckd
    /// request before our indexer has caught up to the request. We need proof of the request
    /// from on-chain in order to participate in the computation.
    pub async fn get(&self, id: CKDId) -> Result<CKDRequest, anyhow::Error> {
        let key = borsh::to_vec(&id)?;
        let mut rx = self.add_sender.subscribe();
        if let Some(request_ser) = self.db.get(DBCol::CKDRequest, &key)? {
            return Ok(serde_json::from_slice(&request_ser)?);
        }
        loop {
            let added_id = match rx.recv().await {
                Ok(added_id) => added_id,
                Err(e) => match e {
                    broadcast::error::RecvError::Closed => {
                        metrics::CKD_REQUEST_CHANNEL_FAILED.inc();
                        return Err(anyhow::anyhow!("Error in ckd_request channel recv, {e}"));
                    }
                    broadcast::error::RecvError::Lagged(msg_n) => {
                        tracing::info!("{msg_n} messages lagged during ckd_request channel recv");
                        continue;
                    }
                },
            };
            if added_id == id {
                break;
            }
        }
        let request_ser = self.db.get(DBCol::CKDRequest, &key)?.unwrap();
        Ok(serde_json::from_slice(&request_ser)?)
    }
}

#[cfg(test)]
mod tests {
    use mpc_contract::primitives::{
        domain::DomainId,
        signature::{Payload, Tweak},
    };
    use near_indexer_primitives::CryptoHash;
    use near_sdk::AccountId;

    use crate::types::CKDRequest;
    use crate::{
        db::SecretDB,
        storage::{CKDRequestStorage, SignRequestStorage},
        types::SignatureRequest,
    };
    use std::str::FromStr;

    #[tokio::test]
    async fn test_sig_request_storage() {
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let storage = SignRequestStorage::new(db).unwrap();

        let req1 = SignatureRequest {
            id: CryptoHash(rand::random()),
            // All other fields are irrelevant for the test.
            receipt_id: CryptoHash([0; 32]),
            entropy: [0; 32],
            payload: Payload::from_legacy_ecdsa([0; 32]),
            timestamp_nanosec: 0,
            tweak: Tweak::new([0; 32]),
            domain: DomainId::legacy_ecdsa_id(),
        };
        assert!(storage.add(&req1));
        assert!(!storage.add(&req1));
        assert!(storage.get(req1.id).await.is_ok());
        let req2 = SignatureRequest {
            id: CryptoHash(rand::random()),
            // All other fields are irrelevant for the test.
            receipt_id: CryptoHash([0; 32]),
            entropy: [0; 32],
            payload: Payload::from_legacy_ecdsa([0; 32]),
            timestamp_nanosec: 0,
            tweak: Tweak::new([0; 32]),
            domain: DomainId::legacy_ecdsa_id(),
        };
        storage.add(&req2);
        assert!(storage.get(req1.id).await.is_ok());
        assert!(storage.get(req2.id).await.is_ok());
    }

    #[tokio::test]
    async fn test_ckd_request_storage() {
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let storage = CKDRequestStorage::new(db).unwrap();

        let req1 = CKDRequest {
            id: CryptoHash(rand::random()),
            // All other fields are irrelevant for the test.
            receipt_id: CryptoHash([0; 32]),
            app_public_key:
                "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                    .parse()
                    .unwrap(),
            app_id: AccountId::from_str("test-app").unwrap(),
            entropy: [0; 32],
            timestamp_nanosec: 0,
            domain_id: DomainId::legacy_ecdsa_id(),
        };
        assert!(storage.add(&req1));
        assert!(!storage.add(&req1));
        assert!(storage.get(req1.id).await.is_ok());
        let req2 = CKDRequest {
            id: CryptoHash(rand::random()),
            // All other fields are irrelevant for the test.
            receipt_id: CryptoHash([0; 32]),
            app_public_key:
                "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                    .parse()
                    .unwrap(),
            app_id: AccountId::from_str("test-app").unwrap(),
            entropy: [0; 32],
            timestamp_nanosec: 0,
            domain_id: DomainId::legacy_ecdsa_id(),
        };
        storage.add(&req2);
        assert!(storage.get(req1.id).await.is_ok());
        assert!(storage.get(req2.id).await.is_ok());
    }
}
