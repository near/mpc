use crate::db::{DBCol, SecretDB};
use crate::metrics;
use crate::types::{CKDId, CKDRequest, VerifyForeignTxId, VerifyForeignTxRequest};
use crate::types::{SignatureId, SignatureRequest};
use anyhow::ensure;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use tokio::sync::broadcast;

fn insert_request<T: Serialize + DeserializeOwned>(
    db: &Arc<SecretDB>,
    column: DBCol,
    key: &[u8],
    request: &T,
    check_existing: bool,
) -> anyhow::Result<bool> {
    if let Some(stored) = db.get(column, key)? {
        if check_existing {
            let existing: T = serde_json::from_slice(&stored)?;
            ensure!(
                serde_json::to_value(existing)? == serde_json::to_value(request)?,
                "conflicting request content for existing ID in {column}"
            );
        }
        return Ok(false);
    }
    let mut update = db.update();
    update.put(column, key, &serde_json::to_vec(request)?);
    update.commit()?;
    Ok(true)
}

pub struct SignRequestStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<SignatureId>,
}

impl SignRequestStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(500);
        Ok(Self { db, add_sender: tx })
    }

    /// Inserts a request, rejecting conflicting content for an existing ID.
    /// Returns false for an identical replay without writing or broadcasting.
    pub fn add_checked(&self, request: &SignatureRequest) -> anyhow::Result<bool> {
        let key = borsh::to_vec(&request.id)?;
        let inserted = insert_request(&self.db, DBCol::SignRequest, &key, request, true)?;
        if inserted {
            let _ = self.add_sender.send(request.id);
        }
        Ok(inserted)
    }

    /// Inserts a request only if its ID is absent, preserving first-write behavior.
    pub fn add(&self, request: &SignatureRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        let inserted = insert_request(&self.db, DBCol::SignRequest, &key, request, false)
            .expect("request storage insertion failed");
        if inserted {
            let _ = self.add_sender.send(request.id);
        }
        inserted
    }

    /// Returns when a signature request with given id is present, then returns it.
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

    /// Inserts a request, rejecting conflicting content for an existing ID.
    /// Returns false for an identical replay without writing or broadcasting.
    pub fn add_checked(&self, request: &CKDRequest) -> anyhow::Result<bool> {
        let key = borsh::to_vec(&request.id)?;
        let inserted = insert_request(&self.db, DBCol::CKDRequest, &key, request, true)?;
        if inserted {
            let _ = self.add_sender.send(request.id);
        }
        Ok(inserted)
    }

    /// Inserts a request only if its ID is absent, preserving first-write behavior.
    pub fn add(&self, request: &CKDRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        let inserted = insert_request(&self.db, DBCol::CKDRequest, &key, request, false)
            .expect("request storage insertion failed");
        if inserted {
            let _ = self.add_sender.send(request.id);
        }
        inserted
    }

    /// Returns when a ckd request with given id is present, then returns it.
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

pub struct VerifyForeignTransactionRequestStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<VerifyForeignTxId>,
}

impl VerifyForeignTransactionRequestStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(500);
        Ok(Self { db, add_sender: tx })
    }

    /// Inserts a request, rejecting conflicting content for an existing ID.
    /// Returns false for an identical replay without writing or broadcasting.
    pub fn add_checked(&self, request: &VerifyForeignTxRequest) -> anyhow::Result<bool> {
        let key = borsh::to_vec(&request.id)?;
        let inserted =
            insert_request(&self.db, DBCol::VerifyForeignTxRequest, &key, request, true)?;
        if inserted {
            let _ = self.add_sender.send(request.id);
        }
        Ok(inserted)
    }

    /// Inserts a request only if its ID is absent, preserving first-write behavior.
    pub fn add(&self, request: &VerifyForeignTxRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        let inserted = insert_request(
            &self.db,
            DBCol::VerifyForeignTxRequest,
            &key,
            request,
            false,
        )
        .expect("request storage insertion failed");
        if inserted {
            let _ = self.add_sender.send(request.id);
        }
        inserted
    }

    /// Returns when a verify foreign tx request with given id is present, then returns it.
    /// This behavior is necessary because a peer might initiate computation for a verify foreign tx
    /// request before our indexer has caught up to the request. We need proof of the request
    /// from on-chain in order to participate in the computation.
    pub async fn get(
        &self,
        id: VerifyForeignTxId,
    ) -> Result<VerifyForeignTxRequest, anyhow::Error> {
        let key = borsh::to_vec(&id)?;
        let mut rx = self.add_sender.subscribe();
        if let Some(request_ser) = self.db.get(DBCol::VerifyForeignTxRequest, &key)? {
            return Ok(serde_json::from_slice(&request_ser)?);
        }
        loop {
            let added_id = match rx.recv().await {
                Ok(added_id) => added_id,
                Err(e) => match e {
                    broadcast::error::RecvError::Closed => {
                        metrics::VERIFY_FOREIGN_TX_REQUEST_CHANNEL_FAILED.inc();
                        return Err(anyhow::anyhow!(
                            "Error in verify_foreign_tx_request channel recv, {e}"
                        ));
                    }
                    broadcast::error::RecvError::Lagged(msg_n) => {
                        tracing::info!(
                            "{msg_n} messages lagged during verify_foreign_tx_request channel recv"
                        );
                        continue;
                    }
                },
            };
            if added_id == id {
                break;
            }
        }
        let request_ser = self.db.get(DBCol::VerifyForeignTxRequest, &key)?.unwrap();
        Ok(serde_json::from_slice(&request_ser)?)
    }
}

#[cfg(test)]
mod tests {
    use mpc_primitives::domain::DomainId;
    use near_indexer_primitives::CryptoHash;
    use near_mpc_contract_interface::types as dtos;
    use near_mpc_contract_interface::types::{CKDAppPublicKey, Payload, Tweak};
    use serde_json::to_value;
    use tokio::sync::broadcast::error::TryRecvError;

    use crate::types::{CKDRequest, VerifyForeignTxRequest};
    use crate::{
        db::SecretDB,
        storage::{CKDRequestStorage, SignRequestStorage, VerifyForeignTransactionRequestStorage},
        types::SignatureRequest,
    };

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn sign_request_storage__should_accept_replay_and_reject_changed_inputs() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let storage = SignRequestStorage::new(db).unwrap();
        let request = SignatureRequest {
            id: CryptoHash([1; 32]),
            receipt_id: CryptoHash([2; 32]),
            entropy: [3; 32],
            payload: Payload::from_legacy_ecdsa([4; 32]),
            timestamp_nanosec: 5,
            tweak: Tweak::new([6; 32]),
            domain: DomainId::legacy_ecdsa_id(),
        };
        let mut notifications = storage.add_sender.subscribe();

        // When
        assert!(storage.add_checked(&request).unwrap());
        let replay = storage.add_checked(&request).unwrap();
        let mut different_entropy = request.clone();
        different_entropy.entropy = [7; 32];
        let legacy_replay = storage.add(&different_entropy);
        let entropy_conflict = storage.add_checked(&different_entropy);
        let mut different_payload = request.clone();
        different_payload.payload = Payload::from_legacy_ecdsa([8; 32]);
        let payload_conflict = storage.add_checked(&different_payload);

        // Then
        assert!(!replay);
        assert!(!legacy_replay);
        entropy_conflict.unwrap_err();
        payload_conflict.unwrap_err();
        assert_eq!(
            to_value(storage.get(request.id).await.unwrap()).unwrap(),
            to_value(&request).unwrap()
        );
        assert_eq!(notifications.try_recv().unwrap(), request.id);
        assert_eq!(notifications.try_recv(), Err(TryRecvError::Empty));
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn ckd_request_storage__should_accept_replay_and_reject_changed_inputs() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let storage = CKDRequestStorage::new(db).unwrap();
        let request = CKDRequest {
            id: CryptoHash([1; 32]),
            receipt_id: CryptoHash([2; 32]),
            app_public_key: CKDAppPublicKey::AppPublicKey(
                "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                    .parse()
                    .unwrap(),
            ),
            app_id: [3; 32].into(),
            entropy: [4; 32],
            timestamp_nanosec: 5,
            domain_id: DomainId::legacy_ecdsa_id(),
        };
        let mut notifications = storage.add_sender.subscribe();

        // When
        assert!(storage.add_checked(&request).unwrap());
        let replay = storage.add_checked(&request).unwrap();
        let mut conflicting = request.clone();
        conflicting.entropy = [6; 32];
        let conflict = storage.add_checked(&conflicting);

        // Then
        assert!(!replay);
        conflict.unwrap_err();
        assert_eq!(
            to_value(storage.get(request.id).await.unwrap()).unwrap(),
            to_value(&request).unwrap()
        );
        assert_eq!(notifications.try_recv().unwrap(), request.id);
        assert_eq!(notifications.try_recv(), Err(TryRecvError::Empty));
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn foreign_request_storage__should_accept_replay_and_reject_changed_inputs() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let storage = VerifyForeignTransactionRequestStorage::new(db).unwrap();
        let request = VerifyForeignTxRequest {
            id: CryptoHash([1; 32]),
            receipt_id: CryptoHash([2; 32]),
            request: dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
                tx_id: dtos::BitcoinTxId([3; 32]),
                confirmations: 2.into(),
                extractors: [dtos::BitcoinExtractor::BlockHash].into(),
            }),
            payload_version: dtos::ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
            entropy: [4; 32],
            timestamp_nanosec: 5,
            domain_id: DomainId(0),
        };
        let mut notifications = storage.add_sender.subscribe();

        // When
        assert!(storage.add_checked(&request).unwrap());
        let replay = storage.add_checked(&request).unwrap();
        let mut conflicting = request.clone();
        conflicting.entropy = [6; 32];
        let conflict = storage.add_checked(&conflicting);

        // Then
        assert!(!replay);
        conflict.unwrap_err();
        assert_eq!(
            to_value(storage.get(request.id).await.unwrap()).unwrap(),
            to_value(&request).unwrap()
        );
        assert_eq!(notifications.try_recv().unwrap(), request.id);
        assert_eq!(notifications.try_recv(), Err(TryRecvError::Empty));
    }

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
        let _ = storage
            .get(req1.id)
            .await
            .expect("Stored signature request should be retrievable");
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
        let _ = storage
            .get(req1.id)
            .await
            .expect("Stored signature request should be retrievable");
        let _ = storage
            .get(req2.id)
            .await
            .expect("Stored signature request should be retrievable");
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
            app_public_key: near_mpc_contract_interface::types::CKDAppPublicKey::AppPublicKey(
                "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                    .parse()
                    .unwrap(),
            ),
            app_id: [1u8; 32].into(),
            entropy: [0; 32],
            timestamp_nanosec: 0,
            domain_id: DomainId::legacy_ecdsa_id(),
        };
        assert!(storage.add(&req1));
        assert!(!storage.add(&req1));
        let _ = storage
            .get(req1.id)
            .await
            .expect("Stored CKD request should be retrievable");
        let req2 = CKDRequest {
            id: CryptoHash(rand::random()),
            // All other fields are irrelevant for the test.
            receipt_id: CryptoHash([0; 32]),
            app_public_key: near_mpc_contract_interface::types::CKDAppPublicKey::AppPublicKey(
                "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                    .parse()
                    .unwrap(),
            ),
            app_id: [1u8; 32].into(),
            entropy: [0; 32],
            timestamp_nanosec: 0,
            domain_id: DomainId::legacy_ecdsa_id(),
        };
        storage.add(&req2);
        let _ = storage
            .get(req1.id)
            .await
            .expect("Stored CKD request should be retrievable");
        let _ = storage
            .get(req2.id)
            .await
            .expect("Stored CKD request should be retrievable");
    }
}
