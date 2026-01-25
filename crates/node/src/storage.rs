use crate::db::{DBCol, SecretDB};
use crate::metrics;
use crate::types::{CKDId, CKDRequest};
use crate::types::{SignatureId, SignatureRequest};
use crate::types::{VerifyForeignTxId, VerifyForeignTxRequest};
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

    /// Returns a reference to the broadcast sender for notifying about new requests.
    /// Used by VerifyForeignTxStorage for atomic writes.
    pub fn sender(&self) -> &broadcast::Sender<SignatureId> {
        &self.add_sender
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

pub struct VerifyForeignTxStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<VerifyForeignTxId>,
}

impl VerifyForeignTxStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(500);
        Ok(Self { db, add_sender: tx })
    }

    /// If given request is already in the database, returns false.
    /// Otherwise, inserts the request and returns true.
    pub fn add(&self, request: &VerifyForeignTxRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        if self
            .db
            .get(DBCol::VerifyForeignTxRequest, &key)
            .expect("Unrecoverable error reading from database")
            .is_some()
        {
            return false;
        }
        let value_ser = serde_json::to_vec(&request).unwrap();
        let mut update = self.db.update();
        update.put(DBCol::VerifyForeignTxRequest, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        let _ = self.add_sender.send(request.id);
        true
    }

    /// Atomically adds both the VerifyForeignTxRequest and the corresponding SignatureRequest.
    /// This ensures crash recovery consistency - either both are written or neither.
    /// Returns false if the request already exists.
    pub fn add_with_signature_request(
        &self,
        verify_request: &VerifyForeignTxRequest,
        signature_request: &SignatureRequest,
        sign_request_sender: &broadcast::Sender<SignatureId>,
    ) -> bool {
        let key = borsh::to_vec(&verify_request.id).unwrap();
        if self
            .db
            .get(DBCol::VerifyForeignTxRequest, &key)
            .expect("Unrecoverable error reading from database")
            .is_some()
        {
            return false;
        }

        // Serialize both requests
        let verify_value_ser = serde_json::to_vec(&verify_request).unwrap();
        let sign_value_ser = serde_json::to_vec(&signature_request).unwrap();

        // Write both atomically in a single batch
        let mut update = self.db.update();
        update.put(DBCol::VerifyForeignTxRequest, &key, &verify_value_ser);
        update.put(DBCol::SignRequest, &key, &sign_value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");

        // Notify both channels (in-memory, so order doesn't matter for crash safety)
        let _ = self.add_sender.send(verify_request.id);
        let _ = sign_request_sender.send(signature_request.id);
        true
    }

    /// Blocks until a verify foreign tx request with given id is present, then returns it.
    /// This behavior is necessary because a peer might initiate computation for a verification
    /// request before our indexer has caught up to the request. We need proof of the request
    /// from on-chain in order to participate in the computation.
    pub async fn get(&self, id: VerifyForeignTxId) -> Result<VerifyForeignTxRequest, anyhow::Error> {
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
        let request_ser = self
            .db
            .get(DBCol::VerifyForeignTxRequest, &key)?
            .unwrap();
        Ok(serde_json::from_slice(&request_ser)?)
    }
}

#[cfg(test)]
mod tests {
    use mpc_contract::primitives::{
        domain::DomainId,
        foreign_chain::{FinalityLevel, ForeignChain, SolanaSignature, TransactionId},
        signature::{Payload, Tweak},
    };
    use near_indexer_primitives::CryptoHash;

    use crate::types::{CKDRequest, VerifyForeignTxRequest};
    use crate::{
        db::SecretDB,
        storage::{CKDRequestStorage, SignRequestStorage, VerifyForeignTxStorage},
        types::SignatureRequest,
    };

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
            app_id: [1u8; 32].into(),
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
            app_id: [1u8; 32].into(),
            entropy: [0; 32],
            timestamp_nanosec: 0,
            domain_id: DomainId::legacy_ecdsa_id(),
        };
        storage.add(&req2);
        assert!(storage.get(req1.id).await.is_ok());
        assert!(storage.get(req2.id).await.is_ok());
    }

    /// Helper to create a test VerifyForeignTxRequest
    fn create_test_verify_request(tx_bytes: [u8; 64]) -> VerifyForeignTxRequest {
        VerifyForeignTxRequest {
            id: CryptoHash(rand::random()),
            receipt_id: CryptoHash([0; 32]),
            chain: ForeignChain::Solana,
            tx_id: TransactionId::SolanaSignature(SolanaSignature::new(tx_bytes)),
            finality: FinalityLevel::Final,
            tweak: Tweak::new([0u8; 32]),
            entropy: [0u8; 32],
            timestamp_nanosec: 0,
            domain: DomainId::legacy_ecdsa_id(),
        }
    }

    #[tokio::test]
    async fn test_verify_foreign_tx_storage_basic() {
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let storage = VerifyForeignTxStorage::new(db).unwrap();

        let req1 = create_test_verify_request([1u8; 64]);

        // First add should succeed
        assert!(storage.add(&req1));
        // Duplicate add should return false
        assert!(!storage.add(&req1));
        // Should be retrievable
        assert!(storage.get(req1.id).await.is_ok());

        // Add another request
        let req2 = create_test_verify_request([2u8; 64]);
        assert!(storage.add(&req2));
        assert!(storage.get(req2.id).await.is_ok());
    }

    #[tokio::test]
    async fn test_verify_foreign_tx_with_signature_request_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let verify_storage = VerifyForeignTxStorage::new(db.clone()).unwrap();
        let sign_storage = SignRequestStorage::new(db).unwrap();

        let verify_req = create_test_verify_request([42u8; 64]);

        // Create the corresponding signature request with derived payload
        let signature_req = SignatureRequest {
            id: verify_req.id,
            receipt_id: verify_req.receipt_id,
            payload: verify_req.payload(),
            tweak: verify_req.tweak.clone(),
            entropy: verify_req.entropy,
            timestamp_nanosec: verify_req.timestamp_nanosec,
            domain: verify_req.domain,
        };

        // Add both atomically
        let added = verify_storage.add_with_signature_request(
            &verify_req,
            &signature_req,
            sign_storage.sender(),
        );
        assert!(added, "First add should succeed");

        // Both should be retrievable
        let retrieved_verify = verify_storage.get(verify_req.id).await.unwrap();
        let retrieved_sign = sign_storage.get(verify_req.id).await.unwrap();

        // Verify consistency
        assert_eq!(retrieved_verify.id, retrieved_sign.id);
        assert_eq!(retrieved_verify.receipt_id, retrieved_sign.receipt_id);
        assert_eq!(retrieved_verify.tweak, retrieved_sign.tweak);
        assert_eq!(retrieved_verify.entropy, retrieved_sign.entropy);
        assert_eq!(retrieved_verify.domain, retrieved_sign.domain);

        // Verify payload derivation is consistent
        assert_eq!(retrieved_verify.payload(), retrieved_sign.payload);
    }

    #[tokio::test]
    async fn test_verify_foreign_tx_with_signature_request_duplicate_handling() {
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let verify_storage = VerifyForeignTxStorage::new(db.clone()).unwrap();
        let sign_storage = SignRequestStorage::new(db).unwrap();

        let verify_req = create_test_verify_request([99u8; 64]);
        let signature_req = SignatureRequest {
            id: verify_req.id,
            receipt_id: verify_req.receipt_id,
            payload: verify_req.payload(),
            tweak: verify_req.tweak.clone(),
            entropy: verify_req.entropy,
            timestamp_nanosec: verify_req.timestamp_nanosec,
            domain: verify_req.domain,
        };

        // First add should succeed
        assert!(verify_storage.add_with_signature_request(
            &verify_req,
            &signature_req,
            sign_storage.sender(),
        ));

        // Duplicate add should return false
        assert!(!verify_storage.add_with_signature_request(
            &verify_req,
            &signature_req,
            sign_storage.sender(),
        ));

        // Both should still be retrievable (not corrupted by duplicate attempt)
        assert!(verify_storage.get(verify_req.id).await.is_ok());
        assert!(sign_storage.get(verify_req.id).await.is_ok());
    }

    #[tokio::test]
    async fn test_verify_foreign_tx_payload_derivation_uses_sha256() {
        use sha2::{Digest, Sha256};

        let tx_bytes = [123u8; 64];
        let verify_req = create_test_verify_request(tx_bytes);

        // Calculate expected payload using SHA-256 directly
        let expected_hash = Sha256::digest(&tx_bytes);
        let expected_hash_array: [u8; 32] = expected_hash.into();

        // Get the payload from the request
        let payload = verify_req.payload();

        // Verify it matches SHA-256
        match payload {
            Payload::Ecdsa(payload_bytes) => {
                assert_eq!(
                    payload_bytes.as_fixed_bytes(),
                    &expected_hash_array,
                    "Payload must be SHA-256 hash of tx_id bytes"
                );
            }
            _ => panic!("Expected ECDSA payload"),
        }
    }

    #[tokio::test]
    async fn test_storage_consistency_across_restart_simulation() {
        // This test simulates a "restart" by creating new storage instances
        // pointing to the same database, verifying data persists correctly.

        let dir = tempfile::tempdir().unwrap();

        let verify_req = create_test_verify_request([77u8; 64]);
        let signature_req = SignatureRequest {
            id: verify_req.id,
            receipt_id: verify_req.receipt_id,
            payload: verify_req.payload(),
            tweak: verify_req.tweak.clone(),
            entropy: verify_req.entropy,
            timestamp_nanosec: verify_req.timestamp_nanosec,
            domain: verify_req.domain,
        };

        // "First run" - write data
        {
            let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
            let verify_storage = VerifyForeignTxStorage::new(db.clone()).unwrap();
            let sign_storage = SignRequestStorage::new(db).unwrap();

            verify_storage.add_with_signature_request(
                &verify_req,
                &signature_req,
                sign_storage.sender(),
            );
        }

        // "Second run" (after restart) - verify data persists
        {
            let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
            let verify_storage = VerifyForeignTxStorage::new(db.clone()).unwrap();
            let sign_storage = SignRequestStorage::new(db).unwrap();

            // Both should be retrievable after "restart"
            let retrieved_verify = verify_storage.get(verify_req.id).await.unwrap();
            let retrieved_sign = sign_storage.get(verify_req.id).await.unwrap();

            // Verify data integrity
            assert_eq!(retrieved_verify.id, verify_req.id);
            assert_eq!(retrieved_sign.id, verify_req.id);
            assert_eq!(retrieved_verify.payload(), retrieved_sign.payload);

            // Verify tx_id was preserved correctly
            match &retrieved_verify.tx_id {
                TransactionId::SolanaSignature(sig) => {
                    assert_eq!(sig.as_bytes(), &[77u8; 64]);
                }
            }
        }
    }
}
