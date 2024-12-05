use near_crypto::{InMemorySigner, Signer};
use near_indexer_primitives::near_primitives::transaction::{
    FunctionCallAction, SignedTransaction, Transaction, TransactionV0,
};
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::CryptoHash;
use std::io;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

pub(crate) struct TransactionSigner {
    signer: Signer,
    nonce: AtomicU64,
}

impl TransactionSigner {
    pub(crate) fn from_file(path: &Path) -> io::Result<Self> {
        Ok(TransactionSigner {
            signer: Signer::InMemory(InMemorySigner::from_file(path)?),
            nonce: AtomicU64::new(1),
        })
    }

    /// Atomically increments the nonce and returns the previous value
    fn increment_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, Ordering::SeqCst)
    }

    pub(crate) fn create_and_sign_function_call_tx(
        &self,
        receiver_id: AccountId,
        method_name: String,
        args: Vec<u8>,
        block_hash: CryptoHash,
    ) -> SignedTransaction {
        let action = FunctionCallAction {
            method_name,
            args,
            gas: 300000000000000,
            deposit: 0,
        };
        let signer_id = match &self.signer {
            Signer::InMemory(InMemorySigner { account_id, .. }) => account_id.clone(),
            _ => unreachable!(),
        };
        let transaction = Transaction::V0(TransactionV0 {
            signer_id,
            public_key: self.signer.public_key().clone(),
            nonce: self.increment_nonce(),
            receiver_id,
            block_hash,
            actions: vec![action.into()],
        });

        let tx_hash = transaction.get_hash_and_size().0;
        let signature = self.signer.sign(tx_hash.as_ref());

        SignedTransaction::new(signature, transaction.clone())
    }
}
