use crate::config::RespondConfig;
use crate::indexer::types::ChainSendTransactionRequest;
use chain_gateway::transaction_sender::TransactionSigner;
use ed25519_dalek::SigningKey;
use near_account_id::AccountId;
use std::sync::Arc;

pub(crate) struct TransactionSigners {
    /// Signers that we cycle through for responding to signature requests.
    /// These can correspond to arbitrary near accounts.
    respond_signers: Vec<Arc<TransactionSigner>>,
    /// Signer we use for signing vote_pk, vote_reshared, etc., which must
    /// correspond to the account that this node runs under.
    owner_signer: Arc<TransactionSigner>,
    /// next respond signer to use.
    next_id: usize,
}

impl TransactionSigners {
    pub fn new(
        respond_config: RespondConfig,
        owner_account_id: AccountId,
        owner_signing_key: SigningKey,
    ) -> anyhow::Result<Self> {
        let respond_signers = respond_config
            .access_keys
            .iter()
            .map(|key| {
                Arc::new(TransactionSigner::from_key(
                    respond_config.account_id.clone(),
                    key.clone(),
                ))
            })
            .collect::<Vec<_>>();
        let owner_signer = Arc::new(TransactionSigner::from_key(
            owner_account_id,
            owner_signing_key,
        ));
        anyhow::ensure!(
            !respond_signers.is_empty(),
            "At least one responding access key must be provided",
        );
        Ok(TransactionSigners {
            respond_signers,
            owner_signer,
            next_id: 0,
        })
    }

    fn next_respond_signer(&mut self) -> Arc<TransactionSigner> {
        let signer = self.respond_signers[self.next_id].clone();
        self.next_id = (self.next_id + 1) % self.respond_signers.len();
        signer
    }

    fn owner_signer(&self) -> Arc<TransactionSigner> {
        self.owner_signer.clone()
    }

    pub fn signer_for(&mut self, req: &ChainSendTransactionRequest) -> Arc<TransactionSigner> {
        match req {
            ChainSendTransactionRequest::Respond(_) => self.next_respond_signer(),
            ChainSendTransactionRequest::CKDRespond(_) => self.next_respond_signer(),
            _ => self.owner_signer(),
        }
    }
}
