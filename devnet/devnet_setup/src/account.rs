use crate::rpc::NearRpcClients;
use crate::types::{NearAccount, NearAccountKind};
use futures::FutureExt;
use near_crypto::{InMemorySigner, PublicKey, SecretKey, Signer};
use near_jsonrpc_client::methods;
use near_jsonrpc_client::methods::send_tx::SignedTransaction;
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::account::AccessKey;
use near_primitives::action::{Action, AddKeyAction};
use near_primitives::hash::CryptoHash;
use near_primitives::types::BlockReference;
use near_primitives::types::Finality;
use near_primitives::views::{QueryRequest, TxExecutionStatus};
use near_sdk::AccountId;
use reqwest::StatusCode;
use std::collections::HashMap;
use std::sync::Arc;

pub struct OperatingAccount {
    account_data: NearAccount,
    recent_block_hash: CryptoHash,
    client: Arc<NearRpcClients>,
    keys: Vec<Arc<tokio::sync::Mutex<OperatingAccessKey>>>,
}

impl OperatingAccount {
    pub fn new(
        account_data: NearAccount,
        recent_block_hash: CryptoHash,
        client: Arc<NearRpcClients>,
    ) -> Self {
        Self {
            keys: account_data
                .access_keys
                .iter()
                .map(|key| {
                    Arc::new(tokio::sync::Mutex::new(OperatingAccessKey::new(
                        account_data.account_id.clone(),
                        key.clone(),
                        recent_block_hash,
                        client.clone(),
                    )))
                })
                .collect(),
            recent_block_hash,
            client,
            account_data,
        }
    }

    pub fn new_access_key_added(&mut self, key: SecretKey) {
        self.account_data.access_keys.push(key.clone());
        self.keys
            .push(Arc::new(tokio::sync::Mutex::new(OperatingAccessKey::new(
                self.account_data.account_id.clone(),
                key,
                self.recent_block_hash,
                self.client.clone(),
            ))));
    }
}

struct OperatingAccessKey {
    account_id: AccountId,
    nonce: Option<u64>,
    recent_block_hash: CryptoHash,
    client: Arc<NearRpcClients>,
    signer: Signer,
}

pub fn make_random_account_name(suffix: &str) -> AccountId {
    format!("{}{}", hex::encode(&rand::random::<[u8; 6]>()), suffix,)
        .try_into()
        .unwrap()
}

impl OperatingAccessKey {
    pub fn new(
        account_id: AccountId,
        secret_key: SecretKey,
        recent_block_hash: CryptoHash,
        client: Arc<NearRpcClients>,
    ) -> Self {
        let signer = Signer::InMemory(InMemorySigner::from_secret_key(
            account_id.clone(),
            secret_key,
        ));
        Self {
            account_id,
            nonce: None,
            recent_block_hash,
            client,
            signer,
        }
    }

    async fn next_nonce(&mut self) -> u64 {
        match &mut self.nonce {
            Some(nonce) => {
                *nonce += 1;
                *nonce
            }
            None => {
                let request = near_primitives::views::QueryRequest::ViewAccessKey {
                    account_id: self.account_id.clone(),
                    public_key: self.signer.public_key(),
                };
                let nonce = self
                    .client
                    .with_retry(10, |rpc| {
                        let request = request.clone();
                        async move {
                            let result = rpc
                                .call(methods::query::RpcQueryRequest {
                                    block_reference: BlockReference::Finality(Finality::None),
                                    request,
                                })
                                .await?;
                            match result.kind {
                                QueryResponseKind::AccessKey(access_key) => {
                                    anyhow::Ok(access_key.nonce)
                                }
                                _ => anyhow::bail!("Unexpected response: {:?}", result),
                            }
                        }
                        .boxed()
                    })
                    .await
                    .unwrap();
                self.nonce = Some(nonce + 1);
                nonce + 1
            }
        }
    }

    pub async fn create_account(
        &mut self,
        new_account_id: AccountId,
        secret_key: SecretKey,
        amount: u128,
    ) -> NearAccount {
        println!(
            "[{}] Creating account {} with {} NEAR",
            self.account_id, new_account_id, amount,
        );
        let request = methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: SignedTransaction::create_account(
                self.next_nonce().await,
                self.account_id.clone(),
                new_account_id.clone(),
                amount,
                secret_key.public_key(),
                &self.signer,
                self.recent_block_hash,
            ),
            wait_until: TxExecutionStatus::Final,
        };
        let rpc = self.client.lease().await;
        rpc.call(request).await.unwrap();
        NearAccount {
            account_id: new_account_id,
            access_keys: vec![secret_key],
            kind: NearAccountKind::Normal,
        }
    }

    pub async fn add_access_key(&mut self, key: PublicKey) {
        println!(
            "[{}] Adding access key {} to account {}",
            self.account_id, key, self.account_id,
        );
        let request = methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: SignedTransaction::from_actions(
                self.next_nonce().await,
                self.account_id.clone(),
                self.account_id.clone(),
                &self.signer,
                vec![Action::AddKey(Box::new(AddKeyAction {
                    access_key: AccessKey {
                        nonce: 0,
                        permission: near_primitives::account::AccessKeyPermission::FullAccess,
                    },
                    public_key: key,
                }))],
                self.recent_block_hash,
                0,
            ),
            wait_until: TxExecutionStatus::Final,
        };
        let rpc = self.client.lease().await;
        rpc.call(request).await.unwrap();
    }
}

impl OperatingAccount {
    pub async fn ensure_have_n_access_keys(&mut self, desired_num_keys: usize) {
        while self.keys.len() < desired_num_keys {
            let keys_to_add = (desired_num_keys - self.keys.len()).min(self.keys.len());
            println!(
                "Account {} has {} / {} desired keys; adding {} more...",
                self.account_data.account_id,
                self.keys.len(),
                desired_num_keys,
                keys_to_add
            );
            let futs = self.keys.iter().take(keys_to_add).map(|key| {
                let key = key.clone();
                async move {
                    let mut key = key.lock().await;
                    let new_key = SecretKey::from_random(near_crypto::KeyType::ED25519);
                    key.add_access_key(new_key.public_key()).await;
                    new_key
                }
            });
            let new_keys = futures::future::join_all(futs).await;
            for new_key in new_keys {
                self.new_access_key_added(new_key);
            }
        }
        println!(
            "Account {} now has {} keys",
            self.account_data.account_id,
            self.keys.len()
        );
    }
}

pub struct OperatingAccounts {
    accounts: HashMap<AccountId, OperatingAccount>,
    recent_block_hash: CryptoHash,
    client: Arc<NearRpcClients>,
}

impl OperatingAccounts {
    pub fn new(
        accounts: HashMap<AccountId, NearAccount>,
        recent_block_hash: CryptoHash,
        client: Arc<NearRpcClients>,
    ) -> Self {
        Self {
            accounts: accounts
                .into_iter()
                .map(|(account_id, account_data)| {
                    (
                        account_id.clone(),
                        OperatingAccount::new(account_data, recent_block_hash, client.clone()),
                    )
                })
                .collect(),
            recent_block_hash,
            client,
        }
    }

    pub async fn create_account(
        &mut self,
        new_account_id: AccountId,
        amount: u128,
        funding_account: &AccountId,
    ) {
        let secret_key = SecretKey::from_random(near_crypto::KeyType::ED25519);
        let new_account = self.accounts.get(funding_account).unwrap().keys[0]
            .lock()
            .await
            .create_account(new_account_id.clone(), secret_key.clone(), amount)
            .await;
        let account =
            OperatingAccount::new(new_account, self.recent_block_hash, self.client.clone());
        self.accounts.insert(new_account_id, account);
    }

    pub async fn create_account_from_faucet(&mut self, new_account_id: AccountId) {
        let secret_key = SecretKey::from_random(near_crypto::KeyType::ED25519);
        let mut data = std::collections::HashMap::new();
        data.insert("newAccountId", new_account_id.to_string());
        data.insert("newAccountPublicKey", secret_key.public_key().to_string());
        let result = reqwest::Client::new()
            .post("https://helper.nearprotocol.com/account")
            .json(&data)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let new_account = NearAccount {
            account_id: new_account_id.clone(),
            access_keys: vec![secret_key],
            kind: NearAccountKind::FundingAccount,
        };
        let account =
            OperatingAccount::new(new_account, self.recent_block_hash, self.client.clone());
        self.accounts.insert(new_account_id, account);
    }

    pub fn get_funding_accounts(&self) -> Vec<AccountId> {
        self.accounts
            .iter()
            .filter_map(|(account_id, account)| {
                if let NearAccountKind::FundingAccount = account.account_data.kind {
                    Some(account_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub async fn get_account_balances(&self, accounts: &[AccountId]) -> HashMap<AccountId, u128> {
        let futs = accounts.iter().map(|account_id| async {
            self.client
                .with_retry(10, |rpc| {
                    let account_id = account_id.clone();
                    async move {
                        match rpc
                            .call(methods::query::RpcQueryRequest {
                                block_reference: BlockReference::Finality(Finality::Final),
                                request: QueryRequest::ViewAccount {
                                    account_id: account_id.clone(),
                                },
                            })
                            .await?
                            .kind
                        {
                            QueryResponseKind::ViewAccount(account) => {
                                return anyhow::Ok((account_id.clone(), account.amount))
                            }
                            _ => panic!("Unexpected response"),
                        }
                    }
                    .boxed()
                })
                .await
                .unwrap()
        });
        futures::future::join_all(futs).await.into_iter().collect()
    }

    #[allow(dead_code)]
    pub fn account_mut(&mut self, account_id: &AccountId) -> &mut OperatingAccount {
        self.accounts.get_mut(account_id).unwrap()
    }

    pub fn accounts_mut(
        &mut self,
        account_ids: &[AccountId],
    ) -> HashMap<AccountId, &mut OperatingAccount> {
        let filter = account_ids
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        self.accounts
            .iter_mut()
            .filter(|(account_id, _)| filter.contains(*account_id))
            .map(|(account_id, account)| (account_id.clone(), account))
            .collect()
    }

    pub fn to_data(&self) -> HashMap<AccountId, NearAccount> {
        self.accounts
            .iter()
            .map(|(account_id, account)| (account_id.clone(), account.account_data.clone()))
            .collect()
    }
}
