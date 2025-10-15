use crate::ports;
// TODO: Better name
pub struct BackupService<SecretStorage, KeyShareStorage, P2PClient, MpcContract> {
    secrets_storage: SecretStorage,
    key_shares_storage: KeyShareStorage,
    mpc_p2p_client: P2PClient,
    mpc_contract: MpcContract,
}

impl<SecretStorage, KeyShareStorage, P2PClient, MpcContract> BackupService<SecretStorage, KeyShareStorage, P2PClient, MpcContract> {
    pub fn new(secrets_storage: SecretStorage, key_shares_storage: KeyShareStorage, mpc_p2p_client: P2PClient, mpc_contract: MpcContract) -> Self {
        Self { secrets_storage, key_shares_storage, mpc_p2p_client, mpc_contract }
    }
}




impl<S, K, P, C> BackupService<S, K, P, C>
where
    S: ports::SecretsRepository,
    K: ports::KeyShareRepository,
    P: ports::P2PClient,
    C: ports::ContractInterface,
{
    pub async fn generate_keypair(&self) {
        // TODO: Implement
        let private_key = crate::types::PrivateKey {};
        self.secrets_storage
            .store_private_key(&private_key)
            .await
            .expect("fail to store private key");
    }

    /// Put backup service data to the smart contract
    pub async fn register_backup_service(&self) {
        let public_key = self
            .secrets_storage
            .load_private_key()
            .await
            .expect("fail to load private key")
            .public_key();
        self.mpc_contract
            .register_backup_data(&public_key)
            .await
            .expect("fail to register backup data");
    }

    pub async fn get_keyshares(&self) {
        let keyshare = self
            .mpc_p2p_client
            .get_key_shares()
            .await
            .expect("fail to get key shares");
        self.key_shares_storage
            .store_key_shares(&keyshare)
            .await
            .expect("fail to store key shares");
    }

    pub async fn put_keyshares(&self) {
        let key_shares = self
            .key_shares_storage
            .load_key_shares()
            .await
            .expect("fail to load key shares");
        self.mpc_p2p_client
            .put_key_shares(&key_shares)
            .await
            .expect("fail to put key shares");
    }
}


