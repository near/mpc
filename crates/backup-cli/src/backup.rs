use crate::ports;
// TODO: Better name
pub struct BackupService<SecretStorage, KeyShareStorage, P2PClient, MpcContract> {
    secrets_storage: SecretStorage,
    key_shares_storage: KeyShareStorage,
    mpc_p2p_client: P2PClient,
    mpc_contract: MpcContract,
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
            .expect("todo: Error handling");
    }

    /// Put backup service data to the smart contract
    pub async fn register_backup_service(&self) {
        todo!();
    }

    pub async fn get_keyshares(&self) {
        todo!();
    }

    pub async fn put_keyshares(&self) {
        todo!();
    }
}
