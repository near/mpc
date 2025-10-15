// TODO: Better name
pub struct BackupService<Storage, P2PClient, MpcContract> {
    key_storage: Storage,
    mpc_p2p_client: P2PClient,
    mpc_contract: MpcContract,
}

impl<S, P, C> BackupService<S, P, C>
where
    S: KeyRepository,
    P: P2PClient,
    C: ContractInterface,
{
    pub fn generate_keypair(&self) {
        todo!();
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

// TODO: Decent types
type Ed25519KeyPair = String;

trait KeyRepository {}
trait P2PClient {}
trait ContractInterface {}
