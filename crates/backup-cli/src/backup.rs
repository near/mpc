// TODO: Better name
pub struct BackupService<Storage, P2PClient, MpcContract> {
    key_storage: Storage,
    mpc_p2p_client: P2PClient,
    mpc_contract: MpcContract,
    keypair: Ed25519KeyPair,
}

impl<S, P, C> BackupService<S, P, C>
where
    S: KeyRepository,
    P: P2PClient,
    C: ContractInterface,
{
    /// Put backup service data to the smart contract
    pub fn publish_backup_data() {
        todo!();
    }
}

// TODO: Decent types
type Ed25519KeyPair = String;

trait KeyRepository {}
trait P2PClient {}
trait ContractInterface {}
