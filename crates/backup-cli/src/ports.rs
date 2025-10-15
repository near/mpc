use crate::types;
pub trait SecretsRepository {
    fn store_private_key(&self, private_key: types::PrivateKey) -> impl std::future::Future<Output = ()> + Send;
    fn load_private_key(&self) -> impl std::future::Future<Output = types::PrivateKey> + Send;
}

pub trait KeyShareRepository{

}

pub trait P2PClient {}
pub trait ContractInterface {}