use contract_interface::types as dtos;
use near_sdk::near;

#[near(serializers=[json])]
#[derive(Debug, Clone)]
pub struct CKDResponse {
    pub big_y: dtos::Bls12381G1PublicKey,
    pub big_c: dtos::Bls12381G1PublicKey,
}

#[near(serializers=[json])]
#[derive(Debug, Clone)]
pub struct CKDArgs {
    pub derivation_path: String,
    pub app_public_key: dtos::Bls12381G1PublicKey,
    pub domain_id: DomainId,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct DomainId(pub u64);
