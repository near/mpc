use contract_interface::types::Bls12381G2PublicKey;

use crate::types::DomainId;

#[derive(clap::Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    /// The public key associated to the domain id
    #[arg(long, env)]
    pub mpc_ckd_public_key: Bls12381G2PublicKey,

    /// The domain id in the MPC contract that supports CKD
    #[arg(long, env)]
    pub domain_id: DomainId,

    /// Derivation path for the confidential key, which allows a single account to request several keys
    #[arg(long, env)]
    pub derivation_path: String,

    /// The account that will be used to call the MPC contract
    #[arg(long, env)]
    pub signer_account_id: String,
}
