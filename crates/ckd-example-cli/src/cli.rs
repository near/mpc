use crate::types::Bls12381G2PublicKey;

use crate::types::DomainId;

#[derive(clap::Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    #[arg(long, env)]
    pub mpc_ckd_public_key: Bls12381G2PublicKey,

    #[arg(long, env)]
    pub domain_id: DomainId,

    #[arg(long, env)]
    pub signer_account_id: String,
}
