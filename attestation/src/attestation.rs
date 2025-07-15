use dcap_qvl::verify::VerifiedReport;

use crate::{collateral::Collateral, hash::MpcDockerImageHash, quote::Quote, tcbinfo::TcbInfo};
use derive_more::Constructor;
use near_sdk::PublicKey;

#[allow(dead_code)]
#[derive(Constructor)]
pub struct Attestation {
    quote: Quote,
    collateral: Collateral,
    tcb_info: TcbInfo,
}

#[allow(dead_code)]
struct Measurements {
    rt_mr0: [u8; 48],
    rt_mr1: [u8; 48],
    rt_mr2: [u8; 48],
    rt_td: [u8; 48],
}

#[derive(Debug)]
pub enum MeasurementsError {
    NoTd10Report,
}

impl TryFrom<VerifiedReport> for Measurements {
    type Error = MeasurementsError;

    fn try_from(verified_report: VerifiedReport) -> Result<Self, Self::Error> {
        let td10 = verified_report
            .report
            .as_td10()
            .ok_or(MeasurementsError::NoTd10Report)?;
        Ok(Self {
            rt_mr0: td10.rt_mr0,
            rt_mr1: td10.rt_mr1,
            rt_mr2: td10.rt_mr2,
            rt_td: td10.mr_td,
        })
    }
}

pub enum ValidationContext {
    Tee,
    Local,
}

impl Attestation {
    // TODO(#642): Implement the attestation quote verification logic in the attestation module
    #[allow(dead_code)]
    fn verify_quote(&self, context: &ValidationContext) -> bool {
        match context {
            ValidationContext::Tee => {
                todo!("Implement TEE validation logic")
            }
            ValidationContext::Local => {
                todo!("Implement local attestation validation logic")
            }
        }
    }

    // TODO(#643): Implement the Docker image verification logic in the attestation module
    #[allow(dead_code)]
    fn verify_docker_image(
        &self,
        context: &ValidationContext,
        _allowed_docker_image_hashes: &[MpcDockerImageHash],
        _historical_docker_image_hashes: &[MpcDockerImageHash],
        _measurements: Measurements,
        _public_key: PublicKey,
    ) -> bool {
        match context {
            ValidationContext::Tee => {
                todo!("Implement Docker image validation logic")
            }
            ValidationContext::Local => {
                todo!("Implement local Docker image validation logic")
            }
        }
    }
}
