use dcap_qvl::verify::VerifiedReport;

use crate::{collateral::Collateral, hash::MpcDockerImageHash, quote::Quote, tcbinfo::TcbInfo};
use near_sdk::PublicKey;

pub struct Attestation {
    quote: Quote,
    collateral: Collateral,
    tcb_info: TcbInfo,
}

impl Attestation {
    fn new(quote: Quote, collateral: Collateral, tcb_info: TcbInfo) -> Self {
        Self {
            quote,
            collateral,
            tcb_info,
        }
    }
}

struct Measurements {
    rt_mr0: [u8; 48],
    rt_mr1: [u8; 48],
    rt_mr2: [u8; 48],
    rt_td: [u8; 48],
}

impl From<VerifiedReport> for Measurements {
    fn from(verified_report: VerifiedReport) -> Self {
        if let Some(td10) = verified_report.report.as_td10() {
            Self {
                rt_mr0: td10.rt_mr0,
                rt_mr1: td10.rt_mr1,
                rt_mr2: td10.rt_mr2,
                rt_td: td10.mr_td,
            }
        } else {
            // Default/zero measurements if TD10 report is not available
            Self {
                rt_mr0: [0; 48],
                rt_mr1: [0; 48],
                rt_mr2: [0; 48],
                rt_td: [0; 48],
            }
        }
    }
}

enum ValidationContext {
    Tee,
    Local,
}

impl Attestation {
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
