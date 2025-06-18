use crate::{
    errors::{Error, InvalidCandidateSet},
    get_collateral,
};
use dcap_qvl::verify::{self, VerifiedReport};
use near_sdk::near;

const RTMR0: [u8; 48] = [0u8; 48];
const RTMR1: [u8; 48] = [0u8; 48];
const RTMR2: [u8; 48] = [0u8; 48];
const MRTD: [u8; 48] = [0u8; 48];

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
pub struct TeeParticipantInfo {
    /// TEE Remote Attestation Quote that proves the participant's identity.
    pub tee_quote: Vec<u8>,
    /// Supplemental data for the TEE quote, including Intel certificates to verify it came from
    /// genuine Intel hardware, along with details about the Trusted Computing Base (TCB)
    /// versioning, status, and other relevant info.
    pub quote_collateral: String,
    /// Dstack event log.
    pub raw_tcb_info: String,
}

impl TeeParticipantInfo {
    /// Verifies the TEE quote against the provided collateral.
    pub fn verify_quote(&self, timestamp_s: u64) -> Result<VerifiedReport, Error> {
        let tee_collateral = get_collateral(self.quote_collateral.clone())
            .map_err(|_| Into::<Error>::into(InvalidCandidateSet::InvalidParticipantsTeeQuote))?;
        let verification_result = verify::verify(&self.tee_quote, &tee_collateral, timestamp_s);
        verification_result.map_err(|_| InvalidCandidateSet::InvalidParticipantsTeeQuote.into())
    }

    pub fn verify_static_rtmrs(verified_report: VerifiedReport) -> bool {
        if let Some(td10) = verified_report.report.as_td10() {
            td10.rt_mr0 == RTMR0
                && td10.rt_mr1 == RTMR1
                && td10.rt_mr2 == RTMR2
                && td10.mr_td == MRTD
        } else {
            false
        }
    }

    pub fn verify_report_data(&self) -> Result<(), Error> {
        Ok(())
    }
}
