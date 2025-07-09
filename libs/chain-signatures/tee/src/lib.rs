use dstack_sdk::dstack_client::TcbInfo;
use serde::{Deserialize, Serialize};
use mpc_contract::tee::tee_participant::TeeParticipantInfo;
use hex;
use anyhow::{Context, Result};

#[derive(Serialize, Deserialize)]
pub enum Attestation {
    Tee(TeeAttestation),
    Local(LocalAttestation),
}

#[derive(Serialize, Deserialize)]
pub struct TeeAttestation {
    pub tcb_info: TcbInfo,
    pub tdx_quote: String,
    pub collateral: String,
}

#[derive(Serialize, Deserialize)]
pub struct LocalAttestation {
    is_valid: bool,
}

impl TryFrom<TeeAttestation> for TeeParticipantInfo {
    type Error = anyhow::Error;

    fn try_from(value: TeeAttestation) -> Result<Self, Self::Error> {
        let tee_quote = hex::decode(value.tdx_quote)
            .context("Failed to decode tee quote. Expected it to be in hex format.")?;
        let quote_collateral = value.collateral;
        let raw_tcb_info =
            serde_json::to_string(&value.tcb_info).context("Failed to serialize tcb info")?;

        Ok(Self {
            tee_quote,
            quote_collateral,
            raw_tcb_info,
        })
    }
}
