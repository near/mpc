use std::fmt::{self, Display, Formatter};

use attestation::attestation::VerificationError;
use node_types::http_server::StaticWebData;

use crate::verify::VerificationResult;

pub struct Success<'a> {
    pub data: &'a StaticWebData,
    pub result: &'a VerificationResult,
}

pub struct Failure<'a> {
    pub data: &'a StaticWebData,
    pub err: &'a VerificationError,
}

impl Display for Success<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write_header(f, self.data)?;
        writeln!(f)?;
        writeln!(f, "--- Extracted Values ---")?;
        writeln!(
            f,
            "MPC Image Hash:         {}",
            self.result.mpc_image_hash.as_hex()
        )?;
        writeln!(
            f,
            "Launcher Compose Hash:  {}",
            self.result.launcher_compose_hash.as_hex()
        )?;
        let ts = self.result.expiry_timestamp_seconds;
        writeln!(
            f,
            "Expiry Timestamp:       {} (unix: {ts})",
            format_timestamp(ts)
        )?;
        writeln!(f)?;
        write!(f, "Verdict: PASS")
    }
}

impl Display for Failure<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write_header(f, self.data)?;
        writeln!(f)?;
        writeln!(f, "--- Failure Details ---")?;
        writeln!(f, "Error: {}", self.err)?;
        writeln!(f)?;
        write!(f, "Verdict: FAIL")
    }
}

fn write_header(f: &mut Formatter<'_>, data: &StaticWebData) -> fmt::Result {
    writeln!(f, "=== MPC Node Attestation Verification ===")?;
    writeln!(f)?;
    writeln!(
        f,
        "TLS Public Key (P2P):   ed25519:{}",
        bs58::encode(data.near_p2p_public_key.as_bytes()).into_string()
    )?;
    writeln!(
        f,
        "Account Public Key:     ed25519:{}",
        bs58::encode(data.near_signer_public_key.as_bytes()).into_string()
    )?;
    let attestation_type = match &data.tee_participant_info {
        Some(mpc_attestation::attestation::Attestation::Dstack(_)) => "Dstack (TDX)",
        Some(mpc_attestation::attestation::Attestation::Mock(_)) => "Mock",
        None => "None",
    };
    write!(f, "Attestation Type:       {attestation_type}")
}

fn format_timestamp(unix_secs: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(unix_secs as i64) {
        Ok(dt) => {
            let (y, m, d) = dt.to_calendar_date();
            let (h, mi, s) = dt.to_hms();
            format!("{y:04}-{:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC", m as u8)
        }
        Err(_) => format!("unix:{unix_secs}"),
    }
}
