use attestation::attestation::VerificationError;
use node_types::http_server::StaticWebData;
use time::OffsetDateTime;

use crate::verify::VerificationResult;

pub fn print_success(static_data: &StaticWebData, result: &VerificationResult) {
    print_header(static_data);
    print_verification_details(result);
    println!();
    println!("Verdict: PASS");
}

pub fn print_failure(static_data: &StaticWebData, err: &VerificationError) {
    print_header(static_data);
    println!();
    println!("--- Failure Details ---");
    match err {
        VerificationError::TcbStatusNotUpToDate(status) => {
            println!("Reason:          TCB status is not up to date");
            println!("TCB Status:      {status}");
            println!("Expected Status: UpToDate");
        }
        VerificationError::NonEmptyAdvisoryIds(ids) => {
            println!("Reason:          Outstanding security advisories");
            println!("Advisory IDs:    {ids}");
        }
        VerificationError::WrongHash {
            name,
            found,
            expected,
        } => {
            println!("Reason:          Hash mismatch ({name})");
            println!("Found:           {found}");
            println!("Expected:        {expected}");
        }
        VerificationError::DcapVerification(msg) => {
            println!("Reason:          DCAP quote verification failed");
            println!("Details:         {msg}");
        }
        _ => {
            println!("Error:           {err}");
        }
    }
    println!();
    println!("Verdict: FAIL");
}

fn print_header(static_data: &StaticWebData) {
    println!("=== MPC Node Attestation Verification ===");
    println!();
    println!(
        "TLS Public Key (P2P):   ed25519:{}",
        bs58::encode(static_data.near_p2p_public_key.as_bytes()).into_string()
    );
    println!(
        "Account Public Key:     ed25519:{}",
        bs58::encode(static_data.near_signer_public_key.as_bytes()).into_string()
    );

    let attestation_type = match &static_data.tee_participant_info {
        Some(mpc_attestation::attestation::Attestation::Dstack(_)) => "Dstack (TDX)",
        Some(mpc_attestation::attestation::Attestation::Mock(_)) => "Mock",
        None => "None",
    };
    println!("Attestation Type:       {attestation_type}");
}

fn print_verification_details(result: &VerificationResult) {
    println!();
    println!("--- Extracted Values ---");
    println!("MPC Image Hash:         {}", result.mpc_image_hash.as_hex());
    println!(
        "Launcher Compose Hash:  {}",
        result.launcher_compose_hash.as_hex()
    );
    println!(
        "Expiry Timestamp:       {} (unix: {})",
        format_timestamp(result.expiry_timestamp_seconds),
        result.expiry_timestamp_seconds
    );
}

fn format_timestamp(unix_secs: u64) -> String {
    match OffsetDateTime::from_unix_timestamp(unix_secs as i64) {
        Ok(dt) => {
            let (year, month, day) = dt.to_calendar_date();
            let (hour, minute, second) = dt.to_hms();
            format!(
                "{year:04}-{:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC",
                u8::from(month)
            )
        }
        Err(_) => format!("{unix_secs} (invalid timestamp)"),
    }
}
