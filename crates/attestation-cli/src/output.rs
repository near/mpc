use attestation::attestation::VerificationError;
use node_types::http_server::StaticWebData;

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
    println!("Error:   {err}");
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
    // Simple UTC formatting without pulling in chrono
    let secs_per_day: u64 = 86400;
    let days_since_epoch = unix_secs / secs_per_day;
    let time_of_day = unix_secs % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Rough date calculation (no leap second precision needed for display)
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02} UTC")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil days-to-date algorithm
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
