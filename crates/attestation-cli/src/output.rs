use attestation::attestation::VerificationError;
use node_types::http_server::StaticWebData;
use time::OffsetDateTime;

use dcap_qvl::policy::QuoteClaims;

use crate::tcb_status::{self, Outcome, Report};
use crate::verify::VerificationResult;

pub fn print_success(static_data: &StaticWebData, result: &VerificationResult) {
    print_header(static_data);
    print_accepted_attestation_details(result);
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

fn print_accepted_attestation_details(result: &VerificationResult) {
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
    if !result.advisory_ids.is_empty() {
        println!(
            "Informational advisory IDs: {}",
            result.advisory_ids.join(", ")
        );
    }
}

fn format_timestamp(unix_secs: u64) -> String {
    match OffsetDateTime::from_unix_timestamp(
        i64::try_from(unix_secs).expect("timestamp should be lower than `i64::MAX`"),
    ) {
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

pub fn print_tcb_status(report: &Report) {
    println!("=== MPC Node Platform TCB Status ===");

    // Both rows judge the same quote, so its platform numbers are the same in
    // each; whichever verified first will do. When neither did, the rejection
    // reasons below say why.
    match (&report.served, &report.standard) {
        (Outcome::Verified { claims, .. }, _) | (_, Outcome::Verified { claims, .. }) => {
            print_platform(claims);
        }
        _ => println!("\nThe platform's own numbers are unavailable: neither evaluation verified."),
    }

    print_outcome("served by the node", &report.served);
    print_outcome("Intel `standard`", &report.standard);
}

fn print_outcome(label: &str, outcome: &Outcome) {
    println!();
    match outcome {
        Outcome::Verified {
            tcb_info,
            claims,
            shortfalls,
        } => {
            println!(
                "--- {label}: TCB recovery set {}, issued {} ---",
                tcb_info.tcb_evaluation_data_number, tcb_info.issue_date
            );
            println!("Status:                 {}", claims.tcb.status);
            if !claims.tcb.advisory_ids.is_empty() {
                println!(
                    "Advisory IDs:           {}",
                    claims.tcb.advisory_ids.join(", ")
                );
            }
            for shortfall in shortfalls {
                println!(
                    "  {} is {}, needs {} -> {}",
                    shortfall.component, shortfall.have, shortfall.needs, shortfall.remedy
                );
            }
        }
        Outcome::Rejected(reason) => {
            println!("--- {label} ---");
            println!("Rejected:               {reason}");
        }
    }
}

fn print_platform(claims: &QuoteClaims) {
    // `evaluate` already established the report is TD10, so this never misses.
    let Some(report) = claims.report.as_td10() else {
        return;
    };
    let pck = &claims.platform.pck;
    let (module, module_svn) = tcb_status::tdx_module(&report.tee_tcb_svn);

    println!();
    println!("--- Platform, as the quote reports it ---");
    println!("FMSPC:                  {}", hex::encode_upper(pck.fmspc));
    println!(
        "tee_tcb_svn:            {}",
        hex::encode(report.tee_tcb_svn)
    );
    println!(
        "TDX module:             {} at ISV SVN {}",
        module.as_deref().unwrap_or("unnamed"),
        module_svn
    );
    println!("TDX TCB components:     {:?}", report.tee_tcb_svn);
    println!("SGX TCB components:     {:?}", pck.cpu_svn);
    println!("PCESVN:                 {}", pck.pce_svn);
}
