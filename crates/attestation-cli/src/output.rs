use attestation::attestation::VerificationError;
use node_types::http_server::StaticWebData;
use time::OffsetDateTime;

use dcap_qvl::{SvnComponent, TcbStatus, policy::PckIdentity, quote::TDReport10};

use crate::tcb_status::{self, EarlyDemotion, Report, TcbVerdict};
use crate::verify::VerificationResult;

const UPDATE_TDX_MODULE: &str = "update the TDX module (SEAM loader)";
const UPDATE_BIOS: &str = "update BIOS/microcode";

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
        VerificationError::TcbStatusNotUpToDate { status, .. } => {
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

    // The PCK numbers come from the certificate a successful verification read,
    // not from the collateral, so every row carries identical values and
    // whichever verified will do. The verdicts themselves do differ, which is
    // the point of showing three rows.
    let pck = match (&report.served, &report.standard, &report.early) {
        (TcbVerdict::Verified { claims, .. }, _, _)
        | (_, Some(TcbVerdict::Verified { claims, .. }), _)
        | (_, _, Some(TcbVerdict::Verified { claims, .. })) => Some(&claims.platform.pck),
        _ => None,
    };
    print_platform(&report.td_report, pck);

    let (module, _) = tcb_status::tdx_module(&report.td_report.tee_tcb_svn);
    let module = module.as_deref().unwrap_or("unnamed");
    print_verdict("served by the node", &report.served, module);
    if let Some(standard) = &report.standard {
        print_verdict("Intel `standard`", standard, module);
    }
    if let Some(early) = &report.early {
        print_verdict("Intel `early`", early, module);
    }

    if let Some(EarlyDemotion { cleared, demoted }) = report.early_demotion() {
        println!();
        println!(
            "This platform clears TCB recovery set {cleared} but not set {demoted}, which Intel \
             publishes and has yet to promote."
        );
    }
}

fn print_verdict(label: &str, verdict: &TcbVerdict, module: &str) {
    println!();
    match verdict {
        TcbVerdict::Verified {
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
                let (component, remedy) = describe(shortfall.component, module);
                println!(
                    "  {component} is {}, needs {} -> {remedy}",
                    shortfall.have, shortfall.needs
                );
            }
            // Demoted with nothing to raise: either Intel accepts no level for
            // this platform, or every SVN clears one and the module identity's
            // own advisories carry the status down.
            if shortfalls.is_empty() && claims.tcb.status != TcbStatus::UpToDate {
                if tcb_info
                    .tcb_levels
                    .iter()
                    .all(|level| level.tcb_status != TcbStatus::UpToDate)
                {
                    println!(
                        "  Intel publishes no UpToDate level for this platform, so no SVN upgrade reaches one."
                    );
                } else {
                    println!(
                        "  Every SVN clears an accepted level; the status comes from the advisories above."
                    );
                }
            }
        }
        TcbVerdict::Rejected(reason) => {
            println!("--- {label} ---");
            println!("Rejected:               {reason}");
        }
    }
}

/// How a shortfall line names `component`, and the update that raises it.
/// `module` names the TDX module identity the quote selects.
fn describe(component: SvnComponent, module: &str) -> (String, &'static str) {
    match component {
        SvnComponent::TdxModuleIsvSvn => {
            (format!("TDX module {module} ISV SVN"), UPDATE_TDX_MODULE)
        }
        // The module's own SVNs, judged by the platform level only when the
        // quote selects no module identity.
        SvnComponent::Tdx(index @ (0 | 1)) => {
            (format!("TDX TCB component {index}"), UPDATE_TDX_MODULE)
        }
        SvnComponent::Tdx(index) => (format!("TDX TCB component {index}"), UPDATE_BIOS),
        SvnComponent::Sgx(index) => (format!("SGX TCB component {index}"), UPDATE_BIOS),
        SvnComponent::PceSvn => ("PCESVN".to_owned(), UPDATE_BIOS),
    }
}

/// `pck` is absent when neither collateral verified, which leaves only the half
/// of the platform the quote describes on its own.
fn print_platform(report: &TDReport10, pck: Option<&PckIdentity>) {
    let (module, module_svn) = tcb_status::tdx_module(&report.tee_tcb_svn);

    println!();
    println!("--- Platform, as the quote reports it ---");
    if let Some(pck) = pck {
        println!("FMSPC:                  {}", hex::encode_upper(pck.fmspc));
    }
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
    match pck {
        Some(pck) => {
            println!("SGX TCB components:     {:?}", pck.cpu_svn);
            println!("PCESVN:                 {}", pck.pce_svn);
        }
        None => {
            println!("FMSPC, SGX components and PCESVN come from the PCK certificate,");
            println!("which neither evaluation could read.");
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(
        SvnComponent::TdxModuleIsvSvn,
        "TDX module TDX_03 ISV SVN",
        UPDATE_TDX_MODULE
    )]
    #[case(SvnComponent::Tdx(0), "TDX TCB component 0", UPDATE_TDX_MODULE)]
    #[case(SvnComponent::Tdx(1), "TDX TCB component 1", UPDATE_TDX_MODULE)]
    #[case(SvnComponent::Tdx(2), "TDX TCB component 2", UPDATE_BIOS)]
    #[case(SvnComponent::Sgx(0), "SGX TCB component 0", UPDATE_BIOS)]
    #[case(SvnComponent::PceSvn, "PCESVN", UPDATE_BIOS)]
    fn describe__should_name_the_component_and_the_update_that_raises_it(
        #[case] component: SvnComponent,
        #[case] expected_label: &str,
        #[case] expected_remedy: &str,
    ) {
        // When
        let (label, remedy) = describe(component, "TDX_03");

        // Then
        assert_eq!(label, expected_label);
        assert_eq!(remedy, expected_remedy);
    }
}
