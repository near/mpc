use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};

use mpc_primitives::hash::NodeImageHash;
use near_mpc_contract_interface::types::{Ed25519PublicKey, MockAttestation, VerifiedAttestation};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::report::{
    AttestationResult, NetworkSnapshot, ParticipantRow, attestation_status, expiry_unix_seconds,
    is_stale, rows_sorted_by_tls,
};

const NUM_COLS: usize = 10;

pub fn json(snapshot: &NetworkSnapshot) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer_pretty(&mut out, snapshot)?;
    writeln!(out)?;
    Ok(())
}

pub fn table(snapshot: &NetworkSnapshot) -> anyhow::Result<()> {
    let use_color = std::io::stdout().is_terminal();
    let rows = rows_sorted_by_tls(&snapshot.state);
    let now = snapshot.fetched_at_unix_seconds;

    let header: [&str; NUM_COLS] = [
        "ACCOUNT_ID",
        "TLS_KEY",
        "PARTICIPANT_ID",
        "EPOCH_ID",
        "URL",
        "MPC_IMAGE_HASH",
        "LAUNCHER_COMPOSE_HASH",
        "MPC_VERSION",
        "EXPIRES_AT",
        "EXPIRES_IN",
    ];

    let mut data: Vec<[String; NUM_COLS]> = Vec::with_capacity(rows.len());
    let mut stale_count = 0usize;
    let mut missing_count = 0usize;
    let mut healthy_count = 0usize;

    for row in &rows {
        let attestation = snapshot.attestations.get(&row.tls_public_key);
        let status = attestation_status(attestation, now);
        match status {
            "stale" | "rpc-error" => stale_count += 1,
            "missing" | "no-key" => missing_count += 1,
            "healthy" => healthy_count += 1,
            _ => {}
        }
        data.push(format_row(
            row,
            attestation,
            &snapshot.mpc_image_versions,
            now,
        )?);
    }

    print_table(
        &header,
        &data,
        &rows,
        &snapshot.attestations,
        now,
        use_color,
    )?;

    println!(
        "\n{} participants — {} stale, {} missing-attestation, {} healthy",
        rows.len(),
        stale_count,
        missing_count,
        healthy_count
    );
    Ok(())
}

fn format_row(
    row: &ParticipantRow,
    attestation: Option<&AttestationResult>,
    versions: &BTreeMap<NodeImageHash, String>,
    now: u64,
) -> anyhow::Result<[String; NUM_COLS]> {
    let (mpc_hash, launcher_hash, expires_at, expires_in) = attestation_columns(attestation, now)?;
    let mpc_version = mpc_version_cell(attestation, versions);
    Ok([
        row.account_id.to_string(),
        String::from(&row.tls_public_key),
        row.participant_id.0.to_string(),
        row.epoch_id.0.to_string(),
        row.url.clone(),
        mpc_hash,
        launcher_hash,
        mpc_version,
        expires_at,
        expires_in,
    ])
}

fn mpc_version_cell(
    result: Option<&AttestationResult>,
    versions: &BTreeMap<NodeImageHash, String>,
) -> String {
    match result {
        Some(AttestationResult::Ok(Some(VerifiedAttestation::Dstack(d)))) => {
            if let Some(tag) = versions.get(&d.mpc_image_hash) {
                tag.clone()
            } else if versions.is_empty() {
                "n/a".to_string()
            } else {
                "?".to_string()
            }
        }
        Some(AttestationResult::Ok(Some(VerifiedAttestation::Mock(_)))) => "mock".to_string(),
        _ => dash(),
    }
}

fn attestation_columns(
    result: Option<&AttestationResult>,
    now: u64,
) -> anyhow::Result<(String, String, String, String)> {
    match result {
        None => Ok((dash(), dash(), dash(), "no-attestation-key".to_string())),
        Some(AttestationResult::Err(e)) => Ok((dash(), dash(), dash(), format!("rpc-error: {e}"))),
        Some(AttestationResult::Ok(None)) => Ok((dash(), dash(), dash(), "missing".to_string())),
        Some(AttestationResult::Ok(Some(att))) => {
            let (mpc_hash, launcher_hash) = hashes(att);
            let expiry = expiry_unix_seconds(att);
            let expires_at = expiry.and_then(format_rfc3339).unwrap_or_else(dash);
            let expires_in = match expiry {
                Some(e) => humanize_relative(e, now),
                None => dash(),
            };
            Ok((mpc_hash, launcher_hash, expires_at, expires_in))
        }
    }
}

fn hashes(att: &VerifiedAttestation) -> (String, String) {
    match att {
        VerifiedAttestation::Dstack(d) => (
            truncate_hex(d.mpc_image_hash.as_hex()),
            truncate_hex(d.launcher_compose_hash.as_hex()),
        ),
        VerifiedAttestation::Mock(MockAttestation::WithConstraints {
            mpc_docker_image_hash,
            launcher_docker_compose_hash,
            ..
        }) => (
            mpc_docker_image_hash
                .as_ref()
                .map(|h| truncate_hex(h.as_hex()))
                .unwrap_or_else(dash),
            launcher_docker_compose_hash
                .as_ref()
                .map(|h| truncate_hex(h.as_hex()))
                .unwrap_or_else(dash),
        ),
        VerifiedAttestation::Mock(MockAttestation::Valid) => {
            ("mock(valid)".to_string(), "mock(valid)".to_string())
        }
        VerifiedAttestation::Mock(MockAttestation::Invalid) => {
            ("mock(invalid)".to_string(), "mock(invalid)".to_string())
        }
    }
}

fn print_table(
    header: &[&str; NUM_COLS],
    data: &[[String; NUM_COLS]],
    rows: &[ParticipantRow],
    attestations: &BTreeMap<Ed25519PublicKey, AttestationResult>,
    now: u64,
    use_color: bool,
) -> anyhow::Result<()> {
    let mut widths = [0usize; NUM_COLS];
    for (i, h) in header.iter().enumerate() {
        widths[i] = h.len();
    }
    for row in data {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    print_header(header, &widths);
    for (row, src) in data.iter().zip(rows.iter()) {
        let stale = attestations
            .get(&src.tls_public_key)
            .and_then(|r| match r {
                AttestationResult::Ok(Some(att)) => Some(is_stale(att, now)),
                _ => None,
            })
            .unwrap_or(false);
        print_row(row, &widths, use_color, stale);
    }
    Ok(())
}

fn print_header(header: &[&str; NUM_COLS], widths: &[usize; NUM_COLS]) {
    let mut line = String::new();
    for (i, h) in header.iter().enumerate() {
        if i > 0 {
            line.push_str(" | ");
        }
        line.push_str(&format!("{:width$}", h, width = widths[i]));
    }
    println!("{line}");
    println!("{}", "-".repeat(line.len()));
}

fn print_row(row: &[String; NUM_COLS], widths: &[usize; NUM_COLS], use_color: bool, stale: bool) {
    let mut line = String::new();
    for (i, cell) in row.iter().enumerate() {
        if i > 0 {
            line.push_str(" | ");
        }
        line.push_str(&format!("{:width$}", cell, width = widths[i]));
    }
    if use_color {
        let colored = if stale {
            format!("\x1b[31m{line}\x1b[0m")
        } else {
            format!("\x1b[32m{line}\x1b[0m")
        };
        println!("{colored}");
    } else {
        println!("{line}");
    }
}

fn format_rfc3339(unix_seconds: u64) -> Option<String> {
    let secs = i64::try_from(unix_seconds).ok()?;
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn humanize_relative(target: u64, now: u64) -> String {
    if target >= now {
        let dur = target - now;
        let parts = breakdown(dur);
        format!("in {parts}")
    } else {
        let dur = now - target;
        let parts = breakdown(dur);
        format!("expired {parts} ago")
    }
}

fn breakdown(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

fn truncate_hex(mut s: String) -> String {
    const HEAD: usize = 16;
    if s.len() > HEAD {
        s.truncate(HEAD);
        s.push('…');
    }
    s
}

fn dash() -> String {
    "-".to_string()
}
