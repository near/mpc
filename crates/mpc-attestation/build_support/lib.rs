use serde_json::Value;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Main logic for generating the Rust measurements file.
/// This is fully testable and contains no side effects except writing out_file.
pub fn generate_measurements(in_dir: &Path, out_file: &Path) -> Result<(), String> {
    // Discover measurement files
    let mut measurement_files = Vec::new();

    let entries = fs::read_dir(in_dir)
        .map_err(|e| format!("Failed to read directory '{}': {}", in_dir.display(), e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();

        if path.extension().and_then(|x| x.to_str()) == Some("json") {
            if let Some(fname) = path.file_name().and_then(|x| x.to_str()) {
                if fname.starts_with("tcb_info") {
                    measurement_files.push(path);
                }
            }
        }
    }

    if measurement_files.is_empty() {
        return Err(format!(
            "No tcb_info*.json files found in '{}'",
            in_dir.display()
        ));
    }

    // Create output file
    let mut f = File::create(out_file).map_err(|e| {
        format!(
            "Failed to create output file '{}': {}",
            out_file.display(),
            e
        )
    })?;

    writeln!(
        f,
        "// AUTO-GENERATED FILE. DO NOT EDIT.\n\
         use attestation::measurements::*;\n\
         pub const EXPECTED_MEASUREMENTS: &[ExpectedMeasurements] = &[\n"
    )
    .map_err(|e| e.to_string())?;

    // Process each file
    for path in measurement_files {
        let json_str = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read '{}': {}", path.display(), e))?;

        let tcb: Value = serde_json::from_str(&json_str)
            .map_err(|e| format!("Invalid JSON '{}': {}", path.display(), e))?;

        let mrtd = decode_measurement(&tcb, "mrtd")?;
        let rtmr0 = decode_measurement(&tcb, "rtmr0")?;
        let rtmr1 = decode_measurement(&tcb, "rtmr1")?;
        let rtmr2 = decode_measurement(&tcb, "rtmr2")?;

        let key_provider_digest = extract_key_provider_digest(&tcb)?;

        writeln!(
            f,
            "    ExpectedMeasurements {{ \
                 rtmrs: Measurements {{ \
                     mrtd: {:?}, \
                     rtmr0: {:?}, \
                     rtmr1: {:?}, \
                     rtmr2: {:?} \
                 }}, \
                 key_provider_event_digest: {:?}, \
             }},",
            mrtd, rtmr0, rtmr1, rtmr2, key_provider_digest
        )
        .map_err(|e| e.to_string())?;
    }

    writeln!(f, "];").map_err(|e| e.to_string())?;

    Ok(())
}

/// Extract one 48-byte hex measurement field (mrtd, rtmrX)
fn decode_measurement(tcb: &Value, field: &str) -> Result<[u8; 48], String> {
    let hex = tcb[field]
        .as_str()
        .ok_or_else(|| format!("Missing string field '{}'", field))?;

    decode_hex(hex).map_err(|e| format!("{}: {}", field, e))
}

/// Extract key-provider digest
fn extract_key_provider_digest(tcb: &Value) -> Result<[u8; 48], String> {
    let events = tcb["event_log"]
        .as_array()
        .ok_or_else(|| "event_log missing or not array".to_string())?;

    for event in events {
        if event["event"].as_str().unwrap_or("") == "key-provider" {
            let hex = event["digest"]
                .as_str()
                .ok_or_else(|| "key-provider missing digest".to_string())?;
            return decode_hex(hex);
        }
    }

    Err("No key-provider event found".to_string())
}

/// Decode hex string to 48-byte array
fn decode_hex(hex: &str) -> Result<[u8; 48], String> {
    let bytes = hex::decode(hex).map_err(|e| format!("invalid hex: {}", e))?;

    if bytes.len() != 48 {
        return Err(format!("expected 48 bytes, got {} bytes", bytes.len()));
    }

    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
