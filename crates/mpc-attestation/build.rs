use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

const ASSETS_DIR_NAME: &str = "assets";

fn main() {
    // Find assets directory
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set by Cargo");

    let assets_dir = PathBuf::from(&manifest_dir).join(ASSETS_DIR_NAME);

    println!("cargo:rerun-if-changed={}", ASSETS_DIR_NAME);

    // First pass: ensure directory exists + register rerun triggers
    let entries = fs::read_dir(&assets_dir).unwrap_or_else(|e| {
        panic!(
            "Failed to read assets directory '{}': {}.\n\
             This directory must exist and contain tcb_info*.json files.",
            assets_dir.display(),
            e
        )
    });

    let mut measurement_files = Vec::new();

    for entry in entries {
        let entry = entry.unwrap_or_else(|e| {
            panic!(
                "Failed to read an entry inside '{}': {}",
                assets_dir.display(),
                e
            )
        });

        let path = entry.path();

        if path.extension().and_then(|x| x.to_str()) == Some("json") {
            println!("cargo:rerun-if-changed={}", path.display());

            // Only include tcb_info*.json
            let filename = path
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or_else(|| {
                    panic!(
                        "Found a JSON file with invalid UTF-8 filename inside '{}': {:?}",
                        assets_dir.display(),
                        path.file_name()
                    )
                });

            if filename.starts_with("tcb_info") {
                measurement_files.push(path);
            }
        }
    }

    if measurement_files.is_empty() {
        panic!(
            "No tcb_info*.json files found in directory '{}'. \
             Add files such as tcb_info.json or tcb_info_dev.json.",
            assets_dir.display()
        );
    }

    // Write generated Rust file
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be provided by Cargo"));
    let out_file = out_dir.join("measurements_generated.rs");

    let mut f = File::create(&out_file).unwrap_or_else(|e| {
        panic!(
            "Failed to create output file '{}': {}",
            out_file.display(),
            e
        )
    });

    writeln!(
        f,
        "// AUTO-GENERATED FILE. DO NOT EDIT.\n\
         use attestation::measurements::*;\n\
         pub const EXPECTED_MEASUREMENTS: &[ExpectedMeasurements] = &[\n"
    )
    .expect("failed to write prelude to generated file");

    // Process each file
    for path in measurement_files {
        let json_str = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read JSON file '{}': {}", path.display(), e));

        let tcb: serde_json::Value = serde_json::from_str(&json_str)
            .unwrap_or_else(|e| panic!("Failed to parse JSON file '{}': {}", path.display(), e));

        // Extract RTMRs + MRTD
        let mrtd = decode_measurement(&tcb, "mrtd", &path);
        let rtmr0 = decode_measurement(&tcb, "rtmr0", &path);
        let rtmr1 = decode_measurement(&tcb, "rtmr1", &path);
        let rtmr2 = decode_measurement(&tcb, "rtmr2", &path);

        // Extract key-provider digest
        let key_provider_digest = extract_key_provider_digest(&tcb, &path);

        // Emit Rust struct
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
        .expect("failed writing measurement struct");
    }

    writeln!(f, "];").expect("failed writing closing bracket");
}

/// Extract a measurement field and decode hex, with good error messages.
fn decode_measurement(tcb: &serde_json::Value, field: &str, path: &PathBuf) -> [u8; 48] {
    let hex = tcb[field].as_str().unwrap_or_else(|| {
        panic!(
            "Field '{}' missing or not a string in '{}'",
            field,
            path.display()
        )
    });

    decode_hex(hex, field, path)
}

/// Extract the key-provider hash with clear diagnostics
fn extract_key_provider_digest(tcb: &serde_json::Value, path: &PathBuf) -> [u8; 48] {
    let events = tcb["event_log"]
        .as_array()
        .unwrap_or_else(|| panic!("event_log missing or not an array in '{}'", path.display()));

    for event in events {
        let event_name = event["event"].as_str().unwrap_or("");

        if event_name == "key-provider" {
            let digest_hex = event["digest"].as_str().unwrap_or_else(|| {
                panic!(
                    "key-provider event in '{}' does not contain a valid digest",
                    path.display()
                )
            });

            return decode_hex(digest_hex, "key-provider digest", path);
        }
    }

    panic!("No key-provider event found in '{}'", path.display());
}

/// Decode a hex string into a 48-byte array with validation
fn decode_hex(hex: &str, field: &str, path: &PathBuf) -> [u8; 48] {
    let bytes = hex::decode(hex).unwrap_or_else(|e| {
        panic!(
            "Invalid hex in field '{}' in '{}': {}",
            field,
            path.display(),
            e
        )
    });

    if bytes.len() != 48 {
        panic!(
            "Expected 48-byte measurement for field '{}' in '{}', got {} bytes",
            field,
            path.display(),
            bytes.len()
        );
    }

    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    arr
}
