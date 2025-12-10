use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

fn main() {
    // Location of assets/*.json
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let assets_dir = PathBuf::from(manifest_dir).join("assets");

    // Find all tcb_info*.json files (prod, dev, future ones)
    let mut measurement_files = Vec::new();
    for entry in fs::read_dir(&assets_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.extension().and_then(|x| x.to_str()) == Some("json")
            && path.file_name().unwrap().to_str().unwrap().starts_with("tcb_info")
        {
            measurement_files.push(path);
        }
    }

    // Output file
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file = out_dir.join("measurements_generated.rs");
    let mut f = File::create(out_file).unwrap();

    // Write prelude
    writeln!(
        f,
        "// AUTO-GENERATED FILE. DO NOT EDIT.\n\
        use attestation::measurements::*;
        pub const EXPECTED_MEASUREMENTS: &[ExpectedMeasurements] = &[\n"
    )
    .unwrap();

    // Process each file
    for path in measurement_files {
        let json_str = fs::read_to_string(&path).unwrap();
        let tcb: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // extract 4 RTMRs + MRTD
        let mrtd = decode_hex(tcb["mrtd"].as_str().unwrap());
        let rtmr0 = decode_hex(tcb["rtmr0"].as_str().unwrap());
        let rtmr1 = decode_hex(tcb["rtmr1"].as_str().unwrap());
        let rtmr2 = decode_hex(tcb["rtmr2"].as_str().unwrap());

        // extract key-provider digest
        let mut key_provider_digest = None;
        if let Some(events) = tcb["event_log"].as_array() {
            for event in events {
                if event["event"].as_str().unwrap() == "key-provider" {
                    key_provider_digest =
                        Some(decode_hex(event["digest"].as_str().unwrap()));
                    break;
                }
            }
        }

        let key_provider_digest =
            key_provider_digest.expect("key-provider event not found");

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
        .unwrap();
    }

    // Close the array
    writeln!(f, "];").unwrap();
}

/// Decode a hex string into a fixed 48-byte array
fn decode_hex(hex: &str) -> [u8; 48] {
    let bytes = hex::decode(hex).expect("invalid hex");
    assert!(
        bytes.len() == 48,
        "expected 48-byte measurement, got {} bytes",
        bytes.len()
    );
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    arr
}
