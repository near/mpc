use std::fs;
use std::path::Path;

fn main() {
    let out = Path::new("src/padding.bin");
    if !out.exists() {
        // Generate ~3.5 MiB of pseudo-random padding (non-compressible).
        // The final WASM must exceed the 1.5 MiB RPC limit to exercise chunked uploads,
        // and stay under the NEAR 4 MiB max_contract_size limit.
        let mut padding = vec![0u8; 2_000_000];
        // Simple LCG to produce non-repeating bytes
        let mut state: u64 = 0xDEADBEEF;
        for byte in padding.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (state >> 33) as u8;
        }
        fs::write(out, &padding).expect("failed to write padding.bin");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
