//! Generates a non-compressible padding blob that `src/lib.rs` embeds at build time.
//!
//! The blob must be both large enough to push the assembled WASM above the RPC's
//! ~1.5 MiB single-transaction payload limit (so chunked-upload tests actually
//! exercise the chunked path) and incompressible enough that `wasm-opt`/`gzip`
//! can't shrink it back below that limit. Pseudo-random bytes from a tiny LCG
//! satisfy both at near-zero build cost.

use std::{fs, path::Path};

const PADDING_BYTES: usize = 2_000_000;
const LCG_MULTIPLIER: u64 = 6_364_136_223_846_793_005;

fn main() {
    let out = Path::new("src/padding.bin");
    if !out.exists() {
        let mut padding = vec![0u8; PADDING_BYTES];
        let mut state: u64 = 0xDEAD_BEEF;
        for byte in padding.iter_mut() {
            state = state.wrapping_mul(LCG_MULTIPLIER).wrapping_add(1);
            *byte = (state >> 33) as u8;
        }
        fs::write(out, &padding).expect("failed to write padding.bin");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
