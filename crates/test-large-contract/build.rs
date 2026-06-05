//! Generates a non-compressible padding blob that `src/lib.rs` embeds at build time.
//!
//! The blob must be both large enough to push the assembled WASM above the RPC's
//! ~1.5 MiB single-transaction payload limit (so chunked-upload tests actually
//! exercise the chunked path) and incompressible enough that `wasm-opt`/`gzip`
//! can't shrink it back below that limit. Seeded ChaCha8 output satisfies both:
//! the fixed seed keeps the blob deterministic across builds, while the bytes
//! are statistically random so they don't compress.

use std::{fs, path::Path};

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

const PADDING_BYTES: usize = 2_000_000;

fn main() {
    let out = Path::new("src/padding.bin");
    if !out.exists() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xDEAD_BEEF);
        let mut padding = vec![0u8; PADDING_BYTES];
        rng.fill_bytes(&mut padding);
        fs::write(out, &padding).expect("failed to write padding.bin");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
