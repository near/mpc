//! Generates a non-zero padding blob that `src/lib.rs` embeds at build time.
//!
//! The blob must push the assembled WASM above the RPC's single-transaction
//! payload limit (~1.5 MiB).

use std::{fs, path::Path};

const PADDING_BYTES: usize = 2_000_000;
const PADDING_FILL: u8 = 0xAB;

fn main() {
    let out = Path::new("src/padding.bin");
    if !out.exists() {
        fs::write(out, vec![PADDING_FILL; PADDING_BYTES]).expect("failed to write padding.bin");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
