use std::env;
use std::path::PathBuf;

include!("build_support/lib.rs");


const ASSETS_DIR_NAME: &str = "assets";

fn main() {
    // Rerun if directory changes
    println!("cargo:rerun-if-changed={}", ASSETS_DIR_NAME);

    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set by Cargo");

    let in_dir = PathBuf::from(manifest_dir).join(ASSETS_DIR_NAME);

    let out_dir = PathBuf::from(env::var("OUT_DIR")
        .expect("OUT_DIR must be set by Cargo"));

    let out_file = out_dir.join("measurements_generated.rs");

    generate_measurements(&in_dir, &out_file)
        .expect("Failed to generate measurements file");
}
