use std::env;
use std::process::Command;

fn main() {
    // Get version from Cargo.toml
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());
    
    // Get git commit hash
    let commit = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .chars()
                .take(8)
                .collect::<String>()
        })
        .unwrap_or_else(|_| "unknown".to_string());
    
    // Get rustc version
    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_string()
        })
        .unwrap_or_else(|_| "unknown".to_string());
    
    // Generate build timestamp as epoch time
    let build = chrono::Utc::now().timestamp().to_string();
    
    // Set environment variables for the build
    println!("cargo:rustc-env=MPC_VERSION={}", version);
    println!("cargo:rustc-env=MPC_BUILD={}", build);
    println!("cargo:rustc-env=MPC_COMMIT={}", commit);
    println!("cargo:rustc-env=MPC_RUSTC_VERSION={}", rustc_version);
    
    // Re-run if any of these files change
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
} 