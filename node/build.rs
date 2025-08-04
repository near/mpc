use std::env;
use std::process::Command;
use anyhow::Result;

fn main() {
    if let Err(err) = try_main() {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
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
    
    // Generate build timestamp as epoch time
    let build = chrono::Utc::now().timestamp().to_string();
    
    // Set environment variables for the build
    println!("cargo:rustc-env=MPC_VERSION={}", version);
    println!("cargo:rustc-env=MPC_BUILD={}", build);
    println!("cargo:rustc-env=MPC_RUSTC_VERSION={}", rustc_version::version()?);
    println!("cargo:rustc-env=MPC_COMMIT={}", commit);
    
    Ok(())
} 