use base64::Engine;
use clap::Parser;
use std::path::PathBuf;

async fn download_mainnet_contract() -> Vec<u8> {
    fetch_contract_code("https://rpc.mainnet.near.org", "v1.signer").await
}

async fn download_testnet_contract() -> Vec<u8> {
    fetch_contract_code("https://rpc.testnet.near.org", "v1.signer-prod.testnet").await
}

async fn fetch_contract_code(rpc_endpoint: &str, account_id: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "dontcare",
        "method": "query",
        "params": {
            "request_type": "view_code",
            "finality": "final",
            "account_id": account_id
        }
    });

    let response = reqwest::Client::new()
        .post(rpc_endpoint)
        .timeout(std::time::Duration::from_secs(10))
        .json(&body)
        .send()
        .await
        .expect("contract request should succeed")
        .json::<RpcResponse>()
        .await
        .expect("contract response should be valid JSON");
    let engine = base64::engine::general_purpose::STANDARD;
    engine
        .decode(&response.result.code_base64)
        .expect("response should be base64 encoded")
}

#[derive(serde::Deserialize)]
struct RpcResponse {
    result: RpcResult,
}

#[derive(serde::Deserialize)]
struct RpcResult {
    code_base64: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.target_dir)?;

    std::fs::write(
        args.target_dir.join("signer_mainnet.wasm"),
        download_mainnet_contract().await,
    )?;

    std::fs::write(
        args.target_dir.join("signer_testnet.wasm"),
        download_testnet_contract().await,
    )?;

    println!("Copied contracts to {}", args.target_dir.display());

    Ok(())
}

#[derive(Parser)]
pub struct Args {
    #[arg(short, long, help = "Where to export the contracts to")]
    target_dir: PathBuf,
}
