pub const fn current_mainnet() -> &'static [u8] {
    version_3_2_0()
}

pub const fn current_testnet() -> &'static [u8] {
    version_3_2_0()
}

pub const fn version_2_2_0() -> &'static [u8; 566653] {
    include_bytes!("../archive/signer-2_2_0.wasm")
}

pub const fn version_3_0_2() -> &'static [u8; 1165236] {
    include_bytes!("../archive/signer-3_0_2.wasm")
}

pub const fn version_3_2_0() -> &'static [u8; 1201393] {
    include_bytes!("../archive/signer-3_2_0.wasm")
}

#[cfg(test)]
#[cfg(feature = "external-services-tests")]
mod tests {
    use super::*;

    use sha2::Digest;

    #[tokio::test]
    async fn mainnet_contract_should_be_up_to_date() {
        let on_chain_right_now =
            fetch_contract_code_hash("https://rpc.mainnet.near.org", "v1.signer").await;

        assert_eq!(hash(current_mainnet()), on_chain_right_now);
    }

    #[tokio::test]
    async fn testnet_contract_should_be_up_to_date() {
        let on_chain_right_now =
            fetch_contract_code_hash("https://rpc.testnet.near.org", "v1.signer-prod.testnet")
                .await;

        assert_eq!(hash(current_testnet()), on_chain_right_now);
    }

    async fn fetch_contract_code_hash(rpc_endpoint: &str, account_id: &str) -> [u8; 32] {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "dontcare",
            "method": "query",
            "params": {
                "request_type": "view_account",
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

        bs58::decode(&response.result.code_hash)
            .into_vec()
            .expect("response should be base58 encoded")
            .try_into()
            .expect("should be 32 bytes")
    }

    fn hash(code: &[u8]) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(code);
        hasher.finalize().into()
    }

    #[derive(serde::Deserialize)]
    struct RpcResponse {
        result: RpcResult,
    }

    #[derive(serde::Deserialize)]
    struct RpcResult {
        code_hash: String,
    }
}
