pub const fn current_mainnet() -> &'static [u8] {
    version_2_2_0()
}

pub const fn current_testnet() -> &'static [u8] {
    version_2_2_0()
}

pub const fn version_2_2_0() -> &'static [u8; 566653] {
    include_bytes!("../archive/signer-2_2_0.wasm")
}

#[cfg(test)]
#[cfg(feature = "external-services-tests")]
mod tests {
    use super::*;

    use base64::{Engine as _, prelude::BASE64_STANDARD};

    #[tokio::test]
    async fn mainnet_contract_should_be_up_to_date() {
        let on_chain_right_now =
            fetch_contract_code("https://rpc.mainnet.near.org", "v1.signer").await;

        assert_eq!(current_mainnet(), on_chain_right_now);
    }

    #[tokio::test]
    async fn testnet_contract_should_be_up_to_date() {
        let on_chain_right_now =
            fetch_contract_code("https://rpc.testnet.near.org", "v1.signer-prod.testnet").await;

        assert_eq!(current_testnet(), on_chain_right_now);
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
            .json(&body)
            .send()
            .await
            .expect("contract request should succeed")
            .json::<RpcResponse>()
            .await
            .expect("contract response should be valid JSON");

        BASE64_STANDARD
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
}
