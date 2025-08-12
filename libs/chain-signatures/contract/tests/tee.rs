use common::{check_call_success, init_env_ed25519, init_env_secp256k1};
use mpc_contract::state::ProtocolContractState;
use mpc_primitives::hash::MpcDockerImageHash;
use near_workspaces::Contract;

pub mod common;

async fn get_participants(contract: &Contract) -> anyhow::Result<usize> {
    let state = contract
        .call("state")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?;
    let value: ProtocolContractState = state.json()?;
    let ProtocolContractState::Running(running) = value else {
        panic!("Expected running state")
    };
    Ok(running.parameters.participants().len())
}

#[tokio::test]
async fn test_tee_verify_no_tee() -> anyhow::Result<()> {
    let (_, contract, _, _) = init_env_ed25519(1).await;
    let n_participants_start = get_participants(&contract).await?;

    let verified_tee: bool = contract
        .call("verify_tee")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?
        .json()?;
    assert!(verified_tee);
    assert_eq!(n_participants_start, get_participants(&contract).await?);
    Ok(())
}

#[tokio::test]
async fn test_vote_code_hash() -> anyhow::Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;

    let mpc_hash = MpcDockerImageHash::from([
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56,
        0x78, 0x90,
    ]);
    let args = serde_json::json!({"code_hash": mpc_hash});

    // Helper function to get allowed hashes
    let get_allowed_hashes = || async {
        contract
            .call("allowed_code_hashes")
            .args_json(serde_json::json!(""))
            .max_gas()
            .transact()
            .await?
            .json::<Vec<MpcDockerImageHash>>()
    };

    // Helper function to get latest code hash
    let get_latest_code_hash = || async {
        contract
            .call("latest_code_hash")
            .args_json(serde_json::json!(""))
            .max_gas()
            .transact()
            .await?
            .json::<Option<MpcDockerImageHash>>()
    };

    // Helper function to vote on hash
    let vote_hash = |account_idx: usize| {
        let contract = &contract;
        let accounts = &accounts;
        let args = &args;
        async move {
            check_call_success(
                accounts[account_idx]
                    .call(contract.id(), "vote_code_hash")
                    .args_json(args)
                    .transact()
                    .await?,
            );
            Ok::<(), anyhow::Error>(())
        }
    };

    // First vote - should not be enough
    vote_hash(0).await?;
    assert_eq!(get_allowed_hashes().await?.len(), 0);
    // Should get an error when no code hash is available yet
    assert!(get_latest_code_hash().await.is_err());

    // Second vote - should reach threshold
    vote_hash(1).await?;
    let allowed_hashes = get_allowed_hashes().await?;
    assert_eq!(allowed_hashes, vec![mpc_hash.clone()]);
    // latest_code_hash should return the same hash as the one in allowed_code_hashes
    assert_eq!(get_latest_code_hash().await?, Some(mpc_hash.clone()));

    // Additional votes - should not change the allowed hashes
    for _ in 0..4 {
        vote_hash(2).await?;
        // Should still have exactly one hash
        let allowed_hashes = get_allowed_hashes().await?;
        assert_eq!(allowed_hashes, vec![mpc_hash.clone()]);
        // latest_code_hash should still return the same hash
        assert_eq!(get_latest_code_hash().await?, Some(mpc_hash.clone()));
    }

    Ok(())
}

// todo [#514](https://github.com/near/mpc/issues/514)
