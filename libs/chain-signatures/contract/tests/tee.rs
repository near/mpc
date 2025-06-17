use common::init_env_ed25519;
use mpc_contract::state::ProtocolContractState;
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

// todo [#514](https://github.com/near/mpc/issues/514)
