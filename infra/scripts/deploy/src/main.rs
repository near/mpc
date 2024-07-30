use clap::Parser;
use digest::{Digest, FixedOutput};
use k256::elliptic_curve::ops::Reduce;
use k256::{FieldBytes, Secp256k1};
use near_workspaces::AccountId;

#[derive(Parser, Debug)]
pub enum Cli {
    Check {
        #[arg(long, default_value("testnet"))]
        network: String,
        #[arg(long, default_value("v1.signer-dev.testnet"))]
        mpc_contract_id: AccountId,
    },
}

const CONTRACT_BYTES: &[u8] =
    include_bytes!("../../../../target/wasm32-unknown-unknown/release/mpc_contract.wasm");

fn main() -> anyhow::Result<()> {
    run(Cli::parse())
}

// Can directly call `cargo test` to run this script instead of getting the binary and passing in params:
#[test]
fn run_dev() {
    run(Cli::Check {
        network: "testnet".to_string(),
        mpc_contract_id: "v1.signer-dev.testnet".parse().unwrap(),
    })
    .unwrap();
}

// Can directly call `cargo test` to run this script instead of getting the binary and passing in params:
#[test]
fn run_testnet() {
    run(Cli::Check {
        network: "testnet".to_string(),
        mpc_contract_id: "v1.signer-prod.testnet".parse().unwrap(),
    })
    .unwrap();
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli {
        Cli::Check {
            network,
            mpc_contract_id,
        } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let worker = near_workspaces::sandbox().await.unwrap();
                let local = worker.dev_create_account().await.unwrap();
                let importer =
                    match network.as_str() {
                        "testnet" => worker
                            .import_contract(&mpc_contract_id, &near_workspaces::testnet().await?),
                        "mainnet" => worker
                            .import_contract(&mpc_contract_id, &near_workspaces::mainnet().await?),
                        _ => anyhow::bail!("Unknown network: {network}"),
                    };

                let contract = importer
                    .with_data()
                    .dest_account_id(local.id())
                    .transact()
                    .await?;

                let execution = contract.as_account().deploy(CONTRACT_BYTES).await?;
                let new_contract = execution.into_result()?;

                // Check the contract state is migratable:
                let migrate = new_contract
                    .call("migrate")
                    .max_gas()
                    .transact()
                    .await
                    .unwrap();
                dbg!(&migrate);

                // Check the contract state is viewable:
                let view = new_contract.view("state").await.unwrap();
                let state: mpc_contract::ProtocolContractState = view.json()?;
                println!("Contract state: {state:#?}");

                let msg = "hello world";
                let path = "deploy-check";
                let (_, _, payload_hash) = process_message(msg).await;
                let request = mpc_contract::primitives::SignRequest {
                    payload: payload_hash,
                    path: path.into(),
                    key_version: 0,
                };

                // Check that we can call into `sign`:
                let status = contract
                    .call("sign")
                    .args_json(serde_json::json!({
                        "request": request,
                    }))
                    .deposit(near_workspaces::types::NearToken::from_yoctonear(1))
                    .max_gas()
                    .transact_async()
                    .await?;

                let status = status.await?;
                dbg!(&status);
                assert!(status.is_failure(), "expected to timeout");

                // TODO: add response in.

                anyhow::Ok(())
            })
        }
    }
}

// TODO: Move this to a shared library alongside contract testing code
/// Process the message, creating the same hash with type of Digest, Scalar, and [u8; 32]
pub async fn process_message(msg: &str) -> (impl Digest, k256::Scalar, [u8; 32]) {
    let msg = msg.as_bytes();
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);
    let bytes: FieldBytes = digest.clone().finalize_fixed();
    let scalar_hash =
        <k256::Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            &bytes,
        );

    let payload_hash: [u8; 32] = bytes.into();
    (digest, scalar_hash, payload_hash)
}
