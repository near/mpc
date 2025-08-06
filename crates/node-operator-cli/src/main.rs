use std::{net::SocketAddr, time::Duration};

use clap::{Parser, ValueEnum};
use mpc_types::node_web_server::StaticWebData;
use near_crypto_published::{InMemorySigner, PublicKey, Signer};
use near_jsonrpc_client::{JsonRpcClient, methods};
use near_primitives::{
    account::AccessKey,
    action::{Action, AddKeyAction},
    transaction::SignedTransaction,
    types::Nonce,
    views::TxExecutionStatus,
};
use near_sdk::AccountId;
use rand::{RngCore, thread_rng};
use shadow_rs::shadow;
use tokio_util::time::FutureExt;

shadow!(build);

const TEST_NET_URL: &str = "https://rpc.testnet.near.org";
const MAIN_NET_URL: &str = "https://rpc.mainnet.near.org";

const TRANSACTION_TIMEOUT_DURATION: Duration = Duration::from_secs(10);

/// Simple program to greet a person
///
///
/// Example usage
/// ```
/// ACCOUNT_PRIVATE_KEY="ed25519:1111111111111111111111111111111111111111111111111111111111111111" mpc-node-operator-cli --network mainnet --node-web-address "192.168.1.1:23"
/// ```
#[derive(Parser, Debug, Clone)]
#[command(version = build::CLAP_LONG_VERSION, about, long_about = None)]
struct Args {
    #[arg(long)]
    network: Network,
    #[arg(long)]
    account_id: AccountId,
    #[arg(env("ACCOUNT_PRIVATE_KEY"))]
    account_private_key: near_crypto_published::SecretKey,
    #[arg(long)]
    node_web_address: SocketAddr,
}

#[derive(Debug, Clone, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
}

// /// Adds the given access key to this account.
// pub async fn add_access_key(account_id: AccountId, key: PublicKey) {
//     println!("Adding access key {} to account {}", key, account_id);
//     let request = methods::send_tx::RpcSendTransactionRequest {
//         signed_transaction: SignedTransaction::from_actions(
//             self.next_nonce().await,
//             self.account_id.clone(),
//             self.account_id.clone(),
//             &self.signer,
//             vec![Action::AddKey(Box::new(AddKeyAction {
//                 access_key: AccessKey {
//                     nonce: 0,
//                     permission: near_primitives::account::AccessKeyPermission::FullAccess,
//                 },
//                 public_key: key,
//             }))],
//             self.recent_block_hash,
//             0,
//         ),
//         wait_until: TxExecutionStatus::Final,
//     };
//     self.client.submit(request).await.unwrap();
// }

impl Network {
    fn new_rpc_client(&self) -> JsonRpcClient {
        let server_address = match self {
            Network::Mainnet => MAIN_NET_URL,
            Network::Testnet => TEST_NET_URL,
        };

        JsonRpcClient::connect(server_address)
    }
}

// {
//   "account_id": "example",
//   "public_key": "ed25519:6DSjZ8mvsRZDvFqFxo8tCKePG96omXW7eVYVSySmDk8e",
//   "secret_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr"
// }

fn get_node_data() -> StaticWebData<near_crypto_published::PublicKey> {
    todo!()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let rpc_client = args.network.new_rpc_client();

    let nonce: Nonce = thread_rng().next_u64();
    let signer: Signer =
        InMemorySigner::from_secret_key(args.account_id.clone(), args.account_private_key.clone())
            .into();

    let web_data: StaticWebData<PublicKey> = get_node_data();

    let recent_block_hash = rpc_client
        .call(methods::block::RpcBlockRequest {
            block_reference: near_primitives::types::BlockReference::Finality(
                near_primitives::types::Finality::Final,
            ),
        })
        .timeout(TRANSACTION_TIMEOUT_DURATION)
        .await
        .expect("RPC node is reachable and responsive seconds within timeout.")
        .unwrap()
        .header
        .hash;

    // 1. process responder keys
    for responder_public_key in web_data.near_responder_public_keys {
        let request = methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: SignedTransaction::from_actions(
                nonce,
                args.account_id.clone(),
                args.account_id.clone(),
                &signer,
                vec![Action::AddKey(Box::new(AddKeyAction {
                    access_key: AccessKey {
                        nonce: 0,
                        permission: near_primitives::account::AccessKeyPermission::FullAccess,
                    },
                    public_key: responder_public_key,
                }))],
                recent_block_hash,
                0,
            ),
            wait_until: TxExecutionStatus::Final,
        };

        rpc_client.call(request).await.unwrap();
    }

    // TODO:
    // 2. Process account key

    let request = methods::send_tx::RpcSendTransactionRequest {
        signed_transaction: SignedTransaction::from_actions(
            nonce,
            args.account_id.clone(),
            args.account_id.clone(),
            &signer,
            vec![Action::AddKey(Box::new(AddKeyAction {
                access_key: AccessKey {
                    nonce: 0,
                    permission: near_primitives::account::AccessKeyPermission::FullAccess,
                },
                public_key: web_data.near_signer_public_key,
            }))],
            recent_block_hash,
            0,
        ),
        wait_until: TxExecutionStatus::Final,
    };

    rpc_client.call(request).await.unwrap();

    // rpc_client.
}
