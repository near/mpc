pub mod actions;

use crate::with_multichain_nodes;
use actions::wait_for;
use k256::elliptic_curve::point::AffineCoordinates;
use mpc_recovery_node::kdf::{self, x_coordinate};
use mpc_recovery_node::util::{NearPublicKeyExt, ScalarExt};
use test_log::test;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    with_multichain_nodes(3, |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);

            let account = ctx.nodes.ctx().worker.dev_create_account().await?;
            ctx.nodes
                .add_node(account.id(), account.secret_key())
                .await?;

            let state_1 = wait_for::running_mpc(&ctx, 1).await?;
            assert_eq!(state_1.participants.len(), 4);

            assert_eq!(
                state_0.public_key, state_1.public_key,
                "public key must stay the same"
            );

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_triples_and_presignatures() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            // TODO: add test that checks #triples in datastore
            // for account_id in state_0.participants.keys() {
            //     let triple_storage = ctx.nodes.triple_storage(account_id.to_string()).await?;
            //     // This errs out with
            //     // Err(GcpError(BadRequest(Object {"error": Object {"code": Number(400), "message": String("Payload isn't valid for request."), "status": String("INVALID_ARGUMENT")}})))
            //     let _load_res = triple_storage.load().await;
            //     //print!("result is: {:?}", load_res);
            //     //assert_eq!(load_res.len(), 6);
            // }
            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_production(&ctx, &state_0).await
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_key_derivation() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;

            for _ in 0..5 {
                let mpc_pk: k256::AffinePoint = state_0.public_key.clone().into_affine_point();
                let (_, payload_hashed, account, tx_hash) = actions::request_sign(&ctx).await?;
                let payload_hashed_rev = {
                    let mut rev = payload_hashed.clone();
                    rev.reverse();
                    rev
                };
                let sig = wait_for::signature_responded(&ctx, tx_hash).await?;

                let hd_path = "test";
                let derivation_epsilon = kdf::derive_epsilon(account.id(), hd_path);
                let user_pk = kdf::derive_key(mpc_pk.clone(), derivation_epsilon);
                let multichain_sig =
                    kdf::into_eth_sig(&user_pk, &sig, k256::Scalar::from_bytes(&payload_hashed))
                        .unwrap();

                // start recovering the address and compare them:
                let user_pk_x = kdf::x_coordinate::<k256::Secp256k1>(&user_pk);
                let user_pk_y_parity = match user_pk.y_is_odd().unwrap_u8() {
                    1 => secp256k1::Parity::Odd,
                    0 => secp256k1::Parity::Even,
                    _ => unreachable!(),
                };
                let user_pk_x =
                    secp256k1::XOnlyPublicKey::from_slice(&user_pk_x.to_bytes()).unwrap();
                let user_secp_pk =
                    secp256k1::PublicKey::from_x_only_public_key(user_pk_x, user_pk_y_parity);
                let user_addr = actions::public_key_to_address(&user_secp_pk);
                let r = x_coordinate::<k256::Secp256k1>(&multichain_sig.big_r);
                let s = multichain_sig.s;
                let signature_for_recovery: [u8; 64] = {
                    let mut signature = [0u8; 64];
                    signature[..32].copy_from_slice(&r.to_bytes());
                    signature[32..].copy_from_slice(&s.to_bytes());
                    signature
                };
                let recovered_addr = web3::signing::recover(
                    &payload_hashed_rev,
                    &signature_for_recovery,
                    multichain_sig.recovery_id as i32,
                )
                .unwrap();
                assert_eq!(user_addr, recovered_addr);
            }

            Ok(())
        })
    })
    .await
}
