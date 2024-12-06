use crate::metrics;
use crate::sign_request::SignatureRequest;
use cait_sith::FullSignature;
use k256::{
     AffinePoint,
     elliptic_curve::point::AffineCoordinates,
     elliptic_curve::PrimeField,
     elliptic_curve::ops::Reduce,
     elliptic_curve::bigint::U256,
     Scalar,
     Secp256k1
    };
use near_client;
use near_crypto::KeyFile;
use near_indexer_primitives::near_primitives::transaction::{
    FunctionCallAction, SignedTransaction, Transaction, TransactionV0,
};
use near_indexer_primitives::types::AccountId;
use near_o11y::WithSpanContextExt;
use serde::Serialize;
use std::path::Path;
use tokio::sync::mpsc;

pub fn load_near_credentials(home_dir: &Path, filename: String) -> anyhow::Result<KeyFile> {
    let path = home_dir.join(filename);
    Ok(KeyFile::from_file(&path)?)
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy)]
struct SerializableScalar {
    pub scalar: Scalar,
}

impl From<Scalar> for SerializableScalar {
    fn from(scalar: Scalar) -> Self {
        SerializableScalar { scalar }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy)]
struct SerializableAffinePoint {
    pub affine_point: AffinePoint,
}


pub enum ChainSignatureError {
    InvalidRecoveryId,
}

/* The format in which the chain signatures contract expects
 * to receive the details of the original request. `serializable_tweak`
 * is used to refer to the tweak derived from the caller's
 * account id and the derivation path.
 */
#[derive(Serialize, Debug, Clone)]
struct ChainSignatureRequest {
    pub serializable_tweak: SerializableScalar,
    pub payload_hash: SerializableScalar,
}

impl ChainSignatureRequest {
    pub fn new(payload_hash: Scalar, tweak: Scalar) -> Self {
        let serializable_tweak = SerializableScalar { scalar: tweak };
        let payload_hash = SerializableScalar {
            scalar: payload_hash,
        };
        ChainSignatureRequest {
            serializable_tweak,
            payload_hash,
        }
    }
}

/* The format in which the chain signatures contract expects
 * to receive the completed signature.
 */
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct ChainSignatureResponse {
    pub big_r: SerializableAffinePoint,
    pub s: SerializableScalar,
    pub recovery_id: u8,
}

impl ChainSignatureResponse {
    const MAX_RECOVERY_ID: u8 = 3;
    pub fn new(big_r: AffinePoint, s: Scalar, recovery_id: u8) -> Result<Self,ChainSignatureError> {
        if recovery_id > Self::MAX_RECOVERY_ID {
            return Err(ChainSignatureError::InvalidRecoveryId);
        }
        Ok(ChainSignatureResponse {
            big_r: SerializableAffinePoint { affine_point: big_r },
            s: SerializableScalar { scalar: s },
            recovery_id,
        })
    }

    pub (crate) fn is_ok_or_panic( response : Result<Self, ChainSignatureError>) -> ChainSignatureResponse {
        match response {
            Ok(value) => value,
            Err(_) => panic!("Expected Chain Signature Response instead of error, panicking!"),
        }
    }
}

/* These arguments are passed to the `respond` function of the
 * chain signatures contract. It takes both the details of the
 * original request and the completed signature, then verifies
 * that the signature matches the requested key and payload.
 */
#[derive(Serialize)]
pub struct ChainRespondArgs {
    request: ChainSignatureRequest,
    response: ChainSignatureResponse,
}

impl ChainRespondArgs {
    /// WARNING: this function assumes the input full signature is valid and comes from an authentic response
    pub fn new(request: &SignatureRequest, response: &FullSignature<Secp256k1>) -> Self {
        // figure out correct recovery_id for the public key
        let recovery_id = Self::ecdsa_recovery_from_big_r(&response.big_r);
        ChainRespondArgs {
            request: ChainSignatureRequest::new(request.msg_hash, request.tweak),
            response: ChainSignatureResponse::is_ok_or_panic(
                        ChainSignatureResponse::new(response.big_r, response.s, recovery_id)
                    ),
        }
    }

    /// The recovery id is only made of two significant bits
    /// The lower bit determines the sign bit of the point R
    /// The higher bit determines whether the x coordinate of R exceeded
    /// the curve order when computing R_x mod p
    pub (crate) fn ecdsa_recovery_from_big_r (big_r: &AffinePoint) -> u8 {
        // compare Rx representation before and after reducing it modulo the group order
        let big_r_x = big_r.x();
        let reduced_big_r_x = <Scalar as Reduce<U256>>::reduce_bytes(&big_r_x);
        let is_x_reduced = reduced_big_r_x.to_repr() != big_r_x;


        // if Rx is larger than the group order then set recovery_id higher bit to 1
        // if Ry is odd then set recovery_id lower bit to 1
        return   (is_x_reduced as u8) << 1 | big_r.y_is_odd().unwrap_u8();



    }
}

pub(crate) async fn chain_sender(
    key_file: KeyFile,
    mpc_contract_id: AccountId,
    mut receiver: mpsc::Receiver<ChainRespondArgs>,
    client: actix::Addr<near_client::ClientActor>,
) {
    while let Some(respond_args) = receiver.recv().await {
        let Ok(response_ser) = serde_json::to_string(&respond_args) else {
            tracing::error!(target: "mpc", "Failed to serialize response args");
            continue;
        };

        let Ok(Ok(status)) = client
            .send(
                near_client::Status {
                    is_health_check: false,
                    detailed: false,
                }
                .with_span_context(),
            )
            .await
        else {
            continue;
        };
        let block_hash = status.sync_info.latest_block_hash;
        tracing::info!(target = "mpc", "tx args {:?}", response_ser);

        let action = FunctionCallAction {
            method_name: "respond".to_owned(),
            args: response_ser.into(),
            gas: 300000000000000,
            deposit: 0,
        };
        let transaction = Transaction::V0(TransactionV0 {
            signer_id: key_file.account_id.clone(),
            public_key: key_file.public_key.clone(),
            nonce: 10,
            receiver_id: mpc_contract_id.clone(),
            block_hash,
            actions: vec![action.into()],
        });

        let tx_hash = transaction.get_hash_and_size().0;
        tracing::info!(target = "mpc", "sending response tx {:?}", tx_hash);

        let signature = key_file.secret_key.sign(tx_hash.as_ref());

        metrics::MPC_NUM_SIGN_RESPONSES_SENT.inc();
        let _ = client
            .send(
                near_client::ProcessTxRequest {
                    transaction: SignedTransaction::new(signature, transaction.clone()),
                    is_forwarded: false,
                    check_only: false,
                }
                .with_span_context(),
            )
            .await;
    }
}

// Test the recovery_id generation
#[cfg(test)]
mod recovery_id_tests {
    use k256::AffinePoint;
    use k256::ecdsa::{ SigningKey, RecoveryId};
    use rand::rngs::OsRng;
    use k256::sha2::{Sha256, Digest};
    use k256::elliptic_curve::{point::DecompressPoint, PrimeField};
    use crate::indexer::response::ChainRespondArgs;

    #[test]
    fn test_ecdsa_recovery_from_big_r(){
        // generate a pair of ecdsa keys
        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);

        // compute a signature with recovery id
        let message = b"Testing ECDSA with recovery ID!";
        let digest = Sha256::new_with_prefix(message);
        match signing_key.sign_digest_recoverable(digest){
            Ok((signature, recid)) => {
                // recover R
                let (r, _) = signature.split_scalars();
                let r_bytes = r.to_repr();
                let big_r =  AffinePoint::decompress(&r_bytes, u8::from(recid.is_y_odd()).into())
                                        .unwrap();
                // compute recovery_id using our function
                let tested_recid = ChainRespondArgs::ecdsa_recovery_from_big_r(&big_r);
                let tested_recid = RecoveryId::from_byte(tested_recid).unwrap();

                assert!(tested_recid.is_x_reduced() == recid.is_x_reduced());
                assert!(tested_recid.is_y_odd() == recid.is_y_odd());
            },
            Err(_)  => assert!(false),
        }
    }
}