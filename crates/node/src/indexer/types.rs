use crate::trait_extensions::convert_to_contract_dto::IntoContractInterfaceType;
use crate::types::{SignatureRequest, VerifyForeignTxRequest};
use anyhow::Context;
use k256::{
    AffinePoint, Scalar, Secp256k1,
    ecdsa::RecoveryId,
    elliptic_curve::{Curve, CurveArithmetic, ops::Reduce, point::AffineCoordinates},
};
use near_contract_transport::{FunctionCallArgs, NearGas, NearToken};
use near_mpc_contract_interface::call_args as contract_args;
use near_mpc_contract_interface::method_names::{
    CONCLUDE_NODE_MIGRATION, REGISTER_FOREIGN_CHAINS_CONFIG, RESPOND, RESPOND_CKD,
    RESPOND_VERIFY_FOREIGN_TX, START_KEYGEN_INSTANCE, START_RESHARE_INSTANCE, VERIFY_TEE,
    VOTE_ABORT_KEY_EVENT_INSTANCE, VOTE_PK, VOTE_RESHARED,
};
use near_mpc_contract_interface::types::{self as dtos};
use serde::Serialize;
use threshold_signatures::ecdsa::Signature;
use threshold_signatures::frost_ed25519;
use threshold_signatures::frost_secp256k1::VerifyingKey;

#[expect(deprecated)]
use near_mpc_contract_interface::method_names::REGISTER_FOREIGN_CHAIN_CONFIG;

// TODO(#166): This is too high in most settings
const MAX_GAS: NearGas = NearGas::from_tgas(300);

const MAX_RECOVERY_ID: u8 = 3;

fn k256_signature_response(
    big_r: AffinePoint,
    s: Scalar,
    recovery_id: u8,
) -> anyhow::Result<dtos::SignatureResponse> {
    if recovery_id > MAX_RECOVERY_ID {
        anyhow::bail!("Invalid Recovery Id: recovery id larger than 3.");
    }
    Ok(dtos::SignatureResponse::Secp256k1(dtos::K256Signature {
        big_r: dtos::K256AffinePoint::from(big_r),
        s: dtos::K256Scalar::from(s),
        recovery_id,
    }))
}
pub trait ChainRespondArgs {}

impl ChainRespondArgs for contract_args::SignatureRespondArgs {}
impl ChainRespondArgs for contract_args::CKDRespondArgs {}
impl ChainRespondArgs for contract_args::VerifyForeignTransactionRespondArgs {}

/// Request to send a transaction to the contract on chain.
#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum ChainSendTransactionRequest {
    Respond(contract_args::SignatureRespondArgs),
    CKDRespond(contract_args::CKDRespondArgs),
    VotePk(contract_args::VotePkArgs),
    StartKeygen(contract_args::StartKeygenArgs),
    VoteReshared(contract_args::VoteResharedArgs),
    RegisterForeignChainConfig(contract_args::RegisterForeignChainConfigArgs),
    RegisterForeignChainsConfig(contract_args::RegisterForeignChainsConfigArgs),
    StartReshare(contract_args::StartReshareArgs),
    VoteAbortKeyEventInstance(contract_args::VoteAbortKeyEventInstanceArgs),
    VerifyTee(),
    ConcludeNodeMigration(contract_args::ConcludeNodeMigrationArgs),
    VerifyForeignTransactionRespond(contract_args::VerifyForeignTransactionRespondArgs),
}

impl ChainSendTransactionRequest {
    pub fn method(&self) -> &'static str {
        match self {
            ChainSendTransactionRequest::Respond(_) => RESPOND,
            ChainSendTransactionRequest::CKDRespond(_) => RESPOND_CKD,
            ChainSendTransactionRequest::VotePk(_) => VOTE_PK,
            ChainSendTransactionRequest::VoteReshared(_) => VOTE_RESHARED,
            ChainSendTransactionRequest::RegisterForeignChainConfig(_) =>
            {
                #[expect(deprecated)]
                REGISTER_FOREIGN_CHAIN_CONFIG
            }
            ChainSendTransactionRequest::RegisterForeignChainsConfig(_) => {
                REGISTER_FOREIGN_CHAINS_CONFIG
            }
            ChainSendTransactionRequest::StartReshare(_) => START_RESHARE_INSTANCE,
            ChainSendTransactionRequest::StartKeygen(_) => START_KEYGEN_INSTANCE,
            ChainSendTransactionRequest::VoteAbortKeyEventInstance(_) => {
                VOTE_ABORT_KEY_EVENT_INSTANCE
            }
            ChainSendTransactionRequest::VerifyTee() => VERIFY_TEE,
            ChainSendTransactionRequest::ConcludeNodeMigration(_) => CONCLUDE_NODE_MIGRATION,
            ChainSendTransactionRequest::VerifyForeignTransactionRespond(_) => {
                RESPOND_VERIFY_FOREIGN_TX
            }
        }
    }

    pub fn gas_required(&self) -> NearGas {
        match self {
            Self::Respond(_)
            | Self::CKDRespond(_)
            | Self::VotePk(_)
            | Self::VoteReshared(_)
            | Self::RegisterForeignChainConfig(_)
            | Self::RegisterForeignChainsConfig(_)
            | Self::StartReshare(_)
            | Self::StartKeygen(_)
            | Self::VoteAbortKeyEventInstance(_)
            | Self::VerifyTee()
            | Self::ConcludeNodeMigration(_)
            | Self::VerifyForeignTransactionRespond(_) => MAX_GAS,
        }
    }

    /// The queue currency of the transaction processor: the request's method,
    /// serialized arguments, gas, and deposit. Every enum-sent method attaches
    /// zero deposit.
    pub fn into_function_call(self) -> Result<FunctionCallArgs, serde_json::Error> {
        Ok(FunctionCallArgs {
            method_name: self.method().to_string(),
            gas: self.gas_required(),
            deposit: NearToken::from_yoctonear(0),
            args: serde_json::to_vec(&self)?,
        })
    }
}

/// Extension trait for constructing SignatureRespond arguments from node-internal types.
pub trait SignatureRespondArgsExt {
    fn from_ecdsa(
        request: &SignatureRequest,
        response: &Signature,
        public_key: &VerifyingKey,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn from_eddsa(
        request: &SignatureRequest,
        response: &frost_ed25519::Signature,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl SignatureRespondArgsExt for contract_args::SignatureRespondArgs {
    fn from_ecdsa(
        request: &SignatureRequest,
        response: &Signature,
        public_key: &VerifyingKey,
    ) -> anyhow::Result<Self> {
        let recovery_id = brute_force_recovery_id(
            &public_key.to_element().to_affine(),
            response,
            request
                .payload
                .as_ecdsa()
                .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?,
        )?;
        Ok(contract_args::SignatureRespondArgs::new(
            request.into_contract_interface_type(),
            k256_signature_response(response.big_r, response.s, recovery_id)?,
        ))
    }

    fn from_eddsa(
        request: &SignatureRequest,
        response: &frost_ed25519::Signature,
    ) -> anyhow::Result<Self> {
        let response: [u8; 64] = response
            .serialize()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Response is not 64 bytes"))?;

        Ok(contract_args::SignatureRespondArgs::new(
            request.into_contract_interface_type(),
            dtos::SignatureResponse::Ed25519 {
                signature: dtos::Ed25519Signature::from(response),
            },
        ))
    }
}

/// Brute forces the recovery id to find a recovery_id that matches the public key
pub(crate) fn brute_force_recovery_id(
    expected_pk: &AffinePoint,
    signature: &Signature,
    msg_hash: &[u8; 32],
) -> anyhow::Result<u8> {
    let partial_signature = k256::ecdsa::Signature::from_scalars(
        <<Secp256k1 as CurveArithmetic>::Scalar as Reduce<<Secp256k1 as Curve>::Uint>>
        ::reduce_bytes(&signature.big_r.x()), signature.s)
        .context("Cannot create signature from cait_sith signature")?;
    let expected_pk = match k256::ecdsa::VerifyingKey::from_affine(*expected_pk) {
        Ok(pk) => pk,
        _ => anyhow::bail!("The affine point cannot be transformed into a verifying key"),
    };
    match RecoveryId::trial_recovery_from_prehash(&expected_pk, msg_hash, &partial_signature) {
        Ok(rec_id) => Ok(rec_id.to_byte()),
        _ => anyhow::bail!(
            "No recovery id found for such a tuple of public key, signature, message hash"
        ),
    }
}

pub trait VerifyForeignTransactionRespondArgsExt {
    fn from_signature(
        request: VerifyForeignTxRequest,
        payload_hash: dtos::Hash256,
        signature: Signature,
        public_key: VerifyingKey,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl VerifyForeignTransactionRespondArgsExt for contract_args::VerifyForeignTransactionRespondArgs {
    fn from_signature(
        request: VerifyForeignTxRequest,
        payload_hash: dtos::Hash256,
        signature: Signature,
        public_key: VerifyingKey,
    ) -> anyhow::Result<Self> {
        let recovery_id = brute_force_recovery_id(
            &public_key.to_element().to_affine(),
            &signature,
            payload_hash.as_ref(),
        )?;

        let dto_signature = dtos::K256Signature {
            big_r: dtos::K256AffinePoint::from(signature.big_r),
            s: dtos::K256Scalar::from(signature.s),
            recovery_id,
        };
        Ok(contract_args::VerifyForeignTransactionRespondArgs::new(
            dtos::VerifyForeignTransactionRequest {
                request: request.request,
                domain_id: request.domain_id,
                payload_version: request.payload_version,
            },
            dtos::VerifyForeignTransactionResponse {
                payload_hash,
                signature: dtos::SignatureResponse::Secp256k1(dto_signature),
            },
        ))
    }
}

// TODO(#1957): This code does not belong here in the indexer module
#[cfg(test)]
mod recovery_id_tests {
    use crate::indexer::types::brute_force_recovery_id;
    use k256::AffinePoint;
    use k256::ecdsa::{RecoveryId, SigningKey};
    use k256::elliptic_curve::{PrimeField, point::DecompressPoint};
    use rand::rngs::OsRng;
    use threshold_signatures::ecdsa::Signature;

    #[test]
    fn test_brute_force_recovery_id() {
        for _ in 0..256 {
            // generate a pair of ecdsa keys
            let mut rng = OsRng;
            let signing_key = SigningKey::random(&mut rng);

            // compute a signature with recovery id
            let prehash: [u8; 32] = rand::random();
            match signing_key.sign_prehash_recoverable(&prehash) {
                // match signing_key.sign_digest_recoverable(digest) {
                Ok((signature, recid)) => {
                    let (r, s) = signature.split_scalars();

                    // Create a full signature
                    // any big_r creation works here as we only need its x coordinate during brute force (big_r.x())

                    let r_bytes = r.to_repr();
                    let hypothetical_big_r = AffinePoint::decompress(&r_bytes, 0.into()).unwrap();

                    let full_sig = Signature {
                        big_r: hypothetical_big_r,
                        s: *s.as_ref(),
                    };

                    let tested_recid = brute_force_recovery_id(
                        signing_key.verifying_key().as_affine(),
                        &full_sig,
                        &prehash,
                    )
                    .unwrap();

                    // compute recovery_id using our function
                    let tested_recid = RecoveryId::from_byte(tested_recid).unwrap();

                    assert!(tested_recid.is_x_reduced() == recid.is_x_reduced());
                    assert!(tested_recid.is_y_odd() == recid.is_y_odd());
                }
                Err(_) => panic!("The signature in the test has failed"),
            }
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod request_serialization_tests {
    use super::{ChainSendTransactionRequest, MAX_GAS, START_KEYGEN_INSTANCE, contract_args, dtos};

    /// The queue message carries the request as the bare on-chain call args
    /// (the enum is `#[serde(untagged)]`), keyed by the variant's method name.
    #[test]
    fn into_function_call__should_carry_the_bare_args_under_the_variant_method() {
        // Given
        let args = contract_args::StartKeygenArgs::new(dtos::KeyEventId::new(
            dtos::EpochId::new(1),
            dtos::DomainId(2),
            dtos::AttemptId::new(),
        ));
        let expected_args = serde_json::to_vec(&args).unwrap();
        let request = ChainSendTransactionRequest::StartKeygen(args);

        // When
        let call = request.into_function_call().unwrap();

        // Then
        assert_eq!(call.method_name, START_KEYGEN_INSTANCE);
        assert_eq!(call.gas, MAX_GAS);
        assert_eq!(call.deposit.as_yoctonear(), 0);
        assert_eq!(call.args, expected_args);
    }
}
