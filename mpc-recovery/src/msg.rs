use curv::elliptic::curves::{Ed25519, Point};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::transaction::CreateAccountOptions;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewAccountRequest {
    pub create_account_options: CreateAccountOptions,
    pub near_account_id: String,
    pub oidc_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NewAccountResponse {
    Ok {
        create_account_options: CreateAccountOptions,
        user_recovery_public_key: String,
        near_account_id: String,
    },
    Err {
        msg: String,
    },
}

impl NewAccountResponse {
    pub fn err(msg: String) -> Self {
        NewAccountResponse::Err { msg }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddKeyRequest {
    pub create_account_options: CreateAccountOptions,
    pub near_account_id: Option<String>,
    pub oidc_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AddKeyResponse {
    Ok {
        full_access_keys: Vec<String>,
        limited_access_keys: Vec<String>,
        near_account_id: String,
    },
    Err {
        msg: String,
    },
}

impl AddKeyResponse {
    pub fn err(msg: String) -> Self {
        AddKeyResponse::Err { msg }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LeaderRequest {
    pub payload: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum LeaderResponse {
    Ok {
        #[serde(with = "hex_sig_share")]
        signature: Signature,
    },
    Err,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigShareRequest {
    pub oidc_token: String,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AcceptNodePublicKeysRequest {
    pub public_keys: Vec<Point<Ed25519>>,
}

mod hex_sig_share {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig_share: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = hex::encode(Signature::to_bytes(*sig_share));
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature::from_bytes(
            &<[u8; Signature::BYTE_SIZE]>::try_from(
                hex::decode(s).map_err(serde::de::Error::custom)?,
            )
            .map_err(|v: Vec<u8>| {
                serde::de::Error::custom(format!(
                    "signature has incorrect length: expected {} bytes, but got {}",
                    Signature::BYTE_SIZE,
                    v.len()
                ))
            })?,
        )
        .map_err(serde::de::Error::custom)
    }
}
