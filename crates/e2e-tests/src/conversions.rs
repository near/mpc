//! Small conversion helpers between types used in tests (e.g.
//! [`ed25519_dalek::SigningKey`]) and their `near_kit` counterparts.
//!
//! Grouped into one module so they are easy to find and relocate later.

use ed25519_dalek::SigningKey;

pub trait ToNearKey {
    fn to_near_public_key(&self) -> near_kit::signer::PublicKey;
    fn to_near_secret_key(&self) -> near_kit::signer::SecretKey;
}

impl ToNearKey for SigningKey {
    fn to_near_public_key(&self) -> near_kit::signer::PublicKey {
        near_kit::signer::PublicKey::ed25519_from_bytes(self.verifying_key().to_bytes())
            .expect("an ed25519_dalek verifying key is always a valid curve point")
    }

    fn to_near_secret_key(&self) -> near_kit::signer::SecretKey {
        near_kit::signer::SecretKey::ed25519_from_bytes(self.to_bytes())
    }
}

// TEMPORARY, TODO(#4801): near-kit is on near-account-id 2.x and the contract types on 3.x, so
// the two `AccountId` types are converted by string until near-kit moves to 3.x. Remove both
// traits and their call sites then.
pub trait ToContractAccountId {
    fn to_contract_account_id(&self) -> near_account_id::AccountId;
}

impl ToContractAccountId for near_kit::AccountId {
    fn to_contract_account_id(&self) -> near_account_id::AccountId {
        self.as_str()
            .parse()
            .expect("an account id near-kit accepts is valid under near-account-id 3.x")
    }
}

pub trait ToNearKitAccountId {
    fn to_near_kit_account_id(&self) -> near_kit::AccountId;
}

impl ToNearKitAccountId for near_account_id::AccountId {
    fn to_near_kit_account_id(&self) -> near_kit::AccountId {
        self.as_str()
            .parse()
            .expect("the e2e accounts are valid under near-account-id 2.x")
    }
}
