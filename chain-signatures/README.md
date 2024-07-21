# Chain Signatures API

## `sign()`
This is the main function of the contract API. It is used to sign a request with the MPC service.
```rust
pub fn sign(&mut self, request: SignRequest) -> Result<near_sdk::Promise, SignError>
```
Arguments and return type:
```rust
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

pub struct SignResult {
    pub big_r: String,
    pub s: String,
}
```
- `key_version` must be less than or equal to the value at `latest_key_version`.
- `path` is a derivation path for the key that will be used to sign the payload.
- To avoid overloading the network with too many requests, we ask for a small deposit for each signature request. The fee changes based on how busy the network is.

## `public_key()`
This is the root public key combined from all the public keys of the participants.
```rust
pub fn public_key(&self) -> Result<PublicKey, PublicKeyError>
```

## `derived_public_key()`
This is the derived public key of the caller given path and predecessor. If the predecessor is not provided, it will be the caller of the contract.
```rust
pub fn derived_public_key(
        &self,
        path: String,
        predecessor: Option<AccountId>,
    ) -> Result<PublicKey, PublicKeyError>
```

## `latest_key_version()`
Key versions refer new versions of the root key that we may choose to generate on cohort changes. Older key versions will always work but newer key versions were never held by older signers. Newer key versions may also add new security features, like only existing within a secure enclave. Currently only 0 is a valid key version.
```rust
pub const fn latest_key_version(&self) -> u32
```

For more details check `User contract API` impl block in the [chain-signatures/contracts/src/lib.rs](./chain-signatures/contracts/src/lib.rs) file.

# Environments
Currently, we have 3 environments:
1. Mainnet: `v1.multichain-mpc.near` // TODO: set when available
2. Testnet: `v2.multichain-mpc.testnet`
3. Dev: `v5.multichain-mpc-dev.testnet`

Contracts can be changed from v1 to v2, etc. Older contracts should continue functioning.