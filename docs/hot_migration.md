# Background

HOT want to migrate their keyshares to our MPC network.

There are three challenges associated with this endeavor:
1. We need a way to add a domain by importing keyshares.
2. HOT uses a different authentication mechanism. While we look up the `predecessor_id` and derive the public key from that account, HOT has the notion of a _wallet_:
    1. A _wallet_ consits of a user generated public private ed25519 keypair;
    2. The MPC network uses the public key associated to the wallet to derive a public key owned by the MPC network
    3. For every wallet, a list of authorized accounts exists. Specifically, wallet to authorized accounts is a many-to-many mapping, meaning:
        1. A wallet can be controlled by multiple different user accounts.
        2. one user can control multiple wallets.
3. The key derivation mechanism used by HOT is at the moment unclear. Need to find documentation for that.


## Proposal

The authentication mechanism supported by HOT poses a challenge for our smart contract. For one, we currently don't need to worry about authentication at all, since the derived public key is tied to the account that sgned the signature request. For HOT wallets, this is different due to the above described authentication mechanism.

We must keep a strict separation between the domains used by HOT and the domains used by the rest of the MPC network, as, if we mix them, we might accidentally allow to spend another users balance.

As such, it might make sense to add the following endpoints to the contract:

From the foregin chain transaction doc:
```rust
pub enum DomainPurpose {
    Sign,
    ForeignTx,
    CKD,
}
```
we add Hot:
```rust
pub enum DomainPurpose {
    Sign,
    ForeignTx,
    CKD,
    Hot,
}
```

In the sign function, we need to check if we require a different key derivation function.
If so, then we also expect to require changes as well.

We add this endpoint:
```rust
// must be called by all nodes to add `pk` to the HOT domain
pub fn add_hot_domain(pk: public_key);
```
which will add `pk` to the next available domain_id once all nodes voted on that endpoint. It will do so only in case the contract is in running state.

## Importing secret key

We can add the following functionlity to the MPC node:

- an encrypted web-endpoint: `import_hot_sk`, which can be curld by the node operator and encrypts the imported secret key with `MPC_BACKUP_KEY_HEX`. This should be on a separate port than what we currently have for backup service and web-endpoint.
- import via CLI. Once imported, vote `add_hot_domain` on the contract

Alternative: include at startup once, pass as command-line argument.



How to test?
